import os
import re
import subprocess

def find_function_calls(directory, patterns, ignore_paths):
    lookup_table = []

    for pattern in patterns:

        print(f"Currently grepping for: {pattern}")
        # Compile a regex to extract function calls for this pattern
        escaped_pattern = re.escape(pattern)
        function_call_pattern = re.compile(r'\b([a-zA-Z0-9_]*' + escaped_pattern + r'[a-zA-Z0-9_]*)\s*\(')

        # Construct the grep command for the current pattern
        grep_pattern = rf'\b[a-zA-Z0-9_]*{pattern}[a-zA-Z0-9_]*\s*\('

        grep_command = (f'grep -rnE "{grep_pattern}" {directory} --include="*.c" --include="*.h"')

        try:
            grep_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True)

            for line in grep_output.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                file_path, line_number, code_line = parts
                line_number = int(line_number.strip())

                # Skip unwanted paths
                if any(ignore_path in file_path for ignore_path in ignore_paths):
                    continue
                if "test" in file_path or "mock" in file_path or "classic" in file_path or pattern in file_path:
                    continue

                # Match the function call line and extract function name
                matches = function_call_pattern.finditer(code_line)
                for match_call in matches:
                    function_name = match_call.group(1)
                    file_path = file_path.replace("./", "")
                    lookup_table.append({
                        'function_name': function_name,
                        'file_path': file_path,
                        'line_number': line_number,
                        'type': 'call'
                    })

        except Exception as e:
            print(f"Error running grep for pattern '{pattern}': {e}")

    print("Lookup table generated and saved to file.")
    return lookup_table

def extract_function_patterns(groups):
    patterns = []

    for group in groups.values():
        for func in group.get('functions', []):
            name = func.get('func_name', '')
            if name.startswith('bt_'):
                parts = name.split('_')
                if len(parts) >= 2:
                    pattern = f'bt_{parts[1]}'
                    if pattern not in patterns:
                        patterns.append(pattern)
            else:
                if name not in patterns:
                    patterns.append(name)

    return patterns


def print_functions_simple(all_groups, layer):
    general_filename = f"{layer}_functions.txt"

    with open(general_filename, "w") as output_file:
        for group, details in all_groups.items():
            output_file.write(f"=== {details['name']} ({details['header_path']}) ===\n")
            output_file.write("\n")

            for function in details['functions']:

                output_file.write(f"  function name: {function['func_name']}\n")  # Print function name
                output_file.write(f"  function: {function['full_function']}\n")  # Print function
                output_file.write(f"  Parameters: {function['parameters']}\n")  # Print function params
                # output_file.write("  Parameters:\n")
                # for param_name, param_info in function['parameters'].items():
                #     if 'description' in param_info:
                #         output_file.write(f"    {param_info['clean_param']}: {param_info['description']}\n")
                #     else:
                #         output_file.write(f"    {param_info['clean_param']}\n")
                # output_file.write(f"  Description: {function['description']}\n")  # Print function description
                for subgroup, paths in function['usage_paths'].items():
                    if paths:
                        output_file.write(f"    {subgroup}:\n")
                        for path in paths:
                            output_file.write(f"      {path}\n")
                    output_file.write("\n")
                output_file.write("\n")

    print(f"Output saved to {general_filename}")

def add_usage_to_groups(groups, lookup_table):
    """
    Enhances each function in the 'groups' dictionary by adding a 'usage in WS' key.
    This key contains a list of all locations where the function is called, based on the lookup_table.
    If there are no usages found, the value will be the string "none".

    Parameters:
    - groups (dict): Dictionary structured as:
        groups[group_key] = {
            'name': filename,
            'header_path': header_path,
            'functions': [
                {
                    'full_function': ...,
                    'func_name': ...,
                    'description': ...,
                    'parameters': ...,
                },
                ...
            ]
        }

    - lookup_table (list): List of dictionaries, each like:
        {
            'function_name': ...,
            'file_path': ...,
            'line_number': ...,
            'type': 'call'
        }

    Returns:
    - None. The function modifies the 'groups' dictionary in-place.
    """

    # Iterate over all groups
    for group_key, group_data in groups.items():
        # Make sure 'functions' is present and is a list
        functions = group_data.get('functions', [])

        for function_dict in functions:
            func_name = function_dict.get('func_name')
            usage_list = []

            # We'll track indices to remove after the loop (can't modify list during iteration)
            indices_to_remove = []

            for idx, usage in enumerate(lookup_table):
                if usage.get('function_name') == func_name and usage.get('type') == 'call':
                    file_path = usage.get('file_path')
                    line_number = usage.get('line_number')
                    usage_list.append(f"{file_path}:{line_number}")
                    indices_to_remove.append(idx)

            # Remove used entries from lookup_table in reverse order (to keep indexing correct)
            for index in reversed(indices_to_remove):
                del lookup_table[index]

            if len(usage_list) > 1:
                function_dict['usage in WS'] = usage_list
            else:
                # Determine if group name contains 'internal' (case-insensitive)
                group_name = group_data.get('name', '').lower()
                if 'internal' in group_name:
                    function_dict['usage in WS'] = "None: internal header function, why does this function exist? Just for tests?"
                else:
                    function_dict['usage in WS'] = "None: external header function, can be called by customers or from anywhere."

def extract_caller_groups(all_groups):
    """
    Extracts unique caller groups and maps them to parameters used in functions called within them.

    Returns:
        caller_groups (set): Set of all caller group names.
        caller_group_params (dict): Dict mapping caller group -> param_name -> {description, group}
    """
    caller_groups = set()
    caller_group_params = {}

    for group in all_groups.values():
        group_name = group.get("name", "Unknown Group")
        for func in group.get("functions", []):
            usage_list = func.get("usage in WS", [])
            if isinstance(usage_list, str):
                if usage_list.strip().lower().startswith("none"):
                    continue
                usage_list = [usage_list]

            for usage_path in usage_list:
                path = usage_path.split(":")[0].strip()
                if path.lower().startswith("none"):
                    continue

                parts = path.split("/")
                if len(parts) < 2:
                    continue

                # Detect repo
                repo = parts[0]
                caller_group = None

                if repo not in {"zephyr", "nrf"}:
                    caller_group = path
                else:
                    try:
                        if repo == "zephyr":
                            if parts[1] == "subsys":
                                if parts[2] == "bluetooth":
                                    if parts[3] == "host":
                                        filename = os.path.basename(path)
                                        caller_group = f"{filename.split('.')[0]} - zephyr"
                                    else:
                                        caller_group = f"{parts[3]} - zephyr"
                                else:
                                    caller_group = f"{parts[2]} - zephyr"
                            else:
                                caller_group = f"{parts[1]} - zephyr"
                        elif repo == "nrf":
                            if parts[1] == "samples":
                                caller_group = "samples - nrf"
                            elif parts[1] == "subsys":
                                if parts[2] == "bluetooth":
                                    caller_group = f"{parts[3]} - nrf"
                                else:
                                    caller_group = f"{parts[2]} - nrf"
                            else:
                                caller_group = f"{parts[1]} - nrf"
                    except IndexError:
                        caller_group = path

                if not caller_group or caller_group.lower() == "none":
                    continue

                caller_groups.add(caller_group)
                if caller_group not in caller_group_params:
                    caller_group_params[caller_group] = {}

                # Process parameters
                params = func.get("parameters", {})
                for param_name, param_info in params.items():
                    clean_param = param_info.get("clean_param", param_name)
                    desc = param_info.get("description", param_info.get("param", ""))

                    if clean_param in caller_group_params[caller_group]:
                        caller_group_params[caller_group][clean_param]["groups"].add(group_name)
                    else:
                        caller_group_params[caller_group][clean_param] = {
                            "description": desc,
                            "groups": {group_name}
                        }

    return caller_groups, caller_group_params

def write_caller_group_params_to_file(caller_group_params, filepath, layer):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"====== Input parameters sorted in modules that call {layer} functions ======\n")
        for group in sorted(caller_group_params):
            f.write(f"=== {group} ===\n")

            lines = []
            max_param_len = 0

            for clean_param, info in caller_group_params[group].items():
                group_list = sorted(info["groups"])
                group_str = ", ".join(group_list)
                desc = info["description"] if info["description"] else "None"
                lines.append((clean_param, group_str, desc))
                max_param_len = max(max_param_len, len(clean_param))

            for clean_param, group_str, desc in lines:
                padding = " " * (max_param_len - len(clean_param) + 2)  # +2 for spacing
                f.write(f"  {clean_param}{padding}({group_str})\n")
                f.write(f"    Description: {desc}\n")

            f.write("\n")
