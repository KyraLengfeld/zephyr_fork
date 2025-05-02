import os
import re
import subprocess
from general import STANDARD_C_TYPES

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

def is_standard_c_type(param_str):
    tokens = re.split(r"[ *]+", param_str.replace("const", "").strip())
    return any(t in STANDARD_C_TYPES for t in tokens if t)

def find_header_files(base_dir, subdir):
    matching_headers = []
    for root, _, files in os.walk(os.path.join(base_dir, subdir)):
        if "test" in root or "mock" in root:
            continue
        for file in files:
            if file.endswith(".h"):
                matching_headers.append(os.path.join(root, file))
    return matching_headers

def extract_comment_above(lines, def_index):
    comment_lines = []
    i = def_index - 1
    while i >= 0:
        line = lines[i].strip()
        if line == "" or line.endswith("*/"):
            i -= 1
            continue
        if line.startswith("//") or line.startswith("/*") or line.startswith("/**"):
            comment_lines.insert(0, line.lstrip("/* ").rstrip("*/").strip())
            i -= 1
        else:
            break
    return " ".join(comment_lines) if comment_lines else None

def add_param_def_info(caller_group_params, header_list, base_dir="."):
    grouped_params = caller_group_params

    for caller_group, params in grouped_params.items():
        base_key = caller_group.split(" - ")[0]
        repo = caller_group.split(" - ")[-1]
        calling_headers = find_header_files(base_dir, base_key)

        for param_name, info in params.items():
            clean_param = param_name
            param_type = clean_param.replace(param_name, "").strip()
            if is_standard_c_type(clean_param):
                continue

            found = False
            search_terms = set()

            # Extract type for search term
            struct_match = re.search(r"(struct\s+\w+)", clean_param)
            if struct_match:
                search_terms.add(struct_match.group(1))
            else:
                tokens = clean_param.replace("*", "").split()
                for tok in tokens:
                    if tok not in STANDARD_C_TYPES and tok not in {"const", "volatile"}:
                        search_terms.add(tok)

            for header in header_list + calling_headers:
                try:
                    with open(header, "r", encoding="utf-8") as f:
                        lines = f.readlines()

                    for idx, line in enumerate(lines):
                        for term in search_terms:
                            if re.search(rf"\b{re.escape(term)}\b.*[{{;]", line):
                                # Found match
                                comment = extract_comment_above(lines, idx)
                                info["def_location"] = f"{os.path.relpath(header, base_dir)}:{idx + 1}"
                                if comment and "None" in info["description"]:
                                    info["description"] = comment
                                elif comment:
                                    info["description"] += f" | {comment}"
                                found = True
                                break
                        if found:
                            break
                except Exception as e:
                    continue

            if not found:
                info["def_location"] = "Not found, need to search manually"

    return grouped_params
