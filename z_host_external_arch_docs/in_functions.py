import os
import re
import subprocess
from general import STANDARD_C_TYPES, is_standard_c_type, find_header_files, extract_comment_above

def find_function_calls(directory, patterns, ignore_paths):
    """
    Searches through .c and .h files for function calls matching given patterns,
    while ignoring specific paths and filenames.

    Parameters:
    - directory (str): The root directory to search in.
    - patterns (list of str): Function name fragments to grep for.
    - ignore_paths (list of str): Paths to exclude from results.

    Returns:
    - list of dicts: Each dict represents a function call with file, line number, etc.
    """
    lookup_table = []

    for pattern in patterns:
        print(f"Currently grepping for: {pattern}")  # Debug print
        escaped_pattern = re.escape(pattern)
        function_call_pattern = re.compile(r'\b([a-zA-Z0-9_]*' + escaped_pattern + r'[a-zA-Z0-9_]*)\s*\(')

        grep_pattern = rf'\b[a-zA-Z0-9_]*{pattern}[a-zA-Z0-9_]*\s*\('
        grep_command = f'grep -rnE "{grep_pattern}" {directory} --include="*.c" --include="*.h"'

        try:
            grep_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True)

            for line in grep_output.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                file_path, line_number, code_line = parts
                line_number = int(line_number.strip())

                if any(ignore_path in file_path for ignore_path in ignore_paths):
                    continue
                if "test" in file_path or "mock" in file_path or "classic" in file_path or pattern in file_path:
                    continue

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

    # # Debug print, comment in when needed.
    # print("Lookup table generated.")
    return lookup_table

def extract_function_patterns(groups):
    """
    Extracts short name patterns from functions in groups for grep searching.

    Parameters:
    - groups (dict): Dictionary with group data and their functions.

    Returns:
    - list of str: Extracted pattern names.
    """
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
    """
    Outputs all functions and their metadata into a simple text file for a given layer.

    Parameters:
    - all_groups (dict): All grouped function data.
    - layer (str): Current layer name for file naming.

    Returns:
    - None. Writes to a text file.
    """
    general_filename = f"{layer}_functions.txt"

    with open(general_filename, "w") as output_file:
        for group, details in all_groups.items():
            output_file.write(f"=== {details['name']} ({details['header_path']}) ===\n\n")

            for function in details['functions']:
                output_file.write(f"  function name: {function['func_name']}\n")  # Print function name
                output_file.write(f"  function: {function['full_function']}\n")    # Print function
                output_file.write(f"  Parameters: {function['parameters']}\n")     # Print function params
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
    Updates each function in the groups with usage information from the workspace.

    Parameters:
    - groups (dict): Grouped header/function data.
    - lookup_table (list of dicts): Function call locations.

    Returns:
    - None. Modifies groups in-place.
    """
    for group_key, group_data in groups.items():
        functions = group_data.get('functions', [])

        for function_dict in functions:
            func_name = function_dict.get('func_name')
            usage_list = []
            indices_to_remove = []

            for idx, usage in enumerate(lookup_table):
                if usage.get('function_name') == func_name and usage.get('type') == 'call':
                    file_path = usage.get('file_path')
                    line_number = usage.get('line_number')
                    usage_list.append(f"{file_path}:{line_number}")
                    indices_to_remove.append(idx)

            for index in reversed(indices_to_remove):
                del lookup_table[index]

            if len(usage_list) > 1:
                function_dict['usage in WS'] = usage_list
            else:
                group_name = group_data.get('name', '').lower()
                if 'internal' in group_name:
                    function_dict['usage in WS'] = "None: internal header function, why does this function exist? Just for tests?"
                else:
                    function_dict['usage in WS'] = "None: external header function, can be called by customers or from anywhere."

def extract_caller_groups(all_groups):
    """
    Analyzes usage paths and extracts unique caller groups and their parameter usage.

    Returns:
    - caller_groups (set): Unique group names where calls happen.
    - caller_group_params (dict): Mapping from caller group -> param_name -> description, source groups
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

                params = func.get("parameters", {})
                for param_name, param_info in params.items():
                    clean_param = param_info.get("clean_param", param_name)
                    desc = param_info.get("description", param_info.get("param", ""))
                    print("here")
                    print(f"{desc}")

                    if clean_param in caller_group_params[caller_group]:
                        caller_group_params[caller_group][clean_param]["groups"].add(group_name)
                    else:
                        caller_group_params[caller_group][clean_param] = {
                            "description": desc,
                            "groups": {group_name}
                        }

    return caller_groups, caller_group_params

def is_standard_c_type(clean_param):
    tokens = re.sub(r'[,*()]', '', clean_param).split()
    return all(tok in STANDARD_C_TYPES or tok in {"const", "volatile"} for tok in tokens)

def add_param_def_info(caller_group_params, header_list, layer, base_dir="."):
    """
    Searches headers for parameter definitions and adds them (and their comments) to the param info.

    Parameters:
    - caller_group_params (dict): Param info with caller group mappings.
    - header_list (list of str): Global header paths.
    - base_dir (str): Base path for relative formatting.

    Returns:
    - dict: Enhanced param info with def_location and improved description.
    """
    print("\nRetrieving parameter definition paths and descriptions.\n")
    grouped_params = caller_group_params

    for caller_group, params in grouped_params.items():
        if caller_group == layer:
            continue
        # Determine base folder from caller group name
        base_key = caller_group.split(" - ")[0]
        calling_headers = find_header_files(base_dir, base_key)

        for param_name, info in params.items():
            clean_param = param_name

            # Skip standard C types
            if is_standard_c_type(clean_param):
                continue

            found = False
            search_terms = set()

            # Extract struct or type names from param string
            struct_match = re.search(r"(struct\s+\w+)", clean_param)
            if struct_match:
                search_terms.add(struct_match.group(1))
            else:
                tokens = clean_param.replace("*", "").split()
                for tok in tokens:
                    if tok not in STANDARD_C_TYPES and tok not in {"const", "volatile"}:
                        search_terms.add(tok)

            # Search through the usual suspects
            zephyr_bt_include_dir = os.path.join(base_dir, "zephyr/include/zephyr/bluetooth")
            zephyr_bt_subsys_dir = os.path.join(base_dir, "zephyr/subsys/bluetooth/host")

            zephyr_bt_headers = []
            for root, _, files in os.walk(zephyr_bt_include_dir):
                for file in files:
                    if file.endswith(".h"):
                        zephyr_bt_headers.append(os.path.join(root, file))
            for root, _, files in os.walk(zephyr_bt_subsys_dir):
                for file in files:
                    if file.endswith(".h"):
                        zephyr_bt_headers.append(os.path.join(root, file))

            # Always include these
            zephyr_bt_headers.append(os.path.join(base_dir, "zephyr/include/zephyr/kernel.h"))
            zephyr_bt_headers.append(os.path.join(base_dir, "zephyr/include/zephyr/net_buf.h"))

            # Search through all candidate header files
            # This is taking WAY too long
            ##TODO: remove the "double" ones
            for header in header_list + calling_headers + zephyr_bt_headers:
                try:
                    with open(header, "r", encoding="utf-8") as f:
                        lines = f.readlines()

                    for idx, line in enumerate(lines):
                        for term in search_terms:
                            if re.search(rf"\b{re.escape(term)}\b.*[{{;]", line):
                            # # # # if re.search(rf"\bstruct\b.*\b{re.escape(term)}\b.*\{{", line):
                                comment = extract_comment_above(lines, idx)
                                info["def_location"] = f"{os.path.relpath(header, base_dir)}:{idx + 1}"

                                # Add comment only if relevant
                                if comment:
                                    if "None" in info["description"]:
                                        info["description"] = comment
                                    else:
                                        info["description"] += f" | {comment}"
                                else:
                                    if not info["description"]:
                                        info["description"] = "None available"
                                found = True
                                break
                        if found:
                            break
                except Exception:
                    continue

            if not found:
                info["def_location"] = "Not found."

    return grouped_params
