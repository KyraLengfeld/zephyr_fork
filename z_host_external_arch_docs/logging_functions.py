
from typing import List, Dict

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

def print_functions_moduels(all_groups, layer):
    # Define the filename for output based on the layer variable
    layers_filename = f"{layer}_functions_by_layers.txt"

    # Open the file for writing
    with open(layers_filename, "w") as output_file:
        output_file.write("Functions sorted by all_layers:\n\n")

        # Collect all possible layers dynamically by scanning non-empty usage_paths of functions
        all_layers = set()
        for group in all_groups.values():
            for function in group['functions']:
                valid_layers = {key for key, paths in function['usage_paths'].items() if paths}  # Only include non-empty paths
                all_layers.update(valid_layers)

        # Iterate through each subgroup (layer)
        for subgroup in sorted(all_layers):
            output_file.write(f"=== {subgroup} ===\n\n")

            # Track if any function is found in this subgroup
            found_any_function_in_subgroup = False

            for group in all_groups.values():
                for function in group['functions']:
                    # Check if this function has usage paths in the current subgroup
                    if subgroup in function['usage_paths'] and function['usage_paths'][subgroup]:
                        found_any_function_in_subgroup = True
                        output_file.write(f"  Function name: {function['func_name']}\n")
                        output_file.write(f"  {function['full_function']}\n")
                        output_file.write(f"  Parameters: {function['parameters']}\n")
                        # output_file.write("  Parameters:\n")
                        # for param_name, param_info in function['parameters'].items():
                        #     if 'description' in param_info:
                        #         output_file.write(f"    {param_info['clean_param']}: {param_info['description']}\n")
                        #     else:
                        #         output_file.write(f"    {param_info['clean_param']}\n")
                        # output_file.write(f"  Description: {function['description']}\n")

                        # Print all paths associated with this function in the subgroup
                        for path in function['usage_paths'][subgroup]:
                            output_file.write(f"      {path}\n")

                        output_file.write("\n")

            # If no functions were found for any group in this subgroup, write a message
            if not found_any_function_in_subgroup:
                output_file.write("  No functions found in this subgroup.\n\n")

    print(f"Output saved to {layers_filename}")

def print_functions_groups(all_groups, layer):
    # Define the filename for output based on the layer variable
    layers_filename = f"{layer}_functions_with_layers.txt"

    # Open the file for writing
    with open(layers_filename, "w") as output_file:

        output_file.write("Functions with layers:\n\n")
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
                output_file.write(f"  Description: {function['description']}\n")  # Print function description
                for subgroup, paths in function['usage_paths'].items():
                    if paths:
                        output_file.write(f"    {subgroup}\n")

    print(f"Output saved to {layers_filename}")

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

def write_in_info(all_groups, output_path):
    """
    Write info about the chosen layer's function to a text file.

    Args:
        all_groups (dict): A dictionary where each key is a group name and each value is a dict
                           with group metadata (e.g., name, header_path, and list of functions).
                           Each function entry includes keys like 'full_function', 'func_name',
                           'description', 'parameters', and 'usage in WS'.
        output_path (str): Path to the output text file to be written.

    Returns:
        None. Writes formatted content to the specified file.
    """
    with open(output_path, "w") as f:
        for group_key, group in all_groups.items():
            f.write(f"Group: {group['name']}\n")
            f.write(f"Header: {group['header_path']}\n\n")

            for func in group.get("functions", []):
                f.write(f"  Function: {func['func_name']}\n")
                f.write(f"    Full Function: {func['full_function']}\n")
                f.write(f"    Description: {func['description']}\n")

                for param_name, param_info in func.get("parameters", {}).items():
                    clean_param = param_info.get("clean_param", param_name)
                    description = param_info.get("description")
                    if description:
                        f.write(f"      {clean_param}: {description}\n")
                    else:
                        f.write(f"      {clean_param}\n")

                f.write(f"    Usage in WS:\n")
                usage = func.get("usage in WS", [])
                if isinstance(usage, list):
                    for u in usage:
                        f.write(f"      - {u}\n")
                elif isinstance(usage, str):
                    f.write(f"      {usage}\n")
                else:
                    f.write(f"      N/A\n")

                f.write("\n")  # space between functions
            f.write("\n" + "="*60 + "\n\n")  # separator between groups

def write_output_to_file(function_calls: Dict[str, Dict[str, Dict[str, List[str]]]], output_file: str) -> None:
    with open(output_file, 'w') as f:
        for file, data in function_calls.items():
            f.write(f"File: {file}\n")
            if "function_declarations" in data:
                for func, locations in data["function_declarations"].items():
                    f.write(f"  {func} (declared):\n")
                    for loc in locations:
                        f.write(f"    - {loc}\n")
            if "function_calls" in data:
                for func, locations in data["function_calls"].items():
                    f.write(f"  {func} (called):\n")
                    for loc in locations:
                        f.write(f"    - {loc}\n")
            f.write("\n")

def write_caller_group_params_to_file(caller_group_params, filepath, layer):
    layer_upper = layer.upper()

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"## Which resources and callbacks enter the {layer_upper} module and to where.\n")
        for group in sorted(caller_group_params):
            # Upper-case the first word of the group
            parts = group.split()
            if parts:
                group_upper = parts[0].upper() + " " + " ".join(parts[1:])
            else:
                group_upper = group

            f.write(f"### {group_upper}\n\n")
            f.write(f"|Parameter|{layer_upper} group|Description|Defined at|\n")
            f.write(f"|---------|-------------|-----------|----------|\n")

            lines = []

            for clean_param, info in caller_group_params[group].items():
                group_list = sorted(info["groups"])
                group_str = ", ".join(group_list)
                lines.append((clean_param, group_str, info.get("description", "None"), info.get("def_location", "")))

            for clean_param, group_str, desc, def_loc in lines:
                f.write(f"|{clean_param}|{group_str}|{desc}|{def_loc}|\n")

            f.write("\n")
