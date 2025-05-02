import os
import re
import json
import subprocess
from typing import List, Dict
from collections import Counter

# Compile the regex patterns once
SINGLE_LINE_COMMENT_PATTERN = re.compile(r'^\s*//')
BLOCK_COMMENT_START_PATTERN = re.compile(r'/\*')
BLOCK_COMMENT_END_PATTERN = re.compile(r'\*/')

# Function to find header files containing the specified word in their names
def find_headers(word, directory='zephyr'):
    # Create a regex pattern to match the word in the filename (case-insensitive)
    pattern = re.compile(r'(^|[^a-zA-Z0-9])' + re.escape(word) + r'([^a-zA-Z0-9]|$)', re.IGNORECASE)

    # List to store matched file paths
    header_list = []

    # Walk through the 'zephyr' directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        # Skip unwanted directories early
        dirs[:] = [d for d in dirs if not any(excluded in d.lower() for excluded in ['test', 'mock', 'mesh', 'audio', 'classic', 'services', 'mcumgr', 'net', 'll_sw'])]

        for file in files:
            # Check if file ends with .h and matches the pattern
            if file.endswith('.h') and pattern.search(file):
                # Add the full path to the header list
                header_list.append(os.path.join(root, file))

    return header_list


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

def contains_groups(filename):
    with open(filename, 'r') as file:
        for line in file:
            if '@defgroup' in line:
                return True
    return False

def extract_function_calls(target_function, lookup_table):
    """
    Extracts all occurrences of the given function name from the lookup_table.

    :param target_function: The function name to search for.
    :param lookup_table: The list of dictionaries containing function calls.
    :return: A dictionary where the function name is the key, and the value is a list of file paths and line numbers.
    """
    function_calls = {}

    # Create an empty list to store found occurrences
    function_calls[target_function] = []

    # Create a new list without the found instances
    remaining_entries = []

    for entry in lookup_table:
        if entry['function_name'] == target_function:
            # If the function name matches exactly, store the path and line number
            function_calls[target_function].append({
                'file_path': entry['file_path'],
                'line_number': entry['line_number']
            })
        else:
            # Keep non-matching entries in the lookup table
            remaining_entries.append(entry)

    # Update lookup_table to remove found instances
    lookup_table[:] = remaining_entries  # Modify the list in-place

    return function_calls

def categorize_paths(paths_and_lines):
    """
    Categorizes file paths based on predefined groups and includes line numbers.

    :param paths_and_lines: List of dictionaries containing 'file_path' and 'line_number'.
    :return: A dictionary grouping the paths and their line numbers.
    """
    grouped_paths = {
        "SAMPLE": [],
        "L2CAP": [],
        "GATT": [],
        "ATT": [],
        "SMP": [],
        "HCI": [],
        "IPC": [],
        "DRIVERS": [],
        "SERVICES": [],
        "OTHER": []
    }

    for entry in paths_and_lines:
        path = entry['file_path']
        line_number = entry['line_number']
        categorized_entry = f"{path}:{line_number}"  # Include line number in the entry

        if "sample" in path:
            grouped_paths["SAMPLE"].append(categorized_entry)
        elif "l2cap" in path:
            grouped_paths["L2CAP"].append(categorized_entry)
        elif "gatt" in path:
            grouped_paths["GATT"].append(categorized_entry)
        elif "att" in path:
            grouped_paths["ATT"].append(categorized_entry)
        elif "smp" in path:
            grouped_paths["SMP"].append(categorized_entry)
        elif "hci" in path:
            grouped_paths["HCI"].append(categorized_entry)
        elif "ipc" in path:
            grouped_paths["IPC"].append(categorized_entry)
        elif "driver" in path:
            grouped_paths["DRIVERS"].append(categorized_entry)
        elif "service" in path:
            grouped_paths["SERVICES"].append(categorized_entry)
        else:
            grouped_paths["OTHER"].append(categorized_entry)

    # Now, return a deep copy of the lists inside the dictionary to avoid sharing references.
    return {key: list(value) for key, value in grouped_paths.items()}

def get_brief_comment(lines, current_line, function_name):
    """
    Searches for the nearest @brief or block comment above a function definition.
    Processes the comment block, checking for @file or @group to determine if it
    should be used as the function description.

    :param lines: List of all lines in the file.
    :param current_line: The line number where the function is defined.
    :param function_name: The name of the function.
    :return: Extracted description or function name as a fallback.
    """
    function_description = function_name.replace('_', ' ')  # Default to function name as description
    temp_description = None  # To temporarily store valid comment description
    local_curr_line = current_line

    for i in range(current_line - 1, -1, -1):  # Loop upwards through the file
        line = lines[i].strip()
        # Check if it's the start of a comment block
        if line.startswith('/*') or line.startswith('/**'):
            temp_description = re.sub(r'/\*\*?|\*/', '', line).strip()  # Remove block comment markers
            not_func_comment = False
            local_curr_line = i
            for local_curr_line in range(local_curr_line, current_line + 1, 1):
                block_line = lines[local_curr_line].strip()
                # Check if @file or @group exists within this comment block
                if "@file" in block_line or "@group" in block_line:
                    not_func_comment = True
                    break

            if not_func_comment:
                break
            # Process the description if no @file/@group is found
            if "@brief" in temp_description:
                temp_description = temp_description.replace('@brief', '').strip()

            # Save only the first sentence (or the entire line if no period)
            temp_description = temp_description.split('.')[0] if '.' in temp_description else temp_description

            # If we have a valid description, set it as the function description
            if temp_description:
                function_description = temp_description
                break

        # If a function declaration or end of comment block is reached, break
        elif ');' in line:
            break

    # Return the description, falling back to the function name if no description is found
    return function_description

def get_params(lines, function_line):
    """
    Extracts function parameters and their descriptions from preceding comments.

    :param lines: List of lines from a source file.
    :param function_line: The index of the function definition line.
    :return: Dictionary of parameters with their types and descriptions.
    """
    function_signature = ''

    # Start from the function definition and accumulate the full parameter list
    for i in range(function_line, len(lines)):
        line = lines[i].strip()

        # If we are at the function definition line
        if i == function_line:
            if ");" in line:
                # Single-line function definition
                params_part = line.split('(')[1].split(')')[0]
                function_signature += params_part
                break  # Done parsing parameters
            else:
                # Multi-line function, start accumulating
                params_part = line.split('(')[1]
                function_signature += params_part
                continue

        elif ");" in line:
            # End of function parameter list
            params_part = line.split(')')[0]  # Everything up to the closing bracket
            function_signature += ' ' + params_part
            break  # Stop processing

        else:
            # Accumulate multi-line parameters
            function_signature += ' ' + line.strip()

    # Normalize whitespace
    function_signature = re.sub(r'\s+', ' ', function_signature).strip()

    # Split parameters by commas (handling cases like `int (*func)(int, float)` correctly)
    raw_params = function_signature.split(',')
    cleaned_params = [param.strip() for param in raw_params]

    # Extract parameter names (including pointers and array indicators)
    function_params = {}
    for param in cleaned_params:
        words = param.split()
        if len(words) > 1:
            last_word = words[-1]  # Last word is typically the variable name
            function_params[last_word] = param  # Store full declaration

    # Now, search for @param descriptions in the preceding comment block
    for i in range(function_line - 1, -1, -1):  # Loop upwards through the file
        line = lines[i].strip()

        if line.startswith('/*') or line.startswith('/**'):
            break  # Stop when reaching start of comment block
        elif ');' in line:
            break  # Stop if another function is encountered

        # Match @param comments
        for param_name in function_params.keys():
            match = re.search(rf'@param\s+{re.escape(param_name)}\s+(.*)', line)
            if match:
                description = match.group(1).strip()
                function_params[param_name] = {
                    'param': function_params[param_name],
                    'description': description
                }

    return function_params

def find_usage_of_funcs(target_function, lookup_table):
    """
    Finds all occurrences of the given function name in the lookup_table and removes them from it.

    :param target_function: The function name to search for.
    :param lookup_table: The list of dictionaries containing function calls.
    :return: A dictionary where the function name is the key, and the value is a list of dictionaries with file paths and line numbers.
    """
    function_calls = {target_function: []}
    remaining_entries = []

    for entry in lookup_table:
        if entry['function_name'] == target_function:
            function_calls[target_function].append({
                'file_path': entry['file_path'],
                'line_number': entry['line_number']
            })
        else:
            remaining_entries.append(entry)

    # Remove found function calls from lookup_table
    lookup_table[:] = remaining_entries

    return function_calls

def extract_multiline_function_name(func_description, lines, start_idx):
    """Extracts a multiline function definition by appending lines until encountering ');'."""
    i = start_idx
    while i < len(lines):
        line = lines[i].strip()

        if ");" in line:
            func_description += " " + line.strip()
            break
        else:
            func_description += " " + line.strip()

        i += 1  # Move to the next line

    return func_description

def extract_function_name(function_line):
    """
    Extracts the function name from a function signature by removing C data types.

    :param function_line: The function signature as a string.
    :return: The extracted function name.
    """
    c_types = ['static', 'extern', 'register', 'auto', 'inline', 'int', 'short', 'long',
               'signed', 'unsigned', 'char', 'bool', 'uint8_t', 'uint16_t', 'uint32_t',
               'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'float', 'double',
               'long double', 'void', '_Bool', 'volatile', 'const', 'restrict']

    for keyword in sorted(c_types, key=len, reverse=True): # Sort by length to avoid partial replacements
        function_line = re.sub(r'\b' + re.escape(keyword) + r'\b', '', function_line)

    function_name = function_line.strip().split('(')[0].strip()
    return function_name

def add_external_internal(header_path, file_name):
    if file_name:
        file_name += ", "
    if "internal" in header_path:
        file_name += "internal"
    else:
        file_name += "external"
    return file_name

def save_function_names(header_path, are_groups):
    """
    Extracts functions from a header file, categorizes them into groups,
    and tracks where they are used.

    :param header_path: The file path of the header file being analyzed.
    :param are_groups: Boolean indicating whether the header file contains @defgroup sections.
    :return: A dictionary mapping groups to functions and their usage paths.
    """
    groups = {}
    idx_groups = 0
    group_key = None

    # Open the file for reading
    with open(header_path, 'r') as file:
        lines = file.readlines()

        if not are_groups:
            # If there are no groups, create a single group named after the file
            file_name = os.path.basename(header_path)
            stripped_fn = file_name.removesuffix(".h")
            filename = add_external_internal(header_path, stripped_fn)
            group_key = 'group_0'
            groups[group_key] = {
                'name': filename,
                'header_path': header_path,
                'functions': []
            }

        # go line by line, until you find "@defgroup" in the file
        # i = 0
        for i in range(len(lines)):
            line = lines[i].strip()

            # Look for lines containing '@defgroup'
            if are_groups and '@defgroup' in line:
                # Extract the group name by removing the '@defgroup' part
                group_name = line.replace('* @defgroup', '').strip()
                filename = add_external_internal(header_path, group_name)

                # Increment group index and create a new group key
                idx_groups += 1
                group_key = f'group_{idx_groups}'
                # Initialize the group in the dictionary
                groups[group_key] = {
                    'name': filename,
                    'header_path': header_path,
                    'functions': []
                }
            elif group_key and re.search(r"\(", line): # possible function start
                if re.search(r'\b(memset|typedef|define|return|{|=|:|\)\()\b', line):
                    continue # exclude all you know is not a function
                else:
                    # function found in group
                    line = line.lstrip()
                    full_function = line

                    if full_function.lstrip().startswith("*") or full_function.lstrip().startswith("#"):
                        continue # this is a comment with a function, skip

                    # multiline definition
                    if ");" not in line:
                        full_function = extract_multiline_function_name(full_function, lines, i+1)

                    # Match everything from the start up to the first '*' (only if '*' appears before '(')
                    match = re.match(r'^[^(\n]*\*\s*(.*)', line)
                    if match:
                        line = match.group(1)  # Keep everything after '*'

                    # Extract function name
                    function_name = extract_function_name(line)

                    # Ensure function name is entirely lowercase before '('
                    if not function_name.islower() or " " in function_name:
                        # seems this was not a function
                        continue

                    if function_name == "if" or function_name == "switch":
                        continue

                    # Extract function description from preceding comments
                    func_description = get_brief_comment(lines, i, function_name)

                    # Extract function parameters and their descriptions
                    params = get_params(lines, i)


                    # Add function with usage paths to the dictionary
                    groups[group_key]['functions'].append({
                        'full_function': full_function,
                        'func_name': function_name,
                        'description': func_description,
                        'parameters': params,
                    })

    return groups

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
                output_file.write(f"  Description: {function['description']}\n")  # Print function description
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
                        output_file.write(f"  Description: {function['description']}\n")

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
                output_file.write(f"  Description: {function['description']}\n")  # Print function description
                for subgroup, paths in function['usage_paths'].items():
                    if paths:
                        output_file.write(f"    {subgroup}\n")

    print(f"Output saved to {layers_filename}")

def sanitize_filename(name):
    """Sanitizes the filename to remove problematic characters."""
    return re.sub(r"[^\w\d_-]", "_", name)

def generate_uml_sequence_diagrams(all_groups, layer):
    """
    Generates a UML sequence diagram in PlantUML format for function calls into the specified layer.

    :param all_groups: A dictionary mapping modules to function calls.
    :param layer: The API layer for which to generate the diagram.
    :return: None (saves the diagram as a .puml file).
    """
    layer = layer.upper()

    color_mapping = {
        "SAMPLE": "green",
        "L2CAP": "purple",
        "GAP": "darkblue",
        "GATT": "blue",
        "ATT": "lightblue",
        "SMP": "gold",
        "HCI": "pink",
        "IPC": "red",
        "DRIVERS": "lightyellow",
        "SERVICES": "gray",
        "OTHER": "fuchsia"
    }

    # Iterate through all the groups in all_groups
    for group, details in all_groups.items():
        # Ensure 'functions' exist in the group
        if "functions" not in details or not details["functions"]:
            continue  # Skip empty groups

        # Sanitize group name for filename
        group_name_sanitized = sanitize_filename(details["name"])

        # Create a separate UML file per group
        uml_filename = f"{layer}_{group_name_sanitized}_uml.puml"

        with open(uml_filename, "w") as uml_file:
            uml_file.write("@startuml\n")
            uml_file.write(f"title Function Call Flow to {layer} {details['name']} API\n\n")

            participants = []
            for key in color_mapping:
                if layer not in key: # want to add the layer in question in the end
                    participants.append(key)
            participants.append(layer)  # Add the API layer as a participant

            # Define participants in the UML diagram
            for participant in participants:
                color = color_mapping.get(participant)
                uml_file.write(f"participant \"{participant}\" as {participant} #{color}\n")

            last_function_name = "UnknownFunction"
            # Iterate through all functions in the group
            for function in details["functions"]:
                function_name = function.get("func_name", "UnknownFunction")
                description = function.get("description", "No description available")
                parameters = function.get("parameters", {})


                # Check if function is used in any `usage_path`
                if function.get("usage_paths"):
                    for usage_path, paths in function["usage_paths"].items():
                        if paths:

                            if last_function_name is not function_name:
                                # Add a note over all
                                uml_file.write(f"note over {usage_path}: {description} \\nParameters: {parameters}\n")

                            # Write function call from usage_path to the layer
                            # unfortunately, this doesn't work
                            # color = color_mapping.get(usage_path)
                            # uml_file.write(f"{usage_path} -> {layer}: {function_name} #{color}\n")
                            uml_file.write(f"{usage_path} -> {layer}: {function_name}\n")
                            last_function_name = function_name

            uml_file.write("@enduml\n")

        print(f"UML sequence diagram saved as {uml_filename}")

import subprocess

def generate_deployment_diagrams(all_groups, layer):
    """
    Generates a structured UML deployment diagram (deployment-style) in PlantUML format,
    with one output file per group. The layout is forced into a grid as follows:

    - Top Left: standalone node "OTHER"
    - Top Right: "APP" box containing nodes "SAMPLE" and "SERVICES" (side by side)
    - Below OTHER (left column): node "SMP"
    - Then, in the left column (middle): an "Attributes" box containing nodes "GATT" and "ATT"
         (if the analyzed layer is GATT or ATT, remove it so that only the other remains;
          if only one remains, do not use a box)
    - Middle Right: a standalone (and “larger”) node for the analyzed layer
    - Bottom Left: standalone node "L2CAP"
    - Bottom Right: a "System" box containing nodes "IPC", "DRIVERS", and "HCI" (arranged horizontally)

    Hidden links are added to force grid-like alignment.

    :param all_groups: dict mapping group names to group details (each with a "name" and "functions")
    :param layer: the API layer (e.g. "GATT", "L2CAP", etc.)
    :return: None (saves one .puml file per group)
    """
    layer = layer.upper()

    # Color mapping for modules
    color_mapping = {
        "SAMPLE": "green",
        "L2CAP": "purple",
        "GAP": "darkblue",
        "GATT": "blue",
        "ATT": "lightblue",
        "SMP": "gold",
        "HCI": "pink",
        "IPC": "red",
        "DRIVERS": "lightyellow",
        "SERVICES": "gray",
        "OTHER": "fuchsia"
    }

    # Define static layout clusters (using our desired grid positions)
    # Note: We leave out "Attributes" if the analyzed layer is one of those.
    attributes_modules = ["GATT", "ATT"]
    if layer in attributes_modules:
        attributes_modules.remove(layer)  # e.g., if layer == "GATT", then only "ATT" remains.

    for group, details in all_groups.items():
        # Skip groups with no functions
        if "functions" not in details or not details["functions"]:
            continue

        group_name_sanitized = sanitize_filename(details["name"])
        uml_filename = f"{layer}_{group_name_sanitized}_vertical_deployment.puml"

        with open(uml_filename, "w") as uml_file:
            uml_file.write("@startuml\n")
            uml_file.write(f"title Vertical Deployment Diagram: {layer} {details['name']} API\n\n")

            # Global layout parameters
            uml_file.write("skinparam ranksep 50\n")
            uml_file.write("skinparam nodesep 40\n")
            uml_file.write("left to right direction\n\n")

            # --- Left Column ---
            # Top left: OTHER node
            uml_file.write(f'node "OTHER" as OTHER #{color_mapping["OTHER"]}\n\n')

            # Below OTHER: SMP node
            uml_file.write(f'node "SMP" as SMP #{color_mapping["SMP"]}\n\n')

            # Middle left: Attributes box (if both remain, use a package; if only one remains, output as standalone)
            if len(attributes_modules) == 2:
                uml_file.write("package \"Attributes\" {\n")
                for module in attributes_modules:
                    uml_file.write(f'  node "{module}" as {module} #{color_mapping[module]}\n')
                uml_file.write("}\n\n")
            elif len(attributes_modules) == 1:
                module = attributes_modules[0]
                uml_file.write(f'node "{module}" as {module} #{color_mapping[module]}\n\n')

            # Bottom left: L2CAP node
            uml_file.write(f'node "L2CAP" as L2CAP #{color_mapping["L2CAP"]}\n\n')

            # --- Right Column ---
            # Top right: APP box with SAMPLE and SERVICES (side by side)
            uml_file.write("package \"APP\" {\n")
            uml_file.write(f'  node "SAMPLE" as SAMPLE #{color_mapping["SAMPLE"]}\n')
            uml_file.write(f'  node "SERVICES" as SERVICES #{color_mapping["SERVICES"]}\n')
            uml_file.write("}\n\n")

            # Middle right: The analyzed layer node (make it “bigger” by using a stereotype)
            uml_file.write(f'node "{layer}" as LAYER #{color_mapping.get(layer, "white")}\n')

            # Bottom right: System box with IPC, DRIVERS, and HCI arranged horizontally.
            uml_file.write("package \"System\" {\n")
            uml_file.write(f'  node "IPC" as IPC #{color_mapping["IPC"]}\n')
            uml_file.write(f'  node "DRIVERS" as DRIVERS #{color_mapping["DRIVERS"]}\n')
            uml_file.write(f'  node "HCI" as HCI #{color_mapping["HCI"]}\n')
            uml_file.write("}\n\n")

            # --- Hidden links to force grid alignment ---
            # Left column hidden links (top to bottom): OTHER -> SMP -> (Attributes or its first node) -> L2CAP
            uml_file.write("OTHER -[hidden]-> SMP\n")
            if len(attributes_modules) >= 1:
                # if Attributes is a package, link from SMP to the first node inside (we choose the first in the list)
                first_attr = attributes_modules[0] if isinstance(attributes_modules, list) else attributes_modules
                uml_file.write(f"SMP -[hidden]-> {first_attr}\n")
            uml_file.write("SMP -[hidden]-> L2CAP\n")

            # Right column hidden links: APP -> LAYER -> (first node of System)
            uml_file.write("SAMPLE -[hidden]-> LAYER\n")
            uml_file.write("LAYER -[hidden]-> IPC\n\n")

            # --- Function Call Dependencies ---
            # Build a dictionary of function dependencies based on usage_paths.
            function_dependencies = {}
            for function in details["functions"]:
                function_name = function.get("func_name", "UnknownFunction")
                if function.get("usage_paths"):
                    for usage_path, paths in function["usage_paths"].items():
                        if paths:  # Only consider if there are nonempty paths
                            function_dependencies.setdefault(usage_path, []).append(function_name)

            # For each source module, add a note (grouping calls) and arrows to the layer node.
            for source_module, function_list in function_dependencies.items():
                unique_functions = set(function_list)
                # functions_str = "\\n".join(unique_functions)
                # uml_file.write(f'note right of {source_module}: Calls to {layer}:\\n{functions_str}\n')
                for fname in unique_functions:
                    uml_file.write(f"{source_module} --> LAYER: {fname}\n")

            uml_file.write("@enduml\n")
        subprocess.run(["java", "-jar", "plantuml.jar", "-tsvg", uml_filename])
        print(f"Vertical deployment diagram saved as {uml_filename}")

def generate_deployment_diagram(all_groups, layer):
    """
    Generates a structured UML deployment diagram in PlantUML format for all groups in one diagram.

    :param all_groups: A dictionary mapping modules to function calls.
    :param layer: The API layer for which to generate the diagram.
    :return: None (saves the diagram as a single .puml file).
    """
    layer = layer.upper()

    # Define colors for different modules
    color_mapping = {
        "SAMPLE": "green",
        "L2CAP": "purple",
        "GAP": "darkblue",
        "GATT": "blue",
        "ATT": "lightblue",
        "SMP": "gold",
        "HCI": "pink",
        "IPC": "red",
        "DRIVERS": "lightyellow",
        "SERVICES": "gray",
        "OTHER": "fuchsia"
    }

    # Define logical groups of clusters
    group_clusters = {
        "Application": ["SAMPLE"],
        "Networking": ["L2CAP", "GAP"],
        "Bluetooth Core": ["GATT", "ATT", "SMP", "HCI"],
        "System Services": ["IPC", "DRIVERS", "SERVICES"],
        "Other": ["OTHER"]
    }

    # Start writing the UML diagram
    uml_filename = f"{layer}_deployment.puml"
    with open(uml_filename, "w") as uml_file:
        uml_file.write("@startuml\n")
        uml_file.write(f"title Deployment Diagram: {layer} API\n\n")

        # Force a vertical top-down structure
        uml_file.write("skinparam ranksep 50\n")
        uml_file.write("skinparam nodesep 40\n")
        uml_file.write("left to right direction\n\n")

        # Generate clusters dynamically for all groups
        previous_module = None
        for cluster, modules in group_clusters.items():
            uml_file.write(f"package \"{cluster}\" {{\n")
            for module in modules:
                color = color_mapping.get(module, "white")
                uml_file.write(f"  node \"{module}\" as {module} #{color}\n")

                # Ensure vertical stacking with hidden links
                if previous_module:
                    uml_file.write(f"{previous_module} -[hidden]-> {module}\n")
                previous_module = module

            uml_file.write("}\n\n")

        # Store function dependencies per module
        function_dependencies = {}

        # Now loop through all groups and process functions
        for group, details in all_groups.items():
            if "functions" not in details or not details["functions"]:
                continue  # Skip groups without function calls

            for function in details["functions"]:
                function_name = function.get("func_name", "UnknownFunction")
                if function.get("usage_paths"):
                    for usage_path, paths in function["usage_paths"].items():
                        if paths:
                            if usage_path not in function_dependencies:
                                function_dependencies[usage_path] = []
                            function_dependencies[usage_path].append(function_name)

        # Group function calls by module
        for source_module, function_list in function_dependencies.items():
            unique_functions = set(function_list)

            for function_name in unique_functions:
                uml_file.write(f"{source_module} --> {layer}: {function_name}\n")

        uml_file.write("@enduml\n")

    print(f"Deployment diagram saved as {uml_filename}")

# # import networkx as nx
# # import matplotlib.pyplot as plt

# # # might need to install 'pip install networkx matplotlib'
# # def generate_layered_callout_diagram(all_groups, layer):
# #     """
# #     Generates a Layered Callout Diagram showing which modules call which functions in the given layer.
# #     :param all_groups: A dictionary mapping modules to function calls.
# #     :param layer: The name of the API layer for which to generate the diagram.
# #     :return: None (saves the diagram as an image).
# #     """
# #     # Create a directed graph using networkx
# #     G = nx.DiGraph()

# #     # Add a node for the layer (example, GATT layer)
# #     G.add_node(layer, label=layer, shape='rect', style='filled', color='lightblue')

# #     # Iterate through all groups (modules) in the data
# #     for group, details in all_groups.items():
# #         # Ensure the group has functions and usage_paths
# #         if 'functions' not in details or not details['functions']:
# #             continue

# #         # Add the module (group) node
# #         G.add_node(group, label=group, shape='ellipse', style='filled', color='lightgreen')

# #         # Iterate through the functions in the current group
# #         for function in details['functions']:
# #             function_name = function.get('func_name', 'UnknownFunction')
# #             parameters = function.get('parameters', {})
# #             param_str = ", ".join([f"{k}: {v}" for k, v in parameters.items()])

# #             # Check if there are usage paths (i.e., the function is called by some module)
# #             if function.get('usage_paths'):
# #                 for usage_path, paths in function['usage_paths'].items():
# #                     if paths:  # Only add if there are paths (i.e., it's being called by the module)
# #                         # Create an edge from the usage_path to the function node
# #                         label = f"{function_name} ({param_str})"
# #                         G.add_edge(usage_path, function_name, label=label)

# #     # Draw the graph using matplotlib
# #     plt.figure(figsize=(10, 8))
# #     pos = nx.spring_layout(G, seed=42)  # Positioning layout for better clarity
# #     labels = nx.get_edge_attributes(G, 'label')
# #     nx.draw(G, pos, with_labels=True, node_size=3000, node_color='lightgreen', font_size=10, font_weight='bold', arrows=True)
# #     nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_size=8)

# #     # Save the diagram as an image (e.g., PNG or SVG)
# #     plt.title(f"Function Call Flow to {layer} API")
# #     plt.savefig(f"{layer}_callout_diagram.png")  # Saves the diagram as PNG
# #     plt.show()  # Display the plot

# #     print(f"Layered Callout Diagram saved as '{layer}_callout_diagram.png'.")

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

                f.write(f"    Parameters:\n")
                for param, desc in func.get("parameters", {}).items():
                    f.write(f"      {param}: {desc}\n")

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
                    # Normalize
                    if param_name in caller_group_params[caller_group]:
                        continue  # Already added

                    if isinstance(param_info, dict):
                        desc = param_info.get("description", param_info.get("param", ""))
                    else:
                        desc = param_info

                    caller_group_params[caller_group][param_name] = {
                        "description": desc,
                        "group": group_name
                    }

    return caller_groups, caller_group_params

def write_caller_group_params_to_file(caller_group_params, filepath="caller_group_params.txt", layer):
    with open(filepath, "w", encoding="utf-8") as f:

        f.write(f"====== Input parameters sorted in modules that call {layer} functions ======\n")
        for group in sorted(caller_group_params):
            f.write(f"=== {group} ===\n")

            # Build and format all lines first to align brackets
            lines = []
            max_line_len = 0

            for param, info in caller_group_params[group].items():
                desc = info['description']
                to_group = info['group']
                line = f"  {param}: {desc}"
                lines.append((line, to_group))
                max_line_len = max(max_line_len, len(line))

            for line, to_group in lines:
                padding = " " * (max_line_len - len(line) + 1)  # +1 space before bracket
                f.write(f"{line}{padding}({to_group})\n")

            f.write("\n")  # Separate groups

def extract_common_folders(header_paths: List[str]) -> List[str]:
    """
    Extracts folder names that are common across all given header paths.

    Args:
        header_paths (List[str]): List of header file paths.

    Returns:
        List[str]: Ordered list of folder names common to all header paths without duplicates.
    """
    # Split all paths into folder components
    split_paths = [path.split(os.sep) for path in header_paths]
    if not split_paths:
        return []

    # Flatten and count unique folder names per path
    folder_counter = Counter()
    for path in split_paths:
        folder_counter.update(set(path))

    # Keep folders that appear in all paths (count == number of paths)
    common = {folder for folder, count in folder_counter.items() if count == len(split_paths)}

    # Maintain original order based on first path and remove duplicates
    seen = set()
    ordered_common = []
    for folder in split_paths[0]:
        if folder in common and folder not in seen:
            ordered_common.append(folder)
            seen.add(folder)

    return ordered_common

def find_c_files(common_folders: List[str]) -> List[str]:
    """
    Finds all .c source files within folders that include the common folder names in order.
    Excludes any paths containing 'mock', 'test', 'sample', 'classic', or 'shell'.

    Args:
        common_folders (List[str]): Ordered list of common folders to match in the path.

    Returns:
        List[str]: List of matching .c file paths.
    """
    matching_files = []
    for dirpath, _, filenames in os.walk("."):
        # Skip paths containing mock or test directories
        if any(x in dirpath for x in ["mock", "test", "sample", "classic", "shell"]):
            continue

        path_parts = dirpath.split(os.sep)
        idx = 0
        for folder in common_folders:
            try:
                idx = path_parts.index(folder, idx) + 1
            except ValueError:
                break
        else:
            # All common folders found in order
            for file in filenames:
                if file.endswith(".c"):
                    matching_files.append(os.path.join(dirpath, file))

    return matching_files

def normalize_signature(sig: str) -> str:
    """
    Normalize a function signature string by stripping and collapsing whitespace.

    Args:
        sig (str): The function signature string.

    Returns:
        str: Normalized function signature.
    """
    sig = sig.strip().rstrip(';')
    return re.sub(r"\s+", " ", sig)


def extract_definitions_from_file(filepath: str) -> List[str]:
    """
    Extracts normalized function definitions from a C file, skipping comments.

    Args:
        filepath (str): Path to the C file.

    Returns:
        List[str]: List of normalized function definition strings.
    """
    with open(filepath, 'r') as f:
        content = f.read()

    # Remove both inline and block comments to avoid false positives
    content = re.sub(r"//.*?$|/\*.*?\*/", "", content, flags=re.DOTALL | re.MULTILINE)

    # Match function definitions possibly split across multiple lines
    pattern = re.compile(r"([\w\s\*]+?)\s+([a-zA-Z_][\w]*)\s*\((.*?)\)\s*{", re.DOTALL)
    matches = pattern.findall(content)

    function_defs = []
    for ret_type, name, params in matches:
        # Normalize return type and parameters
        ret_type = re.sub(r"\s+", " ", ret_type.strip())
        params = re.sub(r"\s+", " ", params.strip())
        function_defs.append(f"{ret_type} {name}({params})")

    return [normalize_signature(fn) for fn in function_defs]


def filter_files_with_function_definitions(c_files: List[str], group_functions: List[str]) -> List[str]:
    """
    Filters .c files that contain definitions of any function from the group dictionary.

    Args:
        c_files (List[str]): List of .c file paths.
        group_functions (List[str]): List of function signatures (one-line, normalized).

    Returns:
        List[str]: Files containing one or more matching function definitions.
    """
    normalized_group_fns = [normalize_signature(f) for f in group_functions]
    matched_files = []
    for filepath in c_files:
        definitions = extract_definitions_from_file(filepath)
        if any(fn in definitions for fn in normalized_group_fns):
            matched_files.append(filepath)
    return matched_files

def extract_function_calls(c_files: List[str], layer: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Extracts all valid function calls (excluding definitions, macros, control structures, __* prefixed,
    bt_{layer}/{layer} prefixed, or known non-call macros like memset) from each C file.

    Args:
        c_files (List[str]): List of .c file paths.
        layer (str): Layer prefix to exclude from function calls.

    Returns:
        Dict[str, Dict[str, List[str]]]: A dictionary mapping file paths to a dictionary of
                                         called functions and their respective line locations.
    """
    calls_per_file = {}
    disallowed_keywords = {"if", "while", "for", "switch", "return", "sizeof", "memset", "memcpy", "defined", "CONTAINER_OF"}

    for filepath in c_files:
        with open(filepath, 'r') as f:
            lines = f.readlines()

        in_comment_block = False
        file_calls = {}

        for i, line in enumerate(lines):
            raw_line = line
            line = line.strip()

            # Handle comment blocks
            if '/*' in line:
                in_comment_block = True
            if '*/' in line:
                in_comment_block = False
                continue
            if in_comment_block or line.startswith('//') or line.startswith('*'):
                continue
            if line.startswith("typedef"):
                continue

            # Find function call patterns
            matches = re.findall(r"([a-zA-Z_][\w]*)\s*\(([^)]*)\)", line)
            for fn_name, params in matches:
                # Skip invalid/unsupported patterns
                if fn_name in disallowed_keywords:
                    continue
                if "DBG" in fn_name or "LOG" in fn_name:
                    continue
                if fn_name.startswith("__") or fn_name.startswith(f"bt_{layer}") or fn_name.startswith(layer):
                    continue
                if re.match(r"^(void|int|char|float|double|uint\d+_t|struct|const|static|inline)", raw_line.strip()):
                    continue
                if re.match(r".*\*\s*\(\s*\*?\s*[\w]+\s*\).*", raw_line):  # Function pointer/typedef
                    continue

                # Simplify parameter names
                simplified_params = []
                for p in params.split(','):
                    p = p.strip()
                    last_token = re.split(r"[.->]", p)[-1] if p else ""
                    simplified_params.append(last_token)

                simplified_call = f"{fn_name}({', '.join(simplified_params)})"
                loc = f"{filepath}:{i+1}"

                # Group by function name regardless of parameters
                existing_key = next((key for key in file_calls if key.startswith(f"{fn_name}(")), None)
                if existing_key:
                    file_calls[existing_key].append(loc)
                else:
                    file_calls[simplified_call] = [loc]

        calls_per_file[filepath] = file_calls
    return calls_per_file

def get_function_groups_from_user(function_calls: Dict[str, Dict[str, Dict[str, List[str]]]]) -> List[str]:
    """
    Prompts the user to create named groups by reviewing all detected function names.

    :param function_calls: Dictionary with C file paths mapping to function call data.
    :return: List of group keywords provided by the user.
    """
    all_functions = set()

    # Collect all unique function names across all files.
    for file_data in function_calls.values():
        if "function_calls" in file_data and file_data["function_calls"]:
            all_functions.update(file_data["function_calls"].keys())

    print("\nDetected functions:")
    for func in sorted(all_functions):
        print(func)

    groups = []
    while True:
        # Ask the user to input group keywords separated by spaces.
        user_input = input("\nEnter group keywords (space-separated): ").strip()
        if user_input:
            groups.extend(user_input.split())

        # Show currently collected groups.
        print(f"\nCurrent groups: {groups}")
        more = input("More groups? (yes/y or no/n): ").strip().lower()

        # Handle control flow based on user response.
        if more in ["no", "n"]:
            break
        elif more not in ["yes", "y"] and more:
            groups.extend(more.split())

    return groups

def group_function_calls_by_keyword(function_calls: Dict[str, Dict[str, Dict[str, List[str]]]], groups: List[str]) -> Dict[str, List[str]]:
    """
    Groups functions by user-defined keywords. A function belongs to a group if its name contains the group's keyword.

    :param function_calls: Dictionary mapping file paths to their function call data.
    :param groups: List of group keywords provided by the user.
    :return: Dictionary mapping each group to a list of matched function names.
    """
    grouped_calls = {group: [] for group in groups}

    # Iterate through each file's call data
    for file_data in function_calls.values():
        if "function_calls" in file_data:
            for func_name in file_data["function_calls"]:
                # Add function to matching group(s) if the group keyword is part of the function name
                for group in groups:
                    if group in func_name and func_name not in grouped_calls[group]:
                        grouped_calls[group].append(func_name)

    return grouped_calls


def extract_declarations_for_known_calls(function_calls: Dict[str, Dict[str, Dict[str, List[str]]]], grouped_functions: Dict[str, List[str]], layer: str) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    updated_calls = function_calls.copy()
    all_called_functions = set()
    for funcs in grouped_functions.values():
        all_called_functions.update([fn.split("(")[0] for fn in funcs])

    disallowed_keywords = {"typedef", "inline"}

    for dirpath, _, filenames in os.walk("."):
        if any(skip in dirpath for skip in ["mock", "test", "sample", "classic", "shell"]):
            continue

        for file in filenames:
            if not file.endswith(".h"):
                continue

            filepath = os.path.join(dirpath, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception:
                continue

            in_comment_block = False
            buffer = ""

            for i, line in enumerate(lines):
                stripped = line.strip()

                if '/*' in stripped:
                    in_comment_block = True
                if '*/' in stripped:
                    in_comment_block = False
                    continue
                if in_comment_block or stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('#'):
                    continue
                if any(kw in stripped for kw in disallowed_keywords):
                    continue
                if stripped.startswith("typedef"):
                    continue

                buffer += stripped + " "

                if ");" not in stripped:
                    continue

                matches = re.findall(r"([a-zA-Z_][\w]*)\s*\(([^)]*)\)\s*;", buffer)
                buffer = ""
                for fn_name, params in matches:
                    if fn_name not in all_called_functions:
                        continue

                    simplified_params = []
                    for p in params.split(','):
                        p = p.strip()
                        last_token = re.split(r"[.->]", p)[-1] if p else ""
                        simplified_params.append(last_token)

                    normalized_sig = f"{fn_name}({', '.join(simplified_params)})"
                    loc = f"{filepath}:{i+1}"

                    if filepath not in updated_calls:
                        updated_calls[filepath] = {}
                    if "function_declarations" not in updated_calls[filepath]:
                        updated_calls[filepath]["function_declarations"] = {}
                    if normalized_sig not in updated_calls[filepath]["function_declarations"]:
                        updated_calls[filepath]["function_declarations"][normalized_sig] = []
                    updated_calls[filepath]["function_declarations"][normalized_sig].append(loc)

    return updated_calls


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

def main():
    ### GENERAL ###
    # Input the layer you're looking for
    layer = input("Enter the word to search for in header filenames (e.g., 'gatt'): ")

    # Get the list of header files containing the word
    header_list = find_headers(layer)
    if not header_list:
        print("There are no headers fitting to this, mistyped? Try again.")
        return

    print(f"\nFollowing headers are scaned for {layer} functions:")
    for item in header_list:
        print(item)
    print("\nProcessing workspace")

    all_groups = {}
    for header in header_list:
        if contains_groups(header):
            groups_info = save_function_names(header, True)
        else:
            groups_info = save_function_names(header, False)
        all_groups.update(groups_info)

    ### IN ###
    # # Save the newly generated lookup table
    # all_groups_file = f"all_groups_{layer}.txt"
    # with open(all_groups_file, "w", encoding="utf-8") as file:
    #     json.dump(all_groups, file, indent=4)

    pattern = extract_function_patterns(all_groups)
    print("Grepping in the workspace for following patterns:")
    for func_pattern in pattern:
        print(func_pattern)
    print()
    print("If you see many patterns here, probably means naming conventions in the header isn't followed or the header has many sub-modules.")
    print()
    print("Grepping, this might take a longer moment.")

    # search for function calls in the current directory
    directory = "."  # current directory
    lookup_table = find_function_calls(directory, pattern, header_list)
    # Save the newly generated lookup table
    lookup_table_file = f"lookup_{layer}.txt"
    with open(lookup_table_file, "w", encoding="utf-8") as file:
        json.dump(lookup_table, file, indent=4)

    add_usage_to_groups(all_groups, lookup_table)
    # Save the newly generated lookup table
    all_groups_file = f"{layer}_IN_grouped.txt"
    write_in_info(all_groups, all_groups_file)

    caller_groups, caller_group_params = extract_caller_groups(all_groups)
    in_grouped_params_file = f"IN_grouped_{layer}_params.txt"
    write_caller_group_params_to_file(caller_group_params, in_grouped_params_file, layer)

######## Try with CONN, there might be MAAANY c-files, because of the different function names, so make it user interactible.
    ### OUT ###
    # # Extract common folders
    # common_folders = extract_common_folders(header_list)
    # # print(common_folders) # Debug print, comment-in if needed

    # # Find all relevant .c files
    # c_files = find_c_files(common_folders)
    # # # Debug print, comment-in if needed
    # # for file in c_files:
    # #     print(file)

    # # From the group, extract all functions
    # group_functions = []
    # for group in all_groups.values():
    #     for fn in group["functions"]:
    #         group_functions.append(fn["full_function"])
    # # # Debug print, comment-in if needed
    # # for group in group_functions:
    # #     print(group)

    # # Filter only those .c files which define at least one group function
    # matched_files = filter_files_with_function_definitions(c_files, group_functions)
    # # print(matched_files) # Debug print, comment-in if needed

    # # Extract all function calls (not necessarily group functions) from those matched .c files
    # function_calls = extract_function_calls(matched_files, layer)

    # output_file = f"OUT_{layer}.txt"
    # with open(output_file, "w", encoding="utf-8") as f:
    #     for file, calls in function_calls.items():
    #         f.write(f"\nFile: {file}\n")
    #         for call, locations in sorted(calls.items()):
    #             f.write(f"  {call}:\n")
    #             for loc in sorted(locations):
    #                 f.write(f"    - {loc}\n")
    # # # Debug print, comment-in if needed
    # # for file, calls in function_calls.items():
    # #     print(f"\nFile: {file}")
    # #     for call, locations in sorted(calls.items()):
    # #         print(f"  {call}:")
    # #         for loc in sorted(locations):
    # #             print(f"    - {loc}")

    # groups = get_function_groups_from_user(function_calls)
    # for group in groups:
    #     print(group)
    # grouped = group_function_calls_by_keyword(function_calls, groups)

    # calls_with_decls = extract_declarations_for_known_calls(function_calls, grouped, layer)
    # # Debug print, comment-in if needed
    # for file, data in calls_with_decls.items():
    #     print(f"\nFile: {file}")
    #     if "function_declarations" in data:
    #         print("  Declarations:")
    #         for func, locations in data["function_declarations"].items():
    #             print(f"    {func}:")
    #             for loc in locations:
    #                 print(f"      - {loc}")
    #     if "function_calls" in data:
    #         print("  Calls:")
    #         for func, locations in data["function_calls"].items():
    #             print(f"    {func}:")
    #             for loc in locations:
    #                 print(f"      - {loc}")


    # # Write all function calls to output file
    # write_output_to_file(calls_with_decls, "out_calls.txt")

    # # print("Work Space searched through . . .")

    # # # extract function in {layer} headers and match them with lookup table info,
    # # # remove from lookup table after processed
    # # all_groups = {}
    # # for header in header_list:
    # #     if contains_groups(header):
    # #         groups_info, lookup_table = save_function_names(header, True, lookup_table)
    # #     else:
    # #         groups_info, lookup_table = save_function_names(header, False, lookup_table)
    # #     all_groups.update(groups_info)
    # # # Save the newly generated lookup table
    # # all_groups_file = f"all_groups_{layer}.txt"
    # # with open(all_groups_file, "w", encoding="utf-8") as file:
    # #     json.dump(all_groups, file, indent=4)

    # # print("Matched functions to workspace database . . .")

    # # # printing
    # # print_functions_simple(all_groups, layer)

    # # print_functions_moduels(all_groups, layer)

    # # print_functions_groups(all_groups, layer)

    # # # make UMLs
    # # generate_uml_sequence_diagrams(all_groups, layer)

    # # # make deployment diagram
    # # generate_deployment_diagrams(all_groups, layer)
    # # generate_deployment_diagram(all_groups, layer)


    # # # generate_layered_callout_diagram(all_groups, layer)

# Run the script if executed directly
if __name__ == "__main__":
    main()
