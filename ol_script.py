import os
import re
import json  # For saving and loading lookup table efficiently
import subprocess

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
        dirs[:] = [d for d in dirs if not any(excluded in d.lower() for excluded in ['test', 'mock', 'mesh', 'audio'])]

        for file in files:
            # Check if file ends with .h and matches the pattern
            if file.endswith('.h') and pattern.search(file):
                # Add the full path to the header list
                header_list.append(os.path.join(root, file))

    return header_list


# Function to find gatt function calls in .c and .h files
def find_function_calls(directory, layer, ignore_paths):
    lookup_table = []

    function_call_pattern = re.compile(r'\s*([a-z0-9_]*' + re.escape(layer) + r'[a-z0-9_]*)\s*\(.*\)\s*;')

    # Use grep to search for function calls efficiently
    try:
        grep_command = f'grep -rnE "\\b[a-zA-Z0-9_]*{layer}[a-zA-Z0-9_]*\\s*\\(.*\\)\\s*;" {directory} --include="*.c" --include="*.h"'
        grep_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True)

        for line in grep_output.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            file_path, line_number, code_line = parts
            line_number = int(line_number.strip())

            if any(ignore_path in file_path for ignore_path in ignore_paths):
                continue

            if "test" in file_path or "mock" in file_path or f"{layer}" in file_path:
                continue

            match_call = function_call_pattern.search(code_line)
            if match_call:
                function_name = match_call.group(1)
                # Add the function call details to the lookup table
                file_path = file_path.replace("./", "")
                lookup_table.append({
                    'function_name': function_name,
                    'file_path': file_path,
                    'line_number': line_number,
                    'type': 'call'
                })

    except Exception as e:
        print(f"Error running grep command: {e}")

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

# go through group by group and save functions in group
def save_function_names(header_path, are_groups, lookup_table):
    """
    Extracts functions from a header file, categorizes them into groups,
    and tracks where they are used.

    :param header_path: The file path of the header file being analyzed.
    :param are_groups: Boolean indicating whether the header file contains @defgroup sections.
    :param lookup_table: List of function calls found in source files.
    :return: A dictionary mapping groups to functions and their usage paths,
             and an updated lookup_table with found function calls removed.
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
            group_key = 'group_0'
            groups[group_key] = {
                'name': file_name,
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
                group_name = line.replace(' * @defgroup', '').strip()
                if group_name:
                    # Increment group index and create a new group key
                    idx_groups += 1
                    group_key = f'group_{idx_groups}'
                    # Initialize the group in the dictionary
                    groups[group_key] = {
                        'name': group_name,
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

                    # multiline definition
                    if ");" not in line:
                        full_function = extract_multiline_function_name(full_function, lines, i)

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

                    # Extract function description from preceding comments
                    func_description = get_brief_comment(lines, i, function_name)

                    # Find where this function is used
                    func_paths_and_lines = find_usage_of_funcs(function_name, lookup_table)

                    # Categorize paths with line numbers
                    # so: {LAYER_1: [path_1:line_1, path_2:line_2], LAYER_2: [...], ...}
                    categorized_paths = categorize_paths(func_paths_and_lines[function_name])

                    # Add function with usage paths to the dictionary
                    groups[group_key]['functions'].append({
                        'full_function': full_function,
                        'func_name': function_name,
                        'description': func_description,
                        'usage_paths': categorized_paths
                    })

    return groups, lookup_table

def print_functions_simple(all_groups, layer):
    general_filename = f"{layer}_functions.txt"

    with open(general_filename, "w") as output_file:
        for group, details in all_groups.items():
            output_file.write(f"=== {details['name']} ({details['header_path']}) ===\n")
            output_file.write("\n")

            for function in details['functions']:

                output_file.write(f"  function name: {function['func_name']}")  # Print function name
                output_file.write(f"  function: {function['full_function']}")  # Print function
                output_file.write(f"  Description: {function['description']}")  # Print function description
                output_file.write("\n")
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
                                uml_file.write(f"note across: {description} \\nParameters: {parameters}\n")

                            # Write function call from usage_path to the layer
                            color = color_mapping.get(usage_path)
                            uml_file.write(f"{usage_path} -> {layer}: {function_name} #{color}\n")
                            last_function_name = function_name

            uml_file.write("@enduml\n")

        print(f"UML sequence diagram saved as {uml_filename}")

def generate_deployment_diagrams(all_groups, layer):
    """
    Generates a structured UML deployment diagram in PlantUML format.

    :param all_groups: A dictionary mapping modules to function calls.
    :param layer: The API layer for which to generate the diagram.
    :return: None (saves the diagram as a .puml file).
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

    for group, details in all_groups.items():
        if "functions" not in details or not details["functions"]:
            continue  # Skip groups without function calls

        group_name_sanitized = sanitize_filename(details["name"])
        uml_filename = f"{layer}_{group_name_sanitized}_vertical_deployment.puml"

        with open(uml_filename, "w") as uml_file:
            uml_file.write("@startuml\n")
            uml_file.write(f"title Vertical Deployment Diagram: {layer} {details['name']} API\n\n")

            # Force a vertical top-down structure
            uml_file.write("skinparam ranksep 50\n")
            uml_file.write("skinparam nodesep 40\n")
            uml_file.write("left to right direction\n\n")

            # Generate clusters dynamically
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
                functions_str = "\\n".join(unique_functions)

                # Attach notes close to the relevant module instead of all at the API
                uml_file.write(f"note right of {source_module}: Calls to {layer}:\\n{functions_str}\n")

                for function_name in unique_functions:
                    uml_file.write(f"{source_module} --> {layer}: {function_name}\n")

            uml_file.write("@enduml\n")

        print(f"Vertical deployment diagram saved as {uml_filename}")

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


def main():
    # Input the layer you're looking for
    layer = input("Enter the word to search for in header filenames (e.g., 'gatt'): ")

    # Get the list of header files containing the word
    header_list = find_headers(layer)
    if not header_list:
        print("There are no headers fitting to this, mistyped? Try again.")
        return
    print("Processing workspace")

    # search for function calls in the current directory
    directory = "."  # current directory
    lookup_table = find_function_calls(directory, layer, header_list)
    # Save the newly generated lookup table
    lookup_table_file = f"lookup_{layer}.txt"
    with open(lookup_table_file, "w", encoding="utf-8") as file:
        json.dump(lookup_table, file, indent=4)

    print("Work Space searched through . . .")

    # extract function in {layer} headers and match them with lookup table info,
    # remove from lookup table after processed
    all_groups = {}
    for header in header_list:
        if contains_groups(header):
            groups_info, lookup_table = save_function_names(header, True, lookup_table)
        else:
            groups_info, lookup_table = save_function_names(header, False, lookup_table)
        all_groups.update(groups_info)
    # Save the newly generated lookup table
    all_groups_file = f"all_groups_{layer}.txt"
    with open(all_groups_file, "w", encoding="utf-8") as file:
        json.dump(all_groups, file, indent=4)

    print("Matched functions to workspace database . . .")

    # printing
    print_functions_simple(all_groups, layer)

    print_functions_moduels(all_groups, layer)

    print_functions_groups(all_groups, layer)

    # make UMLs
    generate_uml_sequence_diagrams(all_groups, layer)

    # make deployment diagram
    generate_deployment_diagrams(all_groups, layer)


    # generate_layered_callout_diagram(all_groups, layer)

# Run the script if executed directly
if __name__ == "__main__":
    main()
