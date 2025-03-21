import os
import re
import json  # For saving and loading lookup table efficiently
import subprocess

# Compile the regex patterns once
SINGLE_LINE_COMMENT_PATTERN = re.compile(r'^\s*//')
BLOCK_COMMENT_START_PATTERN = re.compile(r'/\*')
BLOCK_COMMENT_END_PATTERN = re.compile(r'\*/')

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
        "OTHER": []  # Default group for uncategorized paths
    }

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

    # Check if lookup table already exists
    lookup_table_file = f"{layer}.txt"
    if os.path.exists(lookup_table_file):
        try:
            with open(lookup_table_file, "r", encoding="utf-8") as file:
                lookup_table = json.load(file)  # Load the existing lookup table
            print("Loaded existing lookup table from file.")
            return lookup_table  # Return early to avoid re-scanning
        except (json.JSONDecodeError, IOError):
            print("Lookup table file is corrupted or unreadable. Regenerating...")

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

    # Save the newly generated lookup table
    with open(lookup_table_file, "w", encoding="utf-8") as file:
        json.dump(lookup_table, file, indent=4)

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

    return grouped_paths

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
        for line in file:

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
            elif group_key and re.search(r'.*\(.*\);', line):
                if re.search(r'\b(memset|return|typedef|\)\()\b', line):
                    continue
                else:
                    # function found in group
                    line = line.lstrip()
                    current_function = line

                    # Match everything from the start up to the first '*' (only if '*' appears before '(')
                    match = re.match(r'^[^(\n]*\*\s*(.*)', line)
                    if match:
                        line = match.group(1)  # Keep everything after '*'

                    # Remove C data types and extract function name
                    c_types = [
                        'static', 'extern', 'register', 'auto', 'inline', 'int', 'short', 'long',
                        'signed', 'unsigned', 'char', 'bool', 'uint8_t', 'uint16_t', 'uint32_t',
                        'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'float', 'double',
                        'long double', 'void', '_Bool', 'volatile', 'const', 'restrict'
                    ]

                    # Remove C types from the line
                    for keyword in sorted(c_types, key=len, reverse=True):  # Sort by length to avoid partial replacements
                        line = re.sub(r'\b' + re.escape(keyword) + r'\b', '', line)

                    # remove all white spaces
                    function_name = line.strip()

                    # Save the result in function_name
                    function_name = function_name.split("(")[0]
                    function_name = function_name.rstrip("\n")

                    # Find where this function is used
                    func_paths_and_lines = find_usage_of_funcs(function_name, lookup_table)
                    #TODO remove currently found info (and only that) from the lookup table

                    # Categorize paths with line numbers
                    categorized_paths = categorize_paths(func_paths_and_lines[function_name])

                    # Add function with usage paths to the dictionary
                    groups[group_key]['functions'].append({'name': current_function, 'usage_paths': categorized_paths})
                    #TODO does this work with the header_path being connected to the group as well?


    return groups, lookup_table

def main():
    # Input the layer you're looking for
    layer = input("Enter the word to search for in header filenames (e.g., 'gatt'): ")

    # Get the list of header files containing the word
    header_list = find_headers(layer)
    if not header_list:
        print("There are no headers fitting to this, mistyped? Try again.")
        return
    print("Processing.")
    print("This might take a minute if you run this the first time for this layer.")

    # search for function calls in the current directory
    directory = "."  # current directory
    lookup_table = find_function_calls(directory, layer, header_list)
    print("Work Space searched through . . .")

    all_groups = {}
    for header in header_list:
        if contains_groups(header):
            groups_info, lookup_table = save_function_names(header, True, lookup_table)
        else:
            groups_info, lookup_table = save_function_names(header, False, lookup_table)
        all_groups.update(groups_info)

    print("Matched functions to workspace database . . .")

    # printing
    general_filename = f"{layer}_functions.txt"

    with open(general_filename, "w") as output_file:
        for group, details in all_groups.items():
            output_file.write(f"=== {details['name']} ({details['header_path']}) ===\n")
            output_file.write("\n")

            for function in details['functions']:
                output_file.write(f"  function: {function['name']}")  # Print function name
                output_file.write("\n")
                for subgroup, paths in function['usage_paths'].items():
                    if paths:
                        output_file.write(f"    {subgroup}:\n")
                        for path in paths:
                            output_file.write(f"      {path}\n")
                    output_file.write("\n")
                output_file.write("\n")

    print(f"Output saved to {general_filename}")

    # Define the filename for output based on the layer variable
    layers_filename = f"{layer}_functions_by_layers.txt"

    # Open the file for writing
    with open(layers_filename, "w") as output_file:

        output_file.write("Functions sorted by all_layers:\n\n")

        # Collect all possible layers dynamically by scanning the usage_paths of functions
        all_layers = set()
        for group in all_groups.values():
            for function in group['functions']:
                all_layers.update(function['usage_paths'].keys())

        # Iterate through each subgroup (layer)
        for subgroup in sorted(all_layers):
            output_file.write(f"=== {subgroup} ===\n\n")

            # Track if any function is found in this subgroup for any group
            found_any_function_in_subgroup = False

            # Iterate over each group
            for group_name, group_details in all_groups.items():
                relevant_functions = []  # Track relevant functions for the subgroup in this group

                # Find all functions in the group that are associated with this subgroup
                for function in group_details['functions']:
                    if subgroup in function['usage_paths'] and function['usage_paths'][subgroup]:
                        relevant_functions.append(function)

                if not relevant_functions:
                    continue  # Skip the rest and move to the next group

                # If there are relevant functions, print the group name and path
                found_any_function_in_subgroup = True
                output_file.write(f"Group: {group_details['name']} ({group_details['header_path']})\n\n")

                # For each relevant function in the group
                for function in relevant_functions:
                    output_file.write(f"  {function['name']}\n")  # Function name

                    # Print all paths associated with this function and subgroup
                    for path in function['usage_paths'][subgroup]:
                        output_file.write(f"      {path}\n")  # Indented paths

                    output_file.write("\n")  # Add an empty line after each function's paths

            # If no functions were found for any group in this subgroup, write a message
            if not found_any_function_in_subgroup:
                output_file.write(f"  (No functions found for {subgroup})\n\n")

            output_file.write("\n")  # Add a space between subgroups

    print(f"Output saved to {layers_filename}")



# Run the script if executed directly
if __name__ == "__main__":
    main()
