import os
import re

STANDARD_C_TYPES = {
    'static', 'extern', 'register', 'auto', 'inline', 'int', 'short', 'long',
    'signed', 'unsigned', 'char', 'bool', 'uint8_t', 'uint16_t', 'uint32_t',
    'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'float', 'double',
    'long double', 'void', '_Bool', 'volatile', 'const', 'restrict'
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
        dirs[:] = [d for d in dirs if not any(excluded in d.lower() for excluded in ['test', 'mock', 'mesh', 'audio', 'classic', 'services', 'mcumgr', 'net', 'll_sw'])]

        for file in files:
            # Check if file ends with .h and matches the pattern
            if file.endswith('.h') and pattern.search(file):
                # Add the full path to the header list
                header_list.append(os.path.join(root, file))

    return header_list

def contains_groups(filename):
    with open(filename, 'r') as file:
        for line in file:
            if '@defgroup' in line:
                return True
    return False

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
            param_name = words[-1]
            function_params[param_name] = {
                'clean_param': param
            }

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
                function_params[param_name]['description'] = description
    return function_params

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

    for keyword in sorted(STANDARD_C_TYPES, key=len, reverse=True): # Sort by length to avoid partial replacements
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

def is_standard_c_type(param_str):
    """
    Determines if a given parameter string is a standard C type.

    Parameters:
    - param_str (str): The type string to check.

    Returns:
    - bool: True if it's a standard type, False otherwise.
    """
    tokens = re.split(r"[ *]+", param_str.replace("const", "").strip())
    return any(t in STANDARD_C_TYPES for t in tokens if t)

def find_header_files(base_dir, subdir):
    """
    Recursively finds .h files under a given subdirectory.

    Parameters:
    - base_dir (str): Base project directory.
    - subdir (str): Subdirectory to scan.

    Returns:
    - list of str: Paths to .h files found.
    """
    matching_headers = []
    for root, _, files in os.walk(os.path.join(base_dir, subdir)):
        if "test" in root or "mock" in root:
            continue
        for file in files:
            if file.endswith(".h"):
                matching_headers.append(os.path.join(root, file))
    return matching_headers

def extract_comment_above(lines, def_index):
    """
    Extracts description in comment above a line index in a source file.

    Parameters:
    - lines (list of str): File lines.
    - def_index (int): Index of definition line.

    Returns:
    - str: Extracted comment or None.
    """
    i = def_index - 1
    cleaned_line = "None available."

    while i >= 0:
        brief_found = False
        line = lines[i].strip()

        if line == "":
            i -= 1
            continue

        # Go to beginning of the comment block
        while i >= 0 and "/*" in line:
            if "@brief" in line:
                brief_found = True
                cleaned_line = re.sub(r'(/\*\*?|(\*/)|@brief)', '', line).strip()
                break
            i -= 1
            if i >= 0:
                line = lines[i].strip()
            else:
                break

        if ";" in line or "{" in line or "}" in line or brief_found:
            break

        i -= 1

    return cleaned_line
