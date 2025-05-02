import os
import re
from typing import List, Dict
from collections import Counter

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

