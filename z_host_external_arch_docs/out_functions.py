import json
import os
import re
from typing import List, Dict, Tuple
from collections import defaultdict, Counter
from general import STANDARD_C_TYPES, is_standard_c_type, find_header_files, extract_comment_above

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

def detect_include_header(line):
    """
    Detects #include statements and extracts the header file path.

    Supports:
        - #include "header.h"
        - #include <header.h>

    Ignores:
        - Comments
        - Non-#include lines
        - Duplicates should be filtered externally

    Args:
        line (str): A stripped line from the C file.

    Returns:
        str or None: The included header path (e.g., "my_header.h" or "stdio.h"), or None if not an include line.
    """
    # Skip comment-only lines
    if not line or line.startswith('//') or line.startswith('*'):
        return None

    # Match #include "something.h" or <something.h>
    match = re.match(r'#\s*include\s*["<]([^">]+)[">]', line)
    if match:
        return match.group(1)

    return None

def detect_function_definition(line, in_macro_block):
    """
    Detects if a line contains a function-like definition.

    Supports:
        - Regular function declarations and definitions
        - Static/inline/extern/const modifiers
        - Function-like macros (including multi-line macros with backslashes)
        - Function pointer declarations
        - Struct fields with function pointers

    Skips:
        - Typedefs
        - Comments
        - Empty lines
        - Nested functions
        - typedef function pointer aliases

    Args:
        line (str): A single line of code from a C file (assumed stripped).
        in_macro_block (bool): Whether the parser is currently inside a multi-line macro.

    Returns:
        tuple: (function_name or None, updated_macro_state)
    """
    if not line or line.startswith('//') or line.startswith('*'):
        return None, in_macro_block

    # Continue multi-line macro if previous line ended with '\'
    if in_macro_block:
        if line.endswith('\\'):
            return None, True  # Still in macro block
        else:
            return None, False  # Macro block ends here

    # Skip typedefs
    if line.startswith('typedef'):
        return None, False

    # Start of multi-line macro
    if line.startswith('#define') and line.endswith('\\'):
        match = re.match(r'#define\s+([A-Z_][A-Z0-9_]*)(\s*\(|\s+)', line)
        if match:
            return match.group(1), True
        return None, True

    # Single-line function-like macro
    match = re.match(r'#define\s+([A-Z_][A-Z0-9_]*)\s*(\([^)]*\))?', line)
    if match:
        return match.group(1), False

    # Struct-style function pointer: void (*func)(int);
    match = re.match(r'.*\(\s*\*\s*(\w+)\s*\)\s*\([^)]*\)\s*;', line)
    if match:
        return match.group(1), False

    # Regular function definition or declaration (with or without modifiers)
    match = re.match(
        r'(static\s+|inline\s+|extern\s+|const\s+|unsigned\s+)?'     # optional modifiers
        r'[a-zA-Z_][\w\s\*]*\s+'                                     # return type
        r'([a-zA-Z_][\w]*)\s*\([^;]*\)\s*(;|\{)?',                   # function name and args
        line
    )
    if match:
        return match.group(2), False

    return None, False

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
        in_macro_block = False  # Track multi-line macro
        defined_functions = set()  # Track all function-like definitions
        include_headers = []
        file_calls = {}


        for i, line in enumerate(lines):
            raw_line = line
            line = line.strip()
            # Detect #include headers
            header = detect_include_header(line)
            if header and header not in include_headers:
                include_headers.append(header)

            # Detect function definitions
            definition, in_macro_block = detect_function_definition(line, in_macro_block)
            if definition:
                defined_functions.add(definition)

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

        # Debug, uncomment if needed
        out_file = f"{os.path.basename(filepath)}.includes.txt"
        with open(out_file, "w", encoding="utf-8") as file:
            json.dump(include_headers, file, indent=4)
        # # Debug, uncomment if needed
        # out_file = f"{os.path.basename(filepath)}.definitions.txt"
        # with open(out_file, "w", encoding="utf-8") as file:
        #     json.dump(sorted(defined_functions), file, indent=4)

        # Filter out calls to locally defined functions/macros
        file_calls = {
            k: v for k, v in file_calls.items()
            if not any(k.startswith(f"{fn}(") for fn in defined_functions)
        }
        calls_per_file[filepath] = file_calls
    return calls_per_file, include_headers

def resolve_include_paths(include_headers, c_files):
    """
    Resolves actual file paths for headers found in #include statements.

    Searches directories in this specific order:
        1. All parent directories of the provided C files
        2. ./zephyr
        3. ./nrf
        4. Full recursive walk from current directory

    Already searched directories (or their subdirs) are not re-searched to avoid redundancy.

    Args:
        include_headers (List[str]): Header paths extracted from #include lines.
        c_files (List[str]): List of .c file paths (used to prioritize relevant directories).

    Returns:
        List[str]: A list of resolved, absolute file paths to each found header.
    """
    resolved_paths = []
    found_headers = set()

    # Create ordered list of unique base directories to search
    seen_dirs = set()
    search_dirs = []

    # 1. Directories of the C files
    for file_path in c_files:
        dir_path = os.path.abspath(os.path.dirname(file_path))
        if not any(dir_path.startswith(d + os.sep) or dir_path == d for d in seen_dirs):
            search_dirs.append(dir_path)
            seen_dirs.add(dir_path)

    # 2. ./zephyr
    zephyr = os.path.abspath("./zephyr")
    if not any(zephyr.startswith(d + os.sep) or zephyr == d for d in seen_dirs):
        search_dirs.append(zephyr)
        seen_dirs.add(zephyr)

    # 3. ./nrf
    nrf = os.path.abspath("./nrf")
    if not any(nrf.startswith(d + os.sep) or nrf == d for d in seen_dirs):
        search_dirs.append(nrf)
        seen_dirs.add(nrf)

    # 4. Entire workspace
    current_dir = os.path.abspath(".")
    if not any(current_dir.startswith(d + os.sep) or current_dir == d for d in seen_dirs):
        search_dirs.append(current_dir)
        seen_dirs.add(current_dir)

    # Walk and resolve each header
    for header in include_headers:
        found = False
        for base_dir in search_dirs:
            for root, _, files in os.walk(base_dir, followlinks=False):
                for file in files:
                    if file == os.path.basename(header):
                        full_path = os.path.join(root, file)

                        # Header match = full path must end with the header string
                        if full_path.endswith(header) and header not in found_headers:
                            abs_path = os.path.abspath(full_path)
                            resolved_paths.append(abs_path)
                            found_headers.add(header)
                            found = True
                            break
                if found:
                    break
            if found:
                break
        if not found:
            print(f"Warning: Header '{header}' not found in workspace.")

    # Debug output
    os.makedirs("debug", exist_ok=True)
    with open("debug/resolved_include_paths.json", "w", encoding="utf-8") as f:
        json.dump(resolved_paths, f, indent=2)

    return resolved_paths

def group_out_functions(function_calls: Dict[str, Dict[str, Dict[str, List[str]]]]) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Groups detected function names by common prefixes and identifies single (ungrouped) functions.

    :param function_calls: Dictionary with C file paths mapping to function call data.
    :return: Tuple of (grouped functions dictionary, list of single functions).
    """
    all_functions = set()

    # Collect all unique function names (stripping arguments)
    for file_calls in function_calls.values():
        for call in file_calls:
            func = call.split("(", 1)[0]
            all_functions.add(func)

    all_functions = sorted(all_functions)

    # # Debug print, comment in if needed
    # print("\nDetected functions:")
    # for func in all_functions:
    #     print(func)

    # Step 1: Find 2-word prefixes that apply to 2+ functions
    prefix_counts = defaultdict(list)
    for func in all_functions:
        words = func.split("_")
        if len(words) >= 2:
            prefix = "_".join(words[:2])
            prefix_counts[prefix].append(func)

    groups = {prefix: funcs for prefix, funcs in prefix_counts.items() if len(funcs) >= 2}
    single_functions = [func for func in all_functions if not any(func.startswith(group) for group in groups)]

    return groups, single_functions

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

def gather_header_files():
    """
    Recursively walks through the current directory to collect all .h files,
    excluding any paths that contain mock, test, sample, classic, or shell.

    Also appends specific required headers if not already included:
    - ./zephyr/include/zephyr/kernel.h
    - ./zephyr/include/zephyr/net_buf.h

    Returns:
        List of header file paths to be scanned.
    """
    header_files = []
    for dirpath, _, filenames in os.walk("."):
        if any(skip in dirpath for skip in ["mock", "test", "sample", "classic", "shell"]):
            continue
        for file in filenames:
            if file.endswith(".h"):
                header_files.append(os.path.join(dirpath, file))

    for must_have in ["./zephyr/include/zephyr/kernel.h", "./zephyr/include/zephyr/net_buf.h"]:
        if must_have not in header_files:
            header_files.append(must_have)

    return header_files

def update_result_containers(result_dict, ungrouped_dict, grouped_functions, name, location):
    """
    Inserts a matched function or macro name with its declaration location into the results.

    Parameters:
        result_dict: Dictionary of grouped function results to update.
        ungrouped_dict: Dictionary of ungrouped function results to update.
        grouped_functions: Original mapping of group names to lists of known names.
        name: The matched function or macro name.
        location: The location string (file path + line number) to store.
    """
    for group, funcs in grouped_functions.items():
        if name in funcs and location not in result_dict[group][name]:
            result_dict[group][name].append(location)
    if name in ungrouped_dict and location not in ungrouped_dict[name]:
        ungrouped_dict[name].append(location)

def process_lines(filepath, lines, all_known, special_lowercase_macros, grouped_functions,
                  updated_grouped, ungrouped, function_pattern, macro_pattern, special_macro_pattern):
    """
    Parses lines of a single header file to detect function declarations, macro defines,
    and special-case lowercase macros.

    Handles:
    - Inline and regular function declarations or definitions
    - Macro definitions (UPPERCASE and special lowercase)
    - Tracks buffer to support multi-line declarations

    Parameters:
        filepath: Full path to the current header file.
        lines: List of lines read from the file.
        all_known: Set of all function/macro names to detect.
        special_lowercase_macros: String prefix for lowercase macros from kernel.h.
        grouped_functions: Group mapping from user input.
        updated_grouped: Accumulator for found grouped results.
        ungrouped: Accumulator for found ungrouped results.
        function_pattern: Compiled regex for function declarations.
        macro_pattern: Compiled regex for macro defines.
        special_macro_pattern: Regex for special macros (like k_fifo_get).
    """
    buffer = ""
    in_comment_block = False
    pending_start_line = 0

    for i, line in enumerate(lines):
        stripped = line.strip()

        if '/*' in stripped:
            in_comment_block = True
        if '*/' in stripped:
            in_comment_block = False
            continue
        if in_comment_block or stripped.startswith(('//', '*')):
            continue

        # Handle macro defines
        macro_match = macro_pattern.match(stripped)
        if macro_match:
            macro_name = macro_match.group(1)
            if macro_name in all_known:
                location = f"{filepath}:{i+1}"
                update_result_containers(updated_grouped, ungrouped, grouped_functions, macro_name, location)
            continue

        # Handle special macros in kernel.h
        if filepath.endswith("kernel.h"):
            special_match = special_macro_pattern.match(stripped)
            if special_match:
                macro_name = special_match.group(1)
                if special_lowercase_macros in macro_name:
                    location = f"{filepath}:{i+1}"
                    update_result_containers(updated_grouped, ungrouped, grouped_functions, macro_name, location)

        # Accumulate lines for multi-line function declarations/definitions
        if not buffer:
            pending_start_line = i
        buffer += line

        # If function ends here
        if ';' in stripped or '{' in stripped:
            func_match = function_pattern.match(buffer.strip())
            if func_match:
                fn_name, _ = func_match.groups()
                if fn_name in all_known:
                    location = f"{filepath}:{pending_start_line+1}"
                    update_result_containers(updated_grouped, ungrouped, grouped_functions, fn_name, location)
            buffer = ""

def finalize_results(updated_grouped, ungrouped):
    """
    Ensures every function or macro name has at least one result entry.

    Adds "No declaration found" if no matches were recorded.

    Parameters:
        updated_grouped: Dictionary of grouped result matches to finalize.
        ungrouped: Dictionary of ungrouped result matches to finalize.
    """
    for group in updated_grouped:
        for fn in updated_grouped[group]:
            if not updated_grouped[group][fn]:
                updated_grouped[group][fn] = ["No declaration found"]

    for fn in ungrouped:
        if not ungrouped[fn]:
            ungrouped[fn] = ["No declaration found"]

def extract_declarations_for_known_calls(grouped_functions, single_funcs, layer):
    # get header include lists for the different c-files
    """
    Searches all .h files under the current directory (recursively),
    as well as specific important headers, to locate valid **function declarations**
    and macro defines for a given list of known function or macro names.

    Recognizes:
    - C-style function declarations and inline definitions (including static inline)
    - Macro defines (uppercase, snake_case style)
    - Special case lowercase defines (e.g., k_fifo_get) from specific known headers

    Parameters:
        grouped_functions: Dictionary mapping group labels to lists of function/macro names.
        single_funcs: List of function/macro names that are not grouped.
        layer: Layer name for context (not used in logic).

    Returns:
        A dictionary like grouped_functions, with each name mapping to a list of
        declaration locations (file path + line number), or ["No declaration found"] if not found.
        Also includes an additional group called "Ungrouped functions" for the single_funcs.
    """
    all_known = set(sum(grouped_functions.values(), [])) | set(single_funcs)
    special_lowercase_macros = "k_fifo"
    updated_grouped = {group: {fn: [] for fn in funcs} for group, funcs in grouped_functions.items()}
    ungrouped = {fn: [] for fn in single_funcs}

    function_pattern = re.compile(
        r"^(?:static\s+)?(?:inline\s+)?[\w\s\*]+\*?\s+([a-zA-Z_][\w]*)\s*\(([^)]*)\)"
    )
    macro_pattern = re.compile(r"^#\s*define\s+([A-Z_][A-Z0-9_]*)\b")
    special_macro_pattern = re.compile(r"^#\s*define\s+([a-z_][a-z0-9_]*)\s*\(", re.IGNORECASE)

    header_files = gather_header_files()

    for filepath in header_files:
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue

        process_lines(filepath, lines, all_known, special_lowercase_macros, grouped_functions,
                      updated_grouped, ungrouped, function_pattern, macro_pattern, special_macro_pattern)

    finalize_results(updated_grouped, ungrouped)
    updated_grouped["Ungrouped functions"] = ungrouped
    return updated_grouped

# def add_param_def_info_out(group_calls, ungrouped_calls, layer, base_dir="."):
#     """
#     Searches headers for parameter definitions and adds them (and their comments) to the param info.

#     Parameters:
#     - base_dir (str): Base path for relative formatting.

#     Returns:
#     - dict: Enhanced param info with def_location and improved description.
#     """
#     print("\nRetrieving parameter definition paths and descriptions.\n")
#     grouped_params = {}

#     for caller_group, params in grouped_params.items():
#         if caller_group == layer:
#             continue
#         # Determine base folder from caller group name
#         base_key = caller_group.split(" - ")[0]
#         calling_headers = find_header_files(base_dir, base_key)

#         for param_name, info in params.items():
#             clean_param = param_name

#             # Skip standard C types
#             if is_standard_c_type(clean_param):
#                 continue

#             found = False
#             search_terms = set()

#             # Extract struct or type names from param string
#             struct_match = re.search(r"(struct\s+\w+)", clean_param)
#             if struct_match:
#                 search_terms.add(struct_match.group(1))
#             else:
#                 tokens = clean_param.replace("*", "").split()
#                 for tok in tokens:
#                     if tok not in STANDARD_C_TYPES and tok not in {"const", "volatile"}:
#                         search_terms.add(tok)

#             # Search through the usual suspects
#             zephyr_bt_include_dir = os.path.join(base_dir, "zephyr/include/zephyr/bluetooth")
#             zephyr_bt_subsys_dir = os.path.join(base_dir, "zephyr/subsys/bluetooth/host")

#             zephyr_bt_headers = []
#             for root, _, files in os.walk(zephyr_bt_include_dir):
#                 for file in files:
#                     if file.endswith(".h"):
#                         zephyr_bt_headers.append(os.path.join(root, file))
#             for root, _, files in os.walk(zephyr_bt_subsys_dir):
#                 for file in files:
#                     if file.endswith(".h"):
#                         zephyr_bt_headers.append(os.path.join(root, file))

#             # Always include these
#             zephyr_bt_headers.append(os.path.join(base_dir, "zephyr/include/zephyr/kernel.h"))
#             zephyr_bt_headers.append(os.path.join(base_dir, "zephyr/include/zephyr/net_buf.h"))

#             # Search through all candidate header files
#             # This is taking WAY too long
#             ##TODO: remove the "double" ones
#             for header in header_list:
#                 try:
#                     with open(header, "r", encoding="utf-8") as f:
#                         lines = f.readlines()

#                     for idx, line in enumerate(lines):
#                         for term in search_terms:
#                             if re.search(rf"\b{re.escape(term)}\b.*[{{;]", line):
#                             # # # # if re.search(rf"\bstruct\b.*\b{re.escape(term)}\b.*\{{", line):
#                                 comment = extract_comment_above(lines, idx)
#                                 info["def_location"] = f"{os.path.relpath(header, base_dir)}:{idx + 1}"

#                                 # Add comment only if relevant
#                                 if comment:
#                                     if "None" in info["description"]:
#                                         info["description"] = comment
#                                     else:
#                                         info["description"] += f" | {comment}"
#                                 else:
#                                     if not info["description"]:
#                                         info["description"] = "None available"
#                                 found = True
#                                 break
#                         if found:
#                             break
#                 except Exception:
#                     continue

#             if not found:
#                 info["def_location"] = "Not found."

#     return grouped_params
