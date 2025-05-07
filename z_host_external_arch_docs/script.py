import json
from general import find_headers, contains_groups, save_function_names
from in_functions import (
    extract_function_patterns,
    find_function_calls,
    add_usage_to_groups,
    extract_caller_groups,
    add_param_def_info
)
from logging_functions import (
    write_in_info,
    write_output_to_file,
    write_caller_group_params_to_file
)
from out_functions import (
    extract_common_folders,
    find_c_files,
    filter_files_with_function_definitions,
    extract_function_calls,
    get_function_groups_from_user,
    group_function_calls_by_keyword,
    extract_declarations_for_known_calls
)


def main():
    ### GENERAL ###
    # Input the layer you're looking for
    layer = input("Enter the word to search for in header filenames (e.g., 'gatt'): ")

    # Get the list of header files containing the word
    header_list = find_headers(layer)
    if not header_list:
        print("There are no headers fitting to this, mistyped? Try again.")
        return

    print(f"\nFollowing headers are scanned for {layer} functions:")
    for item in header_list:
        print(item)
    print("\nProcessing workspace\n")

    all_groups = {}
    for header in header_list:
        if contains_groups(header):
            groups_info = save_function_names(header, True)
        else:
            groups_info = save_function_names(header, False)
        all_groups.update(groups_info)

    ### IN ###
    # # Debug write all the infocollected from header_list to file, comment-in if needed
    # all_groups_file = f"all_groups_{layer}.txt"
    # with open(all_groups_file, "w", encoding="utf-8") as file:
    #     json.dump(all_groups, file, indent=4)
    # print(f"\nDGB: See {layer} fucntions info in {all_groups_file}\n")

    pattern = extract_function_patterns(all_groups)
    print("Grepping in the workspace for following patterns:")
    for func_pattern in pattern:
        print(func_pattern)
    print()
    print("If you see many patterns here, probably means naming conventions in the header isn't followed or the header has many sub-modules.\n")
    print("Grepping, this might take a longer moment.\n\n")

    # Search for function calls in the current directory
    directory = "."  # current directory
    lookup_table = find_function_calls(directory, pattern, header_list)

    # # Debug write lookup_table to file, comment-in if needed
    # lookup_table_file = f"lookup_{layer}.txt"
    # with open(lookup_table_file, "w", encoding="utf-8") as file:
    #     json.dump(lookup_table, file, indent=4)
    # print(f"\nDGB: Find the lookup table in {lookup_table_file}\n")

    # Add function usage info into the groups
    add_usage_to_groups(all_groups, lookup_table)

    # Save the grouped IN info
    all_groups_file = f"IN_{layer}_functions_info.txt"
    write_in_info(all_groups, all_groups_file)

    # Extract caller groups and params, then enrich with param type/def info
    caller_groups, caller_group_params = extract_caller_groups(all_groups)
    grouped_params = add_param_def_info(caller_group_params, header_list, layer)

    # Save grouped param definitions
    in_grouped_params_file = f"IN_grouped_{layer}_params.txt"
    write_caller_group_params_to_file(grouped_params, in_grouped_params_file, layer)

    ######## Try with CONN, there might be MAAANY c-files, because of the different function names, so make it user interactible.
    ########### Need to fix these!
    # ### OUT ###
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

    # # Write OUT scan results to a file
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

    # # Prompt user to group function calls based on keywords
    # groups = get_function_groups_from_user(function_calls)
    # for group in groups:
    #     print(group)

    # # Group function calls using the user-defined keywords
    # grouped = group_function_calls_by_keyword(function_calls, groups)

    # # Extract declarations for calls we now have groups for
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

    # # Write all function call analysis to output file
    # write_output_to_file(calls_with_decls, "out_calls.txt")


# Run the script if executed directly
if __name__ == "__main__":
    main()
