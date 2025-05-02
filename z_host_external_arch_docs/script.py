import os
import re
import json
import subprocess
from typing import List, Dict
from collections import Counter

# def categorize_paths(paths_and_lines):
#     """
#     Categorizes file paths based on predefined groups and includes line numbers.

#     :param paths_and_lines: List of dictionaries containing 'file_path' and 'line_number'.
#     :return: A dictionary grouping the paths and their line numbers.
#     """
#     grouped_paths = {
#         "SAMPLE": [],
#         "L2CAP": [],
#         "GATT": [],
#         "ATT": [],
#         "SMP": [],
#         "HCI": [],
#         "IPC": [],
#         "DRIVERS": [],
#         "SERVICES": [],
#         "OTHER": []
#     }

#     for entry in paths_and_lines:
#         path = entry['file_path']
#         line_number = entry['line_number']
#         categorized_entry = f"{path}:{line_number}"  # Include line number in the entry

#         if "sample" in path:
#             grouped_paths["SAMPLE"].append(categorized_entry)
#         elif "l2cap" in path:
#             grouped_paths["L2CAP"].append(categorized_entry)
#         elif "gatt" in path:
#             grouped_paths["GATT"].append(categorized_entry)
#         elif "att" in path:
#             grouped_paths["ATT"].append(categorized_entry)
#         elif "smp" in path:
#             grouped_paths["SMP"].append(categorized_entry)
#         elif "hci" in path:
#             grouped_paths["HCI"].append(categorized_entry)
#         elif "ipc" in path:
#             grouped_paths["IPC"].append(categorized_entry)
#         elif "driver" in path:
#             grouped_paths["DRIVERS"].append(categorized_entry)
#         elif "service" in path:
#             grouped_paths["SERVICES"].append(categorized_entry)
#         else:
#             grouped_paths["OTHER"].append(categorized_entry)

#     # Now, return a deep copy of the lists inside the dictionary to avoid sharing references.
#     return {key: list(value) for key, value in grouped_paths.items()}

# def find_usage_of_funcs(target_function, lookup_table):
#     """
#     Finds all occurrences of the given function name in the lookup_table and removes them from it.

#     :param target_function: The function name to search for.
#     :param lookup_table: The list of dictionaries containing function calls.
#     :return: A dictionary where the function name is the key, and the value is a list of dictionaries with file paths and line numbers.
#     """
#     function_calls = {target_function: []}
#     remaining_entries = []

#     for entry in lookup_table:
#         if entry['function_name'] == target_function:
#             function_calls[target_function].append({
#                 'file_path': entry['file_path'],
#                 'line_number': entry['line_number']
#             })
#         else:
#             remaining_entries.append(entry)

#     # Remove found function calls from lookup_table
#     lookup_table[:] = remaining_entries

#     return function_calls

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
