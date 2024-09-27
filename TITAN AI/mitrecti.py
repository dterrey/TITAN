# -----------------------------------------------------------------------------
# TITAN (Threat Investigation and Tactical Analysis Network)
# Created by: [David Terrey - https://www.linkedin.com/in/david-terrey-a06b1312/]
# Copyright (c) 2024 [David Terrey - https://www.linkedin.com/in/david-terrey-a06b1312/]
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------

import os
import re
import json
import logging
from rich.console import Console

# Initialize console for styled text output
console = Console()

# Function to load and combine all JSON files from a folder and its subfolders with a static progress counter
def load_attack_data_from_folder(folder_path):
    attack_data = {"objects": []}  # Initialize with an empty "objects" list to combine all data
    file_counter = 0  # Counter for loaded files
    try:
        for root, dirs, files in os.walk(folder_path):
            for file_name in files:
                if file_name.endswith('.json'):
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'r') as f:
                        try:
                            data = json.load(f)
                            if "objects" in data:
                                attack_data["objects"].extend(data["objects"])  # Append all objects
                                file_counter += 1
                                print(f"\rUploading Mitre CTI files to ADAM... Files loaded: {file_counter}", end="", flush=True)
                        except json.JSONDecodeError:
                            logging.error(f"Failed to parse {file_path} as JSON.")
        print()  # To ensure the cursor goes to the next line after the process finishes
    except FileNotFoundError:
        logging.error(f"Folder not found: {folder_path}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    
    return attack_data

# Function to search for a name, alias, or ID in the JSON data, avoiding duplicate results and filtering by Object Type
def search_attack_data(query, attack_data):
    query = query.lower()
    results = []
    seen_results = set()  # To store already displayed names to avoid duplicates
    
    for obj in attack_data['objects']:
        name = obj.get('name', 'N/A').lower()
        description = obj.get('description', 'No description available')
        external_refs = obj.get('external_references', [])
        obj_type = obj.get('type', 'N/A')
        obj_id = obj.get('id', 'N/A')

        # Skip results without a valid Object Type
        if obj_type == 'N/A':
            continue

        # Build a formatted list of external references (show even if N/A)
        external_ids = []
        for ref in external_refs:
            external_id = ref.get('external_id', 'N/A')
            external_url = ref.get('url', '')
            external_ids.append(f"[{external_id}]({external_url})")

        # Check if the query matches the name, description, or external references
        if query in name or query in description.lower() or query in ' '.join(external_ids).lower():
            # Only add the result if it hasn't been displayed before
            if obj_id not in seen_results:
                results.append({
                    'name': obj.get('name', 'N/A'),
                    'description': description,
                    'external_ids': external_ids,
                    'id': obj_id,
                    'type': obj_type
                })
                seen_results.add(obj_id)  # Track this ID as seen
    return results

# No code is executed upon import

