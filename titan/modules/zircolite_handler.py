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
import json
import subprocess
import pandas as pd
from rich.console import Console
from timesketch_import_client import importer
from modules.utils import export_to_jsonl, ensure_directory_exists

console = Console()

def import_zircolite_json_files_into_timesketch(json_folder_path, sketch):
    # List all JSON files in the folder
    json_files = [f for f in os.listdir(json_folder_path) if f.endswith('.json')]

    all_events = []

    for json_file in json_files:
        var_name = os.path.splitext(json_file)[0]  # Get the variable name from the filename
        file_path = os.path.join(json_folder_path, json_file)
        with open(file_path, 'r') as f:
            data = json.load(f)
            
            # If data is a string, parse it
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError as e:
                    console.print(f"Error decoding JSON data in file {json_file}: {e}", style="bold red")
                    continue

            # Ensure data is a list
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                console.print(f"Unexpected data format in file {json_file}. Skipping.", style="bold red")
                continue

            # Process each event in the data list
            for event in data:
                if isinstance(event, str):
                    try:
                        event = json.loads(event)
                    except json.JSONDecodeError as e:
                        console.print(f"Error decoding event in file {json_file}: {e}", style="bold red")
                        continue
                if not isinstance(event, dict):
                    console.print(f"Skipping invalid event in file {json_file}.", style="bold red")
                    continue
                
                # Add the variable name as 'variable_name' and tag
                event['variable_name'] = var_name
                tag_info = MITRE_TACTIC_MAPPINGS.get(var_name, {'tag': var_name})
                event['tag'] = [tag_info['tag']]  # Tags should be a list

                # Handle timestamp
                timestamp = event.get('UtcTime') or event.get('SystemTime')
                if timestamp:
                    try:
                        parsed_timestamp = pd.to_datetime(timestamp, infer_datetime_format=True, utc=True, errors='raise')
                        event['datetime'] = parsed_timestamp.isoformat()
                    except Exception as e:
                        console.print(f"Error parsing timestamp '{timestamp}' in file {json_file}: {e}", style="bold red")
                        event['datetime'] = datetime.datetime.utcnow().isoformat()
                else:
                    event['datetime'] = datetime.datetime.utcnow().isoformat()

                all_events.append(event)

    # Export all events to a JSONL file
    jsonl_file = os.path.join(json_folder_path, 'zircolite_events.jsonl')
    export_to_jsonl(all_events, jsonl_file)

    # Import into Timesketch
    try:
        with importer.ImportStreamer() as streamer:
            streamer.set_sketch(sketch)
            streamer.set_timeline_name('Zircolite Timeline')
            streamer.set_timestamp_description('Event Timestamp')
            streamer.add_file(jsonl_file)
        console.print("Data successfully imported into Timesketch using ImportStreamer.", style="bold green")
    except Exception as e:
        console.print(f"Error importing file into Timesketch: {e}", style="bold red")

def handle_zircolite_import():
    # Paths to the Node.js script and data.js
    nodejs_script_path = '/home/triagex/Downloads/ADAM/extract_data.js'  # Replace with the actual path
    data_js_path = '/home/triagex/Downloads/ADAM/data.js'  # Replace with the actual path
    json_output_directory = '/home/triagex/Downloads/ADAM/zircolite'  # Same as outputDirectory in extract_data.js

    # Ensure the JSON output directory exists
    if not os.path.exists(json_output_directory):
        os.makedirs(json_output_directory)

    # Run the Node.js script to generate JSON files
    console.print(f"Running Node.js script to extract data from data.js...", style="bold blue")
    try:
        subprocess.run(['node', nodejs_script_path], check=True)
        console.print("Node.js script executed successfully.", style="bold green")
    except subprocess.CalledProcessError as e:
        console.print(f"Error executing Node.js script: {e}", style="bold red")
        return

    # Proceed to import the JSON files into Timesketch
    console.print(f"Importing Zircolite data from JSON files in {json_output_directory} into Timesketch...", style="bold blue")
    import_zircolite_json_files_into_timesketch(json_output_directory, sketch, MITRE_TACTIC_MAPPINGS)

def run_zircolite_report():
    try:
        # Run the zircolitereport.py script
        subprocess.run(['python3', '/home/triagex/Downloads/ADAM/zircolitereport.py'], check=True)
        print("Zircolite report generated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error generating zircolite report: {e}")

