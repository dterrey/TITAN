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

import json
from rich.console import Console
import os

console = Console()

# Define the MITRE ATT&CK mappings based on variable names and associated tags
MITRE_TACTIC_MAPPINGS = {
    'InitialAccessData': {'tag': 'Initial Access'},
    'PersistenceData': {'tag': 'Persistence'},
    'PrivilegeEscalationData': {'tag': 'Privilege Escalation'},
    'DefenseEvasionData': {'tag': 'Defense Evasion'},
    'CredentialAccessData': {'tag': 'Credential Access'},
    'DiscoveryData': {'tag': 'Discovery'},
    'LateralMovementData': {'tag': 'Lateral Movement'},
    'ExecutionData': {'tag': 'Execution'},
    'CollectionData': {'tag': 'Collection'},
    'ExfiltrationData': {'tag': 'Exfiltration'},
    'CommandAndControlData': {'tag': 'Command and Control'},
    'ImpactData': {'tag': 'Impact'},
    'OtherData': {'tag': 'Other'},
    'UnknownData': {'tag': 'Unknown'},
    'LowData': {'tag': 'Low Severity'},
    'MediumData': {'tag': 'Medium Severity'},
    'HighData': {'tag': 'High Severity'},
    'CriticalData': {'tag': 'Critical Severity'},
    'InformationalData': {'tag': 'Informational'}
}

def extract_data_from_json_files(json_folder_path):
    data_dict = {}
    for var_name in MITRE_TACTIC_MAPPINGS.keys():
        json_file = os.path.join(json_folder_path, f"{var_name}.json")
        if os.path.exists(json_file):
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                data_dict[var_name] = data
        else:
            console.print(f"JSON file for {var_name} not found.", style="bold yellow")
    return data_dict

def display_events_line_by_line(events, fields):
    if not events:
        console.print("No events found for the specified category.", style="bold yellow")
        return

    for event in events:
        console.print("\n--- Event ---", style="bold magenta")
        for field in fields:
            value = event.get(field, 'N/A')
            console.print(f"{field}: {value}", style="cyan")

def show_events_by_category(json_folder_path, category):
    data = extract_data_from_json_files(json_folder_path)
    category_var_name = category.replace(' ', '') + 'Data'  # E.g., 'InitialAccessData'

    # Handle special case for full timeline
    if category.lower() in ['full timeline', 'all events']:
        all_events = []
        for var_name, events in data.items():
            all_events.extend(events)
        # Sort events by UtcTime if available
        all_events.sort(key=lambda x: x.get('UtcTime', ''))
        events_to_display = all_events
    else:
        # Attempt to find the variable matching the category
        events_to_display = data.get(category_var_name, [])
        if not events_to_display:
            # Try alternative approach by checking if category is part of the variable name
            for var_name in data.keys():
                if category.lower().replace(' ', '') in var_name.lower():
                    events_to_display = data[var_name]
                    break

    fields = [
        'title', 'description', 'Image', 'ProcessId', 'UtcTime', 'Computer',
        'EventID', 'UserID', 'SystemTime', 'CommandLine', 'CurrentDirectory',
        'Description', 'Hashes', 'ParentCommandLine', 'ParentImage',
        'ParentProcessId', 'User', 'Destination', 'ScriptBlockText',
        'Details', 'OriginalFileName', 'tag'
    ]

    display_events_line_by_line(events_to_display, fields)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Parse JSON files and display events.')
    parser.add_argument('--json_folder', required=True, help='Path to the folder containing the JSON files')
    parser.add_argument('--category', required=True, help='Event category to display')

    args = parser.parse_args()

    show_events_by_category(args.json_folder, args.category)

