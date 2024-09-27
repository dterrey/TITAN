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

# /home/triagex/Downloads/ADAM/modules/timesketch_handler.py

import os
import re
import json
import pandas as pd
from timesketch_api_client import client, search
from urllib.parse import urlencode
from rich.console import Console
import logging

from modules.utils import ensure_directory_exists  # Import utility functions

console = Console()

def run_sigma_rule_in_timesketch(rule, sketch):
    """
    Execute a single Sigma rule against a Timesketch sketch.

    Args:
        rule (dict): The Sigma rule as a dictionary.
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.
    """
    if 'detection' in rule:
        detection_condition = rule['detection'].get('selection_img', [])
        
        query_conditions = []
        
        if isinstance(detection_condition, list):  # Ensure it's a list before processing
            for condition in detection_condition:
                if isinstance(condition, dict):  # Check if it's a dictionary
                    for key, value in condition.items():
                        # If the value is a list, build a valid Timesketch query by connecting with OR
                        if isinstance(value, list):
                            value_query = ' OR '.join([f"{key}:{v}" for v in value])
                            query_conditions.append(f"({value_query})")
                        else:
                            query_conditions.append(f"{key}:{value}")
    
        if query_conditions:
            query = ' OR '.join(query_conditions)
            
            # Run the query in Timesketch
            search_obj = search.Search(sketch=sketch)
            search_obj.query_string = query
            try:
                search_results = search_obj.table
                events_df = pd.DataFrame(search_results)
                
                # Display the total number of events found
                event_count = len(events_df)
                console.print(f"Total events found: {event_count} for Sigma rule '{rule.get('title')}'.", style="bold yellow")
                
                if event_count > 0:
                    # Apply tags to matching events
                    tag_name = rule.get('tags', ['Sigma Rule Match'])[0]
                    events_to_tag = []
                    for _, event in events_df.iterrows():
                        event_id = event['_id']
                        index_id = event['_index']

                        # Retrieve event details to check existing tags
                        event_details = sketch.get_event(event_id=event_id, index_id=index_id)
                        existing_tags = event_details.get('tag', [])

                        # Only add the tag if it's not already there
                        if tag_name not in existing_tags:
                            events_to_tag.append({
                                '_id': event_id,
                                '_index': index_id
                            })

                    # Tag events if there are any to tag
                    if events_to_tag:
                        sketch.tag_events(events_to_tag, [tag_name])
                        console.print(f"Tagged {len(events_to_tag)} events with tag '{tag_name}'.", style="bold green")
                    else:
                        console.print(f"No new tags were applied; all relevant events are already tagged.", style="bold yellow")
                else:
                    console.print(f"No events found for Sigma rule '{rule.get('title')}'.")
            except Exception as e:
                console.print(f"Failed to query Timesketch for Sigma rule '{rule.get('title')}'. Error: {e}", style="bold red")

def process_sigma_rules_in_folder(folder_path, sketch):
    """
    Process and execute all Sigma rules found in a specified folder against a Timesketch sketch.

    Args:
        folder_path (str): Path to the folder containing Sigma rule YAML files.
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.
    """
    from modules.data_parser import parse_sigma_rule  # Import here to avoid circular dependency
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.yml') or file_name.endswith('.yaml'):
                rule_path = os.path.join(root, file_name)
                rule = parse_sigma_rule(rule_path)
                console.print(f"Processing Sigma rule: {rule.get('title')}")
                run_sigma_rule_in_timesketch(rule, sketch)

def handle_data_parser_action(params):
    action = params.get('action')
    js_file_path = params.get('js_file')
    category = params.get('category')

    if not js_file_path or not category:
        console.print("JavaScript file path or category is missing.", style="bold red")
        return

    # Call data_parser.py as a subprocess
    try:
        # Capture the output of data_parser.py
        result = subprocess.run(['python3', 'data_parser.py', '--js_file', js_file_path, '--category', category],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Print the output to the console
        console.print(result.stdout, style="bold green")
        if result.stderr:
            console.print(result.stderr, style="bold red")
    except subprocess.CalledProcessError as e:
        console.print(f"Error executing data_parser.py: {e}", style="bold red")


def query_timesketch_for_mitre_attack(sketch):
    """
    Query Timesketch for events tagged with MITRE ATT&CK techniques.

    Args:
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.

    Returns:
        pandas.DataFrame: DataFrame containing the matching events.
    """
    query = 'tag:"mitre.attack.*"'  # Adjusted to search for any tag that starts with "mitre.attack"
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)

    if not events_df.empty:
        console.print("Events tagged with MITRE ATT&CK techniques found:", style="bold green")
        console.print(events_df.head(5), style="cyan")
    else:
        console.print("No events tagged with MITRE ATT&CK techniques found in Timesketch.", style="bold red")
    
    return events_df

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
    import_zircolite_json_files_into_timesketch(json_output_directory, sketch)

def remove_tags_from_timesketch(sketch, tag_to_remove):
    """
    Remove a specific tag from all events in a Timesketch sketch.

    Args:
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.
        tag_to_remove (str): The name of the tag to remove.
    """
    try:
        # Search for events with the specified tag
        query = f'tag:"{tag_to_remove}"'
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = query
        search_results = search_obj.table
        events_df = pd.DataFrame(search_results)

        if events_df.empty:
            console.print(f"No events found with the tag '{tag_to_remove}'.", style="bold yellow")
            return

        events_to_update = []
        for _, event in events_df.iterrows():
            event_id = event['_id']
            index_id = event['_index']

            # Retrieve event details to check existing tags
            event_obj = sketch.get_event(event_id=event_id, index_id=index_id)
            existing_tags = event_obj.get('objects', {}).get('tag', [])

            # If the tag is present, add to the list for removal
            if tag_to_remove in existing_tags:
                events_to_update.append({'_id': event_id, '_index': index_id})

        # Use the untag_events method to remove the tag in batches of 500
        if events_to_update:
            batch_size = 500  # Maximum allowed per request
            total_events = len(events_to_update)
            for i in range(0, total_events, batch_size):
                batch = events_to_update[i:i + batch_size]
                sketch.untag_events(batch, [tag_to_remove])
                console.print(f"Removed tag '{tag_to_remove}' from batch {i // batch_size + 1}", style="bold green")
            console.print(f"Successfully removed the tag '{tag_to_remove}' from {len(events_to_update)} events.", style="bold green")
        else:
            console.print("No tags were removed; all relevant tags are already absent.", style="bold yellow")

    except Exception as e:
        console.print(f"An unexpected error occurred while removing tags: {e}", style="bold red")

def display_events_line_by_line(events_df):
    """
    Display events from a DataFrame line by line in a readable format.

    Args:
        events_df (pandas.DataFrame): DataFrame containing event data.
    """
    if events_df.empty:
        console.print("No events found.", style="bold yellow")
        return
    console.print("\n--- Search Results ---", style="bold magenta")
    for index, event in events_df.iterrows():
        timestamp = event.get('datetime', 'Unknown Time')
        message = event.get('message', 'No Message')
        event_id = event.get('event_identifier', 'No Event ID')
        source = event.get('source_short', 'No Source')
        user = event.get('username', 'No User')
        computer = event.get('hostname', 'No Computer')
        tag = ', '.join(event.get('tag', [])) if event.get('tag') else 'No Tags'

        # Attempt to extract [User] and [Computer] from the message if they are 'No User' and 'No Computer'
        if (user == 'No User' or pd.isna(user)) and message:
            user_match = re.search(r'\[User\] = ([^\[\],]+)', message)
            if user_match:
                user = user_match.group(1).strip()
        if (computer == 'No Computer' or pd.isna(computer)) and message:
            computer_match = re.search(r'\[Computer\] = ([^\[\],]+)', message)
            if computer_match:
                computer = computer_match.group(1).strip()
        if (event_id == 'No Event ID' or pd.isna(event_id)) and message:
            event_id_match = re.search(r'\[EventID\] = ([^\[\],]+)', message)
            if event_id_match:
                event_id = event_id_match.group(1).strip()                

        console.print(f"Time: {timestamp}", style="cyan")
        console.print(f"Event ID: {event_id}", style="green")
        console.print(f"Source: {source}", style="yellow")
        console.print(f"User: {user}", style="blue")
        console.print(f"Computer: {computer}", style="blue")
        console.print(f"Tags: {tag}", style="magenta")
        console.print(f"Message: {message}\n", style="white")

def export_all_tagged_events_to_csv(export_folder, csv_filename, sketch):
    """
    Export all tagged events from Timesketch to a CSV file.

    Args:
        export_folder (str): The directory where the CSV will be saved.
        csv_filename (str): The name of the CSV file.
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.
    """
    try:
        # Ensure the filename ends with .csv
        if not csv_filename.endswith('.csv'):
            csv_filename += '.csv'

        # Define the query to find all tagged events
        query = 'tag:*'

        # Search for all tagged events in Timesketch
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = query
        search_results = search_obj.to_dict()  # Convert search results to a dictionary

        # Flatten the nested JSON structure to include all fields
        events_df = pd.json_normalize(search_results['objects'])  # Use the 'objects' key to access event data

        if events_df.empty:
            console.print(f"No tagged events found in Timesketch.", style="bold yellow")
            return

        # Ensure the export folder exists
        ensure_directory_exists(export_folder)

        # Define the full path for the CSV file
        full_path = os.path.join(export_folder, csv_filename)

        # Export the DataFrame to CSV, including all fields
        events_df.to_csv(full_path, index=False)
        console.print(f"All tagged events successfully exported to {full_path}", style="bold green")

    except Exception as e:
        console.print(f"An unexpected error occurred while exporting tagged events: {e}", style="bold red}")

def search_timesketch_and_tag_iocs(query, sketch, csv_filename=None, summary_template=None, action="timesketch_tag"):
    """
    Search Timesketch with a given query, optionally tag the results, and export them.

    Args:
        query (str): The Timesketch query string.
        sketch (timesketch_api_client.sketch.Sketch): The Timesketch sketch object.
        csv_filename (str, optional): Filename to export the results as CSV.
        summary_template (dict, optional): Template for generating summaries.
        action (str, optional): The action to perform, default is "timesketch_tag".

    Returns:
        pandas.DataFrame: DataFrame containing the search results.
    """
    from modules.utils import filter_invalid_query_parts  # Import utility function
    from modules.user_interface import generate_nlg_summary  # Import summary function

    try:
        if query is None:
            console.print("No valid query was generated.", style="bold red")
            if summary_template:
                generate_nlg_summary(pd.DataFrame(), summary_template)
            return pd.DataFrame()

        # Prompt for a custom tag name only if action is "timesketch_tag"
        tag_name = None
        if action == "timesketch_tag":
            tag_name = input("Please enter the tag name to apply: ").strip()
            if not tag_name:
                console.print("Tag name cannot be empty. Operation aborted.", style="bold red")
                return pd.DataFrame()

        # Split the query into parts and filter out invalid parts
        query_parts = query.split(" OR ")
        filtered_query_parts = filter_invalid_query_parts(query_parts)

        # Ensure there are still valid parts after filtering
        if not filtered_query_parts:
            console.print("All query parts were skipped due to invalid characters or starting with '-'. No valid query remains.", style="bold yellow")
            return pd.DataFrame()

        # Combine filtered query parts
        combined_query = " OR ".join(filtered_query_parts)
        console.print(f"Executing query: {combined_query}", style="bold blue")

        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = combined_query
        search_results = search_obj.table
        all_results_df = pd.DataFrame(search_results)

        if all_results_df.empty:
            console.print("No results found.", style="bold yellow")
            return pd.DataFrame()

        # Show total number of matching events
        total_events = len(all_results_df)
        console.print(f"Total number of events matching '{query}': {total_events}\n", style="bold green")

        # Limit to first 5 results
        limited_events_df = all_results_df.head(5)

        # Display the first 5 results
        display_events_line_by_line(limited_events_df)

        # Generate Timesketch URL with the query
        base_url = 'http://localhost'  # Replace with your Timesketch web interface URL if different
        sketch_id = sketch.id
        query_params = {'q': query}
        timesketch_url = f"{base_url}/sketch/{sketch_id}/explore/?" + urlencode(query_params)
        console.print(f"View more events at: {timesketch_url}", style="bold blue")

        # Export results if a filename is provided
        if csv_filename:
            full_path = os.path.join(export_folder, csv_filename)
            ensure_directory_exists(full_path)
            try:
                all_results_df.to_csv(full_path, index=False)
                console.print(f"Results successfully exported to {full_path}", style="bold green")
            except Exception as e:
                console.print(f"Failed to export results to CSV: {e}", style="bold red")

        # Tag events only if the action is "timesketch_tag"
        if action == "timesketch_tag":
            events_to_tag = []
            for _, event in all_results_df.iterrows():
                event_id = event['_id']
                index_id = event['_index']

                # Retrieve event details to check existing tags
                event_details = sketch.get_event(event_id=event_id, index_id=index_id)
                existing_tags = event_details.get('tag', [])

                # Only add the custom tag if it's not already there
                if tag_name not in existing_tags:
                    events_to_tag.append({
                        '_id': event_id,
                        '_index': index_id,
                        '_type': 'generic_event'
                    })

            # Tag events if there are any to tag
            if events_to_tag:
                sketch.tag_events(events_to_tag, [tag_name])
                console.print(f"Tagged {len(events_to_tag)} events with '{tag_name}'.", style="bold green")
            else:
                console.print("No new tags were applied; all relevant events are already tagged.", style="bold yellow")

        return all_results_df

    except Exception as e:
        console.print(f"An unexpected error occurred: {e}", style="bold red")
        return pd.DataFrame()

