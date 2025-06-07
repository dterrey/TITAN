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
import csv
from datetime import datetime

# ANSI escape codes for coloring the output
RESET = "\033[0m"
BOLD = "\033[1m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RED = "\033[91m"
DIVIDER = "\033[94m" + "=" * 80 + RESET  # Divider line in blue color

# Load the Zircolite JSONL file
file_path = '/home/titan/Downloads/ADAM/zircolite/zircolite_events.jsonl'

# Read the JSONL file into a list of events
events = []
with open(file_path, 'r') as file:
    for line in file:
        events.append(json.loads(line))

# Extract key fields from the events with MITRE ATT&CK focus and sort by time
def extract_mitre_attack_data(events):
    mitre_summaries = []
    sorted_events = []

    # Extract and format each event, adding to a timeline list
    for event in events:
        tactic = event.get("tag", ["Unknown"])[0]  # MITRE ATT&CK tactic (e.g., Persistence)
        title = event.get("title", "No title")  # Event title
        description = event.get("description", "No description provided")  # Event description
        process_name = event.get("Image", "Unknown process")  # Executed process
        datetime_str = event.get("datetime", "Unknown time")
        computer = event.get("Computer", "Unknown asset")
        event_id = event.get("EventID", "Unknown")
        process_id = event.get("ProcessId", "Unknown")
        user_id = event.get("UserID", "Unknown")
        user = event.get("User", "Unknown")
        subject_username = event.get("SubjectUserName", "Unknown")
        
        # Only add events with valid datetime
        if datetime_str != "Unknown time":
            try:
                event_time = datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
            except ValueError:
                event_time = datetime.min  # Fallback if datetime parsing fails
        else:
            event_time = datetime.min

        # Based on the MITRE tactic, generate summaries
        if tactic:
            # Add to sorted events for CSV export
            sorted_events.append({
                "event_time": event_time,
                "tactic": tactic,
                "title": title,
                "description": description,
                "process_name": process_name,
                "computer": computer,
                "event_id": event_id,
                "process_id": process_id,
                "user_id": user_id,
                "user": user,
                "subject_username": subject_username
            })

    # Sort the events by time
    sorted_events = sorted(sorted_events, key=lambda x: x["event_time"])

    return sorted_events

# Function to export events to CSV
def export_to_csv(events, csv_file_path):
    with open(csv_file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=[
            "event_time", "tactic", "title", "description", "process_name", 
            "computer", "event_id", "process_id", "user_id", "user", "subject_username"
        ])
        writer.writeheader()
        for event in events:
            writer.writerow({
                "event_time": event["event_time"].strftime('%Y-%m-%d %H:%M:%S'),
                "tactic": event["tactic"],
                "title": event["title"],
                "description": event["description"],
                "process_name": event["process_name"],
                "computer": event["computer"],
                "event_id": event["event_id"],
                "process_id": event["process_id"],
                "user_id": event["user_id"],
                "user": event["user"],
                "subject_username": event["subject_username"]
            })

# Generate MITRE ATT&CK-focused summaries and sort them by time
sorted_mitre_summaries = extract_mitre_attack_data(events)

# Display the sorted summaries with color coding and dividers
for event in sorted_mitre_summaries:
    print(f"{BOLD}{GREEN}Detected {event['tactic']} activity{RESET}: '{event['title']}'.\n"
          f"{CYAN}The process '{event['process_name']}' (ProcessID: {event['process_id']}){RESET} was involved.\n"
          f"{WHITE}Event description: {event['description']}.{RESET}\n"
          f"{YELLOW}EventID: {event['event_id']}, UserID: {event['user_id']}, User: {event['user']}, "
          f"SubjectUserName: {event['subject_username']}, Computer: {event['computer']}.{RESET}\n"
          f"{RED}The event occurred on {event['event_time'].strftime('%Y-%m-%d %H:%M:%S')} involving {event['computer']}. "
          f"This activity could lead to persistence or privilege escalation depending on the context.{RESET}\n"
          f"{DIVIDER}\n")

# Export sorted event data to a CSV file
export_to_csv(sorted_mitre_summaries, '/home/titan/Downloads/ADAM/mitre_attack_events.csv')

