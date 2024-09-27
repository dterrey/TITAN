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

# /home/triagex/Downloads/ADAM/modules/user_interface.py

import re
import pandas as pd
from rich.console import Console

console = Console()

def should_generate_summary(question, summary_template):
    """
    Determine if a summary should be generated based on the question and the presence of a summary template.
    """
    if summary_template:
        # If a summary template is provided, we should generate a summary.
        return True
    if "event" in question.lower() or "events" in question.lower():
        # If the question refers to events and a summary template is available, generate the summary.
        return True
    return False

# Function to interpret the user question and map it to a Timesketch query, Codex query, file query, or URLScan.io query
def interpret_question(question):
    global active_mode, export_folder

    # Check if the question is requesting to show events of a specific category
    match = re.match(r'show me all (.+) events', question.lower())
    if match:
        category = match.group(1).strip()
        js_file_path = '/home/triagex/Downloads/ADAM/data.js'  # Update this path to your actual data.js file
        action = 'data_parser'
        extra_params = {'action': 'show_category', 'js_file': js_file_path, 'category': category}
        return None, None, action, extra_params

    # Check if the user asked to generate the zircolite report
    if "generate zircolite report" in question.lower():
        return None, None, "zircolite_report", None

    # Handle 'show me the full timeline of events' command
    if "show me the full timeline of events" in question.lower():
        js_file_path = '/home/triagex/Downloads/ADAM/data.js'  # Update this path to your actual data.js file
        category = 'full timeline'
        action = 'data_parser'
        extra_params = {'action': 'show_category', 'js_file': js_file_path, 'category': category}
        return None, None, action, extra_params

    # Handle importing Zircolite data
    if "import zircolite data" in question.lower():
        return None, None, "zircolite_import", None

    # Handle export folder setting
    if question.lower().startswith("set export"):
        path = question[10:].strip()
        set_export_folder(path)
        return None, None, "info", None

    # Handle export to specific CSV filename
    csv_filename = None
    if "export to" in question:
        parts = question.split("export to")
        question = parts[0].strip()
        csv_filename = parts[1].strip()

    # Export all tagged events to CSV
    if "export all tagged events to" in question.lower():
        csv_filename = question.lower().split("export all tagged events to")[-1].strip()
        return None, None, "export_tagged_events", csv_filename

    # Tag all specific events based on identifier or keyword
    if question.lower().startswith("tag all"):
        tag_target = question[8:].strip()

        # Determine if it's a specific event ID or a keyword
        if tag_target.isdigit():
            query = f"event_identifier:{tag_target}"
        else:
            query = f"message:{tag_target}"

        return query, None, "timesketch_tag", csv_filename

    # Tag events based on keywords (e.g., "tag test.exe events")
    if question.lower().startswith("tag "):
        tag_target = question[4:].strip().split(" events")[0].strip()

        if tag_target:
            query = f"message:{tag_target}"
            return query, None, "timesketch_tag", csv_filename

    # Remove a specific tag from events
    if question.lower().startswith("remove ") and " tag" in question.lower():
        tag_to_remove = question.lower().split("remove ")[1].split(" tag")[0].strip()
        return None, tag_to_remove, "remove_tag", None

    # Handle "show me all [tag_name] tagged events" queries
    if "tagged events" in question.lower():
        tag_name = question.lower().split("tagged events")[0].strip().split("show me all")[1].strip()
        query = f'tag:"{tag_name}"'
        return query, None, "timesketch", csv_filename

    # Handle IOC search and tagging in Timesketch
    if "search for iocs in timesketch and tag iocs" in question.lower():
        iocs = load_iocs()
        query_parts = []
        for key, ioc_list in iocs.items():
            if ioc_list:
                query_parts.append(" OR ".join([f"message:{ioc}" for ioc in ioc_list]))

        combined_query = " OR ".join(query_parts)
        if combined_query:
            return combined_query, None, "timesketch_tag", csv_filename
        else:
            console.print("No IOCs found in storage to search in Timesketch.", style="bold yellow")
            return None, None, None, None

    # Handle Codex file or hash queries
    if "codex file" in question.lower():
        file_path = input("Please enter the full path to the file for Codex analysis: ").strip()
        send_file_and_get_report(file_path)
        return None, None, "codex", None
    elif "codex hash" in question.lower():
        file_hash = input("Please enter the file hash (MD5, SHA1, or SHA256) for Codex analysis: ").strip()
        process_hash(file_hash)
        return None, None, "codex", None

    # Handle URLScan.io queriesquery, summary_template, action, extra_params = interpret_question(question)
    if "scan url" in question.lower():
        url_match = re.search(r'scan url\s+(\S+)', question, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            scan_id = scan_url(url)
            if scan_id:
                console.print("Waiting for scan results...", style="bold yellow")
                scan_data = get_scan_results(scan_id)
                if scan_data:
                    folder_name = create_safe_folder_name(url)
                    folder_path = os.path.join('/home/triagex/Downloads/ADAM/url', folder_name)
                    os.makedirs(folder_path, exist_ok=True)
                    display_results(scan_data)
                    export_results_to_csv(scan_data, folder_path)
                    save_results_to_json(scan_data, folder_path)
                    save_screenshot(scan_data, folder_path)
                    download_all_responses(scan_data, folder_path)
            return None, None, "urlscan", None

    # Handle specific event ID query in the custom event database
    event_id_match = re.search(r'event\s?(\d+)', question, re.IGNORECASE)
    if event_id_match:
        event_id = event_id_match.group(1)
        if event_id in event_descriptions:
            description = event_descriptions[event_id]['description']
            analyst_summary = event_descriptions[event_id]['analyst_summary']
            summary_template = {
                "title": f"Details for Event {event_id}",
                "content": [
                    f"Event ID: {event_id}",
                    f"Description: {description}",
                    f"Analyst Summary: {analyst_summary}"
                ],
                "detailed_analysis": event_descriptions[event_id].get('detailed_analysis', []),
                "suggestions": event_descriptions[event_id].get('suggestions', [])
            }
            return f"event_identifier:{event_id}", summary_template, "timesketch", csv_filename
        else:
            console.print(f"No description found for Event ID {event_id}.", style="bold red")
            return None, None, None, None

    # Handle keyword search (e.g., "show me all test.exe events")
    keyword_match = re.search(r'show me all (.+) events', question, re.IGNORECASE)
    if keyword_match:
        keyword = keyword_match.group(1).strip()
        query = f"message:{keyword}"
        return query, None, "timesketch", csv_filename

    # Handle simple keyword search (e.g., "show me test.exe events")
    simple_keyword_match = re.search(r'show me (.+) events', question, re.IGNORECASE)
    if simple_keyword_match:
        keyword = simple_keyword_match.group(1).strip()
        query = f"message:{keyword}"
        return query, None, "timesketch", csv_filename

    # Handle multiple event IDs in Timesketch queries (e.g., show me all 4624 and 4625 events)
    timesketch_event_ids = re.findall(r'\b\d+\b', question)
    if timesketch_event_ids:
        query = " OR ".join([f"event_identifier:{eid}" for eid in timesketch_event_ids])
        return query, None, "timesketch", csv_filename

    # Look for a predefined question match
    matched_question = match_question(question)
    if matched_question:
        return matched_question['query'], matched_question['summary_template'], "timesketch", csv_filename

    # Handle switching between modes
    if "switch to timesketch" in question.lower():
        active_mode = "timesketch"
        return "Switched to Timesketch mode.", None, "info", None
    elif "switch to file" in question.lower():
        active_mode = "file"
        return "Switched to file mode.", None, "info", None
        
    # Handle removal of a specific tag from events
    if question.lower().startswith("remove "):
        tag_part = question[7:].strip()  # Remove the word 'remove '
        # Remove trailing 'tag' or 'tags'
        if tag_part.endswith(' tag'):
            tag_to_remove = tag_part[:-4].strip()  # Strip the word 'tag'
        elif tag_part.endswith(' tags'):
            tag_to_remove = tag_part[:-5].strip()  # Strip the word 'tags'
        else:
            tag_to_remove = tag_part
        return None, tag_to_remove, "remove_tag", None        

    return None, None, None, None

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

def generate_event_summary(events_df):
    """
    Generate a summary of events from a DataFrame.

    Args:
        events_df (pandas.DataFrame): DataFrame containing event data.
    """
    console.print("\n--- Summary of Events ---", style="bold magenta")

    total_events = len(events_df)
    console.print(f"Total events: {total_events}", style="bold green")

    # Extract users
    users = []
    for index, event in events_df.iterrows():
        user = event.get('username')
        message = event.get('message', '')
        if pd.notna(user) and user != 'No User':
            users.append(user)
        else:
            user_match = re.search(r'\[User\] = ([^\[\],]+)', message)
            if user_match:
                users.append(user_match.group(1).strip())
    users = list(set(users))
    console.print(f"Users involved: {', '.join(users)}", style="cyan")

    # Extract computers
    computers = []
    for index, event in events_df.iterrows():
        computer = event.get('hostname')
        message = event.get('message', '')
        if pd.notna(computer) and computer != 'No Computer':
            computers.append(computer)
        else:
            computer_match = re.search(r'\[Computer\] = ([^\[\],]+)', message)
            if computer_match:
                computers.append(computer_match.group(1).strip())
    computers = list(set(computers))
    console.print(f"Computers involved: {', '.join(computers)}", style="cyan")

    # Extract Event IDs
    event_ids = []
    if 'event_identifier' in events_df.columns:
        event_ids = events_df['event_identifier'].dropna().unique().tolist()
    else:
        for index, event in events_df.iterrows():
            event_id = event.get('event_identifier')
            message = event.get('message', '')
            if pd.notna(event_id) and event_id != 'No Event ID':
                event_ids.append(event_id)
            else:
                event_id_match = re.search(r'\[EventID\] = ([^\[\],]+)', message)
                if event_id_match:
                    event_id = event_id_match.group(1).strip()
                    event_ids.append(event_id)
        event_ids = list(set(event_ids))
    if event_ids:
        console.print(f"Event IDs: {', '.join(map(str, event_ids))}", style="cyan")
    else:
        console.print("No Event IDs found.", style="cyan")

    # Common actions or messages
    messages = events_df['message'].unique().tolist()
    if len(messages) <= 5:
        console.print("\nMessages:", style="cyan")
        for msg in messages:
            console.print(f"- {msg}", style="white")
    else:
        console.print(f"\nUnique messages: {len(messages)}", style="cyan")

    # Tags
    tags = []
    for tag_list in events_df['tag']:
        if isinstance(tag_list, list):
            tags.extend(tag_list)
    tags = list(set(tags))
    console.print(f"Tags: {', '.join(tags)}", style="cyan")

    # Generate a commentary
    console.print("\n--- Commentary ---", style="bold magenta")
    commentary = f"A total of {total_events} events were found"
    if users:
        commentary += f" involving users {', '.join(users)}"
    if computers:
        commentary += f" on computers {', '.join(computers)}"
    if event_ids:
        commentary += f". The events include Event IDs {', '.join(map(str, event_ids))}"
    if tags:
        commentary += f" and are tagged with {', '.join(tags)}."
    else:
        commentary += "."
    console.print(commentary, style="green")

def match_question(user_question, predefined_questions):
    """
    Match the user's question with predefined questions using TF-IDF similarity.

    Args:
        user_question (str): The question input by the user.
        predefined_questions (dict): Dictionary containing predefined questions.

    Returns:
        dict or None: The best matched predefined question or None if no match exceeds the threshold.
    """
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.feature_extraction.text import TfidfVectorizer

    questions = [q['question'] for q in predefined_questions['questions']]
    vectorizer = TfidfVectorizer().fit_transform(questions + [user_question])
    vectors = vectorizer.toarray()
    cosine_similarities = cosine_similarity(vectors[-1:], vectors[:-1])
    best_match_index = cosine_similarities.argmax()
    best_match_score = cosine_similarities[0][best_match_index]
    if best_match_score > 0.5:  # Threshold for matching
        return predefined_questions['questions'][best_match_index]
    return None

def generate_nlg_summary(events_df, summary_template):
    """
    Generate a Natural Language Generation (NLG) summary based on a summary template.

    Args:
        events_df (pandas.DataFrame): DataFrame containing event data.
        summary_template (dict): Template containing title, content, detailed analysis, and suggestions.
    """
    # Print the title
    console.print(f"\n{summary_template['title']}", style="bold magenta")

    # Print the content
    for line in summary_template['content']:
        console.print(line, style="cyan")

    # Print the detailed analysis, if available
    if 'detailed_analysis' in summary_template and summary_template['detailed_analysis']:
        console.print("\nDetailed Analysis:", style="bold blue")
        for detail in summary_template['detailed_analysis']:
            console.print(f"- {detail}", style="yellow")

    # Print the suggestions, if available
    if 'suggestions' in summary_template and summary_template['suggestions']:
        console.print("\nSuggestions:", style="bold blue")
        for suggestion in summary_template['suggestions']:
            console.print(f"- {suggestion}", style="green")

    # Print a summary of event counts if the DataFrame is not empty
    if not events_df.empty:
        if 'event_identifier' in events_df.columns:
            console.print("\nEvent Summary:", style="bold blue")
            event_counts = events_df['event_identifier'].value_counts()
            for event_id, count in event_counts.items():
                console.print(f"Event ID {event_id}: {count} occurrences", style="cyan")
        else:
            console.print("Event identifier not found in the Timesketch results.", style="bold red")

