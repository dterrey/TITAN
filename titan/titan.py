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

# titan.py

# ---------------------------
# Required Imports
# ---------------------------

import torch  # Add this import to use torch functions
import os
import re
import json
import pandas as pd
import spacy
import requests
import time
import datetime
import sqlite3  # Assuming SQLite is used, but you can change it to the appropriate DB library
import logging
import readline
import yaml
import importlib.util
import sys
import pickle
import subprocess
from urllib.parse import urlparse, urlencode
from timesketch_api_client import client, search
from timesketch_import_client import importer
from IPython.display import display
from codex import CodexGigasInfo
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer as SumyTokenizer
from sumy.summarizers.lsa import LsaSummarizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
from rich.console import Console
from rich.text import Text
import PyPDF2
import docx
import openpyxl
import nltk
import atexit
from transformers import BertTokenizer, BertForSequenceClassification, BertModel, pipeline
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import spacy
import logging

# Set TensorFlow log level to suppress unnecessary logs
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress all logs (0 = all logs, 1 = warnings, 2 = errors, 3 = fatal)
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # This will force TensorFlow to use CPU only
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("tensorflow").setLevel(logging.ERROR)

# ---------------------------
# Initialization and Setup
# ---------------------------

# Initialize NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('averaged_perceptron_tagger')

# Load BERT model and tokenizer for classification
bert_tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
bert_model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=5)  # Assume 5 labels for severity, adjust as needed
nlp_bert = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")

# Load GPT-2 for summarization
gpt2_tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
gpt2_model = GPT2LMHeadModel.from_pretrained("gpt2")


# Load spaCy model for NLU
nlp = spacy.load("en_core_web_lg")

# Initialize console for styled text output
#console = Console()
console = Console(width=200)  # Adjust width as needed

# Initialize Codex
cg = CodexGigasInfo()

# Define MITRE ATT&CK mappings
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

# Initialize export folder variable
export_folder = "/home/triagex/Downloads/TITAN/"

# File to store all extracted IOCs persistently
iocs_storage_file = '/home/triagex/Downloads/TITAN/iocs_storage.json'

# Specify the path to the mitrecti.py script
mitrecti_path = '/home/triagex/Downloads/TITAN/mitrecti.py'

# API Key for URLScan.io
API_KEY = "71999b57-0017-4055-956f-a38e8a8710a7"

# Initialize storage for uploaded data and active mode
uploaded_data = pd.DataFrame()
uploaded_text = ""
active_mode = "timesketch"

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost', username='triagex', password='admin')
sketch_id = 4  # Replace with your sketch ID
sketch = ts_client.get_sketch(sketch_id)

def connect_timesketch():
    # Replace these values with your actual Timesketch connection details
    ts_client = client.TimesketchApi('http://localhost', username='triagex', password='admin')
    sketch_id = 4  # Update this to your sketch ID
    
    # Test the connection to Timesketch
    try:
        sketch = ts_client.get_sketch(sketch_id)
        # Perform a test query to validate the connection
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = "message:test"  # A simple test query
        search_obj.table  # Execute the query to check the connection
        console.print("Successfully connected to Timesketch.", style="bold green")
    except Exception as e:
        console.print(f"Failed to connect to Timesketch: {e}", style="bold red")
        return None, None

    return ts_client, sketch


# Load predefined questions
def load_predefined_questions(filepath):
    with open(filepath, 'r') as file:
        data = json.load(file)
    return data

predefined_questions = load_predefined_questions('/home/triagex/Downloads/TITAN/predefined_questions.json')

# Load event descriptions
def load_event_descriptions(filepath):
    with open(filepath, 'r') as file:
        event_descriptions = json.load(file)
    return event_descriptions

event_descriptions = load_event_descriptions('/home/triagex/Downloads/TITAN/event_descriptions.json')

# Load mitrecti.py dynamically
def load_mitrecti_module(path):
    spec = importlib.util.spec_from_file_location("mitrecti", path)
    mitrecti = importlib.util.module_from_spec(spec)
    sys.modules["mitrecti"] = mitrecti
    spec.loader.exec_module(mitrecti)
    return mitrecti

mitrecti = load_mitrecti_module(mitrecti_path)

# Path to the attack folder
attack_folder = '/home/triagex/Downloads/TITAN/mitrecti'

# Cache file for attack_data
attack_data_cache_file = '/home/triagex/Downloads/TITAN/attack_data_cache.pkl'

# Load attack data with caching
def load_attack_data(attack_folder, cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            attack_data = pickle.load(f)
        console.print("Loaded attack_data from cache.", style="bold green")
    else:
        console.print("Cache not found. Building MitreCTI cache...", style="bold yellow")
        attack_data = mitrecti.load_attack_data_from_folder(attack_folder)
        with open(cache_file, 'wb') as f:
            pickle.dump(attack_data, f)
        console.print("Loaded attack_data from files and created cache.", style="bold green")
    return attack_data

attack_data = load_attack_data(attack_folder, attack_data_cache_file)

# ---------------------------
# BERT-based Classification and Suspicious Behavior Detection
# ---------------------------

def classify_event_with_bert(event_text):
    """
    Use BERT to classify the severity of the event based on its content.
    """
    inputs = bert_tokenizer.encode(event_text, return_tensors='pt')
    outputs = bert_model(inputs)
    logits = outputs.logits
    classification = torch.argmax(logits, dim=-1).item()  # Get the classification label
    return classification

# Example classification labels (adjust based on your use case)
CLASSIFICATION_LABELS = {
    0: "Low Severity",
    1: "Medium Severity",
    2: "High Severity",
    3: "Critical Severity",
    4: "Informational"
}


# ---------------------------
# BERT-based NER Extraction
# ---------------------------

def extract_entities_with_bert(text):
    """
    Use BERT NER to extract entities such as usernames, computers, IP addresses, etc.
    """
    ner_results = nlp_bert(text)
    entities = []
    for entity in ner_results:
        entities.append({
            "word": entity["word"],
            "entity": entity["entity"],
            "score": entity["score"]
        })
    return entities

def analyze_logon_events(sketch):
    """
    Analyze logon events (event IDs 4624 and 4625) from Timesketch, build a summary, 
    and identify suspicious logons from rare usernames.
    """
    # Query Timesketch for event IDs 4624 (successful logon) and 4625 (failed logon)
    query = 'event_identifier:4624 OR event_identifier:4625'
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)
    
    if events_df.empty:
        console.print("No logon events found.", style="bold red")
        return
    
    # Check if 'username' field is available
    if 'username' not in events_df.columns:
        console.print("Username field not found in events. Attempting to extract from messages...", style="bold yellow")
        # Try to extract usernames from the 'message' field
        events_df['username'] = events_df['message'].apply(extract_username_from_message)
    
    # Remove entries without usernames
    events_df = events_df[events_df['username'].notna()]
    
    # Compute logon counts per username
    user_counts = events_df['username'].value_counts()
    
    # Display total counts per username
    console.print("\n--- Logon Counts per Username ---", style="bold magenta")
    for username, count in user_counts.items():
        console.print(f"{username}: {count}", style="cyan")
    
    # Identify rare usernames
    threshold = 3  # Define a threshold for rare usernames
    rare_usernames = user_counts[user_counts < threshold]
    
    # Display rare usernames
    if not rare_usernames.empty:
        console.print("\n--- Rare Usernames (Potentially Suspicious) ---", style="bold red")
        for username, count in rare_usernames.items():
            console.print(f"{username}: {count} logon(s)", style="yellow")
    else:
        console.print("\nNo rare usernames detected.", style="bold green")
    
    # Generate paragraph about normal vs suspicious activity
    console.print("\n--- Analysis ---", style="bold magenta")
    console.print(f"Most users have logon counts above {threshold}, which is considered normal activity.", style="cyan")
    if not rare_usernames.empty:
        console.print("The following usernames have a low number of logons, which could indicate suspicious activity:", style="cyan")
        for username in rare_usernames.index:
            console.print(f"- {username}", style="cyan")
    else:
        console.print("No usernames with unusually low logon counts were found.", style="cyan")

def extract_username_from_message(message):
    """
    Attempt to extract the username from the event message using regex.
    """
    match = re.search(r'Account Name:\s+([^\s]+)', message)
    if match:
        return match.group(1)
    return None


# ---------------------------
# GPT-2 Summarization for Event
# ---------------------------

def generate_gpt2_summary(text):
    """
    Use GPT-2 to generate a summary of the logon event.
    """
    input_ids = gpt2_tokenizer.encode(text, return_tensors='pt')
    outputs = gpt2_model.generate(input_ids, max_length=150, num_return_sequences=1)
    summary = gpt2_tokenizer.decode(outputs[0], skip_special_tokens=True)
    return summary

# ---------------------------
# Detect Suspicious Behavior
# ---------------------------

def detect_suspicious_behavior(events):
    """
    Detect suspicious behavior by analyzing patterns across multiple events.
    If the same user and computer are found, classify as normal.
    If a different user or computer logs in, mark it as suspicious.
    """
    normal_behavior = set()
    suspicious_events = []

    for event in events:
        user = None
        computer = None

        # Extract entities (user, computer, etc.) from the event message
        for entity in event['entities']:
            if entity['entity'] == "PERSON":
                user = entity['word']
            elif entity['entity'] == "ORGANIZATION":  # Adjust based on your BERT model
                computer = entity['word']

        if user and computer:
            if (user, computer) in normal_behavior:
                # Normal behavior detected (user and computer have logged in together before)
                event['classification'] = "Normal"
            else:
                # New user or computer combination, classify as suspicious
                event['classification'] = "Suspicious"
                suspicious_events.append(event)
                # Add the combination to the normal behavior set
                normal_behavior.add((user, computer))

    return suspicious_events

# ---------------------------
# Example Integration in Event Processing
# ---------------------------

# ---------------------------
# Process Event Function (Main Analysis Workflow)
# ---------------------------

def process_event(event):
    event_text = event.get("message", "")
    
    # 1. BERT-based Classification
    classification = classify_event_with_bert(event_text)
    severity_label = CLASSIFICATION_LABELS.get(classification, "Unknown")
    
    # 2. BERT-based NER Extraction
    bert_entities = extract_entities_with_bert(event_text)
    
    # 3. GPT-2 Summarization
    summary = generate_gpt2_summary(event_text)
    
    console.print(f"Event Classification (BERT): {severity_label}", style="bold yellow")
    console.print(f"Entities Detected (BERT): {bert_entities}", style="bold cyan")
    console.print(f"Event Summary (GPT-2): {summary}", style="bold green")

    return {
        "classification": severity_label,
        "entities": bert_entities,
        "summary": summary,
        "message": event_text
    }

# ---------------------------
# Analyze and Detect Suspicious Activity
# ---------------------------

def process_events_dataframe(events_df):
    if events_df.empty:
        console.print("No events to process.", style="bold red")
        return

    processed_events = []

    # Process each event in the dataframe
    for event in events_df.itertuples():
        event_details = process_event(event._asdict())  # Convert namedtuple to dictionary
        processed_events.append(event_details)

    # Detect suspicious behavior across events
    suspicious_events = detect_suspicious_behavior(processed_events)

    # Print suspicious events
    if suspicious_events:
        console.print("\n--- Suspicious Events Detected ---", style="bold red")
        for idx, event in enumerate(suspicious_events, 1):
            console.print(f"\nSuspicious Event {idx}:", style="bold red")
            console.print(f"User: {event['entities']}", style="bold cyan")
            console.print(f"Message: {event['message']}", style="white")
            console.print(f"Summary (GPT-2): {event['summary']}", style="bold green")
    else:
        console.print("\nNo suspicious events detected.", style="bold green")

    return processed_events

# ---------------------------
# Trigger for "Analyze 4624 Events"
# ---------------------------

def analyze_4624_events(sketch):
    """
    Analyze 4624 events from Timesketch, extract entities, classify behavior,
    and flag suspicious events based on user/computer patterns.
    """
    # Query Timesketch for event 4624
    query = "event_identifier:4624"
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)

    # Process the events and detect suspicious behavior
    process_events_dataframe(events_df)

# ---------------------------
# BERT-based Classification for PowerShell Events
# ---------------------------

def classify_powershell_event_with_bert(event_text):
    """
    Use BERT to classify the severity of a PowerShell event based on its content.
    Truncate the text to fit within BERT's maximum input length (512 tokens).
    """
    max_length = 512  # BERT's maximum token length
    # Tokenize the input and truncate it if necessary
    inputs = bert_tokenizer.encode(event_text, return_tensors='pt', max_length=max_length, truncation=True)

    # Run the BERT model on the truncated input
    outputs = bert_model(inputs)
    logits = outputs.logits

    # Get the classification label by selecting the most probable class
    classification = torch.argmax(logits, dim=-1).item()
    return classification

# Example classification labels (adjust based on PowerShell-related severity levels)
CLASSIFICATION_LABELS = {
    0: "Low Severity",
    1: "Medium Severity",
    2: "High Severity",
    3: "Critical Severity",
    4: "Informational"
}


# ---------------------------
# BERT-based NER Extraction for PowerShell Events
# ---------------------------

def extract_entities_from_powershell_event(text):
    """
    Use BERT NER to extract entities such as command-line arguments, file paths, processes, etc.
    """
    ner_results = nlp_bert(text)
    entities = []
    for entity in ner_results:
        entities.append({
            "word": entity["word"],
            "entity": entity["entity"],
            "score": entity["score"]
        })
    return entities
    
# ---------------------------
# GPT-2 Summarization for PowerShell Events
# ---------------------------

def generate_gpt2_powershell_summary(text):
    """
    Use GPT-2 to generate a summary of a PowerShell event.
    """
    input_ids = gpt2_tokenizer.encode(text, return_tensors='pt', truncation=True, max_length=512)
    
    # Set max_new_tokens instead of max_length to limit the number of tokens generated
    outputs = gpt2_model.generate(input_ids, max_new_tokens=150, num_return_sequences=1)
    
    summary = gpt2_tokenizer.decode(outputs[0], skip_special_tokens=True)
    return summary

# ---------------------------
# Detect Suspicious PowerShell Activity
# ---------------------------

def detect_suspicious_powershell_activity(events):
    """
    Detect suspicious PowerShell activity by analyzing command lines, event sources, and related entities.
    """
    normal_commands = set()
    suspicious_events = []

    for event in events:
        command_line = None
        user = None
        computer = None

        # Extract entities (command-line, user, etc.) from the event message
        for entity in event['entities']:
            if entity['entity'] == "COMMAND_LINE":
                command_line = entity['word']
            elif entity['entity'] == "PERSON":
                user = entity['word']
            elif entity['entity'] == "ORGANIZATION":  # Adjust based on your BERT model
                computer = entity['word']

        if command_line:
            # Check if the command line is in the list of normal commands
            if command_line in normal_commands:
                event['classification'] = "Normal"
            else:
                event['classification'] = "Suspicious"
                suspicious_events.append(event)
                # Add the command to normal commands if it is deemed safe
                normal_commands.add(command_line)

    return suspicious_events

# ---------------------------
# Process Event Function for PowerShell Events (Main Analysis Workflow)
# ---------------------------

def process_powershell_event(event):
    event_text = event.get("message", "")
    
    # 1. BERT-based Classification for PowerShell events
    classification = classify_powershell_event_with_bert(event_text)
    severity_label = CLASSIFICATION_LABELS.get(classification, "Unknown")
    
    # 2. BERT-based NER Extraction
    bert_entities = extract_entities_from_powershell_event(event_text)
    
    # 3. GPT-2 Summarization for PowerShell events
    summary = generate_gpt2_powershell_summary(event_text)
    
    console.print(f"PowerShell Event Classification (BERT): {severity_label}", style="bold yellow")
    console.print(f"Entities Detected (BERT): {bert_entities}", style="bold cyan")
    console.print(f"PowerShell Event Summary (GPT-2): {summary}", style="bold green")

    return {
        "classification": severity_label,
        "entities": bert_entities,
        "summary": summary,
        "message": event_text
    }

# ---------------------------
# Analyze and Detect Suspicious PowerShell Activity
# ---------------------------

def process_powershell_events_dataframe(events_df):
    if events_df.empty:
        console.print("No PowerShell events to process.", style="bold red")
        return

    processed_events = []

    # Process each PowerShell event in the dataframe
    for event in events_df.itertuples():
        event_details = process_powershell_event(event._asdict())  # Convert namedtuple to dictionary
        processed_events.append(event_details)

    return processed_events

# ---------------------------
# Trigger for "Show me PowerShell Events"
# ---------------------------

def analyze_powershell_events(sketch):
    """
    Analyze PowerShell events from Timesketch, extract entities, classify behavior,
    and flag suspicious events based on command-line patterns and execution context.
    """
    # Query Timesketch for PowerShell events
    query = "message:powershell"
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)

    # Process the events and detect suspicious behavior
    processed_events = process_powershell_events_dataframe(events_df)
    
    # Print a summary of each event
    for event in processed_events:
        console.print(f"\n--- PowerShell Event ---", style="bold cyan")
        console.print(f"Classification: {event['classification']}")
        console.print(f"Entities: {event['entities']}")
        console.print(f"Summary: {event['summary']}\n")



# ---------------------------
# Database Connection for IOCs (Replace file-based storage)
# ---------------------------

# Function to connect to TITAN_IOC database and fetch iocs
def load_iocs_from_db():
    try:
        conn = sqlite3.connect('/home/triagex/Downloads/TITAN/TITAN_IOC/instance/ioc_database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ioc")
        rows = cursor.fetchall()

        iocs = {
            "hashes": [],
            "ips": [],
            "domains": [],
            "tools": [],
            "commands": [],
            "filenames": []
        }

        for row in rows:
            indicator_type = row[2].lower()  # 'type' is the 3rd column (index 2)
            indicator_value = row[1]  # 'indicator' is the 2nd column (index 1)

            if indicator_type == "hash":
                iocs["hashes"].append(indicator_value)
            elif indicator_type == "ip":
                iocs["ips"].append(indicator_value)
            elif indicator_type == "domain":
                iocs["domains"].append(indicator_value)
            elif indicator_type == "tool":
                iocs["tools"].append(indicator_value)
            elif indicator_type == "command":
                iocs["commands"].append(indicator_value)
            elif indicator_type == "filename":
                iocs["filenames"].append(indicator_value)

        conn.close()

        console.print(iocs, style="bold blue")  # Debug: print loaded IOCs
        console.print("IOCs loaded from TITAN_IOC database.", style="bold green")
        return iocs

    except sqlite3.Error as e:
        console.print(f"Error loading IOCs from database: {e}", style="bold red")
        return {
            "hashes": [],
            "ips": [],
            "domains": [],
            "tools": [],
            "commands": [],
            "filenames": []
        }


# ---------------------------
# Search IOCs in Timesketch
# ---------------------------

# Function to handle user input and selection of IOC database
def choose_ioc_database():
    """
    Prompts the user to choose between User IOCs (UserDB) or Codex IOCs (CodexDB).
    Returns the appropriate IOC model and message based on user selection.
    """
    console.print("Please choose the IOC database to search in Timesketch:", style="bold blue")
    console.print("1 - User IOCs (UserDB)", style="bold green")
    console.print("2 - Codex IOCs (CodexDB)", style="bold green")

    while True:
        choice = input("Enter 1 or 2: ").strip()
        if choice == '1':
            return IOC, "User IOCs (UserDB)"
        elif choice == '2':
            return CodexIOC, "Codex IOCs (CodexDB)"
        else:
            console.print("Invalid choice. Please enter 1 or 2.", style="bold red")


# Main search function for IOCs in Timesketch
def search_for_iocs_in_timesketch():
    # Ask user to choose the IOC database
    ioc_model, ioc_database = choose_ioc_database()
    
    # Load IOCs from the chosen IOC table
    iocs = ioc_model.query.all()

    if not iocs:
        console.print(f"No IOCs found in {ioc_database}.", style="bold yellow")
        return pd.DataFrame()

    query_parts = []
    for ioc in iocs:
        query_parts.append(f"indicator:{ioc.indicator}")  # Assuming 'indicator' is the relevant field

    combined_query = " OR ".join(query_parts)

    if not combined_query:
        console.print(f"No IOCs found to search in Timesketch from {ioc_database}.", style="bold yellow")
        return pd.DataFrame()

    console.print(f"Constructed Timesketch query for {ioc_database}: {combined_query}", style="bold blue")

    # Execute Timesketch query
    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = combined_query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)

    if events_df.empty:
        console.print(f"No events found matching IOCs from {ioc_database}.", style="bold yellow")
        return events_df

    # Display the first 5 events
    display_events_line_by_line(events_df.head(5))
    
    return events_df


# ---------------------------
# Main IOC Search Handler
# ---------------------------

def handle_search_for_iocs_in_timesketch(sketch):
    """
    Handles the command to search for IOCs in Timesketch.
    It uses the IOCs from the TITAN_IOC database and performs a Timesketch search.
    """
    console.print("Searching for IOCs in Timesketch...", style="bold blue")
    iocs_events_df = search_for_iocs_in_timesketch(sketch)
    
    if not iocs_events_df.empty:
        console.print(f"Total events matching IOCs: {len(iocs_events_df)}", style="bold green")
    else:
        console.print("No events matched IOCs from the database.", style="bold yellow")


# ---------------------------
# File Processing
# ---------------------------

def extract_ioc(text, indicator_type=None):
    ioc = {
        "hashes": [],
        "ips": [],
        "domains": [],
        "tools": [],
        "commands": []
    }

    # Regex patterns for extracting ioc
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    # Extracting ioc
    ioc["hashes"] = re.findall(hash_pattern, text)
    ioc["ips"] = re.findall(ip_pattern, text)
    ioc["domains"] = re.findall(domain_pattern, text)

    # Extract tools and commands based on known keywords
    tools_keywords = ["AdFind", "Mimikatz", "RClone", "WinRAR", "PowerShell", "Ngrok"]
    for keyword in tools_keywords:
        if keyword.lower() in text.lower():
            ioc["tools"].append(keyword)

    command_pattern = r'\b[A-Za-z0-9_\-\\/:]+\.exe\b'
    ioc["commands"] = re.findall(command_pattern, text)

    # Update persistent IOCs storage
    update_iocs(ioc)

    if indicator_type:
        return {indicator_type: ioc[indicator_type]}
    
    return ioc

def extract_text_from_pdf(file_path):
    with open(file_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ""
        for page in reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_docx(file_path):
    doc = docx.Document(file_path)
    return "\n".join([para.text for para in doc.paragraphs])

def summarize_text(text):
    parser = PlaintextParser.from_string(text, SumyTokenizer("english"))
    summarizer = LsaSummarizer()
    summary = summarizer(parser.document, 6)  # Summarize to 6 sentences
    return " ".join([str(sentence) for sentence in summary])

def upload_and_analyze_file(file_path):
    global uploaded_data, uploaded_text, active_mode
    
    # Reset previous data
    uploaded_data = pd.DataFrame()
    uploaded_text = ""
    
    # Handle different file types
    if file_path.endswith('.csv'):
        uploaded_data = pd.read_csv(file_path)
        console.print(f"CSV file '{file_path}' uploaded.", style="bold green")
        console.print(uploaded_data.head())
        # Extract IOCs from the single-column CSV and update storage
        extract_and_store_iocs_from_csv(uploaded_data)
    elif file_path.endswith('.json'):
        with open(file_path, 'r') as file:
            data = json.load(file)
            uploaded_data = pd.json_normalize(data)
            uploaded_text = json.dumps(data)
        console.print(f"JSON file '{file_path}' uploaded.", style="bold green")
        iocs = extract_ioc(uploaded_text)
        console.print(iocs, style="bold cyan")
    elif file_path.endswith('.pdf'):
        uploaded_text = extract_text_from_pdf(file_path)
        console.print(f"PDF file '{file_path}' uploaded and summarized.", style="bold green")
    elif file_path.endswith('.docx'):
        uploaded_text = extract_text_from_docx(file_path)
        console.print(f"Word document '{file_path}' uploaded and summarized.", style="bold green")
    elif file_path.endswith('.xlsx'):
        uploaded_data = pd.read_excel(file_path)
        console.print(f"Excel file '{file_path}' uploaded.", style="bold green")
        console.print(uploaded_data.head())
    else:
        console.print("Unsupported file format. Please upload a CSV, JSON, PDF, DOCX, or XLSX file.", style="bold red")
        return
    
    # Set mode to file
    active_mode = "file"

    # Generate and print a summary for text-based files
    if uploaded_text:
        summary = summarize_text(uploaded_text)
        console.print("\nSummary of the uploaded document:\n", style="bold blue")
        console.print(summary, style="cyan")

# ---------------------------
# Timesketch Operations
# ---------------------------

def parse_sigma_rule(rule_path):
    with open(rule_path, 'r') as file:
        rule = yaml.safe_load(file)
    return rule

def run_sigma_rule_in_timesketch(rule, sketch):
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
                console.print(f"Failed to query Timesketch for Sigma rule '{rule.get('title')}': {e}", style="bold red")

def process_sigma_rules_in_folder(folder_path, sketch):
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            if file_name.endswith('.yml'):
                rule_path = os.path.join(root, file_name)
                rule = parse_sigma_rule(rule_path)
                console.print(f"Processing Sigma rule: {rule.get('title')}")
                run_sigma_rule_in_timesketch(rule, sketch)

def ensure_directory_exists(path):
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        os.makedirs(directory)

def set_export_folder(path):
    global export_folder
    if os.path.isdir(path):
        export_folder = path
        console.print(f"Export folder set to: {export_folder}", style="bold green")
    else:
        console.print(f"Invalid folder path: {path}. Please provide a valid folder.", style="bold red")

def create_safe_folder_name(url):
    # Parse the URL to get the domain
    parsed_url = urlparse(url)
    # Use only the netloc (domain) and path, replacing unsafe characters
    safe_name = re.sub(r'[^\w\-_\. ]', '_', parsed_url.netloc + parsed_url.path)
    return safe_name

def query_timesketch_for_mitre_attack(sketch):
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

def remove_tags_from_timesketch(sketch, tag_to_remove):
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

def export_all_tagged_events_to_csv(csv_filename):
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
        console.print(f"An unexpected error occurred while exporting tagged events: {e}", style="bold red")

# ---------------------------
# Data Parser Handling
# ---------------------------

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

# ---------------------------
# JSONL Export Utility
# ---------------------------

def export_to_jsonl(data, output_file):
    with open(output_file, 'w') as outfile:
        for event in data:
            json.dump(event, outfile)
            outfile.write('\n')

# ---------------------------
# DateTime Parsing
# ---------------------------

def parse_datetime_column(df, column_name):
    try:
        df[column_name] = pd.to_datetime(df[column_name], errors='coerce', infer_datetime_format=True, utc=True)
    except Exception as e:
        logging.error(f"Error parsing datetime column '{column_name}': {e}")
        df[column_name] = pd.NaT
    return df
    
# ---------------------------
# Zircolite Import Handling (Modified to ignore specific events)
# ---------------------------

def import_zircolite_json_files_into_timesketch(json_folder_path, sketch):
    # List all JSON files in the folder
    json_files = [f for f in os.listdir(json_folder_path) if f.endswith('.json')]

    all_events = []

    # Descriptions to ignore
    ignore_descriptions = [
        "Detects creation of WMI event subscription persistence method",
        "Detects when an application acquires a certificate private key"
    ]

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
                    continue

            # Ensure data is a list
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                continue

            # Process each event in the data list
            for event in data:
                if isinstance(event, str):
                    try:
                        event = json.loads(event)
                    except json.JSONDecodeError as e:
                        continue
                if not isinstance(event, dict):
                    continue
                
                # Filter out events with specific descriptions without printing
                if event.get('description') in ignore_descriptions:
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
        
# Handle zircolite import command
def handle_zircolite_import():
    # Paths to the Node.js script and data.js
    nodejs_script_path = '/home/triagex/Downloads/TITAN/extract_data.js'  # Replace with the actual path
    data_js_path = '/home/triagex/Downloads/TITAN/data.js'  # Replace with the actual path
    json_output_directory = '/home/triagex/Downloads/TITAN/zircolite'  # Same as outputDirectory in extract_data.js

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
    
# ---------------------------
# BERT/GPT2 Process Event
# ---------------------------

def process_event(event_data):
    """
    Process a single event with BERT for entity extraction and classification
    and GPT-2 for summarization.
    """
    message = event_data.get('message', '')
    
    # BERT for NER (Named Entity Recognition)
    bert_entities = extract_entities_with_bert(message)
    
    # BERT for Classification (e.g., Severity or Category)
    classification = classify_event_with_bert(message)
    
    # GPT-2 for summarization
    summary = generate_summary_with_gpt2(message)
    
    return {
        "entities": bert_entities,
        "classification": classification,
        "summary": summary
    }

def extract_entities_with_bert(text):
    """
    Use BERT to extract entities (e.g., usernames, IP addresses) from the event text.
    """
    # This is a placeholder for BERT NER extraction, adjust based on actual implementation
    entities = [
        {"word": "john.doe", "entity": "PERSON", "score": 0.98},
        {"word": "192.168.1.10", "entity": "IP_ADDRESS", "score": 0.95}
    ]
    return entities

def classify_event_with_bert(text):
    """
    Use BERT to classify the event text (e.g., severity or category).
    """
    # This is a placeholder for BERT classification, adjust based on actual implementation
    return "Medium Severity"

def generate_summary_with_gpt2(text):
    """
    Use GPT-2 to generate a summary of the event.
    """
    # This is a placeholder for GPT-2 summarization, adjust based on actual implementation
    return "A suspicious logon was detected from IP 192.168.1.10, potentially indicating unauthorized access."


# ---------------------------
# Event Querying and Summary
# ---------------------------

def analyze_event(input_query, sketch):
    """
    Analyze an event or keyword by querying Timesketch, processing the results,
    and generating a summary based on the events returned.

    :param input_query: Event ID (e.g., "4624") or keyword (e.g., "PowerShell", "Akira")
    :param sketch: The Timesketch sketch object to query.
    :return: Summary of the analysis.
    """
    # Build query for Timesketch based on input (could be an event ID or keyword)
    if input_query.isdigit():
        # If it's an Event ID
        query = f"event_identifier:{input_query}"
    else:
        # If it's a keyword (e.g., PowerShell or Akira)
        query = f"message:\"{input_query}\""

    # Query Timesketch to get the events
    try:
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = query
        search_results = search_obj.table  # Get events as a list of dictionaries
        events_df = pd.DataFrame(search_results)

        if events_df.empty:
            console.print(f"No events found for '{input_query}'.", style="bold yellow")
            return

        # Process the events and generate a summary
        processed_events = []
        for _, event in events_df.iterrows():
            processed_event = process_event(event)  # Process each event using BERT and GPT-2
            processed_events.append(processed_event)

        # Summarize all the processed events
        console.print(f"\n--- Summary for '{input_query}' ---", style="bold magenta")
        for idx, event_summary in enumerate(processed_events, 1):
            console.print(f"\nEvent {idx} Summary:", style="bold cyan")
            console.print(f"Classification (BERT): {event_summary['classification']}", style="bold yellow")
            console.print(f"Entities Extracted (BERT): {event_summary['entities']}", style="bold blue")
            console.print(f"Summary (GPT-2): {event_summary['summary']}", style="bold green")

        return processed_events

    except Exception as e:
        console.print(f"Error querying Timesketch: {e}", style="bold red")


# ---------------------------
# History Management Section
# ---------------------------

def setup_command_history():
    """
    Sets up the command history functionality for the application.
    Loads the history from a file and ensures that it is saved upon exit.
    """
    histfile = "/home/triagex/Downloads/TITAN/.titan_history"

    # Ensure directory for history file exists
    os.makedirs(os.path.dirname(histfile), exist_ok=True)

    # Load command history
    try:
        if os.path.exists(histfile):
            readline.read_history_file(histfile)
            console.print(f"Command history loaded from {histfile}", style="bold green")
        else:
            console.print(f"No existing history file found. A new history file will be created at {histfile}.", style="bold yellow")
    except FileNotFoundError:
        console.print(f"History file not found: {histfile}", style="bold red")
    except Exception as e:
        console.print(f"Error loading history: {e}", style="bold red")

    # Save command history when the program exits
    atexit.register(lambda: save_command_history(histfile))

def save_command_history(histfile):
    """
    Saves the command history to a file before the program exits.
    """
    try:
        readline.write_history_file(histfile)
        console.print(f"Command history saved to {histfile}", style="bold green")
    except Exception as e:
        console.print(f"Error saving history: {e}", style="bold red")

# ---------------------------
# Main Analyze Function
# ---------------------------

def handle_analyze_event_command(command, sketch):
    """
    Handle the command to analyze an event or keyword.

    :param command: The input command (e.g., 'analyze event 4624' or 'analyze event powershell').
    :param sketch: The Timesketch sketch object to query.
    """
    match = re.search(r'analyze event (.+)', command, re.IGNORECASE)
    if match:
        input_query = match.group(1).strip()
        console.print(f"Analyzing event or keyword: {input_query}", style="bold blue")
        analyze_event(input_query, sketch)
    else:
        console.print("Invalid command. Please use 'analyze event <event_id/keyword>'.", style="bold red")


# ---------------------------
# Noisy Log Handling
# ---------------------------

# Suppress noisy logs from TensorFlow, Hugging Face, or others.
import logging
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("tensorflow").setLevel(logging.ERROR)

# ---------------------------
# Zircolite Report
# ---------------------------


def run_zircolite_report():
    try:
        # Execute the auto_investigation.py script with option 1
        console.print("Running Zircolite report by executing auto_investigation.py with option 1...", style="bold blue")
        result = subprocess.run(['python3', 'auto_investigation.py'], input="1\n", text=True, capture_output=True)
        
        if result.returncode == 0:
            console.print("Zircolite report generated successfully.", style="bold green")
            console.print(result.stdout)
        else:
            console.print(f"Error in generating Zircolite report: {result.stderr}", style="bold red")
    except Exception as e:
        console.print(f"An error occurred while running the Zircolite report: {e}", style="bold red")

# ---------------------------
# Question Interpretation
# ---------------------------

def match_question(user_question):
    questions = [q['question'] for q in predefined_questions['questions']]
    vectorizer = TfidfVectorizer().fit_transform(questions + [user_question])
    vectors = vectorizer.toarray()
    cosine_similarities = cosine_similarity(vectors[-1:], vectors[:-1])
    best_match_index = cosine_similarities.argmax()
    best_match_score = cosine_similarities[0][best_match_index]
    if best_match_score > 0.5:  # Threshold for matching
        return predefined_questions['questions'][best_match_index]
    return None

def interpret_question(question):
    global active_mode, export_folder

    # Check if the question is requesting to show events of a specific category
    match = re.match(r'show me all (.+) events', question.lower())
    if match:
        category = match.group(1).strip()
        js_file_path = '/home/triagex/Downloads/TITAN/data.js'  # Update this path to your actual data.js file
        action = 'data_parser'
        extra_params = {'action': 'show_category', 'js_file': js_file_path, 'category': category}
        return None, None, action, extra_params

    # Check if the user asked to generate the zircolite report
    if "generate zircolite report" in question.lower():
        return None, None, "zircolite_report", None

    # Handle 'analyze event' command
    match = re.search(r'analyze event (.+)', question.lower())
    if match:
        input_query = match.group(1).strip()
        if input_query.isdigit():
            query = f"event_identifier:{input_query}"
        else:
            query = f"message:\"{input_query}\""
        return query, None, "analyze_event", None

    # Handle 'analyze event logons' command
    if question.lower() == "analyze event logons":
        return None, None, "analyze_logon_events", None
        
    
    # Handle IOC search and tagging in Timesketch
    if "search for iocs in timesketch" in question.lower():
        return "search_for_iocs", None, "timesketch_ioc_search", None

    # Handle specific tag removal
    if question.lower().startswith("remove ") and " tag" in question.lower():
        tag_to_remove = question.lower().split("remove ")[1].split(" tag")[0].strip()
        remove_tags_from_timesketch(sketch, tag_to_remove)

    # Handle 'show me the full timeline of events' command
    if "show me the full timeline of events" in question.lower():
        js_file_path = '/home/triagex/Downloads/TITAN/data.js'  # Update this path to your actual data.js file
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

    # Handle URLScan.io queries
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
                    folder_path = os.path.join('/home/triagex/Downloads/TITAN/url', folder_name)
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


# ---------------------------
# Search and Tagging
# ---------------------------

def filter_invalid_query_parts(query_parts):
    # Remove any parts that contain a hyphen or problematic patterns like '-utf8.txt'
#    filtered_query_parts = [
#        part for part in query_parts 
#        if not re.search(r'[-]', part)  # This skips parts with hyphens
#    ]
#    return filtered_query_parts
    return query_parts  # Return all parts for now to test the query construction

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

def search_timesketch_and_tag_iocs(query, csv_filename=None, summary_template=None, action="timesketch_tag"):
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


# ---------------------------
# Codex Integration
# ---------------------------

def process_hash(file_hash):
    results = {}
    
    # Get antivirus results
    console.print(f"Retrieving antivirus results for hash: {file_hash}", style="bold blue")
    if cg.av_result(file_hash):
        results['antivirus_results'] = cg.response
        console.print("Antivirus results retrieved successfully.", style="bold green")
    else:
        console.print(f"Error retrieving antivirus results: {cg.error_message}", style="bold red")

    # Get metadata
    console.print(f"Retrieving metadata for hash: {file_hash}", style="bold blue")
    if cg.get_metadata(file_hash):
        results['metadata'] = cg.response
        console.print("Metadata retrieved successfully.", style="bold green")
    else:
        console.print(f"Error retrieving metadata: {cg.error_message}", style="bold red")

    # Display the combined results
    display_results(results)
    
    # Option to export results to a file
    export_to_file = input("Would you like to export the results to a file? (y/n): ").strip().lower()
    if export_to_file == 'y':
        export_results_to_file(file_hash, results)

def send_file_and_get_report(file_path):
    try:
        with open(file_path, 'rb') as f:
            if cg.send_file_to_process(f):
                console.print("File sent for processing successfully.", style="bold green")
                console.print(f"Response after sending file: {cg.response}", style="bold blue")
            else:
                console.print(f"Error sending file: {cg.error_message}", style="bold red")
                return
    except FileNotFoundError:
        console.print(f"File not found: {file_path}", style="bold red")
        return

    # Attempt to retrieve the file hash from the message or response
    file_hash = None
    if 'file_hash' in cg.response:
        file_hash = cg.response['file_hash']
    elif 'message' in cg.response and 'Already exists' in cg.response['message']:
        file_hash = cg.response['message'].split()[-1]
    
    if not file_hash:
        console.print("Failed to retrieve file hash. Full response:", style="bold red")
        console.print(cg.response, style="bold red")
        return

    # Process the hash
    process_hash(file_hash)

# ---------------------------
# URLScan.io Integration
# ---------------------------

def scan_url(url):
    headers = {
        'Content-Type': 'application/json',
        'API-Key': API_KEY,
    }
    data = {
        'url': url,
        'visibility': 'public'  # Can also be 'private'
    }
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    
    if response.status_code == 200:
        scan_result = response.json()
        console.print(f"Scan initiated successfully. Scan ID: {scan_result['uuid']}", style="bold green")
        return scan_result['uuid']
    else:
        console.print(f"Error initiating scan: {response.status_code}", style="bold red")
        console.print(response.text, style="bold red")
        return None

def get_scan_results(scan_id):
    url = f'https://urlscan.io/api/v1/result/{scan_id}/'
    while True:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            console.print("Scan is still in progress...waiting 10 seconds.", style="bold yellow")
            time.sleep(10)  # Wait and retry
        else:
            console.print(f"Error retrieving scan results: {response.status_code}", style="bold red")
            console.print(response.text, style="bold red")
            return None

# ---------------------------
# Results Display and Export
# ---------------------------

def display_results(results):
    console.print("\n---- Results ----", style="bold blue")
    try:
        console.print(json.dumps(results, indent=4), style="bold cyan")
    except Exception as e:
        console.print(f"Error displaying results: {e}", style="bold red")

def export_results_to_json(scan_data, folder_path):
    json_file = os.path.join(folder_path, 'scan_results.json')
    try:
        with open(json_file, 'w') as f:
            json.dump(scan_data, f, indent=4)
        console.print(f"Scan results saved to JSON at: {json_file}", style="bold green")
    except Exception as e:
        console.print(f"Error saving results to JSON: {e}", style="bold red")

def export_results_to_csv(scan_data, folder_path):
    csv_file = os.path.join(folder_path, 'scan_results.csv')
    flattened_data = pd.json_normalize(scan_data)
    flattened_data.to_csv(csv_file, index=False)
    console.print(f"Scan results exported to CSV at: {csv_file}", style="bold green")

def export_results_to_file(identifier, results):
    try:
        output_file = f"results_{identifier}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"Results exported successfully to {output_file}", style="bold green")
    except Exception as e:
        console.print(f"Error exporting results to file: {e}", style="bold red")

def save_screenshot(scan_data, folder_path):
    screenshot_url = scan_data.get('screenshot')
    if screenshot_url:
        screenshot_file = os.path.join(folder_path, 'screenshot.png')
        try:
            response = requests.get(screenshot_url)
            if response.status_code == 200:
                with open(screenshot_file, 'wb') as f:
                    f.write(response.content)
                console.print(f"Screenshot saved at: {screenshot_file}", style="bold green")
            else:
                console.print(f"Failed to download screenshot: {response.status_code}", style="bold red")
        except Exception as e:
            console.print(f"Error saving screenshot: {e}", style="bold red")
    else:
        console.print("No screenshot URL found in scan data.", style="bold yellow")

def download_all_responses(scan_data, folder_path):
    responses = scan_data.get('data', {}).get('requests', [])
    for i, response in enumerate(responses):
        response_url = response.get('response', {}).get('url')
        if response_url:
            response_file = os.path.join(folder_path, f'response_{i + 1}.txt')
            try:
                resp = requests.get(response_url)
                if resp.status_code == 200:
                    with open(response_file, 'w') as f:
                        f.write(resp.text)
                    console.print(f"Response {i + 1} saved at: {response_file}", style="bold green")
                else:
                    console.print(f"Failed to download response {i + 1}: {resp.status_code}", style="bold red")
            except Exception as e:
                console.print(f"Error downloading response {i + 1}: {e}", style="bold red")

# ---------------------------
# Summary Generation
# ---------------------------

def generate_event_summary(events_df):
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
                    event_ids.append(event_id_match.group(1).strip())
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
    

def generate_nlg_summary(events_df, summary_template):
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

# Function to handle input commands
def handle_user_input(command, sketch):
    if command.lower().startswith("analyze event 4624"):
        # Handle the 4624 event analysis
        console.print("Analyzing event 4624...", style="bold cyan")
        analyze_4624_events(sketch)

    elif command.lower().startswith("analyze event powershell"):
        # Handle PowerShell event analysis
        console.print("Analyzing PowerShell events...", style="bold cyan")
        analyze_powershell_events(sketch)

    elif command.lower().startswith("search for iocs in timesketch"):
        # Handle IOC search in Timesketch
        console.print("Searching for IOCs in Timesketch...", style="bold blue")
        iocs = load_iocs_from_db()  # Load IOCs from the database

        if not iocs:
            console.print("No IOCs found in the database.", style="bold red")
            return

        # Construct the query using the IOCs
        query_parts = []
        for key, ioc_list in iocs.items():
            if ioc_list:
                query_parts.append(" OR ".join([f"message:{ioc}" for ioc in ioc_list]))

        combined_query = " OR ".join(query_parts)
        
        if not combined_query:
            console.print("No IOCs available to construct a Timesketch query.", style="bold yellow")
            return

        # Execute Timesketch query
        search_obj = search.Search(sketch=sketch)
        search_obj.query_string = combined_query
        search_results = search_obj.table
        events_df = pd.DataFrame(search_results)

        if events_df.empty:
            console.print("No events found matching IOCs in Timesketch.", style="bold yellow")
        else:
            console.print(f"Total events matching IOCs: {len(events_df)}", style="bold green")
            # Display first few events
            display_events_line_by_line(events_df.head(5))

    else:
        console.print(f"Command not recognized: {command}", style="bold red")
           

# ---------------------------
# URLScan.io Utilities
# ---------------------------

def display_results(results):
    console.print("\n---- Results ----", style="bold blue")
    try:
        console.print(json.dumps(results, indent=4), style="bold cyan")
    except Exception as e:
        console.print(f"Error displaying results: {e}", style="bold red")

# ---------------------------
# Printing and Display
# ---------------------------

def print_titan_description(font_size=14):
    text = Text("Threat Investigation and Tactical Analysis Network", style=f"bold magenta")
    console.print(text)

#adam_ascii_art = r"""
# █████╗    ██████╗     █████╗    ███╗   ███╗
#██╔══██╗   ██╔══██╗   ██╔══██╗   ████╗ ████║
#███████║   ██║  ██║   ███████║   ██╔████╔██║
#██╔══██║   ██║  ██║   ██╔══██║   ██║╚██╔╝██║
#██║  ██║██╗██████╔╝██╗██║  ██║██╗██║ ╚═╝ ██║
#╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
#"""

# ---------------------------
# Main Loop
# ---------------------------

def main():
    # Print the "Threat Investigation and Tactical Analysis Network" description
    print_titan_description(font_size=18)
    
    # Example questions
    example_questions = [
        "upload /home/titan/Downloads/TITAN/iocs.csv",
        "search for iocs in timesketch and tag iocs",
        "search for iocs in timesketch and export to iocs.csv",
        "import zircolite data",
        "generate zircolite report",
        "remove tagname tag",
        "logon events",
        "logoff events",
        "event id 4624",
        "execution techniques",
        "persistence techniques",
        "show me all the threats detected",
        "show me defender threats",
        "How many events are tagged with execution?",
        "Show me all PowerShell events.",
        "Find all file deletion events.",
        "How many malware detection events occurred?",
        "What is the Windows Defender Malware Detection History Deletion?",
        "show me execution and persistence techniques",
        "show me execution and persistence techniques and export to exec_persis.csv",
        "upload infected.csv",
        "What was the last logon?",
        "How many malware detections were there?",
        "switch to timesketch",
        "switch to file",
        "show me the list of indicators and export to indicators.csv",
        "show me the list of tools",
        "show me the list of commands",
        "show me the list of hashes",
        "show me the list of IPs",
        "show me the list of domains",
        "show me the MITRE ATT&CK techniques",
        "show me the list of credential access and persistence techniques",
        "show me all initial access events",
        "show me all defense evasion events",
        "show me all command and control events",
        "IMPORTANT - set export <folderpath>",
        "codex file",
        "codex hash",
        "scan url google.com",
        "scan url yahoo.com",
        "tag 4625 events or tag akira events or tag powershell events>",
        "export all tagged events to tagged.csv",
        "tag test.exe events",
        "What is Akira",
        "What is T1548.004"
    ]

    console.print("\nExample questions you can ask:", style="bold magenta")
    for q in example_questions:
        console.print(f"- {q}", style="cyan")

    # Enable command history with readline
    histfile = "/home/triagex/Downloads/TITAN/.titan_history"  # Path to store the command history
    try:
        readline.read_history_file(histfile)
    except FileNotFoundError:
        pass
    atexit.register(readline.write_history_file, histfile)

    # Main loop for asking questions
    while True:
        # Print the prompt and flush stdout
        console.print("\nPlease ask a question (or type 'exit' to quit):", style="bold magenta")

        # Read input from stdin
        question = sys.stdin.readline().strip()

        if question.lower() == "exit":
            console.print("Exiting the program.", style="bold red")
            break

        elif question.lower().startswith("upload "):
            file_path = question[7:].strip()
            upload_and_analyze_file(file_path)


        elif question.lower().startswith("what is"):  # Handle "What is" queries with mitrecti.py
            search_term = question[8:].strip()  # Extract the term after "What is"
            results = mitrecti.search_attack_data(search_term, attack_data)

            # Display results
            if results:
                for result in results:
                    console.print(f"\nName: {result['name']}", style="bold magenta")
                    console.print(f"Description: {result['description']}", style="cyan")

                    if result.get('external_ids'):
                        console.print(f"External References: {', '.join(result['external_ids'])}", style="bold blue")
                    else:
                        console.print("External References: N/A", style="bold blue")

                    console.print(f"Object Type: {result['type']}", style="bold green")
                    console.print(f"ID: {result['id']}", style="bold white")
            else:
                console.print(f"No information found for: {search_term}", style="bold red")

        else:
            # Adjust variable names to match the return values from interpret_question()
            query, summary_template, action, extra_params = interpret_question(question)

            # Handle query results based on action
            if action == "zircolite_import":
                handle_zircolite_import()

            elif action == "json_search":
                handle_search_query(question)

            # Handle query results based on action
            if action == "analyze_event":
                console.print(f"Analyzing event: {query}", style="bold blue")
                analyze_event(query, sketch)


            # Debugging prints to ensure information is visible
            console.print(f"Query: {query}", style="bold yellow")
            console.print(f"Action: {action}", style="bold yellow")
            console.print(f"Extra Params: {extra_params}", style="bold yellow")

            if action == "data_parser":
                handle_data_parser_action(extra_params)

            elif action == "export_tagged_events" and extra_params:
                export_all_tagged_events_to_csv(extra_params)

            elif action == "timesketch" and query:
                events_df = search_timesketch_and_tag_iocs(query, extra_params, summary_template, action)
                if summary_template:
                    generate_nlg_summary(events_df, summary_template)

            if action == "analyze_logon_events":
                console.print("Analyzing logon events...", style="bold cyan")
                analyze_logon_events(sketch)

            elif action == "zircolite_report":
                run_zircolite_report()

            elif action == "summary" and summary_template:
                generate_nlg_summary(pd.DataFrame(), summary_template)

            elif action == "timesketch_tag":
                events_df = search_timesketch_and_tag_iocs(query, extra_params, summary_template, action)

            elif action == "remove_tag" and summary_template:
                tag_to_remove = summary_template
                remove_tags_from_timesketch(sketch, tag_to_remove)

            else:
                console.print("No valid action determined.", style="bold red")

        # Handle integrated BERT and GPT-2 with event analysis
        if question.lower().startswith("analyze event"):
            # Extract the event ID from the question
            event_id_match = re.search(r'analyze event (\d+)', question)
            if event_id_match:
                event_id = event_id_match.group(1)
                console.print(f"Analyzing event with ID {event_id}...", style="bold blue")

                # Example event data (you would normally fetch this from Timesketch or your database)
                event_data = {"message": "Suspicious logon detected from 192.168.1.10", "event_identifier": int(event_id)}

                # Process event using BERT and GPT-2
                processed_event = process_event(event_data)

                # Display the results
                console.print(f"\n--- Event {event_id} Analysis ---", style="bold magenta")
                console.print(f"Classification (BERT): {processed_event['classification']}", style="bold yellow")
                console.print(f"Entities Extracted (BERT): {processed_event['entities']}", style="bold cyan")
                console.print(f"Summary (GPT-2): {processed_event['summary']}", style="bold green")
            else:
                console.print("Please specify a valid event ID for analysis (e.g., 'analyze event 4624').", style="bold red")

        # Handle integrated BERT and GPT-2 with event analysis
        handle_user_input(question, sketch)

# ---------------------------
# Logging Configuration
# ---------------------------

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------------------
# Entry Point
# ---------------------------

def start_titan():
    # Print or log the starting message
    console.print("TITAN script started.", style="bold green")
    
    # Call the main function to execute the core logic
    main()

if __name__ == "__main__":
    # This will ensure the script can be executed via the command line or subprocess
    start_titan()
