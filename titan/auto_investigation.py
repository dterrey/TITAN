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
import pandas as pd
from transformers import GPT2LMHeadModel, GPT2Tokenizer
from timesketch_api_client import client, search
from rich.console import Console

# Initialize console for output
console = Console()

# Define local paths for GPT-2 model and tokenizer
LOCAL_MODEL_PATH = "./local_gpt2_model"
LOCAL_TOKENIZER_PATH = "./local_gpt2_tokenizer"

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost', username='triagex', password='admin')
sketch_id = 4  # Replace with your sketch ID
sketch = ts_client.get_sketch(sketch_id)

# MITRE ATT&CK Mappings
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
}

# Function to check and download GPT-2 model and tokenizer if they don't exist
def check_and_download_gpt2():
    if not os.path.exists(LOCAL_MODEL_PATH) or not os.path.exists(LOCAL_TOKENIZER_PATH):
        console.print("GPT-2 model or tokenizer not found locally. Downloading...", style="bold yellow")
        model = GPT2LMHeadModel.from_pretrained("gpt2")
        tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
        model.save_pretrained(LOCAL_MODEL_PATH)
        tokenizer.save_pretrained(LOCAL_TOKENIZER_PATH)
        console.print("GPT-2 model and tokenizer downloaded and saved locally.", style="bold green")
    else:
        console.print("GPT-2 model and tokenizer found locally.", style="bold green")

# Initialize GPT-2 model and tokenizer from local files (offline)
def initialize_gpt2():
    check_and_download_gpt2()  # Ensure the model and tokenizer are available locally
    console.print("Initializing GPT-2 model for AI analysis (Offline)...", style="bold blue")
    tokenizer = GPT2Tokenizer.from_pretrained(LOCAL_TOKENIZER_PATH)
    model = GPT2LMHeadModel.from_pretrained(LOCAL_MODEL_PATH)
    return tokenizer, model

# Function to load Zircolite data from Timesketch using MITRE ATT&CK tags
def load_zircolite_data(sketch):
    mitre_tags = [info['tag'] for info in MITRE_TACTIC_MAPPINGS.values()]
    query = ' OR '.join([f'tag:"{tag}"' for tag in mitre_tags])

    console.print(f"Searching for events tagged with MITRE ATT&CK tactics: {', '.join(mitre_tags)}", style="bold blue")

    search_obj = search.Search(sketch=sketch)
    search_obj.query_string = query
    search_results = search_obj.table
    events_df = pd.DataFrame(search_results)

    if events_df.empty:
        console.print(f"No events found for Zircolite data.", style="bold yellow")
        return pd.DataFrame()

    console.print(f"Loaded {len(events_df)} Zircolite events.", style="bold green")
    return events_df

# Function to perform GPT-2 analysis and generate structured paragraphs
def generate_zircolite_report(events_df, tokenizer, model, output_file):
    if events_df.empty:
        console.print("No events to analyze.", style="bold red")
        return

    summary_data = []

    # Convert the timeline into a summary input for AI model
    event_texts = events_df['message'].tolist()

    # GPT-2 has a token limit of 1024, so we'll set a max token limit for each chunk
    max_tokens_per_chunk = 900  # Keep a buffer from 1024 to prevent overflow

    input_text_chunks = []
    current_chunk = ""

    for event_text in event_texts:
        tokens = tokenizer.encode(event_text)
        if len(tokens) > max_tokens_per_chunk:
            truncated_tokens = tokens[:max_tokens_per_chunk]
            current_chunk = tokenizer.decode(truncated_tokens, skip_special_tokens=True)
            input_text_chunks.append(current_chunk)
            current_chunk = ""
        elif len(current_chunk) + len(tokens) > max_tokens_per_chunk:
            input_text_chunks.append(current_chunk)
            current_chunk = event_text
        else:
            current_chunk += "\n" + event_text

    if current_chunk:
        input_text_chunks.append(current_chunk)

    console.print(f"Performing AI analysis on {len(event_texts)} events split into {len(input_text_chunks)} chunks...", style="bold blue")

    # Process each chunk separately
    for chunk_idx, input_text in enumerate(input_text_chunks):
        console.print(f"Processing chunk {chunk_idx + 1} of {len(input_text_chunks)}...", style="bold cyan")

        inputs = tokenizer.encode(input_text, return_tensors='pt')

        outputs = model.generate(
            inputs.to(model.device), 
            max_new_tokens=200,  # Limit new token generation
            num_return_sequences=1, 
            do_sample=True, 
            temperature=0.7
        )

        # Decode the generated analysis
        generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Construct a summary entry for each event
        for event in events_df.itertuples():
            file_path = getattr(event, 'message', 'Unknown')

            summary_data.append({
                "File Path Detected": file_path,
                "AI Generated Analysis": generated_text
            })

    # Export the results to a CSV file
    output_df = pd.DataFrame(summary_data)
    output_df.to_csv(output_file, index=False)
    console.print(f"Zircolite report saved to {output_file}", style="bold green")

# Main function for Zircolite report generation
def main():
    # Option to choose between report generation
    console.print("Select an option:", style="bold yellow")
    console.print("1. Generate Zircolite report", style="bold green")
    console.print("2. IOC Hunt and Report", style="bold green")
    option = input("Enter your choice (1/2): ")

    if option == "1":
        # Load Zircolite data from Timesketch
        events_df = load_zircolite_data(sketch)

        if events_df.empty:
            console.print("No Zircolite data available for report generation.", style="bold red")
            return

        # Initialize GPT-2 model and tokenizer
        tokenizer, model = initialize_gpt2()

        # Perform AI-based analysis on the Zircolite data and generate the report
        output_file = '/home/triagex/Downloads/ADAM/zircolite_report.csv'  # Specify the output file path
        generate_zircolite_report(events_df, tokenizer, model, output_file)

    elif option == "2":
        console.print("IOC Hunt and Report option will be implemented.", style="bold blue")
        # You can integrate the existing IOC hunt functionality here
    else:
        console.print("Invalid option. Please choose 1 or 2.", style="bold red")

if __name__ == '__main__':
    main()
