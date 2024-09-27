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
from codex import CodexGigasInfo

console = Console()

cg = CodexGigasInfo()

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

def display_results(results):
    console.print("\n---- Results ----", style="bold blue")
    try:
        console.print(json.dumps(results, indent=4), style="bold cyan")
    except Exception as e:
        console.print(f"Error displaying results: {e}", style="bold red")

def export_results_to_file(identifier, results):
    try:
        output_file = f"results_{identifier}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        console.print(f"Results exported successfully to {output_file}", style="bold green")
    except Exception as e:
        console.print(f"Error exporting results to file: {e}", style="bold red")

