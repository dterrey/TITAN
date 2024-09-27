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

import time
import json
from codex import CodexGigasInfo

# Initialize the CodexGigasInfo class
cg = CodexGigasInfo()

def search_and_get_report():
    search_type = input("Choose search type:\n1. File Hash\n2. Upload a File\nEnter the number corresponding to your choice: ").strip()

    if search_type == '1':
        file_hash = input("Enter the file hash (MD5, SHA1, or SHA256): ").strip()
        process_hash(file_hash)
    elif search_type == '2':
        file_path = input("Please enter the full path to the file (including the filename): ").strip()
        send_file_and_get_report(file_path)
    else:
        print("Invalid choice. Please try again.")

def process_hash(file_hash):
    results = {}
    
    # Get antivirus results
    print(f"Retrieving antivirus results for hash: {file_hash}")
    if cg.av_result(file_hash):
        results['antivirus_results'] = cg.response
        print("Antivirus results retrieved successfully.")
    else:
        print(f"Error retrieving antivirus results: {cg.error_message}")

    # Get metadata
    print(f"Retrieving metadata for hash: {file_hash}")
    if cg.get_metadata(file_hash):
        results['metadata'] = cg.response
        print("Metadata retrieved successfully.")
    else:
        print(f"Error retrieving metadata: {cg.error_message}")

    # Display the combined results
    display_results(results)
    
    # Option to export results to a file
    export_to_file = input("Would you like to export the results to a file? (y/n): ").strip().lower()
    if export_to_file == 'y':
        export_results_to_file(file_hash, results)

def send_file_and_get_report(file_path):
    try:
        # Open the file and send it for processing
        with open(file_path, 'rb') as f:
            if cg.send_file_to_process(f):
                print("File sent for processing successfully.")
                print(f"Response after sending file: {cg.response}")
            else:
                print(f"Error sending file: {cg.error_message}")
                return
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return

    # Attempt to retrieve the file hash from the message or response
    file_hash = None
    if 'file_hash' in cg.response:
        file_hash = cg.response['file_hash']
    elif 'message' in cg.response and 'Already exists' in cg.response['message']:
        file_hash = cg.response['message'].split()[-1]  # Extract the hash from the message
    
    if not file_hash:
        print("Failed to retrieve file hash. Full response:")
        print(cg.response)
        return

    # Process the hash
    process_hash(file_hash)

def display_results(results):
    print("\n---- Results ----")
    try:
        # Display the results in a readable format
        print(json.dumps(results, indent=4))
    except Exception as e:
        print(f"Error displaying results: {e}")

def export_results_to_file(identifier, results):
    try:
        output_file = f"results_{identifier}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results exported successfully to {output_file}")
    except Exception as e:
        print(f"Error exporting results to file: {e}")

def main():
    search_and_get_report()

if __name__ == "__main__":
    main()

