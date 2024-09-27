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

# /home/triagex/Downloads/ADAM/modules/utils.py

import os
import re
import json
import pandas as pd
import requests
from urllib.parse import urlparse, urlencode
from rich.console import Console

console = Console()

def ensure_directory_exists(path):
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
def export_to_jsonl(data, output_file):
    with open(output_file, 'w') as outfile:
        for event in data:
            json.dump(event, outfile)
            outfile.write('\n')

def set_export_folder(path):
    global export_folder
    if os.path.isdir(path):
        export_folder = path
        console.print(f"Export folder set to: {export_folder}", style="bold green")
    else:
        console.print(f"Invalid folder path: {path}. Please provide a valid folder.", style="bold red")
    return export_folder

def create_safe_folder_name(url):
    # Parse the URL to get the domain
    parsed_url = urlparse(url)
    # Use only the netloc (domain) and path, replacing unsafe characters
    safe_name = re.sub(r'[^\w\-_\. ]', '_', parsed_url.netloc + parsed_url.path)
    return safe_name

def export_results_to_csv(scan_data, folder_path):
    csv_file = os.path.join(folder_path, 'scan_results.csv')
    flattened_data = pd.json_normalize(scan_data)
    flattened_data.to_csv(csv_file, index=False)
    console.print(f"Scan results exported to CSV at: {csv_file}", style="bold green")

def display_results(results):
    console.print("\n---- Results ----", style="bold blue")
    try:
        console.print(json.dumps(results, indent=4), style="bold cyan")
    except Exception as e:
        console.print(f"Error displaying results: {e}", style="bold red")

def save_results_to_json(scan_data, folder_path):
    json_file = os.path.join(folder_path, 'scan_results.json')
    try:
        with open(json_file, 'w') as f:
            json.dump(scan_data, f, indent=4)
        console.print(f"Scan results saved to JSON at: {json_file}", style="bold green")
    except Exception as e:
        console.print(f"Error saving results to JSON: {e}", style="bold red")

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

def filter_invalid_query_parts(query_parts):
    """
    Filter out any query parts that contain invalid characters or start with '-'.

    Args:
        query_parts (list): List of query strings.

    Returns:
        list: Filtered list of valid query strings.
    """
    # Remove any parts that contain a hyphen or problematic patterns like '-utf8.txt'
    filtered_query_parts = [
        part for part in query_parts 
        if not re.search(r'[-]', part)  # This skips parts with hyphens
    ]
    return filtered_query_parts

