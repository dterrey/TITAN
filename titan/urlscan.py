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
import requests
import time
import json
import pandas as pd
from urllib.parse import urlparse

# URLScan.io API key
API_KEY = '71999b57-0017-4055-956f-a38e8a8710a7'

# Function to create a safe folder name from a URL
def create_safe_folder_name(url):
    parsed_url = urlparse(url)
    folder_name = parsed_url.netloc.replace('.', '_')
    if not folder_name:
        folder_name = parsed_url.path.replace('/', '_')
    return folder_name

# Function to initiate a URL scan
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
        print(f"Scan initiated successfully. Scan ID: {scan_result['uuid']}")
        return scan_result['uuid']
    else:
        print(f"Error initiating scan: {response.status_code}")
        print(response.text)
        return None

# Function to get scan results
def get_scan_results(scan_id):
    url = f'https://urlscan.io/api/v1/result/{scan_id}/'
    while True:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print("Scan is still in progress...waiting 10 seconds.")
            time.sleep(10)  # Wait and retry
        else:
            print(f"Error retrieving scan results: {response.status_code}")
            print(response.text)
            return None

# Function to output results in the terminal
def display_results(scan_data):
    print("\n--- URLScan.io Results ---")
    print(f"URL: {scan_data['page']['url']}")
    print(f"Domain: {scan_data['page']['domain']}")
    print(f"IP Address: {scan_data['page']['ip']}")
    print(f"Country: {scan_data['page']['country']}")
    print(f"ASN: {scan_data['page']['asn']}")
    print(f"Server: {scan_data['page']['server']}")
    print(f"Submission Time: {scan_data['task']['time']}")
    print(f"Result Link: {scan_data['task']['reportURL']}")
    print("\n--- Additional Information ---")
    print(f"Requests: {len(scan_data['data']['requests'])}")
    print(f"Links: {len(scan_data['data']['links'])}")
    print(f"Domains: {len(scan_data['lists']['domains'])}")
    print(f"IP Addresses: {len(scan_data['lists']['ips'])}")

# Function to export results to CSV
def export_results_to_csv(scan_data, folder_path):
    output_file = os.path.join(folder_path, 'urlscan_results.csv')
    data = {
        'URL': [scan_data['page']['url']],
        'Domain': [scan_data['page']['domain']],
        'IP Address': [scan_data['page']['ip']],
        'Country': [scan_data['page']['country']],
        'ASN': [scan_data['page']['asn']],
        'Server': [scan_data['page']['server']],
        'Submission Time': [scan_data['task']['time']],
        'Result Link': [scan_data['task']['reportURL']],
        'Requests': [len(scan_data['data']['requests'])],
        'Links': [len(scan_data['data']['links'])],
        'Domains': [len(scan_data['lists']['domains'])],
        'IP Addresses': [len(scan_data['lists']['ips'])]
    }
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"Results exported to {output_file}")

# Function to download all response files
def download_all_responses(scan_data, folder_path):
    os.makedirs(folder_path, exist_ok=True)
    transactions = scan_data['data']['requests']
    
    for index, transaction in enumerate(transactions, start=1):
        response_link = transaction.get('response', {}).get('responseURL')
        if response_link:
            try:
                response = requests.get(response_link)
                content_type = response.headers.get('Content-Type')
                
                # Determine file extension
                if 'text/html' in content_type:
                    file_extension = '.html'
                elif 'text/javascript' in content_type:
                    file_extension = '.js'
                elif 'text/css' in content_type:
                    file_extension = '.css'
                elif 'image/' in content_type:
                    file_extension = '.png' if 'png' in content_type else '.jpg'
                else:
                    file_extension = '.txt'
                
                # Save the file
                file_name = os.path.join(folder_path, f'response_{index}{file_extension}')
                with open(file_name, 'wb') as file:
                    file.write(response.content)
                print(f"Downloaded and saved: {file_name}")
            except Exception as e:
                print(f"Failed to download from {response_link}: {e}")

# Function to save screenshot
def save_screenshot(scan_data, folder_path):
    screenshot_url = scan_data.get('screenshotURL')
    if screenshot_url:
        screenshot_path = os.path.join(folder_path, 'screenshot.png')
        try:
            response = requests.get(screenshot_url)
            with open(screenshot_path, 'wb') as file:
                file.write(response.content)
            print(f"Screenshot saved to {screenshot_path}")
        except Exception as e:
            print(f"Failed to download screenshot: {e}")

# Main function
def main():
    url = input("Please enter the URL to scan: ").strip()
    scan_id = scan_url(url)
    
    if scan_id:
        print("Waiting for scan results...")
        scan_data = get_scan_results(scan_id)
        
        if scan_data:
            # Create a folder named after the URL
            folder_name = create_safe_folder_name(url)
            folder_path = os.path.join('/home/titan/Downloads/ADAM/url', folder_name)
            os.makedirs(folder_path, exist_ok=True)
            
            # Display and export results
            display_results(scan_data)
            export_results_to_csv(scan_data, folder_path)
            
            # Save screenshot
            save_screenshot(scan_data, folder_path)

            # Download all response files
            download_all_responses(scan_data, folder_path)
        else:
            print("Failed to retrieve scan results.")
    else:
        print("Scan failed.")

if __name__ == "__main__":
    main()

