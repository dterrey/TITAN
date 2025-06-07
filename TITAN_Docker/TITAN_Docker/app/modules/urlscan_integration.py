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

import requests
import time
from rich.console import Console

console = Console()

API_KEY = "71999b57-0017-4055-956f-a38e8a8710a7"

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

