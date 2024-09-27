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
import re
import json
import pandas as pd
from rich.console import Console

console = Console()

def load_iocs(iocs_storage_file):
    if os.path.exists(iocs_storage_file):
        if os.stat(iocs_storage_file).st_size == 0:
            return {
                "hashes": [],
                "ips": [],
                "domains": [],
                "tools": [],
                "commands": []
            }
        with open(iocs_storage_file, 'r') as file:
            return json.load(file)
    return {
        "hashes": [],
        "ips": [],
        "domains": [],
        "tools": [],
        "commands": []
    }

def save_iocs(iocs_storage_file, iocs):
    with open(iocs_storage_file, 'w') as file:
        json.dump(iocs, file, indent=4)

def update_iocs(iocs_storage_file, new_iocs):
    iocs = load_iocs(iocs_storage_file)
    for key in iocs.keys():
        iocs[key].extend(new_iocs[key])
        iocs[key] = list(set(iocs[key]))  # Remove duplicates
    save_iocs(iocs_storage_file, iocs)
    console.print("IOCs updated and saved.", style="bold cyan")

def extract_indicators(text, indicator_type=None):
    indicators = {
        "hashes": [],
        "ips": [],
        "domains": [],
        "tools": [],
        "commands": []
    }

    # Regex patterns for extracting indicators
    hash_pattern = r'\b[A-Fa-f0-9]{64}\b'
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    # Extracting indicators
    indicators["hashes"] = re.findall(hash_pattern, text)
    indicators["ips"] = re.findall(ip_pattern, text)
    indicators["domains"] = re.findall(domain_pattern, text)

    # Extract tools and commands based on known keywords
    tools_keywords = ["AdFind", "Mimikatz", "RClone", "WinRAR", "PowerShell", "Ngrok"]
    for keyword in tools_keywords:
        if keyword.lower() in text.lower():
            indicators["tools"].append(keyword)

    command_pattern = r'\b[A-Za-z0-9_\-\\/:]+\.exe\b'
    indicators["commands"] = re.findall(command_pattern, text)

    # Update persistent IOCs storage
    update_iocs(iocs_storage_file, indicators)

    if indicator_type:
        return {indicator_type: indicators[indicator_type]}
    
    return indicators

def extract_and_store_iocs_from_csv(iocs_storage_file, dataframe):
    iocs = {
        "hashes": [],
        "ips": [],
        "domains": [],
        "tools": [],
        "commands": []
    }

    # Extract IOCs from the dataframe
    for ioc in dataframe.iloc[:, 0]:
        if re.match(r'\b[A-Fa-f0-9]{64}\b', ioc):
            iocs["hashes"].append(ioc)
        elif re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ioc):
            iocs["ips"].append(ioc)
        elif re.match(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', ioc):
            iocs["domains"].append(ioc)
        elif re.match(r'\b[A-Za-z0-9_\-\\/:]+\.exe\b', ioc):
            iocs["commands"].append(ioc)
        else:
            # If not matched by other types, consider it a tool or generic keyword
            iocs["tools"].append(ioc)

    # Update persistent IOCs storage
    update_iocs(iocs_storage_file, iocs)
    console.print("IOCs extracted and stored from the CSV.", style="bold cyan")

