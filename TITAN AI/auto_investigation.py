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
import pandas as pd
from datetime import datetime
from fpdf import FPDF
from timesketch_api_client import client, search
from rich.console import Console
import unicodedata

# Initialize console for output
console = Console()

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost', username='titan', password='admin')
sketch_id = 4  # Replace with your sketch ID
sketch = ts_client.get_sketch(sketch_id)

# MITRE ATT&CK Mappings, including severity levels
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
    'LowData': {'tag': 'Low Severity'},
    'MediumData': {'tag': 'Medium Severity'},
    'HighData': {'tag': 'High Severity'},
    'CriticalData': {'tag': 'Critical Severity'},
    'InformationalData': {'tag': 'Informational'},
    'UnknownData': {'tag': 'Unknown'},
    'OtherData': {'tag': 'Other'}
}

# List of fields to exclude from the report
EXCLUDE_FIELDS = [
    'sigma_yml', 'row_id', 'ProcessGuid', 'EventRecordID', 'ThreadID', 
    'Keywords', 'Level', 'Guid', 'UserID', 'Version', 'OriginalLogfile', 
    'Company', 'FileVersion', 'IntegrityLevel', 'LogonGuid', 'LogonId', 
    'ParentProcessGuid', 'Product', 'variable_name', 'tag'
]

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

# Function to convert the microseconds epoch time to UTC
def convert_epoch_to_utc(epoch_time):
    try:
        epoch_seconds = int(epoch_time) / 1000000
        utc_time = datetime.utcfromtimestamp(epoch_seconds).strftime('%Y-%m-%d %H:%M:%S UTC')
        return utc_time
    except ValueError:
        return epoch_time

# Function to sanitize strings to latin-1 by removing or replacing problematic characters
def sanitize_text(text):
    # Normalize the text to remove any non-latin characters
    text = unicodedata.normalize('NFKD', text).encode('latin-1', 'ignore').decode('latin-1')
    return text

# **Updated Function:** Filter out lines in the description that match the [field] = value pattern
def filter_description(description):
    """
    Removes lines that match [field] = value from the description.
    """
    # Split by comma or newline to handle different separators
    lines = re.split(r'[,\n]', description)
    # Use regex to exclude lines with the EXCLUDE_FIELDS
    filtered_lines = [line.strip() for line in lines if not any(f"[{field}]" in line for field in EXCLUDE_FIELDS)]
    # Join the remaining lines with newline for better formatting in PDF
    return '\n'.join(filtered_lines)

# Create a PDF report with UTF-8 encoding support
def create_pdf_report(events_df, output_file):
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(0, 0, 128)
    pdf.cell(200, 10, txt=sanitize_text("Zircolite Incident Report"), ln=True, align='C')

    # Total events
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(200, 10, txt=sanitize_text(f"Total Events: {len(events_df)}"), ln=True)

    # Loop through each MITRE tactic and add data
    for tactic, details in MITRE_TACTIC_MAPPINGS.items():
        tag = details['tag']
        tactic_events = events_df[events_df['tag'].apply(lambda tags: tag in tags if tags else False)]

        if tactic_events.empty:
            continue

        # Add section heading
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 14)
        pdf.set_text_color(255, 0, 0)
        pdf.cell(200, 10, txt=sanitize_text(f"{tag} ({len(tactic_events)} events)"), ln=True)

        # Add description and mitigation recommendations
        pdf.set_font("Arial", '', 12)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 10, txt=sanitize_text(f"This section covers all events tagged with {tag}, providing detailed information and timestamps."))

        for event in tactic_events.itertuples():
            utc_time = sanitize_text(convert_epoch_to_utc(event.timestamp))
            raw_description = event.message if event.message else "No description available"
            # **Apply filtering to remove unwanted [field] = value lines**
            filtered_description = filter_description(raw_description)
            description = sanitize_text(filtered_description)
            event_id = sanitize_text(event.id) if hasattr(event, 'id') else "Unknown ID"

            # Format the event details with line breaks for each key field
            pdf.set_font("Arial", 'B', 10)
            pdf.multi_cell(0, 10, txt=sanitize_text(f"Event ID: {event_id}"))
            pdf.set_font("Arial", 'B', 10)
            pdf.multi_cell(0, 10, txt=sanitize_text(f"Time: {utc_time}"))
            pdf.set_font("Arial", 'B', 10)
            pdf.multi_cell(0, 10, txt=sanitize_text("Description:"))
            pdf.set_font("Arial", '', 10)

            # **Split by newline since we've filtered out [field] = value lines**
            description_lines = description.split('\n')
            for line in description_lines:
                if line:  # Avoid adding empty lines
                    pdf.multi_cell(0, 10, txt=f"{line}")

        # Mitigation recommendations
        pdf.ln(5)
        pdf.set_font("Arial", 'I', 12)
        
        # Add customized mitigation recommendations based on the tactic
        mitigation_recommendation = sanitize_text(get_mitigation_recommendation(tag))
        pdf.multi_cell(0, 10, txt=sanitize_text(f"Mitigation Recommendations for {tag}: {mitigation_recommendation}\n"))

    # Save the PDF
    try:
        pdf.output(output_file, 'F')
        console.print(f"Incident report saved as PDF to {output_file}", style="bold green")
    except Exception as e:
        console.print(f"Failed to save PDF: {e}", style="bold red")

# Function to provide meaningful and tactic-specific mitigation recommendations
def get_mitigation_recommendation(tactic):
    recommendations = {
        'Initial Access': (
            "Ensure that proper network segmentation is in place to limit the impact of compromised assets. "
            "Enable multi-factor authentication (MFA) for remote access and monitor all ingress points for unusual behavior."
        ),
        'Persistence': (
            "Monitor for changes to persistence mechanisms, such as modifications to the Windows Registry or scheduled tasks. "
            "Utilize Endpoint Detection and Response (EDR) solutions to detect and block unusual persistence activity."
        ),
        'Privilege Escalation': (
            "Ensure that users have only the minimum necessary privileges. Regularly audit accounts for proper permission levels. "
            "Monitor for the creation of new administrator accounts or the modification of privilege levels."
        ),
        'Defense Evasion': (
            "Implement logging mechanisms to detect tampering with security logs or services. "
            "Monitor for unexpected or unauthorized disabling of security software."
        ),
        'Credential Access': (
            "Utilize strong password policies and implement multi-factor authentication (MFA) to prevent credential theft. "
            "Monitor for abnormal credential usage or attempts to access high-privilege accounts."
        ),
        'Discovery': (
            "Monitor network traffic for unusual activity that indicates lateral movement or scanning of internal systems. "
            "Limit the use of unnecessary services and ensure proper access control."
        ),
        'Lateral Movement': (
            "Use network segmentation and firewalls to limit lateral movement. "
            "Monitor for unusual remote access or file transfer activity between internal systems."
        ),
        'Execution': (
            "Restrict the use of PowerShell and other scripting languages to authorized users. "
            "Monitor for unusual script execution and suspicious process creation events."
        ),
        'Collection': (
            "Encrypt sensitive data both at rest and in transit. "
            "Monitor for large or unusual file access requests that could indicate data exfiltration attempts."
        ),
        'Exfiltration': (
            "Monitor for unusual outbound network traffic that may indicate data exfiltration. "
            "Use Data Loss Prevention (DLP) tools to detect and block unauthorized data transfers."
        ),
        'Command and Control': (
            "Monitor for beaconing behavior or suspicious network connections to known malicious command-and-control servers. "
            "Implement network-based detection mechanisms to block suspicious outbound connections."
        ),
        'Impact': (
            "Develop and regularly test an incident response plan to quickly respond to destructive attacks. "
            "Use backup solutions to mitigate the damage from ransomware or other destructive actions."
        ),
        'Other': (
            "Review logs for any unusual activity that does not fit into specific categories. "
            "Implement general cybersecurity best practices to minimize the risk of undetected threats."
        )
    }
    return recommendations.get(tactic, "Please review specific mitigation strategies to enhance defenses.")

# Main function
def main():
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

        # Generate PDF report
        output_file = '/home/titan/Downloads/zircolite_report.pdf'
        create_pdf_report(events_df, output_file)

    elif option == "2":
        # Placeholder for IOC Hunt and Report functionality
        console.print("IOC Hunt and Report option will be implemented.", style="bold blue")
        # You can integrate the existing IOC hunt functionality here
    else:
        console.print("Invalid option. Please choose 1 or 2.", style="bold red")

if __name__ == '__main__':
    main()

