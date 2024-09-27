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


import re
import json

def preprocess_block(block):
    """Preprocess block to fix common JSON issues."""
    # Remove newline and tab characters
    block = block.replace('\n', '').replace('\t', '')

    # Remove trailing commas before closing brackets
    block = block.replace(',]', ']').replace(',}', '}')

    # Add missing commas between adjacent JSON objects
    block = re.sub(r'(?<=\})(?=\{)', ',', block)

    # Fix unescaped quotes around property names and string values
    block = re.sub(r'(?<!\\)"', '"', block)

    # Fix missing commas between properties (looks for "}" or "]" followed by a "{")
    block = re.sub(r'(?<=[\}\]])(?=\s*\{)', ',', block)

    # Fix unquoted property names (convert {key: value} -> {"key": value})
    block = re.sub(r'(?<=\{|\s)(\w+)(?=\s*:)', r'"\1"', block)

    return block

def convert_javascript_to_json(js_object):
    """Convert JavaScript-like objects to JSON placeholders."""
    # Replace JavaScript code with a placeholder
    js_object = re.sub(r'var\s+[\w]+\s*=\s*.*?;', '"javascript_code_placeholder"', js_object)
    js_object = re.sub(r'function\s*\(.*?\)\s*\{.*?\}', '"javascript_function_placeholder"', js_object)
    js_object = re.sub(r'\$\.WMI\(.*?\);', '"javascript_wmi_placeholder"', js_object)
    js_object = re.sub(r'\$\.oHttp.*?\);', '"javascript_http_placeholder"', js_object)

    return js_object

def extract_individual_json_objects(block):
    """Extracts individual JSON objects from a block."""
    block = preprocess_block(block)

    # Regex pattern to extract JSON-like objects
    objects = re.findall(r'\{.*?\}', block)
    parsed_objects = []

    for obj in objects:
        try:
            # Convert JavaScript content to JSON-like using placeholders
            obj = convert_javascript_to_json(obj)
            parsed_objects.append(json.loads(obj))
        except json.JSONDecodeError as e:
            print(f"Failed to parse object: {obj[:100]}... Error: {e}")
            continue

    return parsed_objects

def process_var_block(js_file, var_name):
    try:
        with open(js_file, 'r', encoding='utf-8') as file:
            content = file.read()

            # Regex to isolate the specific `var` block we want to process
            pattern = rf'var\s+{var_name}\s*=\s*(\[.*?\]);'
            match = re.search(pattern, content, re.DOTALL)

            if not match:
                print(f"No data block found for '{var_name}'.")
                return []

            block = match.group(1)
            print(f"Processing block for '{var_name}' with {len(block)} characters.")

            # Split block into manageable chunks
            chunk_size = 10000  # Adjust based on your needs
            chunks = [block[i:i+chunk_size] for i in range(0, len(block), chunk_size)]

            parsed_data = []
            for chunk in chunks:
                parsed_data.extend(extract_individual_json_objects(chunk))

            # Add tag indicating the variable name
            for entry in parsed_data:
                entry['tag'] = var_name

            return parsed_data

    except Exception as e:
        print(f"Error processing file: {e}")
        return []

def save_jsonl(data, output_file):
    """Save processed data to a JSONL file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
        print(f"Data saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSONL file: {e}")

def main():
    js_file = '/home/titan/Downloads/data.js'
    output_dir = '/home/titan/Downloads/'
    var_names = [
        "InitialAccessData", "ExecutionData", "PersistenceData", "PrivilegeEscalationData", 
        "DefenseEvasionData", "CredentialAccessData", "DiscoveryData", "LateralMovementData",
        "CollectionData", "CommandAndControlData", "ExfiltrationData", "ImpactData", 
        "ReconnaissanceData", "ResourceDevelopmentData", "OtherData", "UnknownData", 
        "LowData", "MediumData", "InformationalData", "HighData", "CriticalData"
    ]

    all_data = []

    for var_name in var_names:
        cleaned_data = process_var_block(js_file, var_name)
        if cleaned_data:
            output_file = f"{output_dir}{var_name}.jsonl"
            save_jsonl(cleaned_data, output_file)
            all_data.extend(cleaned_data)
        else:
            print(f"No data extracted for '{var_name}'.")

    if all_data:
        combined_output_file = f"{output_dir}combined_output.jsonl"
        save_jsonl(all_data, combined_output_file)

if __name__ == "__main__":
    main()

