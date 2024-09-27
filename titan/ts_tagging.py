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

def attempt_json_load(lines):
    try:
        combined_line = ''.join(lines)
        return json.loads(combined_line)
    except json.JSONDecodeError:
        return None

def process_jsonl_with_tags(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
        buffer = []
        for line in infile:
            line = line.strip()
            if line == '{' or line == '}':
                buffer.append(line)
            else:
                buffer.append(line)
                if line.endswith('}') and not line.endswith('},'):
                    json_obj = attempt_json_load(buffer)
                    if json_obj:
                        if "tags" in json_obj:
                            # Remove spaces around elements and ensure the tags are formatted as a list
                            json_obj["tags"] = [tag.strip() for tag in json_obj["tags"]]
                            
                            # Map MITRE ATT&CK tags to Timesketch tags
                            mitre_tags = [
                                tag.replace("attack.", "mitre.attack.") for tag in json_obj["tags"] if "attack." in tag
                            ]
                            json_obj["tags"].extend(mitre_tags)
                        
                        # Ensure tags are formatted as a JSON array
                        json_obj["tags"] = json_obj.get("tags", [])
                        
                        # Write the updated JSON object to the output file.
                        outfile.write(json.dumps(json_obj) + "\n")
                    else:
                        print(f"Skipping invalid JSON lines: {buffer}")
                    buffer.clear()

if __name__ == "__main__":
    input_file_path = 'Mitre_Attack_Data.jsonl'  # Input JSONL file path.
    output_file_path = 'timesketch_import.jsonl'  # Output JSONL file path.

    process_jsonl_with_tags(input_file_path, output_file_path)
    print(f"Processed file saved to {output_file_path}")

