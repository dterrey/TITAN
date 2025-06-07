# You must use the custom Zircolite Template which will convert the Zircolite to TimeSketch and then this script parses the data and tags everything. Add the exportForTS.tmpl and move it to /opt/Zircolite-2.20.0/templates/ 
import json

def attempt_json_load(lines):
    try:
        combined_line = ''.join(lines)
        return json.loads(combined_line)
    except json.JSONDecodeError:
        return None

def process_jsonl_with_tags(input_file, output_file):
    cleaned_data = []

    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
        buffer = []
        for line in infile:
            line = line.strip()
            if line == '{' or line == '}':
                buffer.append(line)
            else:
                buffer.append(line)
                if line.endswith('}') and not line.endswith('},'):
                    block = ''.join(buffer)
                    try:
                        json_data = json.loads(block)
                        if isinstance(json_data, list):
                            for item in json_data:
                                if isinstance(item, dict):
                                    if "tags" in item:
                                        # Map MITRE ATT&CK tags to Timesketch tags
                                        mitre_tags = [
                                            tag.replace("attack.", "mitre.attack.") for tag in item["tags"] if "attack." in tag
                                        ]
                                        # Replace 'tags' with 'tag' containing MITRE ATT&CK tags
                                        item['tag'] = list(set(mitre_tags))
                                        del item['tags']  # Remove the original 'tags' field
                                    cleaned_data.append(item)
                        elif isinstance(json_data, dict):
                            if "tags" in json_data:
                                # Map MITRE ATT&CK tags to Timesketch tags
                                mitre_tags = [
                                    tag.replace("attack.", "mitre.attack.") for tag in json_data["tags"] if "attack." in tag
                                ]
                                # Replace 'tags' with 'tag' containing MITRE ATT&CK tags
                                json_data['tag'] = list(set(mitre_tags))
                                del json_data['tags']  # Remove the original 'tags' field
                            cleaned_data.append(json_data)
                    except json.JSONDecodeError as e:
                        print(f"Error parsing JSON block: {e}")
                    
                    buffer.clear()

        for json_obj in cleaned_data:
            # Write the updated JSON object to the output file
            outfile.write(json.dumps(json_obj) + "\n")

if __name__ == "__main__":
    input_file_path = 'datanewnew.jsonl'  # Input JSONL file path.
    output_file_path = 'timesketch_import.jsonl'  # Output JSONL file path.

    process_jsonl_with_tags(input_file_path, output_file_path)
    print(f"Processed file saved to {output_file_path}")
