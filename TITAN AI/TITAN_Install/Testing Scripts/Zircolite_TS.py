#Convert JSON Zircolite to TS (working but may need to be tweaked more.

import re
import json

def extract_and_clean_json(js_file):
    try:
        with open(js_file, 'r', encoding='utf-8') as file:
            content = file.read()

            # Extract JSON-like data between array brackets in var declarations, excluding specific tags
            data_blocks = re.findall(r'var\s+(\w+)\s*=\s*(\[.*?\]);', content, re.DOTALL)
            cleaned_data = []

            excluded_tags = {'LowData', 'MediumData', 'HighData', 'CriticalData'}

            for var_name, block in data_blocks:
                if var_name in excluded_tags:
                    continue  # Skip the excluded tags

                block = block.replace("\n", "")
                block = block.replace("'", "\"")

                # Fix common JSON issues
                block = re.sub(r',(\s*[\]}])', r'\1', block)  # Remove trailing commas
                block = re.sub(r'\\\\"', r'\\', block)  # Fix escaped backslashes
                block = re.sub(r'"\{([^}]*)$', r'"\{\1}"', block)  # Close unterminated objects

                try:
                    json_data = json.loads(block)
                    if isinstance(json_data, list):
                        for item in json_data:
                            if isinstance(item, dict):
                                item['tag'] = var_name
                            cleaned_data.append(item)
                    elif isinstance(json_data, dict):
                        json_data['tag'] = var_name
                        cleaned_data.append(json_data)
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON block: {e}")
                    # Optionally log the problematic block or save for further inspection

            return cleaned_data

    except Exception as e:
        print(f"Error processing file: {e}")
        return None

def add_required_fields(data):
    final_data = []

    for item in data:
        if isinstance(item, dict):  # Ensure item is a dictionary

            # Ensure 'datetime' field is present
            if "datetime" not in item:
                item["datetime"] = item.get("SystemTime", "Unknown Time")

            # Ensure 'message' field is present
            if "message" not in item:
                item["message"] = item.get("title", "No Title") + " - " + item.get("description", "No Description")

            # Ensure 'timestamp_desc' field is present
            if "timestamp_desc" not in item:
                item["timestamp_desc"] = "Event Logged"

            final_data.append(item)

    return final_data

def save_jsonl(data, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item) + "\n")
        print(f"Data saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSONL file: {e}")

def main():
    js_file = '/home/triagex/Downloads/data.js'
    output_file = 'Mitre_Attack_Data.jsonl'

    cleaned_data = extract_and_clean_json(js_file)
    if cleaned_data:
        cleaned_data = add_required_fields(cleaned_data)
        print(f"Extracted and processed {len(cleaned_data)} items.")
        save_jsonl(cleaned_data, output_file)
    else:
        print("Failed to extract or clean data.")

if __name__ == "__main__":
    main()
