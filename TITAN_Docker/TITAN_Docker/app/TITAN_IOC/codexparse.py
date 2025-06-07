import sqlite3
import json
import os
import datetime

# Define paths
codex_db_path = '/home/titan/Downloads/TITAN/TITAN_IOC/instance/codex_db.db'
codex_folder_path = '/home/titan/Downloads/TITAN/codex/'

# Function to generate a timestamped file name
def get_timestamped_filename(base_name, extension=".json"):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')  # Format: YYYYMMDD_HHMMSS
    return f"{base_name}_{timestamp}{extension}"

# Function to recreate the codex_ioc table
def recreate_table():
    conn = sqlite3.connect(codex_db_path)
    cursor = conn.cursor()

    # Drop the old table if it exists
    cursor.execute("DROP TABLE IF EXISTS codex_ioc")

    # Create the new table
    cursor.execute('''CREATE TABLE IF NOT EXISTS codex_ioc (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      indicator TEXT,
                      type TEXT,
                      parsed_file TEXT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                      )''')

    conn.commit()
    conn.close()
    print("Table recreated successfully.")

# Function to extract the last two parts of a file path
def extract_last_two_parts(filepath):
    parts = filepath.split('\\')
    if len(parts) >= 3:
        return '\\'.join(parts[-2:])
    return filepath

# Recursive function to find all occurrences of a key in a nested dictionary/list
def find_key_recursively(data, target_key):
    results = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            if key == target_key:
                if isinstance(value, list):
                    results.extend(value)
                else:
                    results.append(value)
            elif isinstance(value, (dict, list)):
                results.extend(find_key_recursively(value, target_key))

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                results.extend(find_key_recursively(item, target_key))

    return results

# Function to create codex_db and import the parsed JSON
def create_and_import_codex_db():
    conn = sqlite3.connect(codex_db_path)
    cursor = conn.cursor()

    parsed_results = []

    # Iterate through all JSON files in the codex folder
    for file_name in os.listdir(codex_folder_path):
        file_path = os.path.join(codex_folder_path, file_name)

        # Check if the file is already parsed
        cursor.execute("SELECT * FROM codex_ioc WHERE parsed_file = ?", (file_name,))
        if cursor.fetchone():
            print(f"File {file_name} already parsed, skipping.")
            continue

        # Load the JSON data
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {file_name}. Skipping.")
                continue

        # If the JSON data is a list, handle each element in the list
        if isinstance(data, list):
            for item in data:
                dynamic_data = item.get("metadata", {}).get("dynamic", {})
                process_data(dynamic_data, file_name, cursor)
        elif isinstance(data, dict):
            # If data is a dict, proceed as usual
            dynamic_data = data.get("metadata", {}).get("dynamic", {})
            process_data(dynamic_data, file_name, cursor)
        else:
            print(f"Unexpected data format in {file_name}, skipping.")
            continue

    conn.commit()
    conn.close()

    print("Codex IOCs imported and parsed successfully.")

# Function to process dynamic data and insert into the database
def process_data(dynamic_data, file_name, cursor):
    dropped_files = dynamic_data.get("dropped", [])
    process_paths = [item.get("filepath", "") for item in dropped_files if "filepath" in item]

    for dropped in dropped_files:
        hash_value = dropped.get("sha1", "")
        filename = dropped.get("name", "")
        filepath = dropped.get("filepath", "")
        urls = ', '.join(dropped.get("urls", []))

        if hash_value:
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (hash_value, "Hash", file_name))

        if filename:
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (filename, "Filename", file_name))

        if filepath:
            truncated_path = extract_last_two_parts(filepath)
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (truncated_path, "File Path", file_name))

        if urls:
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (urls, "URL", file_name))

    for process_path in process_paths:
        truncated_process_path = extract_last_two_parts(process_path)
        cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                          VALUES (?, ?, ?)''', 
                       (truncated_process_path, "Process Path", file_name))

# Recreate the table and import data
recreate_table()
create_and_import_codex_db()

