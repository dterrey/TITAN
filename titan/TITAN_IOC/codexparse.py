import sqlite3
import json
import os

codex_db_path = '/home/triagex/Downloads/TITAN/TITAN_IOC/instance/codex_db.db'
codex_folder_path = '/home/triagex/Downloads/TITAN/codex/'
parsed_output_path = '/home/triagex/Downloads/TITAN/codex/parsed_codex_output.json'

# Recreate the codex_ioc table
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
                print(f"Successfully loaded {file_name}")
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {file_name}. Skipping.")
                continue

        # Debug dynamic data parsing
        dynamic_data = data.get("metadata", {}).get("dynamic", {})
        dropped_files = dynamic_data.get("dropped", [])
        network_data = dynamic_data.get("network", {})
        tools_data = dynamic_data.get("tools", [])
        commands_data = dynamic_data.get("commands", [])

        print(f"Parsed dropped files: {dropped_files}")
        print(f"Parsed network data: {network_data}")
        print(f"Parsed tools: {tools_data}")
        print(f"Parsed commands: {commands_data}")

        # Process dropped files (hashes, filenames)
        for dropped in dropped_files:
            hash_value = dropped.get("sha1", "")
            filename = dropped.get("name", "")
            urls = ', '.join(dropped.get("urls", []))

            # Insert hash as an indicator
            print(f"Inserting hash: {hash_value}, filename: {filename}")
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (hash_value, "Hash", file_name))

            # Insert filename as an indicator
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (filename, "Filename", file_name))

        # Process IP addresses and domains
        for ip in network_data.get("hosts", []):
            print(f"Inserting IP: {ip}")
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (ip, "IP Address", file_name))

        for domain in network_data.get("domains", []):
            print(f"Inserting domain: {domain}")
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (domain, "Domain", file_name))

        # Process tools and commands
        for tool in tools_data:
            print(f"Inserting tool: {tool}")
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (tool, "Tool", file_name))

        for command in commands_data:
            print(f"Inserting command: {command}")
            cursor.execute('''INSERT INTO codex_ioc (indicator, type, parsed_file)
                              VALUES (?, ?, ?)''', 
                           (command, "Command", file_name))

        # Commit after processing each file
        conn.commit()
        print(f"Committed IOCs from {file_name} to the database.")

    conn.close()

    with open(parsed_output_path, 'w') as outfile:
        json.dump(parsed_results, outfile, indent=4)

    print("Codex IOCs imported and parsed successfully.")

# Recreate the table and import data
recreate_table()
create_and_import_codex_db()
