import os
import subprocess
from flask import Flask, request

# Folder setup
WATCH_FOLDER = "/cases/processor"
PLASO_FOLDER = "/cases/plaso"
LOGS_FOLDER = "/cases/logs"
ZIRCOLITE_FOLDER = "/cases/zircolite"
MOUNTED_FOLDER = "/cases/mounted"
MALWARE_FOLDER = "/cases/malware"
DATA_FOLDER = "/data"

# Create required directories
for folder in [
    '/cases', WATCH_FOLDER, f"{WATCH_FOLDER}/hashes", f"{WATCH_FOLDER}/logfile",
    PLASO_FOLDER, LOGS_FOLDER, ZIRCOLITE_FOLDER, MOUNTED_FOLDER,
    MALWARE_FOLDER, f"{MALWARE_FOLDER}/hashes", f"{MALWARE_FOLDER}/logfile",
    '/cases/evtxproc', DATA_FOLDER
]:
    os.makedirs(folder, exist_ok=True)

# Flask App to expose processing endpoint
app = Flask(__name__)

@app.route('/process', methods=['POST'])
def process_file():
    filename = request.args.get('file')
    if not filename:
        return "No file specified", 400

    file_path = os.path.join(WATCH_FOLDER, filename)
    if not os.path.isfile(file_path):
        return f"File {file_path} does not exist", 404

    name, ext = os.path.splitext(filename)

    print(f"[+] Starting processing for: {file_path}")

    plaso_output = f"/cases/plaso/{name}.plaso"
    log_output = f"/cases/processor/logfile/{name}.log"
    zircolite_output = f"/cases/zircolite/{name}.json"
    mounted_output = f"/cases/mounted/{name}"

    try:
        # Step 1: Run log2timeline
        print(f"[*] Running log2timeline...")
        with open(log_output, 'w') as log:
            subprocess.run(["log2timeline.py", plaso_output, file_path], stdout=log, stderr=subprocess.STDOUT)

        # Step 2: Run Zircolite
        print(f"[*] Running Zircolite...")
        with open(log_output, 'a') as log:
            subprocess.run(["/opt/zircolite/zircolite", "--plaso", plaso_output, "--output", zircolite_output], stdout=log, stderr=subprocess.STDOUT)

        print(f"[✓] Finished processing {file_path}")
        return f"Successfully processed {filename}", 200

    except Exception as e:
        print(f"[!] Error processing {file_path}: {str(e)}")
        return f"Error processing file: {str(e)}", 500

if __name__ == "__main__":
    print("[*] TITAN Processor API is ready and waiting for Node-RED commands on port 5005...")
    app.run(host="0.0.0.0", port=5005)

