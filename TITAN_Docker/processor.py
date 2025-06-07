import os
import time
import subprocess

WATCH_FOLDER = "/cases/processor"

def process_file(file_path):
    filename = os.path.basename(file_path)
    name, ext = os.path.splitext(filename)
    plaso_output = f"/cases/plaso/{name}.plaso"
    log_output = f"/cases/logs/{name}.log"
    zircolite_output = f"/cases/zircolite/{name}.json"

    print(f"[*] Processing {file_path}")

    with open(log_output, 'w') as log:
        subprocess.run(["log2timeline", plaso_output, file_path], stdout=log, stderr=subprocess.STDOUT)
        subprocess.run(["zircolite", "--plaso", plaso_output, "--output", zircolite_output], stdout=log, stderr=subprocess.STDOUT)

    print(f"[+] Finished processing {file_path}")

if __name__ == "__main__":
    print("[*] Watching for new files...")
    processed = set()
    while True:
        for fname in os.listdir(WATCH_FOLDER):
            path = os.path.join(WATCH_FOLDER, fname)
            if fname not in processed and os.path.isfile(path):
                process_file(path)
                processed.add(fname)
        time.sleep(10)
