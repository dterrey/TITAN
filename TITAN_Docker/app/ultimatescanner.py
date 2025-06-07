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
import yara
import pandas as pd
import subprocess
import json
from git import Repo
import fnmatch

# Paths for rule repositories
SIGMA_REPO_PATH = "/opt/sigma_rules"
YARA_REPO_PATH = "/opt/yara_rules"
MOUNT_PATH = "/mnt/partition_0/"

# CSV file for IOC scanning
IOC_CSV_PATH = "/path/to/iocs.csv"

# JSONL output path for Timesketch
OUTPUT_JSONL_PATH = "/path/to/output.jsonl"

# YARA Scanner Function
def update_yara_rules(repo_url, yara_repo_path):
    if os.path.exists(yara_repo_path):
        print("[*] Updating YARA rules repository...")
        repo = Repo(yara_repo_path)
        repo.remotes.origin.pull()
    else:
        print("[*] Cloning YARA rules repository...")
        Repo.clone_from(repo_url, yara_repo_path)

def yara_scan(path, yara_rules_dir):
    print("[*] Running YARA scan on mounted image...")
    matches = []
    for root, _, files in os.walk(yara_rules_dir):
        for yara_file in fnmatch.filter(files, "*.yar"):
            yara_file_path = os.path.join(root, yara_file)
            try:
                # Compile YARA rule
                rule = yara.compile(filepath=yara_file_path)
                for root, _, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            match = rule.match(filepath)
                            if match:
                                matches.append({"file": filepath, "yara_match": [str(m) for m in match]})
                        except Exception as e:
                            print(f"Error scanning file {filepath}: {e}")
            except yara.SyntaxError as e:
                print(f"Error compiling YARA rule {yara_file_path}, skipping: {e}")
    return matches

# IOC Scanner Function
def ioc_scan(mount_path, ioc_csv_path):
    print("[*] Running IOC scan...")
    iocs = pd.read_csv(ioc_csv_path, header=None, names=["ioc"])
    matches = []

    for root, _, files in os.walk(mount_path):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, "rb") as f:
                file_data = f.read()
                for _, row in iocs.iterrows():
                    ioc = row['ioc']
                    if ioc.encode() in file_data:
                        matches.append({"file": filepath, "ioc_match": ioc})

    return matches

# Sigma Scanner Function
def sigma_scan(path, sigma_repo_path):
    print("[*] Running Sigma scan...")
    sigma_converter = "/opt/sigma/tools/sigmac"  # Path to Sigma's sigmac converter
    results = []
    for root, _, files in os.walk(sigma_repo_path):
        for file in fnmatch.filter(files, "*.yml"):
            sigma_rule_path = os.path.join(root, file)
            command = f"{sigma_converter} --target elasticsearch-windows {sigma_rule_path}"
            try:
                output = subprocess.check_output(command, shell=True).decode("utf-8")
                results.append({"sigma_rule": sigma_rule_path, "output": output})
            except subprocess.CalledProcessError as e:
                print(f"Error running Sigma rule {sigma_rule_path}: {e}")
    return results

# Function to Write JSONL File
def write_jsonl_file(output_path, results):
    print("[*] Writing results to JSONL format for Timesketch...")
    with open(output_path, 'w') as jsonl_file:
        for result in results:
            jsonl_file.write(json.dumps(result) + "\n")

# Main Function to run all scanners
def main():
    # URLs for rule repositories
    YARA_REPO_URL = "https://github.com/Yara-Rules/rules"

    # Update YARA rules
    update_yara_rules(YARA_REPO_URL, YARA_REPO_PATH)

    # Run YARA scan
    yara_results = yara_scan(MOUNT_PATH, os.path.join(YARA_REPO_PATH, "malware_index.yar"))
    print("[*] YARA scan results:", yara_results)

    # Run Sigma scan (skip the update and directly scan with local Sigma rules)
    sigma_results = sigma_scan(MOUNT_PATH, SIGMA_REPO_PATH)
    print("[*] Sigma scan results:", sigma_results)

    # Run IOC scan
    ioc_results = ioc_scan(MOUNT_PATH, IOC_CSV_PATH)
    print("[*] IOC scan results:", ioc_results)

    # Combine results and write to JSONL
    combined_results = yara_results + sigma_results + ioc_results
    write_jsonl_file(OUTPUT_JSONL_PATH, combined_results)

if __name__ == "__main__":
    main()

