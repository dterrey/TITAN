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
import hashlib
import logging
import json
import argparse

def setup_logging(log_file):
    """Set up logging to capture which files are being processed."""
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

def calculate_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes for the given file."""
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256()
    }
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read file in 8KB chunks
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
    except (FileNotFoundError, PermissionError, Exception) as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return None

    return {hash_name: hash_obj.hexdigest() for hash_name, hash_obj in hashes.items()}

def count_files(directory):
    """Count the total number of files in the directory."""
    total_files = 0
    for root, dirs, files in os.walk(directory):
        total_files += len(files)
    return total_files

def process_directory(directory, output_json, log_file):
    """Hash files in a directory and save to a JSON file."""
    total_files = count_files(directory)
    files_processed = 0
    skipped_files_no_extension = 0  # Track skipped files without extension

    print(f"Total number of files to process in {directory}: {total_files}\n")

    with open(output_json, 'w') as json_file:
        json_file.write('{\n')
        first_entry = True

        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Skip files without an extension
                if not os.path.splitext(file_name)[1]:
                    skipped_files_no_extension += 1
                    logging.info(f"Skipping file with no extension: {file_path}")
                    continue

                logging.info(f"Processing file: {file_path}")
                try:
                    file_size = os.path.getsize(file_path)
                    hashes = calculate_hashes(file_path)
                    if hashes:
                        if not first_entry:
                            json_file.write(',\n')
                        else:
                            first_entry = False
                        json_entry = json.dumps({
                            'filename': file_path,
                            'MD5': hashes['MD5'],
                            'SHA1': hashes['SHA1'],
                            'SHA256': hashes['SHA256'],
                            'Size': file_size
                        })
                        json_file.write(f'"{file_path}": {json_entry}')
                    files_processed += 1

                    # Display progress count in real-time
                    print(f"Progress: {files_processed}/{total_files} files processed in {directory}", end='\r')

                except Exception as e:
                    logging.error(f"Error processing file {file_path}: {e}")
                    pass
        
        json_file.write('\n}\n')

    print(f"\nProcessing complete for {directory}. Skipped {skipped_files_no_extension} files without extensions.")

def convert_json_to_jsonl(input_json_file, output_jsonl_file):
    """Convert the generated JSON file to JSONL format for Timesketch."""
    import datetime
    system_time = datetime.datetime.now().isoformat()  # Use current system time

    with open(input_json_file, 'r') as f:
        data = json.load(f)

    with open(output_jsonl_file, 'w') as out_file:
        for file_path, details in data.items():
            message = f"Filename: {details['filename']}, MD5: {details['MD5']}, SHA1: {details['SHA1']}, SHA256: {details['SHA256']}"
            jsonl_entry = {
                "datetime": system_time,
                "message": message,
                "timestamp_desc": "File hashes",
            }
            out_file.write(json.dumps(jsonl_entry) + '\n')

def process_partitions(output_dir, log_file, image_base_name):
    """Process all files in the mounted partitions."""
    base_partition_dir = "/mnt/partition"
    
    # List of partition directories to process (up to 10 partitions)
    directories_to_process = [f"{base_partition_dir}_{i}" for i in range(10)]
    
    for directory in directories_to_process:
        if os.path.exists(directory) and os.path.ismount(directory):
            print(f"Processing files in {directory}...\n")
            # Use the image base name for the output files
            output_json = os.path.join(output_dir, f"{image_base_name}.json")
            output_jsonl = os.path.join(output_dir, f"{image_base_name}.jsonl")
            
            process_directory(directory, output_json, log_file)
            convert_json_to_jsonl(output_json, output_jsonl)
        else:
            print(f"{directory} does not exist or is not mounted. Skipping...")

def get_image_base_name(image_path):
    """Extract the base name of the image file (e.g., fileserver from fileserver.E01)."""
    return os.path.splitext(os.path.basename(image_path))[0]

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hash files in mounted partitions for DFIR analysis. "
                    "Calculates MD5, SHA1, and SHA256 hashes for each file in the mounted partitions, "
                    "and saves the results in a JSON file."
    )
    parser.add_argument('--image-file', '-i', required=True, help="Path to the original image file (e.g., fileserver.E01).")
    parser.add_argument('--output-dir', '-o', required=True, help="Directory where the JSON output files will be saved.")
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()

    # Get the base name of the image file (e.g., fileserver from fileserver.E01)
    image_base_name = get_image_base_name(args.image_file)

    # Set up logging
    log_file = "file_processing.log"
    setup_logging(log_file)

    # Ensure the output directory exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Process all files in mounted partitions using the base name of the image for output files
    process_partitions(args.output_dir, log_file, image_base_name)

