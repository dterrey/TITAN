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

#Usage sudo python3 hash_filehash.py -o /cases/processor/hashes/ -b filename

import os
import hashlib
import logging
import json
import argparse
import datetime

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

def process_directory(directory, output_jsonl, log_file):
    """Hash files in a directory and save to a JSONL file with a live progress counter."""
    total_files = count_files(directory)
    files_processed = 0
    skipped_files_no_extension = 0  # Track skipped files without extension
    skipped_zero_byte_files = 0  # Track skipped zero-byte files

    print(f"Total number of files to process in {directory}: {total_files}\n")
    logging.info(f"Starting to process directory: {directory}, Total files: {total_files}")

    with open(output_jsonl, 'w') as jsonl_file:
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Skip files without an extension
                if not os.path.splitext(file_name)[1]:
                    skipped_files_no_extension += 1
                    logging.info(f"Skipping file with no extension: {file_path}")
                    continue

                try:
                    file_size = os.path.getsize(file_path)
                    
                    # Skip files that are 0 bytes in size
                    if file_size == 0:
                        skipped_zero_byte_files += 1
                        logging.info(f"Skipping 0-byte file: {file_path}")
                        continue

                    # Process the file and calculate hashes
                    hashes = calculate_hashes(file_path)
                    if hashes:
                        message = f"Filename: {file_path}, MD5: {hashes['MD5']}, SHA1: {hashes['SHA1']}, SHA256: {hashes['SHA256']}"
                        jsonl_entry = {
                            "datetime": datetime.datetime.now().isoformat(),
                            "message": message,
                            "timestamp_desc": "File hashes",
                        }
                        jsonl_file.write(json.dumps(jsonl_entry) + '\n')
                        logging.info(f"Successfully processed file: {file_path}")
                    files_processed += 1

                    # Display progress count in real-time
                    print(f"Progress: {files_processed}/{total_files} files processed in {directory}", end='\r')

                except FileNotFoundError as e:
                    logging.error(f"File not found: {file_path}. Error: {e}")
                    continue  # Skip and move to the next file

                except Exception as e:
                    logging.error(f"Error processing file {file_path}: {e}")
                    continue

    print(f"\nProcessing complete for {directory}. Skipped {skipped_files_no_extension} files without extensions and {skipped_zero_byte_files} 0-byte files.")
    logging.info(f"Processing complete for directory: {directory}. Total processed: {files_processed}. Skipped: {skipped_files_no_extension} files without extensions, {skipped_zero_byte_files} zero-byte files.")

def process_partitions(output_dir, log_file, output_base_name="partition_hashes"):
    """Process all files in the mounted partitions."""
    base_partition_dir = "/mnt/partition"
    
    # List of partition directories to process (up to 10 partitions)
    directories_to_process = [f"{base_partition_dir}_{i}" for i in range(10)]
    
    for directory in directories_to_process:
        if os.path.exists(directory) and os.path.ismount(directory):  # Corrected to use os.path.ismount()
            print(f"Processing files in {directory}...\n")
            # Use the base name for the output files
            output_jsonl = os.path.join(output_dir, f"{output_base_name}.jsonl")
            
            process_directory(directory, output_jsonl, log_file)
        else:
            print(f"{directory} does not exist or is not mounted. Skipping...")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hash files in mounted partitions for DFIR analysis. "
                    "Calculates MD5, SHA1, and SHA256 hashes for each file in the mounted partitions, "
                    "and saves the results in a JSONL file."
    )
    parser.add_argument('--output-dir', '-o', required=True, help="Directory where the JSONL output files will be saved.")
    parser.add_argument('--output-base-name', '-b', required=False, default="partition_hashes", help="Base name for the output JSONL file (default: partition_hashes).")
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_arguments()

    # Set up logging
    log_file = "file_processing.log"
    setup_logging(log_file)

    # Ensure the output directory exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Process all files in mounted partitions using the base name of the image for output files
    process_partitions(args.output_dir, log_file, args.output_base_name)


