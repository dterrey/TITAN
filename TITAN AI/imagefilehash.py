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

"""
Script Name: imagefilehash.py

Description:
This script is designed for use in Digital Forensics and Incident Response (DFIR) workflows, particularly for hashing all files within multiple raw disk images (e.g., .E01, .vmdk, .vhd, .vhdx, .raw, .dd formats). The script mounts each raw image, processes each file within the mounted file system, and calculates three different cryptographic hash values (MD5, SHA1, and SHA256) for each file. The results are then saved to a JSON file in a specified output directory.

The generated JSON file can be used with forensic tools like ADAM (Automated Disk and Artifact Management) to search for Indicators of Compromise (IOCs) across the disk images.

How It Works:
1. **Mounting the Images**: 
   - The script begins by identifying the type of image (e.g., `.E01`, `.vmdk`, `.vhd`, `.vhdx`, `.raw`, `.dd`) and then mounts it using the appropriate tool (`xmount`, `qemu-nbd`, `losetup`).
   - It then identifies all the partitions within each raw image using loopback devices and mounts each partition read-only to a specified directory.

2. **Processing Files**:
   - The script recursively traverses the mounted file systems, processing each file by calculating its cryptographic hashes (MD5, SHA1, SHA256).
   - Files that do not have an extension are skipped, as they may cause the script to freeze.

3. **Handling Exceptions**:
   - The script is robust against common issues such as files that cannot be read due to permission errors or other I/O errors. These are logged, and the script continues processing other files.

4. **Output**:
   - The hashes for each processed file, along with its path and size, are written to individual JSON files in the specified output directory. Each JSON file is named after the corresponding disk image.

5. **Cleanup**:
   - After processing, the script ensures that all loop devices are detached and mount points are unmounted. This prevents the accumulation of loop devices, which could interfere with future forensic operations.

Usage:
- This script is typically used in a DFIR context when an investigator needs to process multiple raw disk images to extract hash values for all files. 
- The resulting JSON files can be loaded into ADAM to search for IOCs, helping to identify malicious files or artifacts across the disk images.

Prerequisites:
- The system running this script must have the necessary tools installed (`xmount`, `losetup`, `mount`, `qemu-nbd`, etc.).
- Ensure that the script is run with sufficient privileges to mount file systems and access all files within the disk images.

Example Command:
    $ sudo python3 imagefilehash.py --image-dir "/path/to/image/folder" --output-dir "/path/to/output/folder"

This will process each image in the specified folder and output the results to individual JSON files in the output folder.

"""

import os
import hashlib
import json
import subprocess
import sys
import shutil
import readline
import rlcompleter
import atexit
import logging
import argparse
import time
import datetime

def setup_readline():
    """Configure readline for tab completion and command history."""
    readline.parse_and_bind("tab: complete")
    histfile = os.path.join(os.path.expanduser("~"), ".python_history")
    try:
        readline.read_history_file(histfile)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
    atexit.register(readline.write_history_file, histfile)
    readline.set_completer_delims(' \t\n;')
    readline.set_completer(rlcompleter.Completer().complete)

def setup_logging(log_file):
    """Set up logging to capture which files are being processed."""
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

def cleanup_mounts(mount_points):
    """Cleanup previous mounts and remove directories if needed."""
    for mount_point in mount_points:
        if os.path.ismount(mount_point):
            try:
                subprocess.run(['umount', '-l', mount_point], check=True)
            except subprocess.CalledProcessError:
                pass
        
        if os.path.exists(mount_point):
            try:
                shutil.rmtree(mount_point)
            except Exception as e:
                print(f"Failed to remove mount point {mount_point}: {e}")

def cleanup_loop_devices():
    """Detach any leftover loop devices."""
    try:
        loop_devices = subprocess.check_output(['losetup', '-a']).decode().strip().split('\n')
        for device in loop_devices:
            loop_device = device.split(':')[0]
            try:
                subprocess.run(['losetup', '-d', loop_device], check=True)
                print(f"Detached {loop_device}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to detach {loop_device}: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to list loop devices: {e}")

def calculate_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes for the given file."""
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256()
    }
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
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
    hashes_dict = {}

    with open(output_json, 'w') as json_file:
        json_file.write('{\n')
        first_entry = True
        
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Log the skipping of files without extensions
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
                    print(f"Progress: {files_processed}/{total_files} files processed", end='\r')
                
                except Exception as e:
                    logging.error(f"Error processing file {file_path}: {e}")
                    pass
        
        json_file.write('\n}\n')
    
    print(f"\nProcessing complete. Skipped {skipped_files_no_extension} files without extensions.")

def convert_json_to_jsonl(input_json_file, output_jsonl_file):
    """Convert the generated JSON file to JSONL format for Timesketch."""
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

def mount_image_with_xmount(image_path, xmount_point):
    """Mount the E01 image to a mount point using xmount and return the path to the raw image."""
    try:
        if not os.path.exists(xmount_point):
            os.makedirs(xmount_point)
        subprocess.run(['xmount', '--in', 'ewf', '--out', 'raw', image_path, xmount_point], check=True)
        print(f"Image mounted at {xmount_point}")
        
        # Find the raw image file created by xmount
        raw_image = None
        for file in os.listdir(xmount_point):
            raw_image = os.path.join(xmount_point, file)
            break  # Assuming there is only one raw image file
        
        if raw_image:
            return raw_image
        else:
            print(f"No raw image file found in {xmount_point}.")
            return None

    except subprocess.CalledProcessError:
        return None

def mount_generic_image(image_path, mount_point):
    """Mount a generic disk image to a mount point using loopback or qemu-nbd."""
    try:
        if image_path.endswith('.vmdk') or image_path.endswith('.vhd') or image_path.endswith('.vhdx'):
            # Use qemu-nbd for VMDK, VHD, VHDX
            subprocess.run(['modprobe', 'nbd'], check=True)
            subprocess.run(['qemu-nbd', '--connect=/dev/nbd0', image_path], check=True)
            subprocess.run(['partprobe', '/dev/nbd0'], check=True)
            partition_device = '/dev/nbd0p1'
        else:
            # Use loopback for raw images and .dd files
            partition_device = subprocess.check_output(['losetup', '--show', '-fP', image_path]).strip().decode('utf-8') + 'p1'

        if not os.path.exists(mount_point):
            os.makedirs(mount_point)

        # Mount the partition as read-only
        subprocess.run(['mount', '-o', 'ro', partition_device, mount_point], check=True)
        print(f"Mounted {partition_device} at {mount_point}")
        return mount_point, partition_device
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount image {image_path}: {e}")
        return None, None

def unmount_image(mount_point):
    """Unmount the image and remove the mount point directory."""
    try:
        print(f"Attempting to unmount {mount_point}")
        subprocess.run(['umount', '-l', mount_point], check=True)  # Lazy unmount to ensure the unmount completes
    except subprocess.CalledProcessError:
        pass

    # Adding a longer delay before attempting to remove the directory
    time.sleep(10)  # 10 seconds delay to give time for unmounting

    # Retry mechanism for removing the mount point directory
    for attempt in range(20):  # Try up to 20 times
        try:
            os.rmdir(mount_point)  # Remove the empty mount point directory
            print(f"Successfully removed mount point directory {mount_point}")
            break
        except OSError as e:
            print(f"Attempt {attempt + 1}: Failed to remove mount point directory {mount_point}: {e}")
            time.sleep(5)  # Wait 5 seconds before retrying

def detach_device(device):
    """Detach the loop or nbd device."""
    try:
        if device.startswith('/dev/nbd'):
            subprocess.run(['qemu-nbd', '--disconnect', device], check=True)
        else:
            subprocess.run(['losetup', '-d', device], check=True)
    except subprocess.CalledProcessError:
        pass

def mount_partitions(raw_image_path, partition_mount_base):
    """Mount all partitions of the raw image to separate mount points."""
    try:
        # Setup loop device
        loop_device = subprocess.check_output(['losetup', '--show', '-fP', raw_image_path]).strip().decode('utf-8')
        
        # Identify the available partitions
        partitions = subprocess.check_output(['lsblk', '-no', 'NAME', loop_device]).decode('utf-8').split()
        partitions = [f"/dev/{part.strip()}" for part in partitions if part.strip().startswith(loop_device.split('/')[-1])]

        mounted_partitions = []

        for index, partition in enumerate(partitions):
            mount_point = f"{partition_mount_base}_{index}"
            if not os.path.exists(mount_point):
                os.makedirs(mount_point)

            # Mount the partition as read-only
            subprocess.run(['mount', '-o', 'ro', partition, mount_point], check=True)
            print(f"Partition mounted at {mount_point}")
            mounted_partitions.append(mount_point)

        return mounted_partitions, loop_device
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount partitions from {raw_image_path}: {e}")
        return [], None

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hash files in raw disk images for DFIR analysis. The script mounts .E01 images, "
                    "and other image formats (.vmdk, .vhd, .vhdx, .raw, .dd), calculates MD5, SHA1, and SHA256 hashes for each file in the mounted file systems, "
                    "and saves the results in a JSON file."
    )
    parser.add_argument('--image-dir', '-d', required=True, help="Directory containing the image files (.E01, .vmdk, .vhd, .vhdx, .raw, .dd).")
    parser.add_argument('--output-dir', '-o', required=True, help="Directory where the JSON output files will be saved.")
    return parser.parse_args()

if __name__ == "__main__":
    # Setup readline for tab completion and command history
    setup_readline()

    # Parse command-line arguments
    args = parse_arguments()

    # Set up logging
    log_file = "file_processing.log"
    setup_logging(log_file)

    # Ensure the output directory exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    # Define mount points
    xmount_point = "/mnt/ewf"
    partition_mount_base = "/mnt/partition"

    # Discover all image files in the specified directory
    supported_extensions = ('.E01', '.vmdk', '.vhd', '.vhdx', '.raw', '.dd')
    image_files = [os.path.join(args.image_dir, f) for f in os.listdir(args.image_dir) if f.endswith(supported_extensions)]

    if not image_files:
        print("No supported image files found in the specified directory.")
        sys.exit(1)

    # Process each discovered image
    for image_path in image_files:
        print(f"Processing image: {image_path}")
        
        # Cleanup any previous mounts or leftover directories
        cleanup_mounts([xmount_point])
        cleanup_loop_devices()

        # Determine image type and mount accordingly
        if image_path.endswith('.E01'):
            # Mount the image using xmount
            raw_image_path = mount_image_with_xmount(image_path, xmount_point)
            if raw_image_path:
                mounted_partitions, device = mount_partitions(raw_image_path, partition_mount_base)
            else:
                mounted_partitions, device = [], None
        else:
            # Mount other image types, including .dd files
            mounted_partitions, device = mount_generic_image(image_path, partition_mount_base)

        if mounted_partitions:
            try:
                # Prepare the output JSON file path
                output_json = os.path.join(args.output_dir, os.path.basename(image_path) + ".json")

                # Process each mounted partition
                for mount_point in mounted_partitions:
                    process_directory(mount_point, output_json, log_file)

                # Convert the JSON file to JSONL format for Timesketch
                output_jsonl = os.path.join(args.output_dir, os.path.basename(image_path) + ".jsonl")
                convert_json_to_jsonl(output_json, output_jsonl)

            finally:
                # Unmount all partitions and detach device
                for mount_point in mounted_partitions:
                    unmount_image(mount_point)
                if device:
                    detach_device(device)
        else:
            print(f"Failed to process image: {image_path}")

    # Final cleanup of loop devices in case of issues
    cleanup_loop_devices()
