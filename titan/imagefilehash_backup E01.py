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
This script is designed for use in Digital Forensics and Incident Response (DFIR) workflows, particularly for hashing all files within multiple raw disk images (e.g., .E01 format). The script mounts each raw image, processes each file within the mounted file system, and calculates three different cryptographic hash values (MD5, SHA1, and SHA256) for each file. The results are then saved to a JSON file. 

The generated JSON file can be used with forensic tools like ADAM (Automated Disk and Artifact Management) to search for Indicators of Compromise (IOCs) across the disk images.

How It Works:
1. **Mounting the Images**: 
   - The script begins by mounting each raw disk image (in .E01 format) using the `xmount` tool. This converts the .E01 image into a raw image format that can be accessed like a physical disk.
   - It then identifies all the partitions within each raw image using loopback devices, and mounts each partition read-only to a specified directory.

2. **Processing Files**:
   - The script recursively traverses the mounted file systems, processing each file by calculating its cryptographic hashes (MD5, SHA1, SHA256).
   - Files that do not have an extension are skipped, as they may cause the script to freeze.

3. **Handling Exceptions**:
   - The script is robust against common issues such as files that cannot be read due to permission errors or other I/O errors. These are logged, and the script continues processing other files.

4. **Output**:
   - The hashes for each processed file, along with its path and size, are written to a JSON file. This JSON file can then be utilized with tools like ADAM for searching known IOCs or other forensic analysis.

5. **Cleanup**:
   - After processing, the script ensures that all loop devices are detached and mount points are unmounted. This prevents the accumulation of loop devices, which could interfere with future forensic operations.

Usage:
- This script is typically used in a DFIR context when an investigator needs to process multiple raw disk images to extract hash values for all files. 
- The resulting JSON file can be loaded into ADAM to search for IOCs, helping to identify malicious files or artifacts across the disk images.

Prerequisites:
- The system running this script must have the necessary tools installed (`xmount`, `losetup`, `mount`, etc.).
- Ensure that the script is run with sufficient privileges to mount file systems and access all files within the disk images.

Example Command:
    $ sudo python3 imagefilehash.py --images "/path/to/image1.E01" "/path/to/image2.E01" --output "/path/to/output.json"

This will process each image and output the results to the specified JSON file.

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

def setup_readline():
    """Configure readline for tab completion and command history."""
    readline.parse_and_bind("tab: complete")
    
    # Enable command history
    histfile = os.path.join(os.path.expanduser("~"), ".python_history")
    try:
        readline.read_history_file(histfile)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
    atexit.register(readline.write_history_file, histfile)

    # Enable tab completion for file paths
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
            except Exception:
                pass

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
    hashes_dict = {}

    with open(output_json, 'w') as json_file:
        json_file.write('{\n')
        first_entry = True
        
        for root, dirs, files in os.walk(directory):
            for file_name in files:
                file_path = os.path.join(root, file_name)

                # Skip files without extensions
                if not os.path.splitext(file_name)[1]:
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
    
    print("\nProcessing complete.")

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
    except subprocess.CalledProcessError:
        return [], None

def unmount_image(mount_point):
    """Unmount the image and remove the mount point."""
    try:
        subprocess.run(['umount', mount_point], check=True)
        shutil.rmtree(mount_point)
    except subprocess.CalledProcessError:
        pass

def detach_loop_device(loop_device):
    """Detach the loop device."""
    try:
        subprocess.run(['losetup', '-d', loop_device], check=True)
    except subprocess.CalledProcessError:
        pass

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hash files in raw disk images for DFIR analysis. The script mounts .E01 images, "
                    "calculates MD5, SHA1, and SHA256 hashes for each file in the mounted file systems, "
                    "and saves the results in a JSON file."
    )
    parser.add_argument('--images', '-i', nargs='+', required=True, help="Paths to the .E01 image files.")
    parser.add_argument('--output', '-o', required=True, help="Path for the output JSON file.")
    return parser.parse_args()

if __name__ == "__main__":
    # Setup readline for tab completion and command history
    setup_readline()

    # Parse command-line arguments
    args = parse_arguments()

    # Set up logging
    log_file = "file_processing.log"
    setup_logging(log_file)

    # Define mount points
    xmount_point = "/mnt/ewf"
    partition_mount_base = "/mnt/partition"

    # Process each .E01 image provided
    for image_path in args.images:
        print(f"Processing image: {image_path}")
        
        # Cleanup any previous mounts or leftover directories
        cleanup_mounts([xmount_point])
        cleanup_loop_devices()

        # Mount the image using xmount
        raw_image_path = mount_image_with_xmount(image_path, xmount_point)

        if raw_image_path:
            # Mount all partitions of the raw image
            mounted_partitions, loop_device = mount_partitions(raw_image_path, partition_mount_base)

            if mounted_partitions:
                try:
                    # Process each mounted partition
                    for partition_mount_point in mounted_partitions:
                        process_directory(partition_mount_point, args.output, log_file)
                finally:
                    # Unmount all partitions and detach the loop device
                    for partition_mount_point in mounted_partitions:
                        unmount_image(partition_mount_point)
                    detach_loop_device(loop_device)

            # Unmount the xmount image
            unmount_image(xmount_point)
        else:
            print(f"Failed to mount image: {image_path}")

    # Final cleanup of loop devices in case of issues
    cleanup_loop_devices()
