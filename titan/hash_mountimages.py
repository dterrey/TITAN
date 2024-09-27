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
import subprocess
import time
import shutil

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

def mount_image_with_xmount(image_path, xmount_point):
    """Mount the E01 image to a mount point using xmount and return the path to the raw image."""
    try:
        if not os.path.exists(xmount_point):
            os.makedirs(xmount_point)
        subprocess.run(['xmount', '--in', 'ewf', '--out', 'raw', image_path, xmount_point], check=True)
        print(f"Image mounted at {xmount_point}")
        
        raw_image = None
        for file in os.listdir(xmount_point):
            raw_image = os.path.join(xmount_point, file)
            break
        return raw_image

    except subprocess.CalledProcessError:
        return None

def mount_dd_image(image_path, partition_mount_base):
    """Mount partitions from a dd image using losetup."""
    try:
        # Setup loop device
        loop_device = subprocess.check_output(['losetup', '--show', '-fP', image_path]).strip().decode('utf-8')
        print(f"Loop device created: {loop_device}")
        
        # List partitions using `lsblk`
        partitions = subprocess.check_output(['lsblk', '-no', 'NAME', loop_device]).decode('utf-8').split()
        partitions = [f"/dev/{part.strip()}" for part in partitions if part.strip().startswith(loop_device.split('/')[-1])]

        mounted_partitions = []

        for index, partition in enumerate(partitions):
            mount_point = f"{partition_mount_base}_{index}"
            if not os.path.exists(mount_point):
                os.makedirs(mount_point)

            # Mount the partition as read-only
            subprocess.run(['mount', '-o', 'ro', partition, mount_point], check=True)
            print(f"Partition {partition} mounted at {mount_point}")
            mounted_partitions.append(mount_point)

        return mounted_partitions, loop_device
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount dd image {image_path}: {e}")
        return [], None

def parse_arguments():
    """Parse command-line arguments."""
    import argparse
    parser = argparse.ArgumentParser(
        description="Mount .E01 and .dd images and their partitions."
    )
    parser.add_argument('--image-dir', '-d', required=True, help="Directory containing the image files (.E01, .dd).")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    # Define mount points
    xmount_point = "/mnt/ewf"
    partition_mount_base = "/mnt/partition"

    # Cleanup previous mounts and loop devices
    cleanup_mounts([xmount_point, partition_mount_base])
    cleanup_loop_devices()

    # Find all image files
    image_files = [os.path.join(args.image_dir, f) for f in os.listdir(args.image_dir) if f.endswith(('.E01', '.dd'))]

    if not image_files:
        print("No supported image files found.")
    else:
        for image_path in image_files:
            if image_path.endswith('.E01'):
                raw_image_path = mount_image_with_xmount(image_path, xmount_point)
                if raw_image_path:
                    mount_dd_image(raw_image_path, partition_mount_base)
                else:
                    print(f"Failed to mount E01 image: {image_path}")
            elif image_path.endswith('.dd'):
                mount_dd_image(image_path, partition_mount_base)

