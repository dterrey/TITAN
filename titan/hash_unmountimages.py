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

def unmount_image(mount_point):
    """Unmount the image and remove the mount point directory."""
    try:
        if os.path.ismount(mount_point):
            print(f"Attempting to unmount {mount_point}")
            subprocess.run(['umount', '-l', mount_point], check=True)
            time.sleep(2)  # Give the system a moment to finish unmounting

        # Check if unmounted successfully
        if not os.path.ismount(mount_point):
            print(f"Successfully unmounted {mount_point}")
        else:
            print(f"Failed to unmount {mount_point}")
    except subprocess.CalledProcessError as e:
        print(f"Error while unmounting {mount_point}: {e}")

    # Try to remove the directory if it exists
    for attempt in range(5):
        try:
            if os.path.exists(mount_point):
                os.rmdir(mount_point)
                print(f"Successfully removed mount point directory {mount_point}")
            break
        except OSError as e:
            print(f"Attempt {attempt + 1}: Failed to remove {mount_point}: {e}")
            time.sleep(2)

def detach_device(device):
    """Detach the loop or nbd device."""
    try:
        if device.startswith('/dev/nbd'):
            subprocess.run(['qemu-nbd', '--disconnect', device], check=True)
        else:
            subprocess.run(['losetup', '-d', device], check=True)
        print(f"Detached device: {device}")
    except subprocess.CalledProcessError as e:
        print(f"Error detaching device {device}: {e}")

def cleanup_loop_devices():
    """Detach any leftover loop devices."""
    try:
        loop_devices = subprocess.check_output(['losetup', '-a']).decode().strip().split('\n')
        for device in loop_devices:
            loop_device = device.split(':')[0]
            detach_device(loop_device)
    except subprocess.CalledProcessError as e:
        print(f"Error listing loop devices: {e}")

def cleanup_mounts_and_devices():
    """Unmount /mnt/ewf and up to 10 partitions, then clean up associated devices."""
    # Define the mount points to check
    mount_points = ["/mnt/ewf"] + [f"/mnt/partition_{i}" for i in range(10)]

    # Unmount and clean up all found mount points
    for mount_point in mount_points:
        if os.path.exists(mount_point):
            unmount_image(mount_point)

    # Cleanup any loop devices
    cleanup_loop_devices()

if __name__ == "__main__":
    # Automatically clean up /mnt/ewf and partitions
    cleanup_mounts_and_devices()

