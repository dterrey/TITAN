#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# TITAN (Threat Investigation and Tactical Analysis Network)
# hash_mountimages.py: Mounts E01 or DD images and their partitions.
# For E01: uses ewfexport to create a temporary raw DD, then losetup.
# For DD: uses losetup directly.
# -----------------------------------------------------------------------------
import os
import subprocess
import time
import shutil
import argparse
import logging
import tempfile

# Setup basic logging for the script itself
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("hash_mountimages")

# Define a base for temporary files created by this script
TEMP_PROCESSING_BASE_DIR = os.path.join(tempfile.gettempdir(), "titan_mount_processing")
os.makedirs(TEMP_PROCESSING_BASE_DIR, exist_ok=True)


def run_command(command_list, check=True, capture_output=True, shell=False, timeout=None, cwd=None):
    """Helper function to run a subprocess command and log its output."""
    cmd_str = ' '.join(command_list) if isinstance(command_list, list) else command_list
    logger.info(f"Executing command: {cmd_str}")
    try:
        result = subprocess.run(
            command_list,
            check=check,
            capture_output=capture_output,
            text=True,
            shell=shell,
            timeout=timeout,
            cwd=cwd
        )
        if result.stdout and result.stdout.strip():
            logger.info(f"STDOUT:\n{result.stdout.strip()}")
        if result.stderr and result.stderr.strip():
            log_level = logging.ERROR if check and result.returncode != 0 else logging.INFO
            logger.log(log_level, f"STDERR:\n{result.stderr.strip()}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd_str}")
        if e.stdout: logger.error(f"STDOUT:\n{e.stdout.strip()}")
        if e.stderr: logger.error(f"STDERR:\n{e.stderr.strip()}")
        raise
    except FileNotFoundError as e:
        logger.error(f"Command not found: {command_list[0] if isinstance(command_list, list) else command_list}. Error: {e}")
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out: {cmd_str}")
        if e.stdout: logger.error(f"STDOUT: {e.stdout.decode(errors='ignore').strip()}")
        if e.stderr: logger.error(f"STDERR: {e.stderr.decode(errors='ignore').strip()}")
        raise


def export_ewf_to_raw(image_path, temp_raw_output_base_dir):
    """
    Exports an EWF (.E01) image to a raw .dd file using ewfexport.
    Returns the path to the created raw .dd file.
    """
    image_filename_no_ext = os.path.splitext(os.path.basename(image_path))[0]
    # Create a unique name for the temporary raw file
    temp_raw_dd_file = os.path.join(temp_raw_output_base_dir, f"{image_filename_no_ext}_{int(time.time())}.dd")

    os.makedirs(os.path.dirname(temp_raw_dd_file), exist_ok=True)
    
    # ewfexport -t <target_dd_file> <source_e01_file>
    ewfexport_cmd = ['ewfexport', '-t', temp_raw_dd_file, image_path]
    logger.info(f"Attempting to export EWF image: {image_path} to raw DD: {temp_raw_dd_file}")
    run_command(ewfexport_cmd, timeout=7200) # Allow up to 2 hours for export

    if not os.path.isfile(temp_raw_dd_file):
        raise FileNotFoundError(f"Exported raw DD file '{temp_raw_dd_file}' not found after ewfexport.")
            
    logger.info(f"EWF image successfully exported to: {temp_raw_dd_file}")
    return temp_raw_dd_file


def mount_raw_image_partitions(raw_image_path, final_partition_base_dir, image_basename_for_subdir):
    """
    Sets up a loop device for the raw image, probes for partitions, and mounts them.
    Returns a list of actual partition mount points and the loop device path.
    """
    loop_device_path = ""
    mounted_partition_paths = []

    try:
        logger.info(f"Setting up loop device for raw image: {raw_image_path}")
        result = run_command(['losetup', '--show', '-fP', raw_image_path])
        loop_device_path = result.stdout.strip()
        if not loop_device_path or not os.path.exists(loop_device_path):
            raise Exception(f"losetup -fP --show did not return a valid device path for {raw_image_path}. Output: '{loop_device_path}'")
        logger.info(f"Loop device created: {loop_device_path}")

        logger.info(f"Probing partitions on {loop_device_path} with partprobe")
        run_command(['partprobe', loop_device_path], timeout=60)
        time.sleep(3) 

        image_specific_mount_subdir = os.path.join(final_partition_base_dir, image_basename_for_subdir + "_partitions")
        os.makedirs(image_specific_mount_subdir, exist_ok=True)
        
        partitions_found_and_attempted_to_mount = False
        for i in range(1, 16): 
            partition_device_node = f"{loop_device_path}p{i}"
            if os.path.exists(partition_device_node):
                partitions_found_and_attempted_to_mount = True
                mount_point = os.path.join(image_specific_mount_subdir, f"p{i}")
                logger.info(f"Attempting to mount partition {partition_device_node} to {mount_point}")
                os.makedirs(mount_point, exist_ok=True)
                try:
                    run_command(['mount', '-o', 'ro,noload', partition_device_node, mount_point], timeout=60)
                    logger.info(f"Successfully mounted {partition_device_node} at {mount_point}")
                    mounted_partition_paths.append(mount_point)
                except subprocess.CalledProcessError as mount_error:
                    logger.warning(f"Could not mount partition {partition_device_node}. Stderr: {mount_error.stderr}")
            else:
                if i > 0 and partitions_found_and_attempted_to_mount: break
                if i == 1 and not partitions_found_and_attempted_to_mount: break
        
        if not mounted_partition_paths and os.path.exists(loop_device_path):
            mount_point = os.path.join(image_specific_mount_subdir, "p0_full_disk")
            logger.info(f"No pX partitions found/mounted. Attempting to mount main loop device {loop_device_path} to {mount_point}")
            os.makedirs(mount_point, exist_ok=True)
            try:
                run_command(['mount', '-o', 'ro,noload', loop_device_path, mount_point], timeout=60)
                logger.info(f"Successfully mounted main loop device {loop_device_path} at {mount_point}")
                mounted_partition_paths.append(mount_point)
            except subprocess.CalledProcessError as mount_error:
                logger.warning(f"Could not mount main loop device {loop_device_path}. Stderr: {mount_error.stderr}")

        if not mounted_partition_paths:
            logger.warning(f"No partitions or main filesystem mounted from {raw_image_path} (loop device {loop_device_path}).")

        return mounted_partition_paths, loop_device_path

    except Exception as e:
        logger.error(f"Error in mount_raw_image_partitions for '{raw_image_path}': {str(e)}")
        if loop_device_path and os.path.exists(loop_device_path):
            try:
                logger.info(f"Error cleanup: Detaching loop {loop_device_path}")
                run_command(['losetup', '-d', loop_device_path], check=False)
            except Exception as cleanup_e:
                logger.warning(f"Failed to detach loop {loop_device_path} during error cleanup: {cleanup_e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="Mount E01 or raw DD images and their partitions.")
    parser.add_argument('--image-file', '-i', required=True, help="Path to the .E01 or .dd image file.")
    parser.add_argument('--mount-output-base', '-m', default="/cases/mounted", 
                        help="Base directory for final partition mount subdirectories.")
    # Temporary directory for the exported raw .dd from E01
    parser.add_argument('--temp-dd-output-base', '-d', default=TEMP_PROCESSING_BASE_DIR,
                        help="Temporary base directory for ewfexport to write raw DD file (if E01).")
    args = parser.parse_args()

    image_path_abs = os.path.abspath(args.image_file)
    mount_output_base_abs = os.path.abspath(args.mount_output_base)
    temp_dd_output_base_abs = os.path.abspath(args.temp_dd_output_base)
    
    image_basename_no_ext = os.path.splitext(os.path.basename(image_path_abs))[0]

    os.makedirs(mount_output_base_abs, exist_ok=True)
    os.makedirs(temp_dd_output_base_abs, exist_ok=True)

    exported_dd_file_path = None # Path to the dd file created by ewfexport
    loop_device_created = None
    all_final_partition_mounts = []

    try:
        if not os.path.isfile(image_path_abs):
            raise FileNotFoundError(f"Input image file not found: {image_path_abs}")

        raw_image_stream_to_process = image_path_abs
        
        if image_path_abs.lower().endswith('.e01'):
            logger.info("E01 image detected. Using ewfexport to convert to raw DD first...")
            exported_dd_file_path = export_ewf_to_raw(image_path_abs, temp_dd_output_base_abs)
            if not exported_dd_file_path:
                raise Exception("ewfexport failed to create raw DD from E01.")
            raw_image_stream_to_process = exported_dd_file_path # Process this DD file
        elif not (image_path_abs.lower().endswith(('.dd', '.raw', '.img'))):
             logger.warning(f"File {image_path_abs} extension is not .dd, .raw, .img, or .E01. Attempting as raw.")
        
        logger.info(f"Processing raw image stream: {raw_image_stream_to_process} for partitions.")
        
        all_final_partition_mounts, loop_device_created = mount_raw_image_partitions(
            raw_image_stream_to_process, 
            mount_output_base_abs,
            image_basename_no_ext
        )

        if all_final_partition_mounts:
            logger.info("Script completed. Successfully mounted partitions are:")
            for mp in all_final_partition_mounts:
                print(mp) 
        else:
            logger.warning("Script completed, but no partitions were mounted.")
            print("No partitions mounted.")

    except Exception as e:
        logger.error(f"Critical error in main processing for {image_path_abs}: {str(e)}")
        logger.exception("Traceback for main error:")
        # Cleanup on error
        if all_final_partition_mounts: # Unmount partitions first
            for mp_path in reversed(all_final_partition_mounts):
                 if os.path.ismount(mp_path):
                    try: run_command(['umount', '-l', mp_path], check=False)
                    except: logger.warning(f"Failed to unmount partition {mp_path} during error cleanup.")
        if loop_device_created and os.path.exists(loop_device_created):
            try: run_command(['losetup', '-d', loop_device_created], check=False)
            except: logger.warning(f"Failed to detach loop device {loop_device_created} during error cleanup.")
        if exported_dd_file_path and os.path.exists(exported_dd_file_path): # Delete temporary DD
            try: 
                logger.info(f"Error cleanup: Deleting temporary DD file {exported_dd_file_path}")
                os.remove(exported_dd_file_path)
            except: logger.warning(f"Failed to delete temporary DD file {exported_dd_file_path} during error cleanup.")
        exit(1)
    finally:
        # This script doesn't clean up the *temporary exported DD file* on SUCCESS by default.
        # The `hash_unmountimages.py` script will need to handle deleting this temporary DD
        # file if it exists, in addition to unmounting partitions and detaching loop devices.
        # To do this, the path to `exported_dd_file_path` would need to be passed back by the API.
        # For now, this script focuses on mounting.
        pass


if __name__ == "__main__":
    main()