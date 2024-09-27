#!/bin/bash

# Path to your E01 image
IMAGE_PATH="/path/to/your/image.E01"

# Create mount point directories
MOUNT_POINT_BASE="/mnt/ewf"
sudo mkdir -p $MOUNT_POINT_BASE

# Identify partitions using mmls
PARTITIONS=$(mmls $IMAGE_PATH | awk '/^ [0-9]/ {print $2, $3, $6}')

# Function to mount a partition
mount_partition() {
  local start_sector=$1
  local mount_point=$2
  local offset=$((start_sector * 512))
  sudo mkdir -p $mount_point
  sudo mount -o ro,loop,offset=$offset $IMAGE_PATH $mount_point
}

# Loop through partitions and mount them
while read -r start end desc; do
  if [[ $desc == "NTFS" || $desc == "exFAT" ]]; then
    mount_point="$MOUNT_POINT_BASE/$start"
    mount_partition $start $mount_point
  fi
done <<< "$PARTITIONS"

# Create output directory
OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

# Hash all files and check for malware
HASH_FILE="$OUTPUT_DIR/file_hashes.txt"
YARA_OUTPUT_FILE="$OUTPUT_DIR/yara_results.txt"
YARA_RULES_PATH="/path/to/yara/rules"  # Replace with the path to your Yara rules

# Hash all files in mounted directories
for mount_point in $MOUNT_POINT_BASE/*; do
  if [ -d "$mount_point" ]; then
    hashdeep -rl $mount_point >> $HASH_FILE
  fi
done

# Run Yara against the mounted directories
for mount_point in $MOUNT_POINT_BASE/*; do
  if [ -d "$mount_point" ]; then
    yara -r $YARA_RULES_PATH $mount_point >> $YARA_OUTPUT_FILE
  fi
done

echo "Hashing and malware check completed. Results are saved in the output directory."
