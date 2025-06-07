import argparse
import pandas as pd
import subprocess
import glob
import os

def upload_to_timesketch(username, password, endpoint, sketch_id, file_path):
    # Construct the dftimewolf command
    command = f"dftimewolf upload_ts --timesketch_username {username} --timesketch_password {password} --timesketch_endpoint {endpoint} --sketch_id {sketch_id} {file_path}"
    
    # Execute the command
    subprocess.run(command, shell=True)

def main():
    parser = argparse.ArgumentParser(description="Script to execute dftimewolf upload_ts command and process parameters.")

    parser.add_argument("--timesketch_username", default="dfir", help="Timesketch username")
    parser.add_argument("--timesketch_password", default="admin", help="Timesketch password")
    parser.add_argument("--timesketch_endpoint", default="http://127.0.0.1", help="Timesketch endpoint")
    parser.add_argument("--sketch_id", default="1", help="Sketch ID")

    args = parser.parse_args()

    # Specify the folders to scan for PLASO files
    plaso_folder_path = '/cases/plaso'

    # Use glob to find all PLASO files in the folder
    plaso_files = glob.glob(f"{plaso_folder_path}/*.plaso")

    if not plaso_files:
        print(f"No PLASO files found in {plaso_folder_path}")
        return
       # Create a file to store processed file names
    processed_file_path = '/opt/dftimewolf/processed_files.txt'

    # Read existing processed file names
    processed_files = set()
    if os.path.exists(processed_file_path):
        with open(processed_file_path, 'r') as f:
            processed_files = set(f.read().splitlines())

    for plaso_file_path in plaso_files:
        # Check if the file has already been processed
        if plaso_file_path in processed_files:
            print(f"Skipping already processed file: {plaso_file_path}")
            continue

        try:
            # Execute dftimewolf upload_ts command for each CSV file
            upload_to_timesketch(args.timesketch_username, args.timesketch_password, args.timesketch_endpoint, args.sketch_id, plaso_file_path)

            # Read the PLASO file using pandas
            df = pd.read_csv(plaso_file_path)

            # Perform any additional processing or analysis here

            # Print a sample of the DataFrame
            print(f"Sample of the DataFrame in {plaso_file_path}:")
            print(df.head())

            # Update the set of processed files
            processed_files.add(plaso_file_path)

            # You can use the args values in your Timesketch integration
            print(f"Timesketch Username: {args.timesketch_username}")
            print(f"Timesketch Password: {args.timesketch_password}")
            print(f"Timesketch Endpoint: {args.timesketch_endpoint}")
            print(f"Sketch ID: {args.sketch_id}")

        except FileNotFoundError:
            print(f"Error: File '{plaso_file_path}' not found.")

    # Write the updated set of processed files to the file
    with open(processed_file_path, 'w') as f:
        f.write('\n'.join(processed_files))

if __name__ == "__main__":
    main()
