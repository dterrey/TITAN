import os
import subprocess
from flask import Flask, request, jsonify
import shlex  # For safely handling command line arguments
import logging # For better logging
import tempfile

# --- Folder setup ---
WATCH_FOLDER = "/cases/processor"
PLASO_FOLDER = "/cases/plaso"
LOGS_FOLDER = "/cases/logs"  # General logs for the processor itself
ZIRCOLITE_FOLDER = "/cases/zircolite"
# Add any other top-level folders under /cases your workflow might need
#
#  Define a base for temporary files created by image mounting scripts
TEMP_PROCESSING_BASE_DIR = os.path.join(tempfile.gettempdir(), "titan_mount_processing") # Define it here

# Ensure this base temporary directory also exists
os.makedirs(TEMP_PROCESSING_BASE_DIR, exist_ok=True) # Add this line

# Your existing loop for creating other directories
for folder in [
    '/cases', WATCH_FOLDER, f"{WATCH_FOLDER}/hashes", f"{WATCH_FOLDER}/logfile",
    PLASO_FOLDER, LOGS_FOLDER, ZIRCOLITE_FOLDER, '/cases/evtxproc',
    # You might also want to ensure /cases/mounted is created if mount_output_base defaults to it
    '/cases/mounted' 
]:
    os.makedirs(folder, exist_ok=True)

# --- Flask App ---
app = Flask(__name__)

# Configure Flask logging
if __name__ != '__main__': # When run by a production WSGI server like Gunicorn
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
else: # For direct `python processor.py` execution
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


@app.route('/run_filehash', methods=['POST'])
def handle_run_filehash():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (FileHash): Invalid or missing JSON payload")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    output_dir_for_hashes = data.get('output_dir', '/cases/processor/hashes') 
    output_base_name = data.get('output_base_name') # This is provided by Node-RED

    if not output_base_name: 
        app.logger.error(f"API Error (FileHash): Missing 'output_base_name' parameter.")
        return jsonify({"status": "error", "message": "Missing output_base_name parameter"}), 400

    abs_output_dir = os.path.abspath(output_dir_for_hashes)

    if not abs_output_dir.startswith('/cases/'):
        app.logger.error(f"API Error (FileHash): OutputDir must be within /cases/. Got OutputDir='{abs_output_dir}'")
        return jsonify({"status": "error", "message": "Output directory must be within /cases/"}), 400
    
    try:
        os.makedirs(abs_output_dir, exist_ok=True)
    except Exception as e:
        app.logger.error(f"API Error (FileHash): Could not create output directory '{abs_output_dir}': {str(e)}")
        return jsonify({"status": "error", "message": f"Could not create output directory: {str(e)}"}), 500

    script_path = "/hash_filehash.py" # Assumes it's at the root of the container

    cmd_list = [
        "python3",
        script_path,
        "-o", abs_output_dir,      # Output directory for hash files
        "-b", output_base_name     # Base name for the output .jsonl file
    ]

    job_log_file = os.path.join(LOGS_FOLDER, f"{output_base_name}_filehash.log")
    app.logger.info(f"[*] Executing file hash command list: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for hashing, adjust as needed
            )
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")
        
        # hash_filehash.py creates a file named <output_base_name>.jsonl in abs_output_dir
        assumed_hash_output_file = os.path.join(abs_output_dir, f"{output_base_name}.jsonl")
        
        if process_result.returncode == 0:
            app.logger.info(f"[✓] File hash script successful. Output in: {abs_output_dir}, assumed file: {assumed_hash_output_file}")
            return jsonify({
                "status": "success",
                "message": "File hash script executed successfully.",
                "output_directory": abs_output_dir,
                "assumed_hash_file": assumed_hash_output_file if os.path.exists(assumed_hash_output_file) else f"Output file '{assumed_hash_output_file}' not found, check script's naming or execution.",
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] File hash script failed. Output base name: '{output_base_name}'. RC: {process_result.returncode}")
            app.logger.error(f"    STDOUT: {process_result.stdout}")
            app.logger.error(f"    STDERR: {process_result.stderr}")
            return jsonify({
                "status": "error",
                "message": "File hash script failed.",
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr,
                "return_code": process_result.returncode
            }), 500

    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] File hash script timed out for output base name: '{output_base_name}'.")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write("\n--- PROCESSING ERROR ---\nFile hash script timed out.")
        return jsonify({"status": "error", "message": "File hash script timed out", "log_file": job_log_file}), 500
    except FileNotFoundError:
        app.logger.error(f"[!] FileNotFoundError: Script '{script_path}' or 'python3' not found.")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- FILE NOT FOUND ERROR ---\nScript '{script_path}' or 'python3' not found.")
        return jsonify({"status": "error", "message": f"Script '{script_path}' or python3 not found", "log_file": job_log_file}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during file hash for output base name '{output_base_name}': {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- PYTHON EXCEPTION ---\n{type(e).__name__}: {str(e)}\nCheck TITAN_Processor logs for full traceback.")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during file hash: {str(e)}", "log_file": job_log_file}), 500

@app.route('/run_hayabusa', methods=['POST'])
def handle_run_hayabusa():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (Hayabusa): Invalid or missing JSON payload")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    evtx_dir_path = data.get('evtx_dir_path') # e.g., /cases/processor/myimage_extracted/C/Windows/System32/winevt/Logs/
    output_csv_path = data.get('output_csv_path') # e.g., /cases/evtxproc/myimage-hayabusa.csv
    # You can also pass other Hayabusa specific options if needed
    # For example, profile, rules path, etc. For now, we'll use a common set.

    if not evtx_dir_path or not output_csv_path:
        app.logger.error(f"API Error (Hayabusa): Missing 'evtx_dir_path' or 'output_csv_path'.")
        return jsonify({"status": "error", "message": "Missing evtx_dir_path or output_csv_path"}), 400

    # Validate paths
    abs_evtx_dir_path = os.path.abspath(evtx_dir_path)
    abs_output_csv_path = os.path.abspath(output_csv_path)

    if not (abs_evtx_dir_path.startswith('/cases/') and abs_output_csv_path.startswith('/cases/')):
        app.logger.error(f"API Error (Hayabusa): All paths must be within /cases/.")
        return jsonify({"status": "error", "message": "EVTX directory and output CSV paths must be within /cases/"}), 400
    
    if not os.path.isdir(abs_evtx_dir_path):
        app.logger.error(f"API Error (Hayabusa): EVTX directory '{abs_evtx_dir_path}' does not exist or is not a directory.")
        return jsonify({"status": "error", "message": f"EVTX directory {abs_evtx_dir_path} does not exist"}), 404

    try:
        os.makedirs(os.path.dirname(abs_output_csv_path), exist_ok=True)
    except Exception as e:
        app.logger.error(f"API Error (Hayabusa): Could not create output directory for '{abs_output_csv_path}': {str(e)}")
        return jsonify({"status": "error", "message": f"Could not create output directory: {str(e)}"}), 500

    hayabusa_executable = "/opt/hayabusa/hayabusa" # Path you confirmed
    # Hayabusa v2 command structure for CSV timeline from a directory:
    # hayabusa.exe csv-timeline -d <directory> -o <output.csv> [options]
    # Options used in your Node-RED flow: --RFC-3339 -p timesketch-verbose -U --no-wizard
    cmd_list = [
        hayabusa_executable,
        "csv-timeline",
        "-d", abs_evtx_dir_path,
        "-o", abs_output_csv_path,
        "--RFC-3339",
        "-p", "timesketch-verbose", # Profile for Timesketch friendly output
        "-U",                     # Update event common knowledge YAML
        "--no-wizard"             # Disable interactive wizard
        # Add other options here if needed, e.g., --rules /path/to/rules
    ]
    
    job_name_base = os.path.splitext(os.path.basename(abs_output_csv_path))[0]
    job_log_file = os.path.join(LOGS_FOLDER, f"{job_name_base}_hayabusa.log")
    app.logger.info(f"[*] Executing Hayabusa command list: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout, adjust as needed
            )
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")

        if process_result.returncode == 0:
            app.logger.info(f"[✓] Hayabusa processing successful for '{abs_evtx_dir_path}'. Output CSV: {abs_output_csv_path}")
            return jsonify({
                "status": "success",
                "message": "Hayabusa processing completed successfully.",
                "input_directory": abs_evtx_dir_path,
                "output_csv_file": abs_output_csv_path,
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] Hayabusa processing failed for '{abs_evtx_dir_path}'. RC: {process_result.returncode}")
            app.logger.error(f"    STDOUT: {process_result.stdout}")
            app.logger.error(f"    STDERR: {process_result.stderr}")
            return jsonify({
                "status": "error",
                "message": "Hayabusa processing failed.",
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr,
                "return_code": process_result.returncode
            }), 500
            
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] Hayabusa processing timed out for '{abs_evtx_dir_path}'")
        # ... (error handling) ...
        return jsonify({"status": "error", "message": "Hayabusa processing timed out"}), 500
    except FileNotFoundError:
        app.logger.error(f"[!] FileNotFoundError: Command '{hayabusa_executable}' not found.")
        # ... (error handling) ...
        return jsonify({"status": "error", "message": f"Command '{hayabusa_executable}' not found"}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during Hayabusa processing: {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        # ... (error handling) ...
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/run_chainsaw', methods=['POST'])
def handle_run_chainsaw():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (Chainsaw): Invalid or missing JSON payload")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    evtx_dir_path = data.get('evtx_dir_path')           # e.g., /cases/processor/myimage_extracted/C/Windows/System32/winevt/Logs/
    chainsaw_output_dir = data.get('output_directory')  # e.g., /cases/evtxproc/chainsaw/myimage-chainsaw/
                                                        # Chainsaw will create CSVs inside this directory.
    # Optional: Pass specific sigma path, mapping path, rules path if they can vary
    # sigma_rules_path = data.get('sigma_rules_path', '/opt/chainsaw/sigma/') # Default example
    # mapping_path = data.get('mapping_path', '/opt/chainsaw/mappings/sigma-event-logs-all.yml') # Default example
    # detection_rules_path = data.get('detection_rules_path', '/opt/chainsaw/rules/') # Default example


    if not evtx_dir_path or not chainsaw_output_dir:
        app.logger.error(f"API Error (Chainsaw): Missing 'evtx_dir_path' or 'output_directory'.")
        return jsonify({"status": "error", "message": "Missing evtx_dir_path or output_directory"}), 400

    abs_evtx_dir_path = os.path.abspath(evtx_dir_path)
    abs_chainsaw_output_dir = os.path.abspath(chainsaw_output_dir)

    if not (abs_evtx_dir_path.startswith('/cases/') and abs_chainsaw_output_dir.startswith('/cases/')):
        app.logger.error(f"API Error (Chainsaw): All paths must be within /cases/.")
        return jsonify({"status": "error", "message": "EVTX input and CSV output paths must be within /cases/"}), 400
    
    if not os.path.isdir(abs_evtx_dir_path):
        app.logger.error(f"API Error (Chainsaw): EVTX directory '{abs_evtx_dir_path}' does not exist or is not a directory.")
        return jsonify({"status": "error", "message": f"EVTX directory {abs_evtx_dir_path} does not exist"}), 404

    try:
        os.makedirs(abs_chainsaw_output_dir, exist_ok=True) # Chainsaw needs this directory to exist
    except Exception as e:
        app.logger.error(f"API Error (Chainsaw): Could not create output directory '{abs_chainsaw_output_dir}': {str(e)}")
        return jsonify({"status": "error", "message": f"Could not create output directory: {str(e)}"}), 500

    chainsaw_executable = "/opt/chainsaw/chainsaw"
    # Standard Chainsaw command: chainsaw hunt <evtx_dir> -s <sigma_rules> --mapping <mapping.yml> -r <rules_dir> --csv --output <output_dir>
    # The --quiet (-q) flag might suppress useful output for debugging; consider removing it initially.
    cmd_list = [
        chainsaw_executable,
        "hunt", # Action
        abs_evtx_dir_path,
        "-s", "/opt/chainsaw/sigma/",             # Path to Sigma rules within the container
        "--mapping", "/opt/chainsaw/mappings/sigma-event-logs-all.yml", # Path to mapping file
        "-r", "/opt/chainsaw/rules/",             # Path to Chainsaw's own detection rules
        "--csv",                                  # Output in CSV format
        "--output", abs_chainsaw_output_dir       # Directory where Chainsaw will save its CSVs
        # Add other flags as needed, e.g., --level critical, --json, etc.
    ]
    
    job_name_base = os.path.basename(abs_chainsaw_output_dir) # e.g., myimage-chainsaw
    job_log_file = os.path.join(LOGS_FOLDER, f"{job_name_base}_chainsaw.log")
    app.logger.info(f"[*] Executing Chainsaw command list: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout, adjust as needed
            )
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")

        if process_result.returncode == 0:
            # List CSV files created by Chainsaw in the output directory
            generated_csv_files = []
            if os.path.isdir(abs_chainsaw_output_dir):
                for f_name in os.listdir(abs_chainsaw_output_dir):
                    if f_name.lower().endswith('.csv'):
                        generated_csv_files.append(os.path.join(abs_chainsaw_output_dir, f_name))
            
            app.logger.info(f"[✓] Chainsaw processing successful for '{abs_evtx_dir_path}'. Output CSVs in: {abs_chainsaw_output_dir}. Files: {generated_csv_files}")
            return jsonify({
                "status": "success",
                "message": "Chainsaw processing completed successfully.",
                "input_directory": abs_evtx_dir_path,
                "output_directory_for_csvs": abs_chainsaw_output_dir,
                "generated_csv_files": generated_csv_files, # List of full paths to CSVs
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] Chainsaw processing failed for '{abs_evtx_dir_path}'. RC: {process_result.returncode}")
            # ... (error logging and response) ...
            return jsonify({
                "status": "error", "message": "Chainsaw processing failed.",
                "log_file": job_log_file, "stdout": process_result.stdout,
                "stderr": process_result.stderr, "return_code": process_result.returncode
            }), 500
            
    # ... (Add TimeoutExpired, FileNotFoundError, generic Exception handlers as in other endpoints) ...
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] Chainsaw processing timed out for '{abs_evtx_dir_path}'")
        return jsonify({"status": "error", "message": "Chainsaw processing timed out"}), 500
    except FileNotFoundError:
        app.logger.error(f"[!] FileNotFoundError: Command '{chainsaw_executable}' not found.")
        return jsonify({"status": "error", "message": f"Command '{chainsaw_executable}' not found"}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during Chainsaw processing: {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during Chainsaw processing: {str(e)}"}), 500

@app.route('/decompress_archive', methods=['POST'])
def handle_decompress_archive():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (Decompress): Invalid or missing JSON payload")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    archive_file_path = data.get('archive_file_path')
    output_directory_path = data.get('output_directory_path')
    archive_type = data.get('archive_type', '').lower() # e.g., "zip", "7z", "rar", "tar.gz", "tar.bz2"

    if not all([archive_file_path, output_directory_path, archive_type]):
        app.logger.error(f"API Error (Decompress): Missing parameters. Got archive_path='{archive_file_path}', output_dir='{output_directory_path}', type='{archive_type}'")
        return jsonify({"status": "error", "message": "Missing archive_file_path, output_directory_path, or archive_type"}), 400

    abs_archive_file_path = os.path.abspath(archive_file_path)
    abs_output_directory_path = os.path.abspath(output_directory_path)

    if not (abs_archive_file_path.startswith('/cases/') and abs_output_directory_path.startswith('/cases/')):
        app.logger.error(f"API Error (Decompress): Archive and output paths must be within /cases/.")
        return jsonify({"status": "error", "message": "Archive and output paths must be within /cases/"}), 400
    
    if not os.path.isfile(abs_archive_file_path):
        app.logger.error(f"API Error (Decompress): Archive file '{abs_archive_file_path}' not found.")
        return jsonify({"status": "error", "message": f"Archive file {abs_archive_file_path} not found"}), 404

    try:
        # Create output directory. The script now creates a *unique* output directory for each archive.
        os.makedirs(abs_output_directory_path, exist_ok=True) 
    except Exception as e:
        app.logger.error(f"API Error (Decompress): Could not create output directory '{abs_output_directory_path}': {str(e)}")
        return jsonify({"status": "error", "message": f"Could not create output directory: {str(e)}"}), 500

    cmd_list = []
    if archive_type == 'zip':
        # -o: overwrite existing files without prompting. -q: quiet mode. -d: output directory.
        cmd_list = ['unzip', '-qo', abs_archive_file_path, '-d', abs_output_directory_path]
    elif archive_type == '7z':
        # x: extract with full paths. -o: output directory (no space after -o). -y: yes to all.
        cmd_list = ['7z', 'x', abs_archive_file_path, f'-o{abs_output_directory_path}', '-y']
    elif archive_type == 'rar':
        # x: extract with full paths. -o+: overwrite existing. -y: yes to all.
        cmd_list = ['unrar', 'x', '-o+', '-y', abs_archive_file_path, abs_output_directory_path + os.path.sep] # unrar needs trailing slash for dir
    elif archive_type == 'tar.gz' or archive_type == 'tgz':
        cmd_list = ['tar', 'xzf', abs_archive_file_path, '-C', abs_output_directory_path]
    elif archive_type == 'tar.bz2' or archive_type == 'tbz2':
        cmd_list = ['tar', 'xjf', abs_archive_file_path, '-C', abs_output_directory_path]
    else:
        app.logger.error(f"API Error (Decompress): Unsupported archive_type '{archive_type}'")
        return jsonify({"status": "error", "message": f"Unsupported archive_type: {archive_type}"}), 400

    job_name_base = os.path.splitext(os.path.basename(abs_archive_file_path))[0]
    job_log_file = os.path.join(LOGS_FOLDER, f"{job_name_base}_decompress.log")
    app.logger.info(f"[*] Executing Decompression command list: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=1800) # 30 min timeout
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")

        if process_result.returncode == 0:
            app.logger.info(f"[✓] Decompression successful for '{abs_archive_file_path}' into '{abs_output_directory_path}'")
            return jsonify({
                "status": "success",
                "message": "Decompression completed successfully.",
                "archive_file": abs_archive_file_path,
                "output_directory": abs_output_directory_path, # This is key for Node-RED
                "log_file": job_log_file,
                "stdout": process_result.stdout,
                "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] Decompression failed for '{abs_archive_file_path}'. RC: {process_result.returncode}")
            return jsonify({
                "status": "error", "message": "Decompression failed.",
                "log_file": job_log_file, "stdout": process_result.stdout,
                "stderr": process_result.stderr, "return_code": process_result.returncode
            }), 500
            
    # ... (Add TimeoutExpired, FileNotFoundError for the decompressor, generic Exception handlers as in other endpoints) ...
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] Decompression timed out for '{abs_archive_file_path}'")
        return jsonify({"status": "error", "message": "Decompression timed out"}), 500
    except FileNotFoundError:
        app.logger.error(f"[!] FileNotFoundError: Command '{cmd_list[0]}' not found. Ensure decompression tools are installed in TITAN_Processor.")
        return jsonify({"status": "error", "message": f"Decompression command '{cmd_list[0]}' not found"}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during decompression of '{abs_archive_file_path}': {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during decompression: {str(e)}"}), 500


@app.route('/mount_image', methods=['POST'])
def handle_mount_image():
    data = request.get_json()
    image_file_to_mount = data.get('image_file_path') 
    mount_output_base = data.get('mount_output_base', "/cases/mounted") 
    # Now TEMP_PROCESSING_BASE_DIR is defined globally and can be used as a default
    temp_dd_base = data.get('temp_dd_output_base', TEMP_PROCESSING_BASE_DIR) 
    if not image_file_to_mount:
        app.logger.error("API Error (Mount Image): Missing 'image_file_path' parameter.")
        return jsonify({"status": "error", "message": "Missing image_file_path parameter"}), 400

    abs_image_file_path = os.path.abspath(image_file_to_mount)
    if not abs_image_file_path.startswith('/cases/'): 
        app.logger.error(f"API Error (Mount Image): Image file path must be within /cases/. Got: '{abs_image_file_path}'")
        return jsonify({"status": "error", "message": "Image file path must be within /cases/"}), 400
    if not os.path.isfile(abs_image_file_path):
        app.logger.error(f"API Error (Mount Image): Image file '{abs_image_file_path}' not found.")
        return jsonify({"status": "error", "message": f"Image file {abs_image_file_path} not found"}), 404

    script_path = "/hash_mountimages.py" 

    cmd_list = [
        "python3", 
        script_path,
        "--image-file", abs_image_file_path,
        "--mount-output-base", mount_output_base,
        "--temp-dd-output-base", temp_dd_base # Now temp_dd_base should be defined
    ]
    
    app.logger.info(f"[*] Executing mount image command list: {cmd_list}")
    job_log_file = os.path.join(LOGS_FOLDER, f"{os.path.basename(abs_image_file_path)}_mount.log")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=600 
            )
            # ... (rest of your existing try block from the previous correct version) ...
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")
        
        if process_result.returncode == 0:
            mounted_partitions = [line for line in process_result.stdout.strip().split('\n') if line.strip() and line.startswith("/")]
            app.logger.info(f"[✓] Image mount script successful for '{abs_image_file_path}'. Mounted partitions: {mounted_partitions}")
            return jsonify({
                "status": "success",
                "message": "Image mounted successfully.",
                "image_file": abs_image_file_path,
                "mounted_partitions": mounted_partitions,
                "raw_stdout": process_result.stdout,
                "raw_stderr": process_result.stderr,
                "log_file": job_log_file
            }), 200
        else:
            app.logger.error(f"[!] Image mount script failed for '{abs_image_file_path}'. RC: {process_result.returncode}")
            app.logger.error(f"    STDOUT: {process_result.stdout}")
            app.logger.error(f"    STDERR: {process_result.stderr}")
            return jsonify({
                "status": "error", 
                "message": "Image mount script failed.",
                "stdout": process_result.stdout,
                "stderr": process_result.stderr,
                "return_code": process_result.returncode,
                "log_file": job_log_file
            }), 500
            
    # ... (your existing except blocks: TimeoutExpired, FileNotFoundError, generic Exception) ...
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] Image mount script timed out for '{abs_image_file_path}'")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write("\n--- PROCESSING ERROR ---\nImage mount script timed out.")
        return jsonify({"status": "error", "message": "Image mount script timed out", "log_file": job_log_file}), 500
    except FileNotFoundError:
        app.logger.error(f"[!] FileNotFoundError: Script '{script_path}' or 'python3' not found.")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write(f"\n--- FILE NOT FOUND ERROR ---\nScript '{script_path}' or 'python3' not found.")
        return jsonify({"status": "error", "message": f"Script '{script_path}' or python3 interpreter not found", "log_file": job_log_file}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during image mount for '{abs_image_file_path}': {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write(f"\n--- PYTHON EXCEPTION ---\n{type(e).__name__}: {str(e)}\nCheck TITAN_Processor logs for full traceback.")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during image mount: {str(e)}", "log_file": job_log_file}), 500

        

@app.route('/import_to_timesketch', methods=['POST'])
def handle_timesketch_import():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (Timesketch Import): Invalid or missing JSON payload")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    plaso_file_path = data.get('plaso_file_path')
    ts_host = data.get('host', 'http://172.19.0.1:80') # Using the gateway IP for host Timesketch
    ts_user = data.get('user')
    ts_pass = data.get('password')
    timeline_name = data.get('timeline_name')
    sketch_id = data.get('sketch_id')

    if not all([plaso_file_path, ts_host, ts_user, ts_pass, timeline_name, sketch_id]):
        app.logger.error(f"API Error (Timesketch Import): Missing one or more required parameters.")
        app.logger.debug(f"Received data for TS Import: {data}")
        return jsonify({"status": "error", "message": "Missing parameters (plaso_file_path, host, user, password, timeline_name, sketch_id)"}), 400

    abs_plaso_file_path = os.path.abspath(plaso_file_path)
    if not abs_plaso_file_path.startswith('/cases/'):
        app.logger.error(f"API Error (Timesketch Import): Plaso file path must be within /cases/. Got: '{abs_plaso_file_path}'")
        return jsonify({"status": "error", "message": "Plaso file path must be within /cases/"}), 400
    
    if not os.path.isfile(abs_plaso_file_path):
        app.logger.error(f"API Error (Timesketch Import): Plaso file '{abs_plaso_file_path}' does not exist.")
        return jsonify({"status": "error", "message": f"Plaso file {abs_plaso_file_path} does not exist"}), 404

    name_only, _ = os.path.splitext(os.path.basename(abs_plaso_file_path))
    job_log_file = os.path.join(PLASO_FOLDER, f"{name_only}_timesketch_import.log")

    importer_executable = "/usr/local/bin/timesketch_importer"
    if not os.path.isfile(importer_executable):
        app.logger.warning(f"Warning: timesketch_importer not found at {importer_executable}. Trying 'timesketch_importer' via PATH.")
        importer_executable = "timesketch_importer"

    cmd_list = [
        importer_executable,
        "-u", ts_user,
        "-p", ts_pass,
        "--host", ts_host,
        "--timeline_name", str(timeline_name),
        "--sketch_id", str(sketch_id),
        abs_plaso_file_path
    ]

    app.logger.info(f"[*] Executing Timesketch import command: {' '.join(cmd_list)}")
    app.logger.info(f"[*] Exact command list for Timesketch import: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(cmd_list,capture_output=True,text=True,timeout=1800)
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")

        if process_result.returncode == 0:
            app.logger.info(f"[✓] Timesketch import successful for '{abs_plaso_file_path}' into sketch '{sketch_id}' as timeline '{timeline_name}'")
            return jsonify({
                "status": "success", "message": "Timesketch import completed successfully.",
                "plaso_file": abs_plaso_file_path, "timeline_name": timeline_name,
                "sketch_id": sketch_id, "log_file": job_log_file,
                "stdout": process_result.stdout, "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] Timesketch import failed for '{abs_plaso_file_path}'. RC: {process_result.returncode}")
            app.logger.error(f"    STDOUT: {process_result.stdout}")
            app.logger.error(f"    STDERR: {process_result.stderr}")
            return jsonify({
                "status": "error", "message": "Timesketch import failed.",
                "plaso_file": abs_plaso_file_path, "log_file": job_log_file,
                "return_code": process_result.returncode,
                "stdout": process_result.stdout, "stderr": process_result.stderr
            }), 500
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] Timesketch import timed out for '{abs_plaso_file_path}'")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write("\n--- PROCESSING ERROR ---\nTimesketch import command timed out.")
        return jsonify({"status": "error", "message": "Timesketch import timed out", "log_file": job_log_file}), 500
    except FileNotFoundError as fnf_error:
        app.logger.error(f"[!] FileNotFoundError: Command '{cmd_list[0]}' not found. Ensure timesketch_importer is installed. Error: {str(fnf_error)}")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- FILE NOT FOUND ERROR ---\nCommand '{cmd_list[0]}' not found: {str(fnf_error)}")
        return jsonify({"status": "error", "message": f"Command '{cmd_list[0]}' not found: {str(fnf_error)}", "log_file": job_log_file}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during Timesketch import for '{abs_plaso_file_path}': {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback (full exception details):")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- PYTHON EXCEPTION ---\n{type(e).__name__}: {str(e)}\nCheck TITAN_Processor logs for full traceback.")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during Timesketch import: {type(e).__name__} - {str(e)}", "log_file": job_log_file}), 500


@app.route('/run_log2timeline', methods=['POST'])
def run_log2timeline_from_nodered():
    data = request.get_json()
    if not data:
        app.logger.error("API Error (Log2Timeline): Invalid or missing JSON payload received.")
        return jsonify({"status": "error", "message": "Invalid or missing JSON payload"}), 400

    input_file_path = data.get('input_file')
    output_plaso_path = data.get('output_file')
    options_str = data.get('options_str', "--partitions all --status_view none") 

    if not input_file_path or not output_plaso_path:
        app.logger.error(f"API Error (Log2Timeline): Missing 'input_file' ('{input_file_path}') or 'output_file' ('{output_plaso_path}') parameters")
        return jsonify({"status": "error", "message": "Missing input_file or output_file parameters"}), 400

    abs_input_file_path = os.path.abspath(input_file_path)
    abs_output_plaso_path = os.path.abspath(output_plaso_path)

    if not (abs_input_file_path.startswith('/cases/') and abs_output_plaso_path.startswith('/cases/')):
        app.logger.error(f"API Error (Log2Timeline): File paths must be within /cases/. Got Input='{abs_input_file_path}', Output='{abs_output_plaso_path}'")
        return jsonify({"status": "error", "message": "File paths must be within /cases/"}), 400
    
    # For log2timeline, input can be a file (E01) or a directory (mounted partition)
    if not (os.path.isfile(abs_input_file_path) or os.path.isdir(abs_input_file_path)):
        app.logger.error(f"API Error (Log2Timeline): Input '{abs_input_file_path}' does not exist or is not a valid file/directory.")
        return jsonify({"status": "error", "message": f"Input {abs_input_file_path} does not exist or is not a valid file/directory"}), 404
    elif os.path.isdir(abs_input_file_path):
         app.logger.info(f"API Info (Log2Timeline): Input '{abs_input_file_path}' is a directory (likely a mounted partition).")


    try:
        os.makedirs(os.path.dirname(abs_output_plaso_path), exist_ok=True)
    except Exception as e:
        app.logger.error(f"API Error (Log2Timeline): Could not create output directory for '{abs_output_plaso_path}': {str(e)}")
        return jsonify({"status": "error", "message": f"Could not create output directory: {str(e)}"}), 500

    app.logger.info(f"[*] Log2Timeline request: Input='{abs_input_file_path}', Output='{abs_output_plaso_path}', Options='{options_str}'")
    
    name_only, _ = os.path.splitext(os.path.basename(abs_input_file_path))
    base_output_name_from_plaso_path = os.path.splitext(os.path.basename(abs_output_plaso_path))[0] # Renamed for clarity
    job_log_file = os.path.join(PLASO_FOLDER, f"{name_only}_{base_output_name_from_plaso_path}_log2timeline.log")

    log2timeline_executable = "/usr/local/bin/log2timeline" # Use .py extension
    if not os.path.isfile(log2timeline_executable):
        app.logger.warning(f"Warning: log2timeline not found at {log2timeline_executable}. Trying 'log2timeline' via PATH.")
        log2timeline_executable = "log2timeline" # Fallback to .py

    cmd_list = [log2timeline_executable]
    try:
        cmd_list.extend(shlex.split(options_str)) 
    except Exception as e:
        app.logger.error(f"Error splitting options_str '{options_str}': {str(e)}")
        return jsonify({"status": "error", "message": f"Error parsing options_str: {str(e)}"}), 500
        
    cmd_list.extend(["--storage-file", abs_output_plaso_path, abs_input_file_path])
    
    app.logger.info(f"[*] Exact command list for Log2timeline: {cmd_list}")

    try:
        with open(job_log_file, 'w') as log_file_handle:
            process_result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=7200)
            log_file_handle.write("--- STDOUT ---\n")
            log_file_handle.write(process_result.stdout if process_result.stdout else "")
            log_file_handle.write("\n--- STDERR ---\n")
            log_file_handle.write(process_result.stderr if process_result.stderr else "")

        if process_result.returncode == 0:
            app.logger.info(f"[✓] log2timeline successfully processed '{abs_input_file_path}' into '{abs_output_plaso_path}'")
            return jsonify({
                "status": "success", "message": "log2timeline completed successfully.",
                "input_file": abs_input_file_path, "output_file": abs_output_plaso_path,
                "log_file": job_log_file, "stdout": process_result.stdout, "stderr": process_result.stderr
            }), 200
        else:
            app.logger.error(f"[!] log2timeline failed for '{abs_input_file_path}'. RC: {process_result.returncode}")
            app.logger.error(f"    STDOUT: {process_result.stdout}")
            app.logger.error(f"    STDERR: {process_result.stderr}")
            return jsonify({
                "status": "error", "message": "log2timeline failed.",
                "input_file": abs_input_file_path, "output_file": abs_output_plaso_path,
                "log_file": job_log_file, "return_code": process_result.returncode,
                "stdout": process_result.stdout, "stderr": process_result.stderr
            }), 500
            
    except subprocess.TimeoutExpired:
        app.logger.error(f"[!] log2timeline timed out for '{abs_input_file_path}'")
        with open(job_log_file, 'a') as log_file_handle:
            log_file_handle.write("\n--- PROCESSING ERROR ---\nLog2timeline command timed out.")
        return jsonify({"status": "error", "message": "log2timeline processing timed out", "log_file": job_log_file}), 500
    except FileNotFoundError as fnf_error: 
        app.logger.error(f"[!] FileNotFoundError: Command '{cmd_list[0]}' not found. Error: {str(fnf_error)}")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- FILE NOT FOUND ERROR ---\nCommand '{cmd_list[0]}' not found: {str(fnf_error)}")
        return jsonify({"status": "error", "message": f"Command '{cmd_list[0]}' not found: {str(fnf_error)}", "log_file": job_log_file}), 500
    except Exception as e:
        app.logger.error(f"[!] Exception during log2timeline processing for '{abs_input_file_path}': {type(e).__name__} - {str(e)}")
        app.logger.exception("Traceback:")
        with open(job_log_file, 'a') as log_file_handle:
             log_file_handle.write(f"\n--- PYTHON EXCEPTION ---\n{type(e).__name__}: {str(e)}\nCheck TITAN_Processor logs for full traceback.")
        return jsonify({"status": "error", "message": f"An unexpected error occurred during log2timeline: {type(e).__name__} - {str(e)}", "log_file": job_log_file}), 500

if __name__ == "__main__":
    app.logger.info(f"[*] TITAN Processor API starting on http://0.0.0.0:5005...")
    app.run(host="0.0.0.0", port=5005, debug=False)