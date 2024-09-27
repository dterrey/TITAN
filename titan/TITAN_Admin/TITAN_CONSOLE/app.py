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

# app.py
import os
import subprocess
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Define the full path to your titan.py script
TITAN_SCRIPT_PATH = "/home/titan/titan/titan.py"

# Keep a global process reference to the running titan.py process
process = None

# Function to run the titan.py script
def run_titan_script():
    global process
    process = subprocess.Popen(['python3', TITAN_SCRIPT_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
    
    # Stream stdout
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            # Yield output as is, without stripping spaces or newlines
            yield output

    # Capture any remaining stderr output after process ends
    error_output = process.stderr.read()
    if error_output:
        yield f"Error: {error_output}\n"

# Route to run titan.py and stream output
@app.route('/run_titan', methods=['POST'])
def run_titan():
    return app.response_class(run_titan_script(), mimetype='text/plain')

# Route to send commands to the running titan.py process
@app.route('/send_command', methods=['POST'])
def send_command():
    global process
    if process is None:
        return jsonify({'output': 'Error: No running process to send the command to.'})

    command = request.json.get('command', '')
    if command:
        try:
            # Write the command to the titan.py process
            process.stdin.write(command + "\n")
            process.stdin.flush()

            # Capture stdout or stderr output
            output = process.stdout.readline()
            if not output:
                # If no stdout, check for stderr
                error_output = process.stderr.readline().strip()
                return jsonify({'output': f"Error: {error_output}"})
            else:
                return jsonify({'output': output.strip() + '\n'})
        except Exception as e:
            return jsonify({'output': f"Error sending command: {str(e)}"})
    else:
        return jsonify({'output': 'Error: No command received.'})

# Serve the index.html from the static folder
@app.route('/')
def index():
    return app.send_static_file('index.html')

# Run Flask app
if __name__ == "__main__":
    app.run(debug=True, host='localhost', port=5232)
