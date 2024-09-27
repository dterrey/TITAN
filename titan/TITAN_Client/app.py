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

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import subprocess
import requests  # Import the requests library

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'

# Node-RED URL for triggering Velociraptor deployment and removal
NODE_RED_URL_WINDOWS = 'http://localhost:1880/trigger-velociraptor-deploy-windows'
NODE_RED_URL_LINUX = 'http://localhost:1880/trigger-velociraptor-deploy-linux'
NODE_RED_URL_MAC = 'http://localhost:1880/trigger-velociraptor-deploy-mac'
NODE_RED_URL_REMOVE_WINDOWS = 'http://localhost:1880/trigger-velociraptor-remove-windows'
NODE_RED_URL_REMOVE_LINUX = 'http://localhost:1880/trigger-velociraptor-remove-linux'
NODE_RED_URL_REMOVE_MAC = 'http://localhost:1880/trigger-velociraptor-remove-mac'

# SFTP connection details for Node-RED VM
SFTP_HOST = '192.168.46.134'
SFTP_PORT = 22
SFTP_USERNAME = 'titan'
SFTP_PASSWORD = 'admin'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def download_velociraptor_agent():
    # Simulate downloading the Velociraptor agent
    agent_url = "https://path-to-velociraptor-agent"
    agent_path = "/tmp/velociraptor-agent.exe"
    # Replace the following line with actual download logic
    subprocess.run(["curl", "-o", agent_path, agent_url])
    # Simulate executing the Velociraptor agent
    subprocess.run([agent_path])

def remove_velociraptor_agent():
    # Simulate removing the Velociraptor agent
    agent_path = "/tmp/velociraptor-agent.exe"
    # Replace the following line with actual removal logic
    subprocess.run(["rm", agent_path])

def deploy_offline_collection():
    # Simulate deploying an offline collection
    collection_script = "/path-to-offline-collection-script.sh"
    subprocess.run(["bash", collection_script])

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        destination = request.form.get('destination')
        if file and destination:
            local_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(local_path)
            if destination == 'Triage':
                remote_path = f'/cases/processor/{file.filename}'
            elif destination == 'Malware':
                remote_path = f'/cases/malware/{file.filename}'
            if upload_to_sftp(local_path, remote_path):
                flash('File successfully uploaded via SFTP')
            else:
                flash('Failed to upload file via SFTP')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/velociraptor')
def velociraptor():
    return render_template('velociraptor.html')

# Deploy routes
@app.route('/deploy_agent_windows', methods=['POST'])
def deploy_agent_windows():
    password = request.form['password']
    try:
        response = requests.post(NODE_RED_URL_WINDOWS, json={'password': password})
        if response.status_code == 200:
            flash('Velociraptor Agent deployed successfully on Windows!')
        else:
            flash('Failed to deploy Velociraptor Agent on Windows.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))

@app.route('/deploy_agent_linux', methods=['POST'])
def deploy_agent_linux():
    username = request.form['username']  # Capture the username from the form
    password = request.form['password']  # Capture the password from the form
    try:
        # POST the username and password to Node-RED
        payload = {'username': username, 'password': password}
        response = requests.post(NODE_RED_URL_LINUX, json=payload)
        if response.status_code == 200:
            flash('Velociraptor Agent deployed successfully on Linux!')
        else:
            flash('Failed to deploy Velociraptor Agent on Linux.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))


@app.route('/deploy_agent_mac', methods=['POST'])
def deploy_agent_mac():
    password = request.form['password']
    try:
        response = requests.post(NODE_RED_URL_MAC, json={'password': password})
        if response.status_code == 200:
            flash('Velociraptor Agent deployed successfully on Mac!')
        else:
            flash('Failed to deploy Velociraptor Agent on Mac.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))

# Remove routes
@app.route('/remove_agent_windows', methods=['POST'])
def remove_agent_windows():
    password = request.form['password']
    try:
        response = requests.post(NODE_RED_URL_REMOVE_WINDOWS, json={'password': password})
        if response.status_code == 200:
            flash('Velociraptor Agent removed successfully on Windows!')
        else:
            flash('Failed to remove Velociraptor Agent on Windows.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))

@app.route('/remove_agent_linux', methods=['POST'])
def remove_agent_linux():
    password = request.form['password']  # Capture the password from the form
    try:
        # POST the password to Node-RED
        payload = {'password': password}
        response = requests.post(NODE_RED_URL_REMOVE_LINUX, json=payload)
        if response.status_code == 200:
            flash('Velociraptor Agent removed successfully on Linux!')
        else:
            flash('Failed to remove Velociraptor Agent on Linux.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))

@app.route('/remove_agent_mac', methods=['POST'])
def remove_agent_mac():
    password = request.form['password']
    try:
        response = requests.post(NODE_RED_URL_REMOVE_MAC, json={'password': password})
        if response.status_code == 200:
            flash('Velociraptor Agent removed successfully on Mac!')
        else:
            flash('Failed to remove Velociraptor Agent on Mac.')
    except requests.exceptions.RequestException as e:
        flash(f'Error: {e}')
    return redirect(url_for('velociraptor'))

@app.route('/deploy_offline_collection', methods=['POST'])
def deploy_offline_collection_route():
    deploy_offline_collection()
    flash('Offline Collection deployed successfully!')
    return redirect(url_for('velociraptor'))

if __name__ == '__main__':
<<<<<<< Updated upstream
    app.run(debug=True, host='0.0.0.0', port=5001)
=======
    app.run(debug=True, host='0.0.0.0', port=5001)
>>>>>>> Stashed changes
