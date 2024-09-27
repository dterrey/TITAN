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

from flask import Flask, redirect, url_for, render_template, flash, send_from_directory, session, request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
import shutil
from datetime import datetime, timedelta
import paramiko
from flask import Blueprint
from dotenv import load_dotenv
import subprocess
from flask_socketio import SocketIO, emit
import threading
import time

load_dotenv()

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)

# Flask-SocketIO setup
socketio = SocketIO(app)

# Ensure necessary environment variables are set
BASE_DIR = os.getenv('BASE_DIR')
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')

if not BASE_DIR or not USERNAME or not PASSWORD:
    raise EnvironmentError("BASE_DIR, USERNAME, and PASSWORD environment variables must be set")

CASES_FOLDER = '/cases/'
LOG_FILE = '/tmp/actions.log'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f:
        f.write('Action Log\n')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    action = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('logs', lazy=True))

def log_action(action):
    log_entry = Log(action=action, user_id=current_user.id)
    db.session.add(log_entry)
    db.session.commit()
    with open(LOG_FILE, 'a') as f:
        f.write(f'{log_entry.timestamp} - {log_entry.action} by {current_user.username}\n')

def upload_to_sftp(local_path, remote_path):
    SFTP_HOST = '192.168.46.134'
    SFTP_PORT = 22
    SFTP_USERNAME = 'titan'
    SFTP_PASSWORD = 'admin'
    
    try:
        transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        transport.connect(username=SFTP_USERNAME, password=SFTP_PASSWORD)
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        sftp.put(local_path, remote_path)
        
        sftp.close()
        transport.close()
    except Exception as e:
        print(f"An error occurred: {e}")
        return False
    return True

@app.route('/')
def default():
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session.pop('user_id', None)  # Clear session data
    return redirect(url_for('login'))

@app.route('/upload_file', methods=['GET', 'POST'])
@login_required
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
                log_action(f'Uploaded {file.filename} to {destination}')
            else:
                flash('Failed to upload file via SFTP')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/action_log')
@login_required
def action_log():
    logs = Log.query.order_by(Log.timestamp.desc()).limit(5).all()
    return render_template('action_log.html', logs=logs)

@app.route('/browse', defaults={'req_path': ''})
@app.route('/browse/<path:req_path>')
@login_required
def browse_files(req_path):
    abs_path = os.path.join(CASES_FOLDER, req_path)
    if not os.path.exists(abs_path):
        return "Path does not exist", 404

    files = []
    dirs = []
    for item in os.listdir(abs_path):
        item_path = os.path.join(abs_path, item)
        if os.path.isdir(item_path):
            dirs.append(item)
        else:
            files.append(item)

    return render_template('browse.html', files=files, dirs=dirs, current_path=req_path)

@app.route('/open_file/<path:filename>')
@login_required
def open_file(filename):
    return send_from_directory(CASES_FOLDER, filename)

@app.route('/delete/<path:target>', methods=['POST'])
@login_required
def delete(target):
    abs_path = os.path.join(CASES_FOLDER, target)
    if os.path.isdir(abs_path):
        shutil.rmtree(abs_path)
    elif os.path.isfile(abs_path):
        os.remove(abs_path)
    flash(f'Deleted: {target}')
    log_action(f'Deleted {target}')
    return redirect(url_for('browse_files', req_path=os.path.dirname(target)))

@app.route('/mitre_dashboard')
@login_required
def mitre_dashboard():
    return redirect(url_for('static_bp.static', filename='index.html'))

# Create a blueprint for serving static files
static_bp = Blueprint('static_bp', __name__, static_url_path='/zircogui', static_folder=os.path.join(BASE_DIR, 'Downloads/zircogui'))

# Register the blueprint
app.register_blueprint(static_bp, url_prefix='/zircogui')

@app.route('/progress')
@login_required
def progress():
    return render_template('progress.html')

# Define the path to the TITAN Console app.py
TITAN_SCRIPT_PATH = '/opt/TITAN_Admin/TITAN_CONSOLE/app.py'

# Start TITAN Console in the background
def start_titan_console():
    try:
        # Start TITAN Console Flask app on port 5232
        subprocess.Popen(['python3', TITAN_SCRIPT_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("TITAN Console started on port 5232")
    except Exception as e:
        print(f"Error launching TITAN Console: {str(e)}")

# Terminal route to redirect to TITAN Console
@app.route('/terminal')
@login_required
def terminal():
    # Redirect to TITAN Console running on port 5232
    return redirect("http://localhost:5232")

# Run main Flask app and start TITAN Console automatically
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Start TITAN Console before the main Flask app
    start_titan_console()

    # Wait for 2 seconds to ensure the TITAN Console app has time to start
    time.sleep(2)

    # Start the main Flask app on port 5111
    socketio.run(app, debug=True, host='localhost', port=5111)
