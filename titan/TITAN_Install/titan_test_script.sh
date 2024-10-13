#!/bin/bash

# Prompt for the base directory, username, and password
read -p "Enter the base directory (e.g., /home/username): " BASE_DIR
read -p "Enter the username: " USERNAME
read -sp "Enter the password: " PASSWORD
echo

# Update and upgrade system packages
sudo apt update && sudo apt upgrade -y

# Install Docker (for Timesketch)
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
sudo sh -c "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable' > /etc/apt/sources.list.d/docker.list"
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io


# Install necessary packages
sudo apt install -y curl gnupg lsb-release ca-certificates apt-transport-https unzip unrar docker.io python3-pip expect docker-compose docker-compose-plugin cargo -y
# Export variables for expect scripts
export BASE_DIR
export USERNAME
export PASSWORD

# Define file paths
CONFIG_FILE="$BASE_DIR/titan/TITAN_Install/config.json"
JSON_FILE="$BASE_DIR/titan/TITAN_Install/titan_NR_Flow.json"
FLASK_APP_FILE="$BASE_DIR/titan/TITAN_Admin/app.py"
BASE_HTML_FILE="$BASE_DIR/titan/TITAN_Admin/templates/base.html"
DEPLOY_TIMESKETCH_EXPECT="$BASE_DIR/titan/TITAN_Install/deploy_timesketch_expect.sh"
NODE_RED_INSTALL="$BASE_DIR/titan/TITAN_Install/node_red_install.sh"
FLASK_DIR="$BASE_DIR/titan/TITAN_Admin"

# Create or update config.json
cat <<EOT > $CONFIG_FILE
{
    "baseDir": "$BASE_DIR",
    "username": "$USERNAME",
    "password": "$PASSWORD"
}
EOT

echo "Configuration updated with base directory: $BASE_DIR, username: $USERNAME, and password."

# Function to update credentials in specified files
update_credentials() {
    local username="$1"
    local password="$2"
    local file="$3"

    sed -i "s/titan/$username/g" "$file"
    sed -i "s/admin/$password/g" "$file"
}

# Update credentials in JSON and Flask files
update_credentials "$USERNAME" "$PASSWORD" "$FLASK_APP_FILE"
update_credentials "$USERNAME" "$PASSWORD" "$BASE_HTML_FILE"

# Set up SFTP in Flask app.py
update_credentials_in_flask() {
    local username="$1"
    local password="$2"
    local file="$3"

    sed -i "s/sftp_upload(local_path, remote_path, 'localhost', 22, 'titan', 'admin')/sftp_upload(local_path, remote_path, 'localhost', 22, '$username', '$password')/g" "$file"
}

update_credentials_in_flask "$USERNAME" "$PASSWORD" "$FLASK_APP_FILE"

# Deploy Timesketch via expect
sudo chmod 775 -R /opt/

cat << EOF > $DEPLOY_TIMESKETCH_EXPECT
#!/usr/bin/expect -f

set timeout -1

spawn sudo /opt/deploy_timesketch.sh

expect {
    "Would you like to start the containers?" {
        send "Y\r"
    }
    timeout {
        puts "Timeout waiting for the first question"
        exit 1
    }
}

expect {
    "Would you like to create a new timesketch user" {
        send "N\r"
    }
    timeout {
        puts "Timeout waiting for the second question"
        exit 1
    }
}

expect eof
EOF

chmod +x $DEPLOY_TIMESKETCH_EXPECT

# Install Node-RED using expect
cat << EOF > $NODE_RED_INSTALL
#!/usr/bin/expect -f

set timeout -1

# Add necessary options to avoid prompts
set UPDATE_SCRIPT_OPTIONS "--confirm-root --confirm-install --skip-pi --no-init --nodered-user=\$USERNAME --restart"

# Run the Node-RED install script with automated responses
spawn sudo -u $USERNAME bash -c "bash /tmp/update_script.sh $UPDATE_SCRIPT_OPTIONS"

expect {
    "*?assword for $USERNAME:*" {
        send "$PASSWORD\r"
        exp_continue
    }
    eof
}
EOF

chmod +x $NODE_RED_INSTALL


# Function to update paths in titan_NR_Flow.json
update_nodered_flow_paths() {
    local json_file="$1"
    local base_dir="$2"

    echo "Updating folder paths in Node-RED flow file ($json_file)..."

    # Replace all instances of "/home/titan" with the new base directory
    sed -i "s|/home/titan|$base_dir|g" "$json_file"

    # Optionally replace other paths like /opt/ if needed
    sed -i "s|/opt/Zircolite-2.20.0|$base_dir/opt/Zircolite-2.20.0|g" "$json_file"

    echo "Folder paths updated successfully in $json_file."
}

# Call the function to update the Node-RED flow file paths
update_nodered_flow_paths "$JSON_FILE" "$BASE_DIR"

# Start Docker and enable it to run on boot
sudo systemctl start docker
sudo systemctl enable docker

# Install Timesketch
sudo curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
sudo chmod 755 deploy_timesketch.sh
sudo mkdir /opt/timesketch
sudo mv deploy_timesketch.sh /opt/timesketch
cd /opt/timesketch
sudo ./deploy_timesketch.sh

# Increase the CSRF token time limit
sudo sh -c "echo '\nWTF_CSRF_TIME_LIMIT = 3600' >> /opt/timesketch/etc/timesketch/timesketch.conf"

# Install required Python packages
pip3 install timesketch-api-client flask-socketio flask flask-login flask-sqlalchemy flask-bcrypt pandas paramiko plotly dash dash-bootstrap-components scikit-learn spacy PyPDF2 python-docx openpyxl gensim IPython tabulate rich yara-python plaso fpdf

# Ensure Node-RED starts on boot
sudo systemctl enable nodered
sudo systemctl start nodered

# Download and install Node-RED flow
sudo chmod 775 $BASE_DIR/.node-red/
sudo npm install node-red-contrib-fs node-red-contrib-fs-ops node-red-contrib-slack node-red-dashboard

# Setup systemd service for Flask UI
SERVICE_FILE="/etc/systemd/system/flaskui.service"
APP_PATH="/opt/TITAN_Admin/app.py"
WORKING_DIR="/opt/TITAN_Admin"
USER=$USERNAME
PYTHON_PATH="/usr/bin/python3"

# Create systemd service for Flask UI
sudo bash -c "cat > $SERVICE_FILE <<EOF
[Unit]
Description=TITAN UI
After=network-online.target

[Service]
ExecStart=$PYTHON_PATH $APP_PATH
WorkingDirectory=$WORKING_DIR
Restart=always
User=$USER
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF"

# Enable and start Flask UI service
sudo systemctl daemon-reload
sudo systemctl enable flaskui.service
sudo systemctl start flaskui.service

# Print out access instructions
echo -e "\n******************************************************************************************"
echo -e "To Access Node-RED: http://localhost:1880"
echo -e "To Access Timesketch: http://localhost"
echo -e "To Access Portainer: http://localhost:9000"
echo -e "To Access UI: http://localhost:5000"
echo -e "Please Reboot to apply all changes to the system."
echo -e "*****************************************************************************************\n"
