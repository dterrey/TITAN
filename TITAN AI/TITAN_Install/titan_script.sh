#!/bin/bash

# Prompt for the base directory, username, and password
read -p "Enter the base directory (e.g., /home/username): " BASE_DIR
read -p "Enter the username: " USERNAME
read -sp "Enter the password: " PASSWORD
echo

# Install necessary packages
sudo apt install curl -y
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
sudo sh -c "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable' > /etc/apt/sources.list.d/docker.list"

# Install all pre-required Linux packages
sudo apt-get update
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release cargo unzip unrar docker.io python3-pip expect docker-compose docker-compose-plugin -y

# Export variables for expect scripts
export BASE_DIR
export USERNAME
export PASSWORD

# Define the paths based on the base directory
CONFIG_FILE="$BASE_DIR/titan/TITAN_Install/config.json"
JSON_FILE="$BASE_DIR/titan/TITAN_Install/titan_NR_Flow.json"
FLASK_APP_FILE="$BASE_DIR/titan/TITAN_Admin/app.py"
BASE_HTML_FILE="$BASE_DIR/titan/TITAN_Admin/templates/base.html"
DEPLOY_TIMESKETCH_EXPECT="$BASE_DIR/titan/TITAN_Install/deploy_timesketch_expect.sh"
NODE_RED_INSTALL="$BASE_DIR/titan/TITAN_Install/node_red_install.sh"
FLASK_DIR="$BASE_DIR/titan/TITAN_Admin"

# Extract local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Create or update config.json
cat <<EOT > $CONFIG_FILE
{
    "baseDir": "$BASE_DIR",
    "username": "$USERNAME",
    "password": "$PASSWORD"
}
EOT

echo "Configuration updated with base directory: $BASE_DIR, username: $USERNAME, and password."

# Function to update references in the script itself
update_script_references() {
    local base_dir="$1"
    local username="$2"
    local password="$3"
    local script_file="$4"

    echo "Updating references in $script_file"
    sed -i "s|/home/titan|$base_dir|g" "$script_file"
    sed -i "s|titan|$username|g" "$script_file"
    sed -i "s|admin|$password|g" "$script_file"
}

# Function to update credentials in specified files
update_credentials_json() {
    local username="$1"
    local password="$2"
    local file="$3"

    # Update username and password in the JSON file
    sed -i "s/\"username\": \"titan\"/\"username\": \"${username}\"/g" "$file"
    sed -i "s/\"password\": \"admin\"/\"password\": \"${password}\"/g" "$file"
}

# Function to update credentials in other specified files
update_credentials() {
    local username="$1"
    local password="$2"
    shift 2
    local files=("$@")

    for file in "${files[@]}"; do
        sed -i "s/titan/${username}/g" "$file"
        sed -i "s/admin/${password}/g" "$file"
    done
}

# Function to update SFTP credentials in app.py
update_sftp_credentials_in_flask() {
    local username="$1"
    local password="$2"
    local file="$3"

    sed -i "s/sftp_upload(local_path, remote_path, 'localhost', 22, 'titan', 'admin')/sftp_upload(local_path, remote_path, 'localhost', 22, '$username', '$password')/g" "$file"
}

# Update Timesketch URL in base.html
update_timesketch_url() {
    local local_ip="$1"
    local file="$2"

    sed -i "s|http://localhost|http://$local_ip|g" "$file"
}

# Files to update (other scripts or files that require username and password updates)
FILES_TO_UPDATE=(
    "$FLASK_APP_FILE"
    "$DEPLOY_TIMESKETCH_EXPECT"
    "$NODE_RED_INSTALL"
    # Add paths to other scripts or files that require username and password updates
)

# Update credentials in the JSON file
update_credentials_json "$USERNAME" "$PASSWORD" "$JSON_FILE"

# Update credentials in other files
update_credentials "$USERNAME" "$PASSWORD" "${FILES_TO_UPDATE[@]}"

# Update references in this script
SCRIPT_PATH=$(realpath "$0")
update_script_references "$BASE_DIR" "$USERNAME" "$PASSWORD" "$SCRIPT_PATH"

# Update SFTP credentials in Flask app.py
update_sftp_credentials_in_flask "$USERNAME" "$PASSWORD" "$FLASK_APP_FILE"

sudo chmod 777 -R /opt/

# Save the updated deploy_timesketch_expect.sh content
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

# Save the updated node_red_install.sh content
cat << EOF > $NODE_RED_INSTALL
#!/usr/bin/expect -f

# Set timeout for expect commands
set timeout -1
set password \$env(PASSWORD)
set username \$env(USERNAME)
set basedir \$env(BASE_DIR)

# Ensure the update script exists
if {![file exists "/tmp/update_script.sh"]} {
    puts "Error: /tmp/update_script.sh does not exist."
    exit 1
}

# Add necessary options to avoid prompts
set UPDATE_SCRIPT_OPTIONS "--confirm-root --confirm-install --skip-pi --no-init --nodered-user=\$username --restart"

# Run the Node-RED install script with automated responses
spawn sudo -u $username bash -c "bash /tmp/update_script.sh $UPDATE_SCRIPT_OPTIONS"

expect {
    "*?assword for $username:*" {
        # Install the required package before sending the password
        exec pip install PyPDF2
        
        send_user "\nSending password for $username: $password\n"
        send "$password\r"
        exp_continue
    }
    eof
}


# Wait for Node-RED to be fully started
sleep 20

# Path to the flow file
set flow_file "\$basedir/titan/titan_NR_Flow.json"

# Create a temporary shell script for the curl command
set temp_curl_script "/tmp/import_nodered_flow.sh"
set curl_command "curl -X POST http://localhost:1880/flows -H \"Content-Type: application/json\" --data-binary @\$flow_file"
spawn bash -c "echo '#!/bin/bash\n\$curl_command' > \$temp_curl_script"
expect eof

# Verify the content of the temporary shell script
spawn cat \$temp_curl_script
expect eof

# Make the temporary shell script executable
spawn chmod +x \$temp_curl_script
expect eof

# Run the temporary shell script to import the flow
spawn bash \$temp_curl_script
expect {
    eof
}
EOF

# Install Portainer for easier container management
sudo systemctl start docker
sudo systemctl enable docker
sudo docker pull portainer/portainer-ce:latest
sudo docker run -d -p 9000:9000 --restart always -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer-ce:latest


# NEED TO FIX TIMESKETCH DEPLOYMENT

# Download and install Timesketch
git clone https://github.com/google/timesketch
#sudo curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
#sudo chmod 777 deploy_timesketch.sh
#sudo chmod 777 -R /opt/
#sudo mv deploy_timesketch.sh /opt/
#cd /opt/

# Run the expect script for Timesketch installation
#expect $DEPLOY_TIMESKETCH_EXPECT

# Update Timesketch URL in base.html
#update_timesketch_url "$LOCAL_IP" "$BASE_HTML_FILE"

# Function to create the Timesketch database and role in PostgreSQL
#create_timesketch_db_and_role() {
#    # Wait for the PostgreSQL container to be up and running
#    until sudo docker exec -it $(sudo docker ps -qf "name=postgres") psql -U postgres -c "\l"; do
#        echo "Waiting for PostgreSQL to be available..."
#        sleep 5
#    done
#
#    # Create the role (user)
#    sudo docker exec -it $(sudo docker ps -qf "name=postgres") psql -U postgres -c "CREATE ROLE $USERNAME WITH LOGIN PASSWORD '$PASSWORD';"
#
#    # Grant privileges to the role
#    sudo docker exec -it $(sudo docker ps -qf "name=postgres") psql -U postgres -c "ALTER ROLE $USERNAME CREATEDB;"
#
#    # Create the database owned by the role
#    sudo docker exec -it $(sudo docker ps -qf "name=postgres") psql -U postgres -c "CREATE DATABASE timesketch OWNER $USERNAME;"
# }


# Continue with the rest of the installation script
echo "Installation script continues..."

# CONSTANTS
# Setting default user creds
USER1_NAME=$USERNAME
USER1_PASSWORD=$PASSWORD

# DATA DIRS
CASES_DIR="/cases"
DATA_DIR="/data"
PLASO_DIR="/cases/plaso"
PROCESSOR_DIR="/cases/processor"
HOST_TRIAGE_DIR="/cases/processor/host-triage"
EVTXPROC="/cases/evtxproc"
OPT="/opt"
CAPA="/opt/capa"
CHAINSAW="/cases/evtxproc/chainsaw"
MALWARE="/cases/malware"
MALWAREHASHES="/cases/malware/hashes"
TRIAGEHASHES="/cases/processor/hashes"
MALWARELOG="/cases/malware/logfile"
TRIAGELOG="/cases/processor/logfile"
ZIRCOLITE="/cases/zircolite"
HAYABUSA="/opt/hayabusa"

# Create directories with -p flag to avoid errors if they already exist
sudo mkdir -p "$CASES_DIR" \
             "$DATA_DIR" \
             "$PLASO_DIR" \
             "$PROCESSOR_DIR" \
             "$EVTXPROC" \
             "$CAPA" \
             "$MALWARE" \
             "$CHAINSAW" \
             "$ZIRCOLITE" \
             "$HAYABUSA" \
             "$MALWAREHASHES" \
             "$TRIAGEHASHES" \
             "$MALWARELOG" \
             "$TRIAGELOG"

# Set permissions
sudo chmod -R 777 $CASES_DIR
sudo chmod -R 777 $DATA_DIR
sudo chmod -R 777 $OPT

touch /cases/malware/hashes/hashes.txt
touch /cases/processor/hashes/hashes.txt
touch /cases/malware/logfile/logfile.txt
touch /cases/processor/logfile/logfile.txt

# Native Install Commented Out
sudo add-apt-repository universe -y
add-apt-repository ppa:gift/stable -y
apt-get update
pip install plaso
sudo apt install xmount

# Install Timesketch import client to assist with larger plaso uploads
pip3 install timesketch-import-client

# Download the latest tags file from dterrey forked repo
sudo wget -Nq https://raw.githubusercontent.com/dterrey/titan/master/tags.yaml -O /opt/timesketch/etc/timesketch/tags.yaml

# Install Chainsaw
cd /opt/
sudo wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_all_platforms+rules.zip
sudo unzip chainsaw_all_platforms+rules.zip
sudo mv /opt/chainsaw/chainsaw_x86_64-unknown-linux-gnu /opt/chainsaw/chainsaw
sudo chmod 777 -R $OPT
sudo chmod +x /opt/chainsaw/chainsaw

# Install Hayabusa
sudo chmod 777 -R /opt/hayabusa
cd /opt/hayabusa/
sudo wget https://github.com/Yamato-Security/hayabusa/releases/download/v2.15.0/hayabusa-2.15.0-all-platforms.zip
sudo unzip hayabusa-2.15.0-all-platforms.zip
sudo chmod 777 -R $OPT
sudo mv /opt/hayabusa/hayabusa-2.15.0-lin-x64-musl /opt/hayabusa/hayabusa
sudo chmod +x /opt/hayabusa/hayabusa

# Install Capa
sudo chmod 777 -R /opt/capa
cd /opt/capa/
sudo wget https://github.com/mandiant/capa/releases/download/v7.0.1/capa-v7.0.1-linux.zip
sudo unzip capa-v7.0.1-linux.zip
sudo chmod 777 -R $OPT
sudo chmod +x /opt/capa

# Download the loop.sh file for the plaso container
sudo wget -Nq https://raw.githubusercontent.com/dterrey/DFIR_NodeRED/master/loop.sh -O /opt/timesketch/loop.sh

# Create the first user account
sudo docker exec -it timesketch-web tsctl create-user $USERNAME --password $PASSWORD

# Install Node-Red
# Download the script
curl -sL https://raw.githubusercontent.com/node-red/linux-installers/master/deb/update-nodejs-and-nodered > /tmp/update_script.sh

# Run the expect script for Node-RED installation
expect $NODE_RED_INSTALL

sudo chmod 777 -R /cases/malware/results/

# Increase the CSRF token time limit
sudo sh -c "echo '\nWTF_CSRF_TIME_LIMIT = 3600' >> /opt/timesketch/etc/timesketch/timesketch.conf"

sudo sh -c "echo 'PATH=\$PATH:\$HOME/.local/bin' >> $HOME/.bashrc"
source ~/.bashrc

sudo -u $USERNAME pip3 install --upgrade pip

pip install matplotlib
pip install Flask
pip install Flask-SQLAlchemy
pip install Flask-Login
pip install Flask-Bcrypt
pip install pandas
pip install timesketch-api-client
pip install paramiko
pip install plotly
pip install dash dash-bootstrap-components
sudo apt install ssh -y
pip install flask flask-login flask-sqlalchemy flask-bcrypt
sudo apt install python3-pip -y
pip install flask paramiko
pip install flask-socketio
pip install scikit-learn
pip install pandas spacy timesketch-api-client PyPDF2 python-docx openpyxl gensim IPython tabulate
python3 -m spacy download en_core_web_sm
pip install os re json pandas spacy requests timesketch-api-client ipython PyPDF2 python-docx openpyxl sumy nltk rich scikit-learn logging readline

pip install yara-python pandas requests gitpython


python -c "import nltk; nltk.download('punkt')"


cd /opt/
wget https://github.com/wagga40/Zircolite/archive/refs/tags/2.20.0.zip
unzip 2.20.0
rm 2.20.0.zip
pip install python-evtx
pip3 install python-evtx

# Setup UI as a service
sudo mv $FLASK_DIR /opt/
sudo chmod 777 -R /opt/

SERVICE_FILE="/etc/systemd/system/flaskui.service"
APP_PATH="/opt/TITAN_Admin/app.py"
WORKING_DIR="/opt/TITAN_Admin"
USER=$USERNAME
PYTHON_PATH="/usr/bin/python3"

# Create the systemd service file
sudo bash -c "cat > $SERVICE_FILE <<EOF
[Unit]
Description=TITAN UI
After=network.target

[Service]
ExecStart=$PYTHON_PATH $APP_PATH
WorkingDirectory=$WORKING_DIR
Restart=always
User=$USER
Environment=PATH=/usr/bin:/usr/local/bin
Environment=PYTHONUNBUFFERED=1
Environment=BASE_DIR=$BASE_DIR
Environment=USERNAME=$USERNAME
Environment=PASSWORD=$PASSWORD

[Install]
WantedBy=multi-user.target
EOF"

# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable flaskui.service

# Start the service immediately
sudo systemctl start flaskui.service

# Check the status of the service
sudo systemctl status flaskui.service --no-pager

sudo useradd -m sftp_user -g $USERNAME

# Add the required configuration to /etc/ssh/sshd_config
sudo bash -c "cat >> /etc/ssh/sshd_config <<EOF

Match group $USERNAME
ChrootDirectory /
X11Forwarding no
AllowTcpForwarding no
ForceCommand internal-sftp
EOF"

# Restart SSH service to apply the changes
sudo systemctl restart ssh

# Install Timesketch import client to assist with larger plaso uploads
pip3 install timesketch-import-client

# Change to the Node-RED user directory (usually ~/.node-red)
cd $BASE_DIR/.node-red

# Install nodered palette
sudo npm install node-red-contrib-fs node-red-contrib-fs-ops node-red-contrib-slack node-red-contrib-slack-files node-red-contrib-simple-queue node-red-contrib-watchdirectory @flowfuse/node-red-dashboard node-red-dashboard


sudo chmod 777 /opt/ -R
sudo chmod 777 /cases/ -R

sudo systemctl enable nodered
sudo systemctl start nodered

unzip /opt/Zircolite-2.20.0/gui/zircolite.zip -d $BASE_DIR/Downloads

sudo apt install net-tools

cd /opt/Zircolite-2.20.0
pip3 install -r requirements.full.txt

sudo apt-get install sleuthkit

echo -e "\n******************************************************************************************"
echo -e "To Access Node-Red: localhost:1880"
echo -e "To Access Timesketch: Local IP or localhost"
echo -e "To Access Portainer via IP:9000"
echo -e "To Access UI: IP:5000"
echo -e "To Access Kibana: localhost:5601"
echo -e "Please Reboot to apply all changes to the system"
echo -e "*****************************************************************************************\n"
