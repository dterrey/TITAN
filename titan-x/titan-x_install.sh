#!/bin/bash

# TITAN-X Install Script for Ubuntu 22.04

# Prompt for the base directory, username, and password
read -p "Enter the base directory (e.g., /home/username): " BASE_DIR
read -p "Enter the username: " USERNAME
read -sp "Enter the password: " PASSWORD
echo

# Install necessary packages
sudo apt-get update -y
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release python3-pip expect -y
sudo apt install cargo unzip unrar docker.io docker-compose docker-compose-plugin -y

# Install Docker dependencies
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
sudo sh -c "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable' > /etc/apt/sources.list.d/docker.list"
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io -y

# Export variables for use in expect scripts
export BASE_DIR
export USERNAME
export PASSWORD

# Install Python packages
sudo -u "$USERNAME" pip3 install --upgrade pip
pip3 install notebook matplotlib Flask Flask-SQLAlchemy Flask-Login Flask-Bcrypt pandas spacy timesketch-api-client paramiko PyPDF2 python-docx openpyxl gensim IPython tabulate os re json pandas requests spacy timesketch-api-client ipython nltk rich scikit-learn

# Install packages for TITAN.py and auto_investigation.py
pip3 install torch transformers sentence-transformers spacy summa flair t5 transformers nltk

# Download spaCy model for TITAN-X
python3 -m spacy download en_core_web_sm

# Install GPT model dependencies
pip3 install openai

# Install other dependencies
sudo apt-get install ssh sleuthkit python3-pip -y

# Install Timesketch import client
pip3 install timesketch-import-client

# Install Chainsaw
sudo mkdir -p /opt/chainsaw && cd /opt/chainsaw
sudo wget https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_all_platforms+rules.zip
sudo unzip chainsaw_all_platforms+rules.zip && rm chainsaw_all_platforms+rules.zip
sudo chmod +x /opt/chainsaw/chainsaw_x86_64-unknown-linux-gnu
sudo mv chainsaw_x86_64-unknown-linux-gnu /opt/chainsaw/chainsaw

# Install Hayabusa
sudo mkdir -p /opt/hayabusa && cd /opt/hayabusa
sudo wget https://github.com/Yamato-Security/hayabusa/releases/download/v2.15.0/hayabusa-2.15.0-all-platforms.zip
sudo unzip hayabusa-2.15.0-all-platforms.zip && rm hayabusa-2.15.0-all-platforms.zip
sudo chmod +x /opt/hayabusa/hayabusa-2.15.0-lin-x64-musl
sudo mv hayabusa-2.15.0-lin-x64-musl /opt/hayabusa/hayabusa

# Install CAPA
sudo mkdir -p /opt/capa && cd /opt/capa
sudo wget https://github.com/mandiant/capa/releases/download/v7.0.1/capa-v7.0.1-linux.zip
sudo unzip capa-v7.0.1-linux.zip && rm capa-v7.0.1-linux.zip
sudo chmod +x /opt/capa/capa

# Install Node-RED
curl -sL https://raw.githubusercontent.com/node-red/linux-installers/master/deb/update-nodejs-and-nodered > /tmp/update_script.sh
expect << EOF
    set timeout -1
    spawn bash /tmp/update_script.sh --confirm-root --confirm-install --skip-pi --no-init --nodered-user=$USERNAME --restart
    expect "*?assword for $USERNAME:*" { send "$PASSWORD\r"; exp_continue }
    expect eof
EOF

# Install Node-RED Palette
cd $BASE_DIR/.node-red
sudo npm install node-red-contrib-fs node-red-contrib-fs-ops node-red-contrib-slack node-red-contrib-simple-queue @flowfuse/node-red-dashboard node-red-dashboard

# Install Timesketch
git clone https://github.com/google/timesketch
cd timesketch
sudo docker-compose up -d

# Set file permissions
sudo chmod 777 -R /opt/ /cases/

# Create user account in Timesketch
sudo docker exec -it timesketch-web tsctl create-user $USERNAME --password $PASSWORD

# Create directories for the project
sudo mkdir -p /cases /cases/processor /cases/plaso /cases/malware /cases/zircolite /cases/evtxproc
sudo chmod 777 -R /cases/

# Setup Flask UI as a service
sudo mv $FLASK_DIR /opt/
sudo chmod 777 -R /opt/

sudo bash -c "cat > /etc/systemd/system/flaskui.service <<EOF
[Unit]
Description=triagex UI
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/Flask/app.py
WorkingDirectory=/opt/Flask
Restart=always
User=$USERNAME
Environment=PATH=/usr/bin:/usr/local/bin
Environment=BASE_DIR=$BASE_DIR
Environment=USERNAME=$USERNAME
Environment=PASSWORD=$PASSWORD

[Install]
WantedBy=multi-user.target
EOF"

# Enable Flask UI service
sudo systemctl daemon-reload
sudo systemctl enable flaskui.service
sudo systemctl start flaskui.service

# Install Zircolite
sudo wget https://github.com/wagga40/Zircolite/archive/refs/tags/2.20.0.zip -O /opt/zircolite.zip
cd /opt/
sudo unzip zircolite.zip && rm zircolite.zip
pip3 install -r /opt/Zircolite-2.20.0/requirements.full.txt

echo -e "\nTITAN-X Installation Completed Successfully. Reboot the system to apply changes."
