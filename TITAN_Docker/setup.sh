#!/bin/bash

mkdir -p /cases /opt/titan /opt/timesketch
chmod -R 777 /cases /opt/titan /opt/timesketch

# Ensure spaCy model is pre-downloaded
python3 -m spacy download en_core_web_lg

# Install Docker
sudo apt install curl -y
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
sudo echo \
"deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install all pre-required Linux packages
sudo apt-get update
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release cargo unzip git unrar docker.io python3-pip expect docker-compose docker-compose-plugin -y

sudo systemctl start docker
sudo systemctl enable docker
sudo docker pull portainer/portainer-ce:latest
sudo docker run -d -p 9000:9000 --restart always -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer-ce:latest

Go to localhost:9000 and create an administrator account.

echo "Say yes to start timesketch containers and user titan and admin for timesketch username and password"

sleep 5


cd /opt
git clone https://github.com/google/timesketch.git
cd /opt/timesketch/contrib/
sudo ./deploy_timesketch.sh

echo "Go to localhost:9000 and create an administrator account."
