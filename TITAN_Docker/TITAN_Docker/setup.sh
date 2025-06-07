#!/bin/bash

#commands - docker system prune -a --volumes to clean up
#commands - sudo docker compose up -d
#commands - sudo docker 
#commands - Install requirements.txt and setup.sh usin bash
mkdir -p /cases /opt/titan /opt/timesketch
chmod -R 777 /cases /opt/titan /opt/timesketch

pip install spacy

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
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh
chmod 755 deploy_timesketch.sh
sudo ./deploy_timesketch.sh

echo "Go to localhost:9000 and create an administrator account."
