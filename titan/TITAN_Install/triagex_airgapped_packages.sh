#!/bin/bash

# Create directories for storing the downloaded packages
mkdir -p ~/airgapped/packages
mkdir -p ~/airgapped/docker-images
mkdir -p ~/airgapped/pip-packages
mkdir -p ~/airgapped/velociraptor

# Update and download necessary packages
sudo apt-get update
apt-get install --download-only -y apt-transport-https ca-certificates curl gnupg lsb-release cargo unzip unrar docker.io python3-pip expect docker-compose

# Move the downloaded packages to the packages directory
find /var/cache/apt/archives/ -name "*.deb" -exec mv {} ~/airgapped/packages/ \;

# Download necessary Python packages
pip3 download Flask Flask-SQLAlchemy Flask-Login Flask-Bcrypt paramiko -d ~/airgapped/pip-packages/

# Download Docker images and save them as tar files
docker pull portainer/portainer-ce:latest
docker save -o ~/airgapped/docker-images/portainer-ce.tar portainer/portainer-ce:latest

docker pull timesketch/timesketch:latest
docker save -o ~/airgapped/docker-images/timesketch.tar timesketch/timesketch:latest

# Download Velociraptor binary
wget -O ~/airgapped/velociraptor/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.6.6/velociraptor-v0.6.6-linux-amd64

# Compress the airgapped directory for easier transfer
tar -czvf ~/airgapped.tar.gz ~/airgapped

echo "All necessary packages, Docker images, and dependencies have been downloaded and saved to ~/airgapped.tar.gz"
