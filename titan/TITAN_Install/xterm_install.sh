#!/bin/bash

# Step 1: Install Node.js and npm (if not installed)
echo "Installing Node.js and npm..."
sudo apt update
sudo apt install -y nodejs npm

# Step 2: Create directories for xterm.js
echo "Creating directories for xterm.js..."
mkdir -p /home/titan/Downloads/TITAN/static/js
mkdir -p /home/titan/Downloads/TITAN/static/css

# Step 3: Navigate to the directory
cd /home/titan/Downloads/TITAN/static

# Step 4: Download xterm.js and xterm.css via npm
echo "Installing xterm.js..."
npm install xterm

# Step 5: Copy xterm.js and xterm.css to static folder
cp node_modules/xterm/lib/xterm.js /home/titan/Downloads/TITAN/static/js/xterm.js
cp node_modules/xterm/css/xterm.css /home/titan/Downloads/TITAN/static/css/xterm.css

# Step 6: Clean up the node_modules folder (optional)
echo "Cleaning up..."
rm -rf node_modules

echo "Xterm.js has been installed and set up at /home/titan/Downloads/TITAN/static."

