<img src="https://github.com/dterrey/TriageX/blob/main/adam_banner_logo.png">

# TriageX
# IMPORTANT
UPDATE.
codex.py is required for ADAM to link to codexgiggas
ZircoliteTS.py - is the Template used for exporting zircolote to JSON
ts_tagging.py - tags formats and tags the events and then creates a new json format the timesketch and upload with all the tags, otherwise use Zircolite.
ADAM is working but WIP


backup files all work but are hardcoded with dfir and admin creds
Client Flask in /opt/flaskclient
Velociraptor being build
APP.py and all over files changed
NodeRED Changed
Timesketch Taggers / Sigma Rules being updated and configured



Currently working on the new deploy nodered and TriageX scripts so it will accept any username and password.
triagex_script.sh now works after multiple testing. - sudo bash triagex_script.sh

Test timesketch analyzer automation script > node-red or click event attached to website. not sure yet.
build out SUPER ANALYZER for timesketch.
NodeRED Flow Nodes (Functions and Execs) need to be updated with new format.

FUTURE PLANS:
Implement Memory, Cloud and Network analysis automation
Deploy custom Elastic Dashboard to present all findings in nice custom dashboard for quick IR Analysis of all logs and Mitre ATT&CK.
Improve FLASK UI.


** UPDATE, LATEST UPDATE WORKS WITH ANY USERNAME AND PASSWORD - sudo bash triagex_script.sh

If you do change the username and password then you will have to make those changes in the main triagex.sh script and in NODERED Flow.
Dont forget to change the settings for Ubuntu Desktop and disable sleep and the screen turning off in both Power and Privacy Settings.
Still work in progress and needs to be fixed up which is what I am working on at the moment - 2/08/2024
# Purpose
Processing of host triage packages is always a challenge when dealing with incidents involving large number of hosts. 
This repository contains 
- a build script to install and configure Timesketch and associated services
- a workflow built using NodeRED to automate handling of triage archives, processing triage archives using log2timeline/plaso and ingestion into Timesketch.
- a custom Timesketch tagger file that has a curated list of pre-built queries (mapped to MITRE ATT&CK were possible). It can be used to quickly identify initial pivot points and get contextual information during investigations. 
- workflow runs Hayabusa against Windows evtx files and ingests results to Timesketch 

# This project leverages the following open-source projects
- [Timesketch](https://github.com/google/timesketch/)
- [Log2timeline/Plaso](https://github.com/log2timeline/plaso)
- [Node-RED](https://github.com/node-red/node-red)
- [Hayabusa](https://github.com/Yamato-Security/hayabusa)


# Basic Information
This section provides a brief overview of the automation setup and how components are configured.

###### IMPORTANT UPDATE 08/05/2024 ######
This script is automated with only a few user prompted entries.
Works with Ubuntu 22.04.4
Latest NR-DFIRFlow-E01.json NodeRed Work Flow has been updated to process .E01 files


###### INSTALL INSTRUCTIONS ######
sudo sh DFIR_NodeRED.sh
Start the containers - Yes 
Create new username - Yes
Username: dfir
Password: admin
If you do change the username and password, you will need to update the NR_DFIRFlow.json
Easy way is to open the file and do a find and replace.

# Install Node-Red

# Download the script
curl -sL https://raw.githubusercontent.com/node-red/linux-installers/master/deb/update-nodejs-and-nodered > /tmp/update_script.sh

# Execute the downloaded script
bash /tmp/update_script.sh

# Create a new Sketch. 

Node-RED Settings File initialisation
=====================================
This tool will help you create a Node-RED settings file.

✔ Settings file · /home/ubuntu/.node-red/settings.js

User Security
=============
✔ Do you want to setup user security? · No

Projects
========
The Projects feature allows you to version control your flow using a local git repository.

✔ Do you want to enable the Projects feature? · No

Flow File settings
==================
✔ Enter a name for your flows file · flows.json
✔ Provide a passphrase to encrypt your credentials file · 

Editor settings
===============
✔ Select a theme for the editor. To use any theme other than "default", you will need to install @node-red-contrib-themes/theme-collection in your Node-RED user directory. · default

✔ Select the text editor component to use in the Node-RED Editor · monaco (default)

Node settings
=============
✔ Allow Function nodes to load external modules? (functionExternalModules) · Yes


Open the script and execute each individually to confirm it works.
Testing may still be required!!!!!
Timesketch_Importer is broken in ubuntu 22.04 and node-red does not like custom bash scripts with virtual environments so I have created a custom bash script which loads into the virtual environment and then executes a custom python script that scans for .csv and .plaso files in a folder and then imports them into timesketch using dftimewolf.
Make sure Poetry is installed and then dftimewolf.

Change the folders inside both custom scripts.


#### Node-RED Workflow to handle triage archive processing
Node-RED is a browser based flow editor which provides an easier way to achieve automation. 
[NR_DFIR](https://raw.githubusercontent.com/dterrey/AllthingsTimesketch/master/NR_DFIRFlow.json) is an automation workflow where the flow will watch for archive files created at /cases/processor directory. When new triage archive files get created (Tested with CyLR and KAPE zips) it will run an integrity check and decompress them to unique folders, parses it with Log2timeline and ingests into Timesketch. It has the ability to queue up archive files for processing. This way you have the option to control how many archive files gets processed at any given point in time. 

The Node-RED workflow contains 5 flows
1. #### Triage Artefact Processor
This is the main workflow for the automation. It consists of archive validation checks, log2timeline processing and ingestion to Timesketch.
![Node-RED Flow in Action](https://github.com/blueteam0ps/AllthingsTimesketch/blob/master/doco/NR1.png?raw=true)

2. ### Hayabusa Process
This flow runs Hayabusa over Windows event logs found in KAPE triage packages. You will need Hayabusa pre-downloaded for this to work.
![Node-RED Flow in Action](https://github.com/blueteam0ps/AllthingsTimesketch/blob/master/doco/HayabusaFlow.png?raw=true)

3. #### Detect Archive & Integrity Check
This flow is used to detect the type of archive and then run an integrity check on the archive
![Node-RED Flow in Action](https://github.com/blueteam0ps/AllthingsTimesketch/blob/master/doco/DetectArchive.jpg?raw=true)

4. #### Decompress Archive
This flow is used to detect the type of the archive and perform the relevant decompression action
![Node-RED Flow in Action](https://github.com/blueteam0ps/AllthingsTimesketch/blob/master/doco/Decompress.jpg?raw=true)

5. #### Slack Notifications
This flow is used to send notifications via Slack. You need a Slack API key for this to work.
![Node-RED Flow in Action](https://github.com/blueteam0ps/AllthingsTimesketch/blob/master/doco/slack-flow.png?raw=true)

### Timesketch
[Timesketch](https://timesketch.org/) is a core component of this project. The uses the docker version of Timesketch and Log2timeline.
[tsplaso_docker_install.sh script](https://raw.githubusercontent.com/blueteam0ps/AllthingsTimesketch/master/tsplaso_docker_install.sh) can be used to simplify install and configuration.
Note: This script was tested on the latest Ubuntu 20.04.5 Server Edition.

#### Usage instructions for the script
##IMPORTANT - This bash script uses a custom version of nginx.conf and docker-compose.yml
wget https://raw.githubusercontent.com/blueteam0ps/AllthingsTimesketch/master/tsplaso_docker_install.sh
chmod a+x ./tsplaso_docker_install.sh
sudo ./tsplaso_docker_install.sh

### Tagging file for Timesketch
A [tagging file](https://raw.githubusercontent.com/blueteam0ps/AllthingsTimesketch/master/tags.yaml) is provided as part of this repository. It is used to get most out of Timesketch (It is already part of the tsplaso_docker_install.sh script


## Pre-requisites NO LONGER REQUIRED however is the manual way if needed.
---------------------
1. Install and configure Timesketch and Log2timeline. [tsplaso_docker_install.sh script](https://raw.githubusercontent.com/blueteam0ps/AllthingsTimesketch/master/tsplaso_docker_install.sh) can assist with that. 
IMPORTANT!!! - tsplaso_docker_install.sh generates a self-signed certificate for the hostname 'localhost' and sets the nginx proxy configuration to use it.
2. Install Node-RED using the instructions given [here](https://nodered.org/docs/getting-started/). This has been tested on Ubuntu 20.04.5 LTS [About Node-RED](https://nodered.org/docs/getting-started/raspberrypi)
3. Pre-install any archiving tools on your host (i.e. unrar, 7z , unzip)
4. Pre-configure Hayabusa and update the "Hayabusa Evtx Process" in "Hayabusa Process" node
5. Enable Incoming Webhooks for your slack and update the "Notification to Slack" in "Slack Notifications" node with you webhook and the posting username 
For more information about setting up incoming webhooks in Slack can be [found here.](https://api.slack.com/messaging/webhooks)

6. This automation depends on the following additonal nodes. I recommend installing it directly via the GUI -> Manage Pallette
- node-red-contrib-fs
- node-red-contrib-fs-ops
- node-red-contrib-simple-queue
- node-red-contrib-watchdirectory
- node-red-contrib-slack-files
7. You should have the following folders pre-created on the host where this workflow is being operated.
- /cases/plaso
- /cases/processor/host-triage/
- /cases/evtxproc/
The account you are running Node-RED must have read and write permissions on /cases and its sub-folders.
8. You should have Timesketch and Log2timeline pre-installed on the same host as your Node-RED installation.
9. You should update the Log2timeline and Timesketch CLI parameters within the flow to meet your requirements.

## How to setup the workflow?
1. Download the workflow JSON and Import it using the Node-RED GUI.
https://github.com/MattETurner/AllthingsTimesketch/blob/master/NR_DFIRFlow.json

2. Update the "Timesketch CLI Params" with you Timesketch credentials
3. Update the "Queue Zips" with the amount of archives you would like to process at any given time
4. Hit Deploy Full!
5. Node-RED will watch for new files into the /cases/processor folder and it will kick off the flow
6. Install the latest rust version by following this guide - https://wiki.crowncloud.net/?How_to_Install_Rust_on_Ubuntu_22_04
7. Download the latest release of Haybusa from the github page.
8. Extract to /opt/hayabusa or if you extract it somewhere else, you will need to fix the node-red mapping of all nodes.
9. to get hayabusa running - node Hayabusa Evtx Proccess - command /home/ubuntu/hayabusa/hayabusa/./hayabusa
10. rename the GNU Linux hayabusa to just hayabusa and make it an executable
11. in terminal go to hayabasa folder and ./hayabasa set-default-profile --profile timesketch-verbose
12. sudo pip3 install timesketch-import-client

## How to setup the velociraptor server?
https://www.atlantic.net/dedicated-server-hosting/how-to-install-and-configure-velociraptor-on-ubuntu/

To give the user dfir SFTP access to the /cases/ folder at the root, you need to modify the SFTP server configuration. Here's how you can do it:

1. Modify the SFTP Configuration
Open the SSHD Configuration File:
Edit the SSHD configuration file. This file is usually located at /etc/ssh/sshd_config.

bash
Copy code
sudo nano /etc/ssh/sshd_config
Configure Chroot for the SFTP Subsystem:
Find the Subsystem sftp line and modify or add the following configuration to set up a chroot environment:

bash
Copy code
Subsystem sftp internal-sftp

Match User dfir
ChrootDirectory /cases
ForceCommand internal-sftp
AllowTcpForwarding no
This configuration will chroot the dfir user to the /cases directory and restrict their access to the SFTP subsystem only.

