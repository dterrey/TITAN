#node_red_install.sh

#!/usr/bin/expect -f

# Set timeout for expect commands
set timeout -1
set password $env(PASSWORD)
set username $env(USERNAME)
set basedir $env(BASE_DIR)

# Ensure the update script exists
if {![file exists "/tmp/update_script.sh"]} {
    puts "Error: /tmp/update_script.sh does not exist."
    exit 1
}

# Add necessary options to avoid prompts
set UPDATE_SCRIPT_OPTIONS "--confirm-root --confirm-install --skip-pi --no-init --nodered-user=$username --restart"

# Run the Node-RED install script with automated responses
spawn sudo -u $username bash -c "bash /tmp/update_script.sh $UPDATE_SCRIPT_OPTIONS"
expect {
    "*?assword for $username:*" {pip install PyPDF2

        send_user "\nSending password for $username: $password\n"
        send "$password\r"
        exp_continue
    }
    eof
}

# Wait for Node-RED to be fully started
sleep 20

# Path to the flow file
set flow_file "$basedir/titan/titan_NR_Flow.json"

# Create a temporary shell script for the curl command
set temp_curl_script "/tmp/import_nodered_flow.sh"
set curl_command "curl -X POST http://localhost:1880/flows -H \"Content-Type: application/json\" --data-binary @$flow_file"
spawn bash -c "echo '#!/bin/bash\n$curl_command' > $temp_curl_script"
expect eof

# Verify the content of the temporary shell script
spawn cat $temp_curl_script
expect eof

# Make the temporary shell script executable
spawn chmod +x $temp_curl_script
expect eof

# Run the temporary shell script to import the flow
spawn bash $temp_curl_script
expect {
    eof
}
