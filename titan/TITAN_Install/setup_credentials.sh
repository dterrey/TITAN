#setup_credentials.sh

#!/bin/bash

# Prompt for username and password
read -p "Enter your username: " USERNAME
read -sp "Enter your password: " PASSWORD
echo

# Export variables for use in other scripts
export USERNAME
export PASSWORD

# Replace default username and password in all files
find /path/to/your/files -type f -exec sed -i "s/titan/$USERNAME/g" {} \;
find /path/to/your/files -type f -exec sed -i "s/admin/$PASSWORD/g" {} \;

echo "Username and password have been updated in all relevant files."
