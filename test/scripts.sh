#!/bin/bash
 
# Set up credentials and host variables
USER="policyadmin"
PASSWORD="zb!XztG34"
HOST="localhost"
 
# Exit immediately if a command exits with a non-zero status
set -e
 
# Step 1: Create a Policy
echo "Creating a new policy..."
sleep 40
curl -u "$USER:$PASSWORD" --header "Content-Type: application/yaml" \
     -X POST --data-binary @policy-new.yaml \
     http://policy-api:6969/policy/api/v1/policytypes
echo "Policy created successfully. Check policy-api logs for details."
 
# Step 2: Create Groups
echo "Creating groups..."
curl -u "$USER:$PASSWORD" --header "Content-Type: application/json" \
     -X POST --data-binary @Opagroup.json \
     http://policy-pap:6969/policy/pap/v1/pdps/groups/batch
 
echo "Groups created successfully. Check policy-pap logs for details."
 
echo "Script execution completed."
