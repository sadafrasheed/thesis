#!/bin/bash

# Get the container name
#export CLIENT_ID=$(cat /etc/hostname)

echo "Client ID: $CLIENT_ID"

cd /app

#source venv/bin/activate
sleep $(shuf -i 2-5 -n 1)
# Run the second script in the foreground
python3 -m client.actions register

# Run the first script in the background (daemon)
python3 -m client.listen 
#tail -f /dev/null