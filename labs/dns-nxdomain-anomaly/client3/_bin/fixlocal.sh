#!/bin/bash
# Runs once, after parameterization. $1 = user password.

password="$1"
log_file=/tmp/fixlocal.output
services="benign dga"

echo "fixlocal start $(date)" >> "$log_file"

if ! printf '%s\n' "$password" | sudo -S true 2>> "$log_file"; then
    echo "Could not authenticate sudo. Check $log_file."
    exit 1
fi

mkdir -p /home/ubuntu/logs

# The units start after waitparam.service; mark parameterization as done.
sudo mkdir -p /var/labtainer/did_param

for svc in $services; do
    if ! sudo systemctl enable "$svc" >> "$log_file" 2>&1; then
        echo "Could not enable $svc. Check $log_file."
        exit 1
    fi
    if ! sudo systemctl start "$svc" >> "$log_file" 2>&1; then
        echo "Could not start $svc. Check $log_file."
        exit 1
    fi
done

echo "fixlocal done $(date)" >> "$log_file"
