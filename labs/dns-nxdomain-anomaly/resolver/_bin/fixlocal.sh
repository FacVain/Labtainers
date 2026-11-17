#!/bin/bash

password="$1"
log_file=/tmp/fixlocal.output

echo "fixlocal start $(date)" >> "$log_file"

if ! printf '%s\n' "$password" | sudo -S true 2>> "$log_file"; then
    echo "Could not authenticate sudo. Check $log_file."
    exit 1
fi

# This container uses its own DNS server.
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf > /dev/null

mkdir -p /home/ubuntu/logs

# Register the parameterized C2 name in the .lab zone.
if ! sudo /usr/local/bin/c2setup.sh >> "$log_file" 2>&1; then
    echo "Could not register the C2 name. Check $log_file."
    exit 1
fi

if ! sudo chown -R bind:bind /etc/bind/zones >> "$log_file" 2>&1; then
    echo "Could not set zone ownership. Check $log_file."
    exit 1
fi

if ! sudo named-checkconf >> "$log_file" 2>&1; then
    echo "BIND configuration is invalid. Check $log_file."
    exit 1
fi

if ! sudo /usr/local/bin/bindctl.sh restart >> "$log_file" 2>&1; then
    echo "BIND could not start. Check $log_file."
    exit 1
fi

echo "fixlocal done $(date)" >> "$log_file"
