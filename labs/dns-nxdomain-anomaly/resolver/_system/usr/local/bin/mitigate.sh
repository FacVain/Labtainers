#!/bin/bash
# mitigate.sh quarantine|release <ip>
# mitigate.sh list
set -e

zone=/etc/bind/zones/db.rpz.local
log=/home/ubuntu/logs/response.log
new_file="$zone.new"
action="$1"
ip="$2"

current_ips() {
    awk '/; quarantine / {print $NF}' "$zone"
}

if [ "$action" = "list" ] && [ "$#" -eq 1 ]; then
    current_ips
    exit 0
fi

if [ "$#" -ne 2 ]; then
    echo "usage: mitigate.sh quarantine|release <ip> | list"
    exit 1
fi
if [ "$action" != "quarantine" ] && [ "$action" != "release" ]; then
    echo "usage: mitigate.sh quarantine|release <ip> | list"
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo."
    exit 1
fi

# Ipv4
if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid IPv4 address: $ip"
    exit 1
fi

IFS=. read -r a b c d <<< "$ip"
for part in "$a" "$b" "$c" "$d"; do

    if [[ ! "$part" =~ ^(0|[1-9][0-9]{0,2})$ ]]; then
        echo "Invalid IPv4 address: $ip"
        exit 1
    fi
    if [ "$part" -gt 255 ]; then
        echo "Invalid IPv4 address: $ip"
        exit 1
    fi
done

# Open lock file as 9, then wait for exclusive access
exec 9>/run/lock/nxlab-rpz.lock
flock -x 9

saved_ips=$(current_ips)
ips=""
found=0
for item in $saved_ips; do
    if [ "$item" = "$ip" ]; then
        found=1
        if [ "$action" = "release" ]; then
            continue
        fi
    fi
    ips="$ips $item"
done

# Add IP if it is not in the list.
if [ "$action" = "quarantine" ] && [ "$found" -eq 0 ]; then
    ips="$ips $ip"
fi

# BIND needs a larger serial number for each update.
old_serial=$(awk '/ IN SOA / {print $7; exit}' "$zone")
if [[ ! "$old_serial" =~ ^[0-9]+$ ]]; then
    echo "Could not read the policy serial."
    exit 1
fi
serial=$(date +%s)
if [ "$serial" -le "$old_serial" ]; then
    serial=$((old_serial + 1))
fi

# Write and check the new zone before replacing the current one.
# Remove the temporary file when the script exits
trap 'rm -f -- "$new_file"' EXIT
echo '$TTL 60' > "$new_file"
echo "@ IN SOA localhost. root.localhost. ( $serial 3600 600 86400 60 )" >> "$new_file"
echo "  IN NS localhost." >> "$new_file"
for item in $ips; do
    IFS=. read -r a b c d <<< "$item"
    echo "32.$d.$c.$b.$a.rpz-client-ip CNAME . ; quarantine $item" >> "$new_file"
done

if ! named-checkzone rpz.local "$new_file" > /dev/null; then
    echo "New policy is invalid. The current policy was not changed."
    exit 1
fi
chown bind:bind "$new_file"
chmod 644 "$new_file"
mv "$new_file" "$zone"

if ! /usr/local/bin/bindctl.sh reload rpz.local; then
    echo "Policy file updated, but BIND reload failed. Check BIND before retrying."
    exit 1
fi

mkdir -p /home/ubuntu/logs
if [ "$action" = "quarantine" ]; then
    echo "$(date +%s) QUARANTINE $ip" | tee -a "$log"
else
    echo "$(date +%s) RELEASE $ip" | tee -a "$log"
fi
