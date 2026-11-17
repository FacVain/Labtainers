#!/bin/bash
# Runs once, after parameterization. $1 = user password.
mkdir -p /home/ubuntu/logs
PERMLOCKDIR=/var/labtainer/did_param
sudo mkdir -p "$PERMLOCKDIR"
for svc in web; do
    sudo systemctl enable $svc
    sudo systemctl start $svc
done
