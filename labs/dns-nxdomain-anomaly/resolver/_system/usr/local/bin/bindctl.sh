#!/bin/bash
action="$1"
zone="$2"

restart_bind() {
    if systemctl restart named 2>/dev/null; then
        return 0
    elif systemctl restart bind9 2>/dev/null; then
        return 0
    elif /etc/init.d/named restart 2>/dev/null; then
        return 0
    else
        /etc/init.d/bind9 restart
        return $?
    fi
}

if [ "$action" = "restart" ]; then
    restart_bind
    exit $?
elif [ "$action" = "reload" ]; then
    if [ -n "$zone" ]; then
        rndc reload "$zone" 2>/dev/null
    else
        rndc reload 2>/dev/null
    fi
    reload_status=$?

    if [ "$reload_status" -ne 0 ]; then
        restart_bind
        exit $?
    fi
else
    echo "usage: bindctl.sh restart|reload [zone]"
    exit 1
fi
