#!/bin/bash
set -e

### generate the telegraf.conf with jinja2 
jinja2 /telegraf.conf.j2 > "/etc/telegraf/telegraf.conf"

### everything else is default from the entrypoint.sh based on the image.
### added below to replace the entrypoint.sh with the entrypoint-shim.sh. If tried to run ./entrypoint.sh it with a privilege errors
if [ "${1:0:1}" = '-' ]; then
    set -- telegraf "$@"
fi

if [ $EUID -ne 0 ]; then
    exec "$@"
else
    # Allow telegraf to send ICMP packets and bind to privliged ports
    setcap cap_net_raw,cap_net_bind_service+ep /usr/bin/telegraf || echo "Failed to set additional capabilities on /usr/bin/telegraf"

    exec setpriv --reuid telegraf --init-groups "$@"
fi
