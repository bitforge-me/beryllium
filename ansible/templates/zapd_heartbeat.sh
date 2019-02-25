#!/bin/bash

dest_email={{ ALERT_EMAIL }}
app_port=5000
app="zapd"
host="localhost"

curl -s ${host}:${app_port} > /dev/null

if [ $? -ne 0 ]; then
        echo "ZAPD is not responding on port ${app_port}." | mail -s "ZAPD not responding on port ${app_port}" $dest_email
        exit
else
        exit
fi

