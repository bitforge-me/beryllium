#!/bin/bash
set -e
set -a # export all variables

# split $TELEGRAF_NAME_DB_USER_PASS using | as the field seperator
IFS="|" read TELEGRAF_NAME TELEGRAF_DB TELEGRAF_USER TELEGRAF_PASS <<< "$TELEGRAF_NAME_DB_USER_PASS"
# generate the telegraf.conf with jinja2
echo using name $TELEGRAF_NAME, db $TELEGRAF_DB, user $TELEGRAF_USER, pass \*\*\* and url $TELEGRAF_INFLUXDB_URL to create \'telegraf.conf\'
jinja2 /tmp/telegraf.conf.j2 > "/etc/telegraf/telegraf.conf"

# run the upstream entrypoint.sh
./entrypoint.sh "$@"