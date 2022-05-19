#!/usr/bin/env bash

: "${EXPOSE_TCP:=false}"

networkdatadir="${LIGHTNINGD_DATA}/${LIGHTNINGD_NETWORK}"
channel_backup="${LIGHTNINGD_CHANNEL_BACKUP}"

if [ "$EXPOSE_TCP" == "true" ]; then
    set -m
    lightningd --wallet="${channel_backup}" "$@" &

    echo "Core-Lightning starting"
    while read -r i; do if [ "$i" = "lightning-rpc" ]; then break; fi; done \
    < <(inotifywait -e create,open --format '%f' --quiet "${networkdatadir}" --monitor)
    echo "Core-Lightning started"
    echo "Core-Lightning started, RPC available on port $LIGHTNINGD_RPC_PORT"

    socat "TCP4-listen:$LIGHTNINGD_RPC_PORT,fork,reuseaddr" "UNIX-CONNECT:${networkdatadir}/lightning-rpc" &
    fg %-
else
    exec lightningd --wallet="${channel_backup}" --network="${LIGHTNINGD_NETWORK}" "$@"
fi
