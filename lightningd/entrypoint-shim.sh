#!/usr/bin/env bash

networkdatadir="${LIGHTNINGD_DATA}/${LIGHTNINGD_NETWORK}"
wallet="sqlite3://$networkdatadir/lightningd.sqlite3"

if [ -n "$LIGHTNINGD_REPLICA" ]; then
  wallet="$wallet:/root/.lightning_replica/lightningd.sqlite3"
fi

./entrypoint.sh --wallet "$wallet" "$@"