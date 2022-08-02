#!/usr/bin/env bash

# set wallet parameter
networkdatadir="${LIGHTNINGD_DATA}/${LIGHTNINGD_NETWORK}"
wallet="sqlite3://$networkdatadir/lightningd.sqlite3"
# if LIGHTNINGD_REPLICA environment parameter present we will replicate the DB
if [ -n "$LIGHTNINGD_REPLICA" ]; then
  wallet="$wallet:/root/.lightning_replica/lightningd.sqlite3"
fi

# move rebalance plugin into place
mkdir "${LIGHTNINGD_DATA}/plugins"
cp "${LN_WORK}/rebalance.py" "${LIGHTNINGD_DATA}/plugins/rebalance.py"

# process config template
jinja2 "${LN_WORK}/config.j2" > "${LIGHTNINGD_DATA}/config"

# run upstream entrypoint.sh script with 'wallet' parameter
./entrypoint.sh --wallet "$wallet" "$@"