#!/bin/bash

dest_email={{ ALERT_EMAIL }}
max_height_diff=2

remote_block=`curl -s https://{{ REMOTE_WAVES_NODES }}/blocks/height | jq '.["height"]'` 
local_block=`curl -s localhost:6869/blocks/height | jq '.["height"]'`
zapd_scanned_block_height=`curl -s -d '{"jsonrpc":"2.0","id":1,"method":"status","params":{}}' -H "Content-Type: application/json-rpc" localhost:5000/api | jq '.["result"]["scanned_block_height"]'`

### Condition to compare two values.
num=$(( $remote_block - $local_block ))
if [ $num -lt 0 ]; then
	num=$((-$num))
fi
if [ $num -ge $max_height_diff ]; then
	echo "The remote node is at $remote_block while the local node is at $local_block." | mail -s "The nodes are not synced" $dest_email
else
	exit
fi
num=$(( $remote_block - $zapd_scanned_block_height ))
if [ $num -lt 0 ]; then
	num=$((-$num))
fi
if [ $num -ge $max_height_diff ]; then
	echo "The remote node is at $remote_block while the zapd scanned height is at $zapd_scanned_block_height." | mail -s "The zapd scanned block height is behind" $dest_email
else
	exit
fi
