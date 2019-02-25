#!/bin/bash


bal=`curl -s -d '{"jsonrpc":"2.0","id":1,"method":"getbalance","params":{}}' -H "Content-Type: application/json-rpc" localhost:5000/api | jq '.["result"]["balance"]'`
zap_bal=$(( bal / 100 ))

min_bal={{ min_zap }}
max_bal={{ max_zap }}
dest_email={{ ALERT_EMAIL }}


if [ $zap_bal -lt $min_bal ]; then
        echo "balance $zap_bal is less than {{ min_zap }} ZAP" | mail -s "The balance is less than {{ min_zap }} ZAP" $dest_email
elif [ $zap_bal -gt $max_bal ]; then
        echo "balance $zap_bal is greater than {{ max_zap }} ZAP" | mail -s "The balance is greater than {{ max_zap }} ZAP" $dest_email
else
        exit
fi

exit
