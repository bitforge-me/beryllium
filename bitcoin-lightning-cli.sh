#!/bin/bash

docker exec clightning_bitcoin lightning-cli --rpc-file /root/.lightning/lightning-rpc "$@"
