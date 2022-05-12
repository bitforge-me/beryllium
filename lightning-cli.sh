#!/bin/bash

docker exec lightningd lightning-cli --rpc-file /root/.lightning/lightning-rpc "$@"
