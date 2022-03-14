#!/bin/bash

docker exec bitcoind bitcoin-cli -datadir="/data" "$@"
