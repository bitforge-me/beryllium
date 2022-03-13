#!/bin/bash

set -e

docker build -t clightning_bitcoin clightning_bitcoin
docker build -t beryllium_app .
