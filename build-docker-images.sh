#!/bin/bash

set -e

(cd clightning_bitcoin; docker build -t clightning_bitcoin .)
docker build -t beryllium_app .
