#!/bin/bash

set -e

docker build -t lightningd lightningd
docker build -t be_app .
