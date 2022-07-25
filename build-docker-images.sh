#!/bin/bash

set -e

docker build -t lightningd lightningd
docker build -t be_app .
docker build -t telegraf telegraf
