#!/bin/bash

set -e

docker build -t be_app .
docker stop be_app
docker rm be_app
docker compose up -d
docker logs be_app -f