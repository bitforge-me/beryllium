#!/bin/bash

set -e

(cd web; docker build -t beryllium_web .)
docker build -t beryllium_app .
