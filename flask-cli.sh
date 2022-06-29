#!/bin/bash

docker exec -it -e FLASK_APP=src/app.py be_app flask "$@"
