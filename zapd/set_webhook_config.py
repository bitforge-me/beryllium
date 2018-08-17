#!/usr/bin/python3

import sys
import config

cfg = config.read_cfg()

webhook_url = sys.argv[1]
webhook_key = sys.argv[2]

config.set_webhook_config(webhook_url, webhook_key)
