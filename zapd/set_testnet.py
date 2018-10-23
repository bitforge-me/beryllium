#!/usr/bin/python3

import sys
import config

cfg = config.read_cfg()

value = sys.argv[1]

config.set_testnet(value)
