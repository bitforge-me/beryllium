#!/usr/bin/python3

import pywaves as pw
import config

cfg = config.read_cfg()

# set pywaves to offline mode and set the chain id
pw.setOffline()
if cfg.testnet:
    pw.setChain("testnet")

if cfg.seed:
    print("Seed already exists")
    address = pw.Address(seed=cfg.seed)
else:
    address = pw.Address()

if address:
    print("Created waves address " + address.address)
    config.init_wallet_address(address.address, address.seed)
else:
    print("ERROR: waves address not found")
    sys.exit(2)
