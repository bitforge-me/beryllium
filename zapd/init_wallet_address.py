#!/usr/bin/python3

import sys
import time

import requests

import config

base_url = "http://localhost:6869/"

def wait_for_waves_node(seconds=60):
    start = time.time()
    while time.time() < start + seconds:
        try:
            response = requests.get(base_url)
            if response.ok:
                return True
        except Exception as ex:
            print(ex)
        time.sleep(2)
    return False

def get_waves_address():
    response = requests.get(base_url + "addresses")
    if response.ok:
        addresses = response.json()
        if len(addresses) > 0:
            return addresses[0]

if not wait_for_waves_node():
    print("ERROR: waves node not reachable at " + base_url)
    sys.exit(1)

address = get_waves_address()
if address:
    print("Found waves address " + address)
    config.init_wallet_address(address)
else:
    print("ERROR: waves address not found")
    sys.exit(2)
