#!/usr/bin/python3

import sys
import json
import random

import requests
from requests.auth import HTTPBasicAuth

url = "http://localhost:5000/api"
#url = "https://testnet.zap.me/api"

def serialize(method_name, params, is_notification):
    data = {"jsonrpc": "2.0", "method": method_name}
    if params:
        data["params"] = params
    if not is_notification:
        # some JSON-RPC servers complain when receiving str(uuid.uuid4()). Let's pick something simpler.
        data["id"] = random.randint(1, sys.maxsize)
    return json.dumps(data)

def request(method_name, params):
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json-rpc",
    })
    data = serialize(method_name, params, False)
    response = session.post(url, data, auth=HTTPBasicAuth("zapd", "s5d4qDHNfmqoEigiSbE6"))
    print(response)
    return response.json()

def print_request(function, params={}):
    print(f"::{function}")
    res = request(function, params)
    print(res)
    print("---\n")
    return res

print_request("status")
print_request("getaddress")
print_request("getbalance")
print_request("listtransactions", {"invoice_id": 123})
print_request("listtransactions", {})
print_request("listtransactions", {"start_date": 1531973964278})
print_request("listtransactions", {"end_date":   1531973964278})
print_request("listtransactions", {"offset": 1})
print_request("listtransactions", {"limit": 1})
res = print_request("createtransaction", {"recipient": "3NAbEPpnw2YmZ3axaPFAXW5LG9R6jJip69e", "amount": 10, "attachment": ""})
if not "error" in res:
    print_request("broadcasttransaction", {"txid": res["result"]["txid"]})
    print_request("gettransaction", {"txid": res["result"]["txid"]})
print_request("expiretransactions", {})
