#!/usr/bin/python3

import sys
import json
import random

import requests

url = "http://localhost:5000/api"

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
    response = session.post(url, data)
    print(response)
    return response.json()

print(request("balance", {}))
print(request("listtransactions", {"invoice_id": 123}))
res = request("createtransaction", {"recipient": "3NAbEPpnw2YmZ3axaPFAXW5LG9R6jJip69e", "amount": 10, "attachment": ""})
print(res)
if not "error" in res:
    print(request("broadcasttransaction", {"txid": res["result"]["txid"]}))
print(request("expiretransactions", {}))
