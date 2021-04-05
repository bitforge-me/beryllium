import json
import base64
import struct
import os
import hashlib
import logging

import requests
import base58
import axolotl_curve25519 as curve
import sha3
import pyblake2
from flask_jsonrpc.exceptions import OtherError

from models import WavesTx
from app_core import app

CHAIN_ID = None

TYPES = dict(issue=3, transfer=4, reissue=5, setscript=13, sponsor=14)

# waves default tx fees
DEFAULT_TX_FEE = 100000
DEFAULT_ASSET_FEE = 100000000
DEFAULT_SPONSOR_FEE = 100000000
DEFAULT_SCRIPT_FEE = 1000000

# waves created transaction states
CTX_CREATED = "created"
CTX_EXPIRED = "expired"
CTX_BROADCAST = "broadcast"

# waves tx creation/broadcast response error codes
ERR_FAILED_TO_BROADCAST = 0
ERR_NO_TXID = 1
ERR_TX_EXPIRED = 2
ERR_FAILED_TO_GET_ASSET_INFO = 3
ERR_EMPTY_ADDRESS = 4

# wave specific config settings
NODE_BASE_URL = app.config["NODE_BASE_URL"]
TESTNET = app.config["TESTNET"]

logger = logging.getLogger(__name__)

def throw_error(msg):
    raise Exception(msg)

def str2bytes(string):
    # warning this method is flawed with some input
    return string.encode("latin-1")

def sign(privkey, message):
    random64 = os.urandom(64)
    return base58.b58encode(curve.calculateSignature(random64, base58.b58decode(privkey), message))

def sha256(data):
    return hashlib.sha256(data).digest()

def waves_hash(data):
    hash1 = pyblake2.blake2b(data, digest_size=32).digest()
    hash2 = sha3.keccak_256(hash1).digest()
    return hash2

def generate_address(pubkey):
    if not CHAIN_ID:
        raise Exception('CHAIN_ID not initialized')

    # convert input to bytes
    chain_id = str2bytes(CHAIN_ID)
    # decode base58 pubkey
    pubkey = base58.b58decode(pubkey)
    # create address
    address_version = bytes([1])
    address = address_version + chain_id + waves_hash(pubkey)[:20]
    checksum = waves_hash(address)[:4]
    # base58 encode pubkey
    address = base58.b58encode(address + checksum)
    return address

def transfer_asset_non_witness_bytes(pubkey, recipient, assetid, amount, attachment, fee_asset, fee, timestamp):
    if amount <= 0:
        msg = 'Amount must be > 0'
        throw_error(msg)
    else:
        sdata = b'\4' + \
            b'\2' + \
            base58.b58decode(pubkey) + \
            (b'\1' + base58.b58decode(assetid) if assetid else b'\0') + \
            (b'\1' + base58.b58decode(fee_asset) if fee_asset else b'\0') + \
            struct.pack(">Q", timestamp) + \
            struct.pack(">Q", amount) + \
            struct.pack(">Q", fee) + \
            base58.b58decode(recipient) + \
            struct.pack(">H", len(attachment)) + \
            str2bytes(attachment)
        return sdata
    return None

def transfer_asset_payload(address, pubkey, privkey, recipient, assetid, amount, attachment, fee_asset, fee, timestamp):
    signature = ""
    if privkey:
        sdata = transfer_asset_non_witness_bytes(pubkey, recipient, assetid, amount, attachment, fee_asset, fee, timestamp)
        signature = sign(privkey, sdata)
    return {
        "type": 4,
        "version": 2,
        "senderPublicKey": pubkey,
        "recipient": recipient,
        "assetId": (assetid if assetid else ""),
        "feeAssetId": (fee_asset if fee_asset else ""),
        "amount": amount,
        "fee": fee,
        "timestamp": timestamp,
        "attachment": base58.b58encode(str2bytes(attachment)),
        "proofs": [
            signature
        ]
    }

def issue_asset_non_witness_bytes(pubkey, name, description, quantity, script, decimals, reissuable, fee, timestamp):
    if len(name) < 4 or len(name) > 16:
        msg = 'Asset name must be between 4 and 16 characters long'
        throw_error(msg)
    else:
        # it looks like script can always be 'None' (might be a bug)
        if script:
            raw_script = base64.b64decode(script)
            script_len = len(raw_script)
        sdata = b'\3' + \
            b'\2' + \
            str2bytes(str(CHAIN_ID)) + \
            base58.b58decode(pubkey) + \
            struct.pack(">H", len(name)) + \
            str2bytes(name) + \
            struct.pack(">H", len(description)) + \
            str2bytes(description) + \
            struct.pack(">Q", quantity) + \
            struct.pack(">B", decimals) + \
            (b'\1' if reissuable else b'\0') + \
            struct.pack(">Q", fee) + \
            struct.pack(">Q", timestamp) + \
            (b'\1' + struct.pack(">H", script_len) + raw_script if script else b'\0')
        return sdata
    return None

def issue_asset_payload(address, pubkey, privkey, name, description, quantity, script, decimals, reissuable, fee, timestamp):
    signature = ""
    if privkey:
        sdata = issue_asset_non_witness_bytes(pubkey, name, description, quantity, script, decimals, reissuable, fee, timestamp)
        signature = sign(privkey, sdata)
    return {
        "type": 3,
        "version": 2,
        "senderPublicKey": pubkey,
        "name": name,
        "description": description,
        "quantity": quantity,
        "decimals": decimals,
        "reissuable": reissuable,
        "fee": fee,
        "timestamp": timestamp,
        "proofs": [
            signature
        ]
    }

def reissue_asset_non_witness_bytes(pubkey, assetid, quantity, reissuable, fee, timestamp):
    sdata = b'\5' + \
        b'\2' + \
        str2bytes(str(CHAIN_ID)) + \
        base58.b58decode(pubkey) + \
        base58.b58decode(assetid) + \
        struct.pack(">Q", quantity) + \
        (b'\1' if reissuable else b'\0') + \
        struct.pack(">Q",fee) + \
        struct.pack(">Q", timestamp)
    return sdata

def reissue_asset_payload(address, pubkey, privkey, assetid, quantity, reissuable, fee, timestamp):
    signature = ""
    if privkey:
        sdata = reissue_asset_non_witness_bytes(pubkey, assetid, quantity, reissuable, fee, timestamp)
        signature = sign(privkey, sdata)
    return {
        "type": 5,
        "version": 2,
        "senderPublicKey": pubkey,
        "assetId": assetid,
        "quantity": quantity,
        "timestamp": timestamp,
        "reissuable": reissuable,
        "fee": fee,
        "proofs": [
            signature
        ]
    }

def sponsor_non_witness_bytes(pubkey, asset_id, minimal_fee_in_assets, fee, timestamp):
    sdata = b'\x0e' + \
        b'\1' + \
        base58.b58decode(pubkey) + \
        base58.b58decode(asset_id) + \
        struct.pack(">Q", minimal_fee_in_assets) + \
        struct.pack(">Q", fee) + \
        struct.pack(">Q", timestamp)
    return sdata

def sponsor_payload(address, pubkey, privkey, asset_id, minimal_fee_in_assets, fee, timestamp):
    signature = ""
    if privkey:
        sdata = sponsor_non_witness_bytes(pubkey, asset_id, minimal_fee_in_assets, fee, timestamp)
        signature = sign(privkey, sdata)

    return {
        "type": 14,
        "version": 1,
        "senderPublicKey": pubkey,
        "assetId": asset_id,
        "fee": fee,
        "timestamp": timestamp,
        "minSponsoredAssetFee": minimal_fee_in_assets,
        "proofs": [
            signature
        ]
    }

def set_script_non_witness_bytes(pubkey, script, fee, timestamp):
    if script:
        if script.startswith('base64:'):
            script = script[7:]
        raw_script = base64.b64decode(script)
        script_len = len(raw_script)
    sdata = b'\x0d' + \
        b'\1' + \
        str2bytes(str(CHAIN_ID)) + \
        base58.b58decode(pubkey) + \
        (b'\1' + struct.pack(">H", script_len) + raw_script if script else b'\0') + \
        struct.pack(">Q", fee) + \
        struct.pack(">Q", timestamp)
    return sdata

def set_script_payload(address, pubkey, privkey, script, fee, timestamp):
    signature = ""
    if privkey:
        sdata = set_script_non_witness_bytes(pubkey, script, fee, timestamp)
        signature = sign(privkey, sdata)

    return {
        "type": 13,
        "version": 1,
        "senderPublicKey": pubkey,
        "fee": fee,
        "timestamp": timestamp,
        "script": ('base64:' + script if script else None),
        "proofs": [
            signature
        ]
    }

def tx_init_chain_id(testnet):
    global CHAIN_ID # pylint: disable=global-statement
    if testnet:
        CHAIN_ID = 'T'
    else:
        CHAIN_ID = 'W'

def tx_serialize(txn):
    if not CHAIN_ID:
        raise Exception('CHAIN_ID not initialized')

    # serialize
    type_ = txn["type"]
    if type_ == 4:
        print(":: transfer tx")
        data = transfer_asset_non_witness_bytes(txn["senderPublicKey"], txn["recipient"], txn["assetId"], \
            txn["amount"], txn["attachment"], txn["feeAssetId"], txn["fee"], txn["timestamp"])
    elif type_ == 3:
        print(":: issue tx")
        data = issue_asset_non_witness_bytes(txn["senderPublicKey"], txn["name"], txn["description"], \
            txn["quantity"], None, txn["decimals"], txn["reissuable"], txn["fee"], txn["timestamp"])
    elif type_ == 5:
        print(":: reissue tx")
        data = reissue_asset_non_witness_bytes(txn["senderPublicKey"], txn["assetId"], txn["quantity"], \
            txn["reissuable"], txn["fee"], txn["timestamp"])
    elif type_ == 14:
        print(":: sponsor tx")
        data = sponsor_non_witness_bytes(txn["senderPublicKey"], txn["assetId"], \
            txn["minSponsoredAssetFee"], txn["fee"], txn["timestamp"])
    elif type_ == 13:
        print(":: set script tx")
        data = set_script_non_witness_bytes(txn["senderPublicKey"], txn["script"], txn["fee"], \
            txn["timestamp"])
    else:
        return None

    return data

def post(host, api, data):
    return requests.post('%s%s' % (host, api), data=data, headers={'content-type': 'application/json'}).json()

def get(host, api):
    return requests.get('%s%s' % (host, api)).json()

def broadcast_tx(host, data):
    return post(host, "/transactions/broadcast", data)

def get_fee(host, default_fee, address, user_provided_fee):
    fee = default_fee
    if user_provided_fee:
        fee = user_provided_fee
    else:
        try:
            data = get(host, f"/addresses/scriptInfo/{address}")
            if "error" in data:
                throw_error(f"unable to check script fees on address ({address})")
            else:
                fee += data["extraFee"]
        except: # pylint: disable=bare-except
            throw_error(f"unable to check script fees on address ({address})")

    return fee

def txid_from_txdata(serialized_txdata):
    txid = pyblake2.blake2b(serialized_txdata, digest_size=32).digest()
    return base58.b58encode(txid)

def tx_to_txid(txn):
    logger.info("tx_to_txid - tx: %s", str(txn))
    tx_init_chain_id(TESTNET)
    return txid_from_txdata(tx_serialize(txn))

def broadcast_transaction(session, txid):
    dbtx = WavesTx.from_txid(session, txid)
    if not dbtx:
        raise OtherError("transaction not found", ERR_NO_TXID)
    if dbtx.state == CTX_EXPIRED:
        raise OtherError("transaction expired", ERR_TX_EXPIRED)
    signed_tx = dbtx.tx_with_sigs()
    logger.info("broadcasting tx: %s", str(signed_tx))
    # broadcast
    logger.debug("requesting broadcast of tx:\n\t%s, ", str(signed_tx))
    path = "/transactions/broadcast"
    headers = {"Content-Type": "application/json"}
    response = requests.post(NODE_BASE_URL + path, headers=headers, data=json.dumps(signed_tx))
    if response.ok:
        # update tx in db
        dbtx.state = CTX_BROADCAST
    else:
        short_msg = "failed to broadcast"
        logger.error("%s: (%d, %s, %s):\n\t%s", short_msg, response.status_code, response.request.method, response.url, response.text)
        err = OtherError(short_msg, ERR_FAILED_TO_BROADCAST)
        err.data = response.text
        raise err
    return dbtx
