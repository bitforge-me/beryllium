#!/usr/bin/python3

# pylint: disable=invalid-name
# pylint: disable=unused-variable

import sys
import argparse
import time
import json
import logging

import requests
import socketio

from web_utils import create_hmac_sig
from utils import log_socketio_version, setup_logging

logger = logging.getLogger(__name__)

URL_BASE = "http://localhost:5000/"
WS_URL = "ws://localhost:5000/"

EXIT_NO_COMMAND = 1

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")

    ## Websocket

    parser_ws = subparsers.add_parser("websocket", help="Listen to a websocket")
    parser_ws.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_ws.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    ## REST commands

    parser_api_key_create = subparsers.add_parser("api_key_create", help="Create an api key with your username and password")
    parser_api_key_create.add_argument("email", metavar="EMAIL", type=str, help="email")
    parser_api_key_create.add_argument("password", metavar="PASSWORD", type=str, help="password")
    parser_api_key_create.add_argument("device_name", metavar="DEVICE_NAME", type=str, help="the device name for the api key")

    parser_user_info = subparsers.add_parser("user_info", help="Get the user info")
    parser_user_info.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_info.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_user_update_email = subparsers.add_parser("user_update_email", help="Update user email")
    parser_user_update_email.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_update_email.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_user_update_email.add_argument("email", metavar="EMAIL", type=str, help="the email address to change to")

    parser_user_update_photo = subparsers.add_parser("user_update_photo", help="Update user photo and photo_type")
    parser_user_update_photo.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_update_photo.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_user_update_photo.add_argument("photo", metavar="PHOTO", type=str, help="user photo")
    parser_user_update_photo.add_argument("photo_type", metavar="PHOTO_TYPE", type=str, help="type of photo")

    parser_transaction_create = subparsers.add_parser("transaction_create", help="Create a transaction")
    parser_transaction_create.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_transaction_create.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_transaction_create.add_argument("action", metavar="ACTION", type=str, help="the transaction action")
    parser_transaction_create.add_argument("recipient", metavar="RECIPIENT", type=str, help="the transaction recipient")
    parser_transaction_create.add_argument("amount", metavar="AMOUNT", type=int, help="the transaction amount (integer, cents)")
    parser_transaction_create.add_argument("attachment", metavar="ATTACHMENT", type=str, help="the transaction attachment")

    parser_transaction_info = subparsers.add_parser("transaction_info", help="Get transaction info")
    parser_transaction_info.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_transaction_info.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_transaction_info.add_argument("token", metavar="TOKEN", type=str, help="the unique transaction token")

    parser_payment_create = subparsers.add_parser("payment_create", help="Create a token distribution payment (magic link)")
    parser_payment_create.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_payment_create.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_payment_create.add_argument("reason", metavar="REASON", type=str, help="the reason for the payment")
    parser_payment_create.add_argument("category", metavar="CATEGORY", type=str, help="the category of the payment")
    parser_payment_create.add_argument("recipient", metavar="RECIPIENT", type=str, help="the recipient of the payment")
    parser_payment_create.add_argument("amount", metavar="AMOUNT", type=int, help="the payment amount (integer, cents)")
    parser_payment_create.add_argument("message", metavar="MESSAGE", type=str, help="the message for the recipient")

    parser_stash_save = subparsers.add_parser("stash_save", help="Save a user stash")
    parser_stash_save.add_argument("key", metavar="KEY", type=str, help="The name of the stash")
    parser_stash_save.add_argument("email", metavar="EMAIL", type=str, help="The email address to send confirmation")
    parser_stash_save.add_argument("iv", metavar="IV", type=str, help="IV")
    parser_stash_save.add_argument("cyphertext", metavar="CYPHERTEXT", type=str, help="cyphertext")
    parser_stash_save.add_argument("question", metavar="QUESTION", type=str, help="question")

    parser_stash_save_check = subparsers.add_parser("stash_save_check", help="Check a user stash request")
    parser_stash_save_check.add_argument("token", metavar="TOKEN", type=str, help="The request token")

    return parser

def req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    if api_key_token:
        if not params:
            params = {}
        params["nonce"] = int(time.time())
        params["api_key"] = api_key_token
    url = URL_BASE + endpoint
    if params:
        headers = {"Content-type": "application/json"}
        body = json.dumps(params)
        if api_key_token:
            headers["X-Signature"] = create_hmac_sig(api_key_secret, body)
        print("   POST - " + url)
        r = requests.post(url, headers=headers, data=body)
    else:
        print("   GET - " + url)
        r = requests.get(url)
    return r

def paydb_req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    return req('paydb/' + endpoint, params, api_key_token, api_key_secret)

def stash_req(endpoint, params=None):
    return req('stash/' + endpoint, params)

def check_request_status(r):
    try:
        r.raise_for_status()
    except Exception as e:
        print("::ERROR::")
        print(str(r.status_code) + " - " + r.url)
        print(r.text)
        raise e

def websocket(args):
    print(":: calling websocket..")
    ns = '/paydb'
    # open websocket
    sio = socketio.Client()
    @sio.event(namespace=ns)
    def connect():
        print("connection established")
        print("authenticating with api key", args.api_key_token)
        # create auth data
        nonce = int(time.time())
        sig = create_hmac_sig(args.api_key_secret, str(nonce))
        auth = {"signature": sig, "api_key": args.api_key_token, "nonce": nonce}
        # emit auth message
        sio.emit("auth", auth, namespace=ns)

    @sio.event(namespace=ns)
    def info(data):
        print("info event received:", data)

    @sio.event(namespace=ns)
    def tx(data):
        print("tx event received:", data)

    @sio.event(namespace=ns)
    def disconnect():
        print("disconnected from server")

    sio.connect(WS_URL, namespaces=[ns])
    sio.wait()

def api_key_create(args):
    print(":: calling api_key_create..")
    r = paydb_req("api_key_create", {"email": args.email, "password": args.password, "device_name": args.device_name})
    check_request_status(r)
    print(r.text)

def user_info(args):
    print(":: calling user_info..")
    r = paydb_req("user_info", {"email": None}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_email(args):
    print(":: calling user_update_email..")
    r = paydb_req("user_update_email", {"email": args.email}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_photo(args):
    print(":: calling user_update_photo..")
    r = paydb_req("user_update_photo", {"photo": args.photo, "photo_type": args.photo_type}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def transaction_create(args):
    print(":: calling transaction_create..")
    r = paydb_req("transaction_create", {"action": args.action, "recipient": args.recipient, "amount": args.amount, "attachment": args.attachment}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def transaction_info(args):
    print(":: calling transaction_info..")
    r = paydb_req("transaction_info", {"token": args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def payment_create(args):
    print(":: calling payment_create..")
    r = req("payment_create", {"reason": args.reason, "category": args.category, "recipient": args.recipient, "amount": args.amount, "message": args.message}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def stash_save(args):
    print(":: calling save..")
    r = stash_req("save", {"key": args.key, "email": args.email, "iv": args.iv, "cyphertext": args.cyphertext, "question": args.question})
    check_request_status(r)
    print(r.text)

def stash_save_check(args):
    print(":: calling save_check..")
    r = stash_req("save_check/" +  args.token)
    check_request_status(r)
    print(r.text)

def run_parser():
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == "websocket":
        function = websocket
    elif args.command == "api_key_create":
        function = api_key_create
    elif args.command == "user_info":
        function = user_info
    elif args.command == "user_update_email":
        function = user_update_email
    elif args.command == "user_update_photo":
        function = user_update_photo
    elif args.command == "transaction_create":
        function = transaction_create
    elif args.command == "transaction_info":
        function = transaction_info
    elif args.command == "payment_create":
        function = payment_create
    elif args.command == "stash_save":
        function = stash_save
    elif args.command == "stash_save_check":
        function = stash_save_check
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)

if __name__ == "__main__":
    setup_logging(logger, logging.DEBUG)
    log_socketio_version(logger)
    run_parser()
