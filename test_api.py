#!/usr/bin/python3

# pylint: disable=invalid-name
# pylint: disable=unused-variable
# pylint: disable-msg=too-many-statements

import sys
import argparse
import time
import json
import logging
import os

import requests
import socketio

from web_utils import create_hmac_sig
from utils import log_socketio_version, setup_logging

logger = logging.getLogger(__name__)

if os.getenv("URL_SCHEMA"):
    URL_SCHEMA = os.getenv("URL_SCHEMA")
else:
    URL_SCHEMA = "http"
if os.getenv("WS_SCHEMA"):
    WS_SCHEMA = os.getenv("WS_SCHEMA")
else:
    WS_SCHEMA = "ws"
if os.getenv("SERVER_NAME"):
    SERVER_NAME = os.getenv("SERVER_NAME")
else:
    SERVER_NAME = "localhost:5000"

URL_BASE = f"{URL_SCHEMA}://{SERVER_NAME}/"
WS_URL = f"{WS_SCHEMA}://{SERVER_NAME}/"

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

    parser_user_reset_password = subparsers.add_parser("user_reset_password", help="Reset password instruction")
    parser_user_reset_password.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_reset_password.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_user_update_email = subparsers.add_parser("user_update_email", help="Update user email")
    parser_user_update_email.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_update_email.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_user_update_email.add_argument("email", metavar="EMAIL", type=str, help="the email address to change to")

    parser_user_update_password = subparsers.add_parser("user_update_password", help="Update user password")
    parser_user_update_password.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_user_update_password.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_user_update_password.add_argument("current_password", metavar="CURRENT_PASSWORD", type=str, help="current user password")
    parser_user_update_password.add_argument("new_password", metavar="NEW_PASSWORD", type=str, help="new user password")

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

    parser_reward_create = subparsers.add_parser("reward_create", help="Create a premio reward")
    parser_reward_create.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_reward_create.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_reward_create.add_argument("reason", metavar="REASON", type=str, help="the reason for the payment")
    parser_reward_create.add_argument("category", metavar="CATEGORY", type=str, help="the category of the payment")
    parser_reward_create.add_argument("recipient", metavar="RECIPIENT", type=str, help="the recipient of the payment")
    parser_reward_create.add_argument("amount", metavar="AMOUNT", type=int, help="the payment amount (integer, cents)")
    parser_reward_create.add_argument("message", metavar="MESSAGE", type=str, help="the message for the recipient")

    parser_referral_config = subparsers.add_parser("referral_config", help="Get the premio referral config")
    parser_referral_config.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_config.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_referral_create = subparsers.add_parser("referral_create", help="Create a premio referral")
    parser_referral_create.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_create.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_referral_create.add_argument("recipient", metavar="RECIPIENT", type=str, help="the referral recipient (email)")

    parser_referral_remind = subparsers.add_parser("referral_remind", help="Remind the recipient of a premio referral")
    parser_referral_remind.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_remind.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_referral_remind.add_argument("token", metavar="TOKEN", type=str, help="the referral unique token")

    parser_referral_list = subparsers.add_parser("referral_list", help="List a users referrals")
    parser_referral_list.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_list.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")

    parser_referral_validate = subparsers.add_parser("referral_validate", help="Validate a premio referral")
    parser_referral_validate.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_validate.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_referral_validate.add_argument("token", metavar="TOKEN", type=str, help="the referral unique token")

    parser_referral_claim = subparsers.add_parser("referral_claim", help="Claim a premio referral")
    parser_referral_claim.add_argument("api_key_token", metavar="API_KEY_TOKEN", type=str, help="the API KEY token")
    parser_referral_claim.add_argument("api_key_secret", metavar="API_KEY_SECRET", type=str, help="the API KEY secret")
    parser_referral_claim.add_argument("token", metavar="TOKEN", type=str, help="the referral unique token")

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

def reward_req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    return req('reward/' + endpoint, params, api_key_token, api_key_secret)

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

def user_reset_password(args):
    print(":: calling user_reset_password..")
    r = paydb_req("user_reset_password", {"email": None}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_email(args):
    print(":: calling user_update_email..")
    r = paydb_req("user_update_email", {"email": args.email}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_password(args):
    print(":: calling user_update_password..")
    r = paydb_req("user_update_password", {"current_password": args.current_password, "new_password": args.new_password}, args.api_key_token, args.api_key_secret)
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

def reward_create(args):
    print(":: calling reward_create..")
    r = reward_req("reward_create", {"reason": args.reason, "category": args.category, "recipient": args.recipient, "amount": args.amount, "message": args.message}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_config(args):
    print(":: calling referral_config..")
    r = reward_req("referral_config", {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_create(args):
    print(":: calling referral_create..")
    r = reward_req("referral_create", {"recipient": args.recipient}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_remind(args):
    print(":: calling referral_remind..")
    r = reward_req("referral_remind", {"token": args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_list(args):
    print(":: calling referral_list..")
    r = reward_req("referral_list", {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_validate(args):
    print(":: calling referral_validate..")
    r = reward_req("referral_validate", {"token": args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_claim(args):
    print(":: calling referral_claim..")
    r = reward_req("referral_claim", {"token": args.token}, args.api_key_token, args.api_key_secret)
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

# pylint: disable=too-many-branches
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
    elif args.command == "user_reset_password":
        function = user_reset_password
    elif args.command == "user_update_email":
        function = user_update_email
    elif args.command == "user_update_password":
        function = user_update_password
    elif args.command == "user_update_photo":
        function = user_update_photo
    elif args.command == "transaction_create":
        function = transaction_create
    elif args.command == "transaction_info":
        function = transaction_info
    elif args.command == "reward_create":
        function = reward_create
    elif args.command == "referral_config":
        function = referral_config
    elif args.command == "referral_create":
        function = referral_create
    elif args.command == "referral_remind":
        function = referral_remind
    elif args.command == "referral_list":
        function = referral_list
    elif args.command == "referral_validate":
        function = referral_validate
    elif args.command == "referral_claim":
        function = referral_claim
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
