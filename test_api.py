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
from log_utils import log_socketio_version, setup_logging

logger = logging.getLogger(__name__)

if os.getenv('URL_SCHEMA'):
    URL_SCHEMA = os.getenv('URL_SCHEMA')
else:
    URL_SCHEMA = 'http'
if os.getenv('WS_SCHEMA'):
    WS_SCHEMA = os.getenv('WS_SCHEMA')
else:
    WS_SCHEMA = 'ws'
if os.getenv('SERVER_NAME'):
    SERVER_NAME = os.getenv('SERVER_NAME')
else:
    SERVER_NAME = 'localhost:5000'

URL_BASE = f'{URL_SCHEMA}://{SERVER_NAME}/'
WS_URL = f'{WS_SCHEMA}://{SERVER_NAME}/'

EXIT_NO_COMMAND = 1

# pylint: disable=too-many-locals
def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    ## General

    parser_sign = subparsers.add_parser('sign', help='Sign an arbritrary message')
    parser_sign.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_sign.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_sign.add_argument('message', metavar='MESSAGE', type=str, help='the message')

    ## Websocket

    parser_ws = subparsers.add_parser('websocket', help='Listen to a websocket')
    parser_ws.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_ws.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    ## REST commands

    parser_api_key_create = subparsers.add_parser('api_key_create', help='Create an api key with your username and password')
    parser_api_key_create.add_argument('email', metavar='EMAIL', type=str, help='email')
    parser_api_key_create.add_argument('password', metavar='PASSWORD', type=str, help='password')
    parser_api_key_create.add_argument('device_name', metavar='DEVICE_NAME', type=str, help='the device name for the api key')

    parser_user_info = subparsers.add_parser('user_info', help='Get the user info')
    parser_user_info.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_user_info.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_user_reset_password = subparsers.add_parser('user_reset_password', help='Reset password instruction')
    parser_user_reset_password.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_user_reset_password.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_user_update_email = subparsers.add_parser('user_update_email', help='Update user email')
    parser_user_update_email.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_user_update_email.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_user_update_email.add_argument('email', metavar='EMAIL', type=str, help='the email address to change to')

    parser_user_update_password = subparsers.add_parser('user_update_password', help='Update user password')
    parser_user_update_password.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_user_update_password.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_user_update_password.add_argument('current_password', metavar='CURRENT_PASSWORD', type=str, help='current user password')
    parser_user_update_password.add_argument('new_password', metavar='NEW_PASSWORD', type=str, help='new user password')

    parser_user_update_photo = subparsers.add_parser('user_update_photo', help='Update user photo and photo_type')
    parser_user_update_photo.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_user_update_photo.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_user_update_photo.add_argument('photo', metavar='PHOTO', type=str, help='user photo')
    parser_user_update_photo.add_argument('photo_type', metavar='PHOTO_TYPE', type=str, help='type of photo')

    parser_assets = subparsers.add_parser('assets', help='Get list of assets')
    parser_assets.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_assets.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_markets = subparsers.add_parser('markets', help='Get list of markets')
    parser_markets.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_markets.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_order_book = subparsers.add_parser('order_book', help='Get a market order book')
    parser_order_book.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_order_book.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_order_book.add_argument('market', metavar='MARKET', type=str, help='the market')

    parser_broker_order_create = subparsers.add_parser('broker_order_create', help='Create a broker order')
    parser_broker_order_create.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_broker_order_create.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_broker_order_create.add_argument('market', metavar='MARKET', type=str, help='the market')
    parser_broker_order_create.add_argument('side', metavar='SIDE', type=str, help='the market side (bid/ask)')
    parser_broker_order_create.add_argument('amount', metavar='AMOUNT', type=str, help='the amount to buy or sell')
    parser_broker_order_create.add_argument('recipient', metavar='RECIPIENT', type=str, help='the of the funds')

    parser_broker_order_status = subparsers.add_parser('broker_order_status', help='Get the status of a broker order')
    parser_broker_order_status.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_broker_order_status.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_broker_order_status.add_argument('token', metavar='TOKEN', type=str, help='the broker order token')

    parser_broker_order_accept = subparsers.add_parser('broker_order_accept', help='Accept a broker order')
    parser_broker_order_accept.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_broker_order_accept.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_broker_order_accept.add_argument('token', metavar='TOKEN', type=str, help='the broker order token')

    parser_broker_orders = subparsers.add_parser('broker_orders', help='Get the list of broker orders')
    parser_broker_orders.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_broker_orders.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_broker_orders.add_argument('offset', metavar='OFFSET', type=int, help='the limit')
    parser_broker_orders.add_argument('limit', metavar='LIMIT', type=int, help='the offset')

    parser_referral_config = subparsers.add_parser('referral_config', help='Get the premio referral config')
    parser_referral_config.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_config.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_referral_create = subparsers.add_parser('referral_create', help='Create a premio referral')
    parser_referral_create.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_create.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_referral_create.add_argument('recipient', metavar='RECIPIENT', type=str, help='the referral recipient (email)')

    parser_referral_remind = subparsers.add_parser('referral_remind', help='Remind the recipient of a premio referral')
    parser_referral_remind.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_remind.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_referral_remind.add_argument('token', metavar='TOKEN', type=str, help='the referral unique token')

    parser_referral_list = subparsers.add_parser('referral_list', help='List a users referrals')
    parser_referral_list.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_list.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')

    parser_referral_validate = subparsers.add_parser('referral_validate', help='Validate a premio referral')
    parser_referral_validate.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_validate.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_referral_validate.add_argument('token', metavar='TOKEN', type=str, help='the referral unique token')

    parser_referral_claim = subparsers.add_parser('referral_claim', help='Claim a premio referral')
    parser_referral_claim.add_argument('api_key_token', metavar='API_KEY_TOKEN', type=str, help='the API KEY token')
    parser_referral_claim.add_argument('api_key_secret', metavar='API_KEY_SECRET', type=str, help='the API KEY secret')
    parser_referral_claim.add_argument('token', metavar='TOKEN', type=str, help='the referral unique token')

    return parser

def req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    if api_key_token:
        if not params:
            params = {}
        params['nonce'] = int(time.time())
        params['api_key'] = api_key_token
    url = URL_BASE + endpoint
    if params:
        headers = {'Content-type': 'application/json'}
        body = json.dumps(params)
        if api_key_token:
            headers['X-Signature'] = create_hmac_sig(api_key_secret, body)
        print('   POST - ' + url)
        r = requests.post(url, headers=headers, data=body)
    else:
        print('   GET - ' + url)
        r = requests.get(url)
    return r

def api_req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    return req('apiv1/' + endpoint, params, api_key_token, api_key_secret)

def reward_req(endpoint, params=None, api_key_token=None, api_key_secret=None):
    return req('reward/' + endpoint, params, api_key_token, api_key_secret)

def check_request_status(r):
    try:
        r.raise_for_status()
    except Exception as e:
        print('::ERROR::')
        print(str(r.status_code) + ' - ' + r.url)
        print(r.text)
        raise e

def sign(args):
    print(':: signing message')
    sig = create_hmac_sig(args.api_key_secret, args.message)
    print('Signature: ', sig)

def websocket(args):
    print(':: calling websocket..')
    ns = '/paydb'
    # open websocket
    sio = socketio.Client()
    @sio.event(namespace=ns)
    def connect():
        print('connection established')
        print('authenticating with api key', args.api_key_token)
        # create auth data
        nonce = int(time.time())
        sig = create_hmac_sig(args.api_key_secret, str(nonce))
        auth = {'signature': sig, 'api_key': args.api_key_token, 'nonce': nonce}
        # emit auth message
        sio.emit('auth', auth, namespace=ns)

    @sio.event(namespace=ns)
    def info(data):
        print('info event received:', data)

    @sio.event(namespace=ns)
    def user_info_update(data):
        print('user_info_update event received:', data)

    @sio.event(namespace=ns)
    def broker_order_new(data):
        print('broker_order_new event received:', data)

    @sio.event(namespace=ns)
    def broker_order_update(data):
        print('broker_order_update event received:', data)

    @sio.event(namespace=ns)
    def disconnect():
        print('disconnected from server')

    sio.connect(WS_URL, namespaces=[ns])
    sio.wait()

def api_key_create(args):
    print(':: calling api_key_create..')
    r = api_req('api_key_create', {'email': args.email, 'password': args.password, 'device_name': args.device_name})
    check_request_status(r)
    print(r.text)

def user_info(args):
    print(':: calling user_info..')
    r = api_req('user_info', {'email': None}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_reset_password(args):
    print(':: calling user_reset_password..')
    r = api_req('user_reset_password', {'email': None}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_email(args):
    print(':: calling user_update_email..')
    r = api_req('user_update_email', {'email': args.email}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_password(args):
    print(':: calling user_update_password..')
    r = api_req('user_update_password', {'current_password': args.current_password, 'new_password': args.new_password}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def user_update_photo(args):
    print(':: calling user_update_photo..')
    r = api_req('user_update_photo', {'photo': args.photo, 'photo_type': args.photo_type}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def assets(args):
    print(':: calling assets..')
    r = api_req('assets', {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def markets(args):
    print(':: calling markets..')
    r = api_req('markets', {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def order_book(args):
    print(':: calling order_book..')
    r = api_req('order_book', {'market': args.market}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def broker_order_create(args):
    print(':: calling broker_order_create..')
    r = api_req('broker_order_create', {'market': args.market, 'side': args.side, 'amount_dec': args.amount, 'recipient': args.recipient}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def broker_order_status(args):
    print(':: calling broker_order_status..')
    r = api_req('broker_order_status', {'token': args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def broker_order_accept(args):
    print(':: calling broker_order_accept..')
    r = api_req('broker_order_accept', {'token': args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def broker_orders(args):
    print(':: calling broker_orders..')
    r = api_req('broker_orders', {'offset': args.offset, 'limit': args.limit}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_config(args):
    print(':: calling referral_config..')
    r = reward_req('referral_config', {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_create(args):
    print(':: calling referral_create..')
    r = reward_req('referral_create', {'recipient': args.recipient}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_remind(args):
    print(':: calling referral_remind..')
    r = reward_req('referral_remind', {'token': args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_list(args):
    print(':: calling referral_list..')
    r = reward_req('referral_list', {}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_validate(args):
    print(':: calling referral_validate..')
    r = reward_req('referral_validate', {'token': args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

def referral_claim(args):
    print(':: calling referral_claim..')
    r = reward_req('referral_claim', {'token': args.token}, args.api_key_token, args.api_key_secret)
    check_request_status(r)
    print(r.text)

# pylint: disable=too-many-branches
def run_parser():
    # parse arguments
    parser = construct_parser()
    args = parser.parse_args()

    # set appropriate function
    function = None
    if args.command == 'sign':
        function = sign
    elif args.command == 'websocket':
        function = websocket
    elif args.command == 'api_key_create':
        function = api_key_create
    elif args.command == 'user_info':
        function = user_info
    elif args.command == 'user_reset_password':
        function = user_reset_password
    elif args.command == 'user_update_email':
        function = user_update_email
    elif args.command == 'user_update_password':
        function = user_update_password
    elif args.command == 'user_update_photo':
        function = user_update_photo
    elif args.command == 'assets':
        function = assets
    elif args.command == 'markets':
        function = markets
    elif args.command == 'order_book':
        function = order_book
    elif args.command == 'broker_order_create':
        function = broker_order_create
    elif args.command == 'broker_order_status':
        function = broker_order_status
    elif args.command == 'broker_order_accept':
        function = broker_order_accept
    elif args.command == 'broker_orders':
        function = broker_orders
    elif args.command == 'referral_config':
        function = referral_config
    elif args.command == 'referral_create':
        function = referral_create
    elif args.command == 'referral_remind':
        function = referral_remind
    elif args.command == 'referral_list':
        function = referral_list
    elif args.command == 'referral_validate':
        function = referral_validate
    elif args.command == 'referral_claim':
        function = referral_claim
    else:
        parser.print_help()
        sys.exit(EXIT_NO_COMMAND)

    if function:
        function(args)

if __name__ == '__main__':
    setup_logging(logger, logging.DEBUG)
    log_socketio_version(logger)
    run_parser()
