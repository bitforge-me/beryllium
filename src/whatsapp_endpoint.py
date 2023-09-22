import logging

from flask import Blueprint, request, render_template, flash, redirect, url_for
from flask_security.decorators import roles_accepted
import shlex
import argparse

from app_core import db, limiter, csrf
from models import PayoutRequest, PayoutGroup, WindcavePaymentRequest, Role
import web_utils
import depwith
import wallet
import assets
from ln import LnRpc, _msat_to_sat, make_json_friendly

logger = logging.getLogger(__name__)
whatsapp_mock = Blueprint('whatsapp_mock', __name__, template_folder='templates')
limiter.limit("100/minute")(whatsapp_mock)
csrf.exempt(whatsapp_mock)

HELP = 'help'
INFO = 'info'
ADDRESS = 'address'
INVOICE = 'invoice'
PAY = 'pay'

class ErrorConsumingArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, message=None):
        pass

    def error(self, message):
        logger.error(message)

parser = ErrorConsumingArgumentParser()
subparsers = parser.add_subparsers(dest='cmd')
parser_help = subparsers.add_parser(HELP, help='display help')
parser_info = subparsers.add_parser(INFO, help='display info about the wallet')
parser_address = subparsers.add_parser(ADDRESS, help='generate a bitcoin address')
parser_invoice = subparsers.add_parser(INVOICE, help='generate a lightning invoice')
parser_invoice.add_argument('sats', help='the amount of satoshis', type=int)
parser_invoice.add_argument('label', help='the invoice label')
parser_invoice.add_argument('description', help='the invoice description')
parser_pay = subparsers.add_parser(PAY, help='pay an address or invoice')
parser_pay.add_argument('recipient', help='a bitcoin address or lightning invoice')
parser_pay.add_argument('sats', help='the amount of satoshis (if recipient is an address) to withdraw', type=int, nargs='?', default=None)

def _format_help():
    return f'''::Commands::
    {HELP} - display help
    {INFO} - display info about the wallet
    {ADDRESS} - generate a bitcoin address
    {INVOICE} <sats> <label> <description> - generate a lightning invoice
    {PAY} <recipient> [sats] - pay an address or invoice
'''

def _info():
    funds = LnRpc().list_funds()
    return f'''::ONCHAIN::
    {funds['sats_onchain']} sats available
    {funds['sats_onchain_reserved']} sats reserved
    {funds['sats_onchain_unconfirmed']} sats unconfirmed
::LN CHANNELS::
    {funds['sats_channels_theirs']} sats inbound liquidity
    {funds['sats_channels']} sats outbound liquidity
    {funds['sats_largest_channel_theirs']} sats largest inbound liquidiy channel
    {funds['sats_largest_channel']} sats largest outbound liquidity channel
'''

#
# Public whatsapp mock endpoints
#

@whatsapp_mock.route('/', methods=['GET'])
def index():
    return render_template('whatsapp_mock/index.html')

@whatsapp_mock.route('/send_msg', methods=['POST'])
def send_msg():
    # get request parameters
    tel = request.form['tel']
    input = request.form['input']
    # parse the input the way a shell would
    shell_args = shlex.split(input)
    logger.info('send_msg - tel: %s, input: %s', tel, shell_args)
    # parse the shell arguments using our argument parser
    args = parser.parse_args(shell_args)
    logger.info('parsed args %s', args)
    # process the selected argument
    if args.cmd == HELP:
        return _format_help()
    if args.cmd == INFO:
        # show info
        return _info()
    if args.cmd == ADDRESS:
        # create a bitcoin address
        address, err_msg = wallet.address_create(assets.BTC.symbol, None)
        if not address:
            return err_msg
        return address
    if args.cmd == INVOICE:
        # create a lightning invoice
        try:
            res = LnRpc().invoice(args.sats, args.label, args.description)
            return res['bolt11']
        except Exception as e:
            return f'Failed to create invoice: {e}'
    if args.cmd == PAY:
        # pay a recipient
        if assets.asset_recipient_validate(assets.BTC.symbol, None, args.recipient):
            # bitcoin address
            if not args.sats:
                return '"sats" argument is required when paying a bitcoin address'
            outputs = [{args.recipient: f'{args.sats}sats'}]
            try:
                res = LnRpc().multi_withdraw(outputs)
                return res['txid']
            except Exception as e:
                return f'Failed to pay address: {e.error}'
        elif assets.asset_recipient_validate(assets.BTC.symbol, assets.BTCLN.symbol, args.recipient):
            # lightning invoice
            if args.sats is not None:
                return '"sats" argument is not used when paying a lightning invoice'
            try:
                LnRpc().pay(bolt11)
                email_utils.send_email('Paid Invoice', info_str)
                store_task_info(category, task_uid, TaskInfo(TaskInfo.STATUS_SUCCESS, info_str))
            except Exception as e:
                return f'Failed to pay invoice: {e}'
    # return dont understand
    return 'I dont understand, try the "help" command'
