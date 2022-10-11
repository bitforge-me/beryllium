import logging
import requests

from flask import Blueprint, jsonify

from app_core import app
from ln import LnRpc, _msat_to_sat
from dasset import account_balances
import crown_financial

logger = logging.getLogger(__name__)
monitor = Blueprint('monitor', __name__, template_folder='templates')
BITCOIN_EXPLORER = app.config["BITCOIN_EXPLORER"]
LN_SPENDABLE_MIN = app.config["LN_SPENDABLE_MIN"]
LN_RECEIVABLE_MIN = app.config["LN_RECEIVABLE_MIN"]
LN_ONCHAIN_MIN = app.config["LN_ONCHAIN_MIN"]
EXCHANGE_MIN = app.config["EXCHANGE_MIN"]
BANK_MIN = app.config["BANK_MIN"]

@monitor.route('/info')
def monitor_info():
    peers = LnRpc().list_peers()['peers']
    channels = []
    total_receivable = 0
    total_spendable = 0
    largest_channel_sats = 0
    overall_total = 0
    total_active_channels = 0
    total_inactive_channels = 0
    total_peer_connected = 0
    for peer in peers:
        for channel in peer['channels']:
            total = channel['msatoshi_total']
            total_sats = _msat_to_sat(total)
            if total_sats > largest_channel_sats:
                largest_channel_sats = total_sats
            ours = channel['msatoshi_to_us']
            theirs = total - ours
            our_reserve = channel['our_channel_reserve_satoshis']
            their_reserve = channel['their_channel_reserve_satoshis']
            receivable = theirs - our_reserve
            spendable = ours - their_reserve

            if peer['connected'] and channel['state'] == 'CHANNELD_NORMAL':
                total_receivable += receivable
                total_spendable += spendable
                overall_total += total
                total_active_channels += 1

            if not peer['connected'] and channel['state'] == 'CHANNELD_NORMAL':
                total_inactive_channels += 1

            if peer['connected']:
                total_peer_connected += 1

            channel['total_sats'] = _msat_to_sat(total)
            channel['our_reserve_sats'] = our_reserve
            channel['their_reserve_sats'] = their_reserve
            channel['receivable_sats'] = _msat_to_sat(receivable)
            channel['spendable_sats'] = _msat_to_sat(spendable)
            channel['peer_id'] = peer['id']
            channel['peer_connected'] = peer['connected']

            channels.append(channel)

    ln_funds = LnRpc().list_funds()
    ln_info = LnRpc().get_info()
    exchange_balances = account_balances(quiet=True)
    crown_balance = crown_financial.balance_float(quiet=True)
    crown_currency = crown_financial.CURRENCY
    remote_height = requests.get(f'{BITCOIN_EXPLORER}/api/blocks/tip/height')

    info = {}
    info['total_spendable'] = _msat_to_sat(total_spendable)
    if info['total_spendable'] < LN_SPENDABLE_MIN:
        info['total_spendable_below_min'] = 1
    else:
        info['total_spendable_below_min'] = 0
    info['total_receivable'] = _msat_to_sat(total_receivable)
    if info['total_receivable'] < LN_RECEIVABLE_MIN:
        info['total_receivable_below_min'] = 1
    else:
        info['total_receivable_below_min'] = 0
    info['overall_total_sats'] = _msat_to_sat(overall_total)
    info['total_active_channels'] = total_active_channels
    info['total_inactive_channels'] = total_inactive_channels
    info['total_peer_connected'] = total_peer_connected
    info['sats_channels'] = ln_funds['sats_channels']
    info['sats_onchain'] = ln_funds['sats_onchain']
    if ln_funds['sats_onchain'] < LN_ONCHAIN_MIN:
        info['sats_onchain_below_min'] = 1
    else:
        info['sats_onchain_below_min'] = 0
    info['blockheight'] = ln_info['blockheight']
    info['num_active_channels'] = ln_info['num_active_channels']
    info['num_inactive_channels'] = ln_info['num_inactive_channels']
    info['num_pending_channels'] = ln_info['num_pending_channels']
    info['num_peers'] = ln_info['num_peers']
    for balance in exchange_balances or []:
        info[f'exchange_{balance.symbol}_available'] = float(format(balance.available, f'.{balance.decimals}f'))
        info[f'exchange_{balance.symbol}_total'] = float(format(balance.total, f'.{balance.decimals}f'))
        if balance.symbol in EXCHANGE_MIN:
            if balance.available < EXCHANGE_MIN[balance.symbol]:
                info[f'exchange_{balance.symbol}_below_min'] = 1
            else:
                info[f'exchange_{balance.symbol}_below_min'] = 0
    info[f'bank_{crown_currency}_available'] = crown_balance
    if crown_currency in BANK_MIN and crown_balance < BANK_MIN[crown_currency]:
        info[f'bank_{crown_currency}_below_min'] = 1
    else:
        info[f'bank_{crown_currency}_below_min'] = 0
    if remote_height.status_code == 200:
        info['remote_blockheight'] = int(remote_height.text)
    else:
        info['remote_blockheight'] = -1
    info['blockheight_diff'] = info['blockheight'] - info['remote_blockheight']
    info['blockheight_diff'] = abs(info['blockheight_diff'])
    return jsonify(info)
