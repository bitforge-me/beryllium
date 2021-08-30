import logging
import decimal
import json
from enum import Enum

import requests
import bitcoin
import bitcoin.wallet
import web3
from munch import Munch

from app_core import app

logger = logging.getLogger(__name__)

TESTNET = app.config['TESTNET']
DASSET_API_SECRET = app.config['DASSET_API_SECRET']
DASSET_ACCOUNT_ID = app.config['DASSET_ACCOUNT_ID']
BROKER_ORDER_FEE = decimal.Decimal(app.config['BROKER_ORDER_FEE'])
NZD = Munch(symbol='NZD', decimals=2)
BTC = Munch(symbol='BTC', decimals=8)
ETH = Munch(symbol='ETH', decimals=18)
ASSETS = Munch(NZD=NZD, BTC=BTC, ETH=ETH)
MARKETS = {'BTC-NZD': Munch(base_asset=BTC, quote_asset=NZD, min_order=decimal.Decimal('0.01')), \
    'ETH-NZD': Munch(base_asset=ETH, quote_asset=NZD, min_order=decimal.Decimal('0.1'))}

URL_BASE = 'https://api.dassetx.com/api'

class QuoteResult(Enum):
    OK = 0
    AMOUNT_TOO_LOW = 1
    INSUFFICIENT_LIQUIDITY = 2

class MarketSide(Enum):
    BID = 'bid'
    ASK = 'ask'

#
# Helper functions
#

def assets_from_market(market):
    return market.split('-')

def asset_decimals(asset):
    return ASSETS[asset].decimals

def asset_int_to_dec(asset, value):
    decimals = asset_decimals(asset)
    return decimal.Decimal(value) / decimal.Decimal(10**decimals)

def asset_dec_to_int(asset, value):
    decimals = asset_decimals(asset)
    return int(value * decimal.Decimal(10**decimals))

def address_validate(market, side, address):
    assert side is MarketSide.BID
    base_asset, _ = assets_from_market(market)
    if base_asset == 'BTC':
        bitcoin.SelectParams('testnet' if TESTNET else 'mainnet')
        try:
            bitcoin.wallet.CBitcoinAddress(address)
            return True
        except: # pylint: disable=bare-except
            pass
    elif base_asset == 'ETH':
        return web3.Web3.isAddress(address)
    return False

def bid_quote_amount(market, amount_dec):
    if amount_dec < MARKETS[market].min_order:
        return decimal.Decimal(-1), QuoteResult.AMOUNT_TOO_LOW

    order_book = order_book_req(market)

    filled = decimal.Decimal(0)
    total_price = decimal.Decimal(0)
    n = 0
    while amount_dec > filled:
        if n >= len(order_book['ask']):
            break
        rate = decimal.Decimal(order_book['ask'][n]['rate'])
        quantity = decimal.Decimal(order_book['ask'][n]['quantity'])
        quantity_to_use = quantity
        if quantity_to_use > amount_dec - filled:
            quantity_to_use = amount_dec - filled
        filled += quantity_to_use
        total_price += quantity_to_use * rate
        if filled == amount_dec:
            return total_price * (decimal.Decimal(1) + BROKER_ORDER_FEE / decimal.Decimal(100)), QuoteResult.OK
        n += 1

    return decimal.Decimal(-1), QuoteResult.INSUFFICIENT_LIQUIDITY

#
# Dasset API Requests
#

def req_get(endpoint, params=None):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    logger.info('   GET - %s', url)
    r = requests.get(url, headers=headers, params=params)
    return r

def req_post(endpoint, params):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    logger.info('   POST - %s', url)
    r = requests.post(url, headers=headers, data=json.dumps(params))
    return r

def assets_req(asset=None):
    endpoint = '/currencies'
    if asset:
        endpoint = f'/currencies/{asset}'
    r = req_get(endpoint)
    if r.status_code == 200:
        assets = r.json()
        assets = [a for a in assets if a['symbol'] in ASSETS]
        return assets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def markets_req():
    endpoint = '/markets'
    r = req_get(endpoint)
    if r.status_code == 200:
        markets = r.json()
        markets = [m for m in markets if m['symbol'] in MARKETS]
        return markets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_book_req(symbol):
    endpoint = f'/markets/{symbol}/orderbook'
    r = req_get(endpoint)
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_create_req(market, side, amount, price):
    assert side is MarketSide.BID
    endpoint = '/orders'
    r = req_post(endpoint, params=dict(amount=float(amount), tradingPair=market, side='BUY', orderType='LIMIT', timeInForce='FILL_OR_KILL', limit=float(price)))
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def orders_req(market, offset, limit):
    endpoint = '/orders'
    page = offset / limit + 1
    r = req_get(endpoint, params=dict(marketSymbol=market, limit=limit, page=page))
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def crypto_withdrawal_create_req(asset, amount, address):
    endpoint = '/crypto/withdrawals'
    r = req_post(endpoint, params=dict(currencySymbol=asset, quantity=float(amount), cryptoAddress=address))
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def crypto_withdrawal_req(withdrawal_id):
    endpoint = f'/crypto/withdrawals/{withdrawal_id}'
    r = req_get(endpoint)
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None
