import logging
import decimal
import json
from enum import Enum

import requests
import bitcoin
import bitcoin.wallet
import base58
import web3
from munch import Munch
from stdnum.nz import bankaccount

import utils
from app_core import app

logger = logging.getLogger(__name__)

TESTNET = app.config['TESTNET']
DASSET_API_SECRET = app.config['DASSET_API_SECRET']
DASSET_ACCOUNT_ID = app.config['DASSET_ACCOUNT_ID']
BROKER_ORDER_FEE = decimal.Decimal(app.config['BROKER_ORDER_FEE'])
NZD = Munch(symbol='NZD', name='New Zealand Dollar', decimals=2, withdraw_fee=decimal.Decimal(7))
BTC = Munch(symbol='BTC', name='Bitcoin', decimals=8, withdraw_fee=decimal.Decimal('0.0003'))
ETH = Munch(symbol='ETH', name='Ethereum', decimals=18, withdraw_fee=decimal.Decimal('0.0099'))
DOGE = Munch(symbol='DOGE', name='Dogecoin', decimals=8, withdraw_fee=decimal.Decimal(5))
LTC = Munch(symbol='LTC', name='Litecoin', decimals=8, withdraw_fee=decimal.Decimal('0.1'))
ASSETS = Munch(NZD=NZD, BTC=BTC, ETH=ETH, DOGE=DOGE, LTC=LTC)
MARKETS = {'BTC-NZD': Munch(base_asset=BTC, quote_asset=NZD, min_order=decimal.Decimal('0.01')), \
    'ETH-NZD': Munch(base_asset=ETH, quote_asset=NZD, min_order=decimal.Decimal('0.1')), \
    'DOGE-NZD': Munch(base_asset=DOGE, quote_asset=NZD, min_order=decimal.Decimal(50)), \
    'LTC-NZD': Munch(base_asset=LTC, quote_asset=NZD, min_order=decimal.Decimal(1))}

URL_BASE = 'https://api.dassetx.com/api'

class QuoteResult(Enum):
    OK = 0
    AMOUNT_TOO_LOW = 1
    INSUFFICIENT_LIQUIDITY = 2

class MarketSide(Enum):
    BID = 'bid'
    ASK = 'ask'

    @classmethod
    def parse(cls, val):
        try:
            return cls(val)
        except: # pylint: disable=bare-except
            return None

#
# Helper functions
#

def _account_mock():
    return app.config['EXCHANGE_ACCOUNT_MOCK']

def _base58_validate(address, mainnet_prefixes, testnet_prefixes):
    try:
        raw = base58.b58decode_check(address)
        prefix = raw[0]
        return not TESTNET and prefix in mainnet_prefixes or TESTNET and prefix in testnet_prefixes
    except ValueError:
        return False

def _parse_balance(item):
    symbol = item['currencySymbol']
    return Munch(symbol=symbol, name=item['currencyName'], total=decimal.Decimal(item['total']), available=decimal.Decimal(item['available']), decimals=asset_decimals(symbol))

def _parse_asset(item):
    symbol = item['symbol']
    message = ''
    if 'notice' in item:
        message = item['notice']
    return Munch(symbol=symbol, name=item['name'], coin_type=item['coinType'], status=item['status'], min_confs=item['minConfirmations'], message=message, decimals=asset_decimals(symbol))

def _parse_market(item):
    message = ''
    if 'notice' in item:
        message = item['notice']
    return Munch(symbol=item['symbol'], base_asset=item['baseCurrencySymbol'], quote_asset=item['quoteCurrencySymbol'], precision=item['precision'], status=item['status'], min_trade=item['minTradeSize'], message=message)

def _parse_order_book(item):
    return Munch(bids=item['bid'], asks=item['ask'])

def _parse_order(item):
    side = MarketSide.BID if item['type'] == 'BUY' else MarketSide.ASK
    return Munch(id=item['id'], base_asset=['baseSymbol'], quote_asset=['quoteSymbol'], date=item['date'], side=side, status=item['status'], \
        base_amount=item['base_amount'], quote_amount=item['quote_amount'], filled=item['details']['filled'])

def _parse_withdrawal(item):
    id_ = item['id'] if 'id' in item else item['transactionId']
    amount = item['amount'] if 'amount' in item else item['quantity']
    return Munch(id=id_, symbol=['currencySymbol'], amount=amount, date=item['createdAt'], status=item['status'], address=item['cryptoAddress'])

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

def balances_req(asset=None):
    endpoint = '/balances'
    if asset:
        endpoint = f'/balances/{asset}'
    if _account_mock():
        balances = []
        for item in ASSETS.values():
            balance = Munch(symbol=item.symbol, name=item.name, total=decimal.Decimal(9999), available=decimal.Decimal(9999), decimals=item.decimals)
            balances.append(balance)
        return balances
    r = req_get(endpoint)
    if r.status_code == 200:
        balances = r.json()
        balances = [_parse_balance(b) for b in balances if b['currencySymbol'] in ASSETS]
        return balances
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def assets_req(asset=None):
    endpoint = '/currencies'
    if asset:
        endpoint = f'/currencies/{asset}'
    r = req_get(endpoint)
    if r.status_code == 200:
        assets = r.json()
        assets = [_parse_asset(a) for a in assets if a['symbol'] in ASSETS]
        return assets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def markets_req():
    endpoint = '/markets'
    r = req_get(endpoint)
    if r.status_code == 200:
        markets = r.json()
        markets = [_parse_market(m) for m in markets if m['symbol'] in MARKETS]
        return markets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_book_req(symbol):
    endpoint = f'/markets/{symbol}/orderbook'
    r = req_get(endpoint)
    if r.status_code == 200:
        min_order = MARKETS[symbol].min_order
        return _parse_order_book(r.json()[0]), min_order, BROKER_ORDER_FEE
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_create_req(market, side, amount, price):
    assert isinstance(amount, decimal.Decimal)
    assert isinstance(price, decimal.Decimal)
    assert side is MarketSide.BID
    if _account_mock():
        return utils.generate_key()
    endpoint = '/orders'
    r = req_post(endpoint, params=dict(amount=float(amount), tradingPair=market, side='BUY', orderType='LIMIT', timeInForce='FILL_OR_KILL', limit=float(price)))
    if r.status_code == 200:
        return r.json()[0]['order']['orderId']
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

def order_status_req(order_id, market):
    if _account_mock():
        return Munch(id=order_id, status='Completed')
    offset = 0
    limit = 1000
    while True:
        orders = orders_req(market, offset, limit)
        if orders:
            for item in orders['results']:
                if item['id'] == order_id:
                    return _parse_order(item)
            offset += limit
            if offset > orders['total']:
                break
        else:
            break
    logger.error('exchange order %s not found for market %s', order_id, market)
    return None

def order_status_check(order_id, market):
    order = order_status_req(order_id, market)
    return order.status == 'Completed'

def crypto_withdrawal_create_req(asset, amount, address):
    assert isinstance(amount, decimal.Decimal)
    if _account_mock():
        return utils.generate_key()
    endpoint = '/crypto/withdrawals'
    r = req_post(endpoint, params=dict(currencySymbol=asset, quantity=float(amount), cryptoAddress=address))
    if r.status_code == 200:
        return r.json()[0]['withdrawal']['id']
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def crypto_withdrawal_status_req(withdrawal_id):
    endpoint = f'/crypto/withdrawals/{withdrawal_id}'
    r = req_get(endpoint)
    if r.status_code == 200:
        return _parse_withdrawal(r.json()[0])
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def crypto_withdrawal_status_check(withdrawal_id):
    if _account_mock():
        return Munch(id=withdrawal_id, status='Completed')
    withdrawal = crypto_withdrawal_status_req(withdrawal_id)
    return withdrawal.status == 'Completed'

#
# Public functions
#

def market_side_is(have, should_have):
    assert isinstance(should_have, MarketSide)
    assert isinstance(have, (MarketSide, str))
    if isinstance(have, str):
        return have == should_have.value
    return have is should_have

def market_side_nice(side):
    if isinstance(side, str):
        if side == MarketSide.ASK.value:
            return 'sell'
        if side == MarketSide.BID.value:
            return 'buy'
    if isinstance(side, MarketSide):
        if side is MarketSide.ASK:
            return 'sell'
        if side is MarketSide.BID:
            return 'buy'
    return 'n/a'

def assets_from_market(market):
    return market.split('-')

def asset_decimals(asset):
    return ASSETS[asset].decimals

def asset_withdraw_fee(asset):
    return ASSETS[asset].withdraw_fee

def asset_int_to_dec(asset, value):
    decimals = asset_decimals(asset)
    return decimal.Decimal(value) / decimal.Decimal(10**decimals)

def asset_dec_to_int(asset, value):
    decimals = asset_decimals(asset)
    return int(value * decimal.Decimal(10**decimals))

def asset_dec_to_str(asset, value):
    decimals = asset_decimals(asset)
    return str(value.quantize(decimal.Decimal(10) ** -decimals))

def recipent_validate(market, side, recipient):
    result = False
    base_asset, quote_asset = assets_from_market(market)
    if side is MarketSide.BID:
        asset = base_asset
    else:
        asset = quote_asset
    if asset == 'NZD':
        result = bankaccount.is_valid(recipient)
    elif asset == 'BTC':
        bitcoin.SelectParams('testnet' if TESTNET else 'mainnet')
        try:
            bitcoin.wallet.CBitcoinAddress(recipient)
            result = True
        except: # pylint: disable=bare-except
            pass
    elif asset == 'ETH':
        result = web3.Web3.isAddress(recipient)
    elif asset == 'DOGE':
        result = _base58_validate(recipient, [0x1E], [0x71])
    elif asset == 'LTC':
        result = _base58_validate(recipient, [0x30], [0x6F])
    if not result:
        logger.error('failed to validate recipient "%s" (%s)', recipient, asset)
    return result

def bid_quote_amount(market, amount):
    assert isinstance(amount, decimal.Decimal)
    if amount < MARKETS[market].min_order:
        return decimal.Decimal(-1), QuoteResult.AMOUNT_TOO_LOW

    base_asset, _ = assets_from_market(market)
    withdraw_fee = asset_withdraw_fee(base_asset)
    order_book, _, broker_fee = order_book_req(market)

    amount_total = amount + withdraw_fee
    filled = decimal.Decimal(0)
    total_price = decimal.Decimal(0)
    n = 0
    while amount_total > filled:
        if n >= len(order_book.asks):
            break
        rate = decimal.Decimal(order_book.asks[n]['rate'])
        quantity = decimal.Decimal(order_book.asks[n]['quantity'])
        quantity_to_use = quantity
        if quantity_to_use > amount_total - filled:
            quantity_to_use = amount_total - filled
        filled += quantity_to_use
        total_price += quantity_to_use * rate
        if filled == amount_total:
            return total_price * (decimal.Decimal(1) + broker_fee / decimal.Decimal(100)), QuoteResult.OK
        n += 1

    return decimal.Decimal(-1), QuoteResult.INSUFFICIENT_LIQUIDITY

def ask_quote_amount(market, amount):
    assert isinstance(amount, decimal.Decimal)
    if amount < MARKETS[market].min_order:
        return decimal.Decimal(-1), QuoteResult.AMOUNT_TOO_LOW

    _, quote_asset = assets_from_market(market)
    withdraw_fee = asset_withdraw_fee(quote_asset)
    order_book, _, broker_fee = order_book_req(market)

    amount_total = amount
    filled = decimal.Decimal(0)
    total_price = decimal.Decimal(0)
    n = 0
    while amount_total > filled:
        if n >= len(order_book.bids):
            break
        rate = decimal.Decimal(order_book.bids[n]['rate'])
        quantity = decimal.Decimal(order_book.bids[n]['quantity'])
        quantity_to_use = quantity
        if quantity_to_use > amount_total - filled:
            quantity_to_use = amount_total - filled
        filled += quantity_to_use
        total_price += quantity_to_use * rate
        if filled == amount_total:
            return total_price * (decimal.Decimal(1) - broker_fee / decimal.Decimal(100)) - withdraw_fee, QuoteResult.OK
        n += 1

    return decimal.Decimal(-1), QuoteResult.INSUFFICIENT_LIQUIDITY

def funds_available(asset, amount):
    assert isinstance(amount, decimal.Decimal)
    balances = balances_req(asset)
    for balance in balances:
        if balance.symbol == asset:
            return balance.available >= amount
    return False
