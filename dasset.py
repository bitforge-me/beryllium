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
NZD = Munch(symbol='NZD', name='New Zealand Dollar', decimals=2, withdraw_fee=decimal.Decimal(7), is_crypto=False)
BTC = Munch(symbol='BTC', name='Bitcoin', decimals=8, withdraw_fee=decimal.Decimal('0.0003'), is_crypto=True)
ETH = Munch(symbol='ETH', name='Ethereum', decimals=18, withdraw_fee=decimal.Decimal('0.0099'), is_crypto=True)
DOGE = Munch(symbol='DOGE', name='Dogecoin', decimals=8, withdraw_fee=decimal.Decimal(5), is_crypto=True)
LTC = Munch(symbol='LTC', name='Litecoin', decimals=8, withdraw_fee=decimal.Decimal('0.1'), is_crypto=True)
ASSETS = Munch(NZD=NZD, BTC=BTC, ETH=ETH, DOGE=DOGE, LTC=LTC)
MARKETS = {'BTC-NZD': Munch(base_asset=BTC, quote_asset=NZD, min_order=decimal.Decimal('0.01')), \
    'ETH-NZD': Munch(base_asset=ETH, quote_asset=NZD, min_order=decimal.Decimal('0.1')), \
    'DOGE-NZD': Munch(base_asset=DOGE, quote_asset=NZD, min_order=decimal.Decimal(50)), \
    'LTC-NZD': Munch(base_asset=LTC, quote_asset=NZD, min_order=decimal.Decimal(1))}

URL_BASE = 'https://api.dassetx.com/api'
URL_BASE_SUBACCOUNT = 'https://api.dassetx.com/prod/api'

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

def _parse_deposit(item):
    return Munch(id=item['id'], symbol=item['currencySymbol'], address=item['cryptoAddress'], amount=decimal.Decimal(item['quantity']), date=item['updatedAt'], status=item['status'], txid=item['txId'])

def _parse_withdrawal(item):
    id_ = item['id'] if 'id' in item else item['transactionId']
    amount = item['amount'] if 'amount' in item else item['quantity']
    return Munch(id=id_, symbol=item['currencySymbol'], amount=amount, date=item['createdAt'], status=item['status'], address=item['cryptoAddress'])

#
# Dasset API Requests
#

def _req_get(endpoint, params=None, subaccount_id=None):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    if subaccount_id:
        headers['x-subaccount-id'] = subaccount_id
    logger.info('   GET - %s', url)
    r = requests.get(url, headers=headers, params=params)
    return r

def _req_post(endpoint, params, subaccount_id=None):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    if subaccount_id:
        headers['x-subaccount-id'] = subaccount_id
    logger.info('   POST - %s', url)
    r = requests.post(url, headers=headers, data=json.dumps(params))
    return r

def _req_subaccount_put(endpoint, params):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    logger.info('   POST - %s', url)
    r = requests.put(url, headers=headers, data=json.dumps(params))
    return r

def assets_req(asset=None):
    endpoint = '/currencies'
    if asset:
        endpoint = f'/currencies/{asset}'
    r = _req_get(endpoint)
    if r.status_code == 200:
        assets = r.json()
        assets = [_parse_asset(a) for a in assets if a['symbol'] in ASSETS]
        return assets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def markets_req():
    endpoint = '/markets'
    r = _req_get(endpoint)
    if r.status_code == 200:
        markets = r.json()
        markets = [_parse_market(m) for m in markets if m['symbol'] in MARKETS]
        return markets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_book_req(symbol):
    endpoint = f'/markets/{symbol}/orderbook'
    r = _req_get(endpoint)
    if r.status_code == 200:
        min_order = MARKETS[symbol].min_order
        return _parse_order_book(r.json()[0]), min_order, BROKER_ORDER_FEE
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _balances_req(asset, subaccount_id):
    endpoint = '/balances'
    if asset:
        endpoint = f'/balances/{asset}'
    r = _req_get(endpoint, subaccount_id=subaccount_id)
    if r.status_code == 200:
        balances = r.json()
        balances = [_parse_balance(b) for b in balances if b['currencySymbol'] in ASSETS]
        return balances
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _order_create_req(market, side, amount, price):
    assert isinstance(amount, decimal.Decimal)
    assert isinstance(price, decimal.Decimal)
    endpoint = '/orders'
    if side is MarketSide.BID:
        dasset_side = 'BUY'
    else:
        dasset_side = 'SELL'
    r = _req_post(endpoint, params=dict(amount=float(amount), tradingPair=market, side=dasset_side, orderType='LIMIT', timeInForce='FILL_OR_KILL', limit=float(price)))
    if r.status_code == 200:
        return r.json()[0]['order']['orderId']
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _orders_req(market, offset, limit):
    endpoint = '/orders'
    page = offset / limit + 1
    r = _req_get(endpoint, params=dict(marketSymbol=market, limit=limit, page=page))
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _order_status_req(order_id, market):
    offset = 0
    limit = 1000
    while True:
        orders = _orders_req(market, offset, limit)
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

def _crypto_withdrawal_create_req(asset, amount, address):
    assert isinstance(amount, decimal.Decimal)
    endpoint = '/crypto/withdrawals'
    r = _req_post(endpoint, params=dict(currencySymbol=asset, quantity=float(amount), cryptoAddress=address))
    if r.status_code == 200:
        return r.json()[0]['withdrawal']['id']
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _crypto_withdrawal_status_req(withdrawal_id):
    endpoint = f'/crypto/withdrawals/{withdrawal_id}'
    r = _req_get(endpoint)
    if r.status_code == 200:
        return _parse_withdrawal(r.json()[0])
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _addresses_req(asset, subaccount_id):
    endpoint = f'/addresses/{asset}'
    r = _req_get(endpoint, subaccount_id=subaccount_id)
    if r.status_code == 200:
        addrs = []
        for item in r.json():
            if item['status'] == 'PROVISIONED':
                addrs.append(item['cryptoAddress'])
        return addrs
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _addresses_create_req(asset, subaccount_id):
    endpoint = '/addresses'
    r = _req_post(endpoint, params=dict(currencySymbol=asset), subaccount_id=subaccount_id)
    if r.status_code == 200:
        return r.json()[0]['status'] == 'REQUESTED'
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return False

def _crypto_deposits_pending_req(asset, subaccount_id):
    endpoint = '/crypto/deposits/open'
    r = _req_get(endpoint, params=dict(currencySymbol=asset, status='PENDING'), subaccount_id=subaccount_id)
    if r.status_code == 200:
        deposits = r.json()
        deposits = [_parse_deposit(d) for d in deposits]
        return deposits
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _crypto_deposits_closed_req(asset, subaccount_id):
    endpoint = '/crypto/deposits/closed'
    r = _req_get(endpoint, params=dict(currencySymbol=asset), subaccount_id=subaccount_id)
    if r.status_code == 200:
        deposits = r.json()
        deposits = [_parse_deposit(d) for d in deposits if d['currencySymbol'] == asset]
        return deposits
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _crypto_deposit_status_req(deposit_id):
    endpoint = f'/crypto/deposits/{deposit_id}'
    r = _req_get(endpoint)
    if r.status_code == 200:
        return _parse_deposit(r.json()[0])
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _subaccount_req(reference):
    endpoint = '/subaccount'
    r = _req_subaccount_put(endpoint, params=dict(reference=reference))
    if r.status_code == 200:
        return _parse_withdrawal(r.json()[0])
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

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

def asset_is_crypto(asset):
    for item in ASSETS.values():
        if item.symbol == asset and item.is_crypto:
            return True
    return False

def asset_is_fiat(asset):
    for item in ASSETS.values():
        if item.symbol == asset and not item.is_crypto:
            return True
    return False

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

def crypto_uri(asset, address, amount_int):
    assert isinstance(amount_int, int)
    amount = asset_int_to_dec(asset, amount_int)
    if asset == 'BTC':
        return f'bitcoin:{address}?amount={amount}'
    if asset == 'ETH':
        return f'ethereum:{address}?value={amount}'
    if asset == 'DOGE':
        return f'dogecoin:{address}?amount={amount}'
    if asset == 'LTC':
        return f'litecoin:{address}?amount={amount}'
    return None

#
# Public functions that rely on an exchange request
#

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

def account_balances(asset=None, subaccount_id=None):
    if _account_mock():
        balances = []
        for item in ASSETS.values():
            if subaccount_id and asset_is_fiat(item.symbol):
                continue
            balance = Munch(symbol=item.symbol, name=item.name, total=decimal.Decimal(9999), available=decimal.Decimal(9999), decimals=item.decimals)
            balances.append(balance)
        return balances
    return _balances_req(asset, subaccount_id)

def order_create(market, side, amount, price):
    if _account_mock():
        return utils.generate_key()
    return _order_create_req(market, side, amount, price)

def order_status(order_id, market):
    if _account_mock():
        return Munch(id=order_id, status='Completed')
    return _order_status_req(order_id, market)

def order_status_check(order_id, market):
    order = order_status(order_id, market)
    return order.status == 'Completed'

def address_get_or_create(asset, subaccount_id):
    if _account_mock():
        return 'XXX'
    addrs = _addresses_req(asset, subaccount_id)
    if addrs:
        return addrs[0]
    if _addresses_create_req(asset, subaccount_id):
        addrs = _addresses_req(asset, subaccount_id)
        if addrs:
            return addrs[0]
    return None

def crypto_withdrawal_create(asset, amount, address):
    if _account_mock():
        return utils.generate_key()
    return _crypto_withdrawal_create_req(asset, amount, address)

def crypto_withdrawal_status_check(withdrawal_id):
    if _account_mock():
        return True
    withdrawal = _crypto_withdrawal_status_req(withdrawal_id)
    return withdrawal and withdrawal.status == 'Completed'

def crypto_deposits(asset, subaccount_id):
    deposits = []
    deps = _crypto_deposits_pending_req(asset, subaccount_id)
    if deps:
        for dep in deps:
            deposits.append(dep)
    deps = _crypto_deposits_closed_req(asset, subaccount_id)
    if deps:
        for dep in deps:
            deposits.append(dep)
    return deposits

def crypto_deposit_search(asset, address, amount, subaccount_id):
    assert isinstance(amount, decimal.Decimal)
    if _account_mock():
        id_ = utils.generate_key()
        txid = utils.generate_key()
        return [Munch(id=id_, symbol=asset, address=address, amount=amount, date='blah', status='COMPLETED', txid=txid)]
    deposits = []
    deps = _crypto_deposits_pending_req(asset, subaccount_id)
    if deps:
        for dep in deps:
            if dep.address == address and amount == dep.amount:
                deposits.append(dep)
    deps = _crypto_deposits_closed_req(asset, subaccount_id)
    if deps:
        for dep in deps:
            if dep.address == address and amount == dep.amount:
                deposits.append(dep)
    return deposits

def crypto_deposit_status_check(deposit_id):
    if _account_mock():
        return True
    deposit = _crypto_deposit_status_req(deposit_id)
    return deposit and deposit.status == 'COMPLETED'

def subaccount_create(reference):
    if _account_mock():
        return utils.generate_key()
    return _subaccount_req(reference)

def funds_available(asset, amount):
    assert isinstance(amount, decimal.Decimal)
    for balance in account_balances(asset):
        if balance.symbol == asset:
            return balance.available >= amount
    return False
