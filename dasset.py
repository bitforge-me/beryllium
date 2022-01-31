import logging
import decimal
import json
from enum import Enum

import requests
from munch import Munch
import pyotp

import utils
from app_core import app
import assets

logger = logging.getLogger(__name__)

DASSET_API_SECRET = app.config['DASSET_API_SECRET']
DASSET_ACCOUNT_ID = app.config['DASSET_ACCOUNT_ID']
BROKER_ORDER_FEE = decimal.Decimal(app.config['BROKER_ORDER_FEE'])

URL_BASE = 'https://api.dassetx.com/api'
URL_BASE_SUBACCOUNT = 'https://api.dassetx.com/prod/api'

CRYPTO_WITHDRAWAL_STATUS_COMPLETED = 'completed'
CRYPTO_WITHDRAWAL_STATUS_2FA = '2fa'
CRYPTO_WITHDRAWAL_STATUS_UNKNOWN = 'unknown'

class QuoteResult(Enum):
    OK = 0
    AMOUNT_TOO_LOW = 1
    INSUFFICIENT_LIQUIDITY = 2

#
# Helper functions
#

def _account_mock():
    return app.config['EXCHANGE_ACCOUNT_MOCK']

def _parse_balance(item):
    symbol = item['currencySymbol']
    return Munch(symbol=symbol, name=item['currencyName'], total=decimal.Decimal(item['total']), available=decimal.Decimal(item['available']), decimals=assets.asset_decimals(symbol))

def _parse_asset(item):
    symbol = item['symbol']
    message = ''
    if 'notice' in item:
        message = item['notice']
    return Munch(symbol=symbol, name=item['name'], coin_type=item['coinType'], status=item['status'], min_confs=item['minConfirmations'], message=message, decimals=assets.asset_decimals(symbol))

def _parse_market(item):
    message = ''
    if 'notice' in item:
        message = item['notice']
    return Munch(symbol=item['symbol'], base_asset=item['baseCurrencySymbol'], quote_asset=item['quoteCurrencySymbol'], precision=item['precision'], status=item['status'], min_trade=item['minTradeSize'], message=message)

def _parse_order_book(item):
    return Munch(bids=item['bid'], asks=item['ask'])

def _parse_order(item):
    side = assets.MarketSide.BID if item['type'] == 'BUY' else assets.MarketSide.ASK
    return Munch(id=item['id'], base_asset=['baseSymbol'], quote_asset=['quoteSymbol'], date=item['timestamp'], side=side, status=item['status'], \
        base_amount=item['baseAmount'], quote_amount=item['quoteAmount'], filled=item['details']['filled'])

def _parse_deposit(item):
    return Munch(id=item['id'], symbol=item['currencySymbol'], address=item['cryptoAddress'], amount=decimal.Decimal(item['quantity']), date=item['updatedAt'], status=item['status'], txid=item['txId'])

def _parse_withdrawal_full(item):
    id_ = item['id'] if 'id' in item else item['transactionId']
    amount = item['amount'] if 'amount' in item else item['quantity']
    return Munch(id=id_, symbol=item['currencySymbol'], amount=amount, date=item['createdAt'], status=item['status'], address=item['cryptoAddress'])

def _parse_withdrawal_2fa(item):
    id_ = item['transactionId']
    if 'status' in item:
        status = item['status']
    else:
        status = item['mfaStatus']
    return Munch(id=id_, symbol='', amount=0, date='', status=status, address='')

def _parse_withdrawal(item):
    try:
        return _parse_withdrawal_full(item)
    except: # pylint: disable=bare-except
        return _parse_withdrawal_2fa(item)

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
    r = requests.get(url, headers=headers, params=params)
    logger.info('GET - %s', url)
    headers['x-api-key'] = 'xxxxx'
    logger.info('HEADERS - %s', headers)
    return r

def _req_post(endpoint, params, subaccount_id=None):
    url = URL_BASE + endpoint
    headers = {}
    headers['x-api-key'] = DASSET_API_SECRET
    headers['x-account-id'] = DASSET_ACCOUNT_ID
    if subaccount_id:
        headers['x-subaccount-id'] = subaccount_id
    r = requests.post(url, headers=headers, data=json.dumps(params))
    logger.info('POST - %s', url)
    headers['x-api-key'] = 'xxxxx'
    logger.info('HEADERS - %s', headers)
    logger.info('PARAMS - %s', params)
    return r

def _req_put(endpoint, params):
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
        return [_parse_asset(a) for a in r.json() if a['symbol'] in assets.ASSETS]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def markets_req():
    endpoint = '/markets'
    r = _req_get(endpoint)
    if r.status_code == 200:
        markets = r.json()
        markets = [_parse_market(m) for m in markets if m['symbol'] in assets.MARKETS]
        return markets
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def order_book_req(symbol):
    endpoint = f'/markets/{symbol}/orderbook'
    r = _req_get(endpoint)
    if r.status_code == 200:
        min_order = assets.MARKETS[symbol].min_order
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
        balances = [_parse_balance(b) for b in balances if b['currencySymbol'] in assets.ASSETS]
        return balances
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _order_create_req(market, side, amount, price):
    assert isinstance(side, assets.MarketSide)
    assert isinstance(amount, decimal.Decimal)
    assert isinstance(price, decimal.Decimal)
    endpoint = '/orders'
    if side is assets.MarketSide.BID:
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
    page = int(offset / limit) + 1
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
        withdrawal = _parse_withdrawal(r.json()[0])
        return withdrawal['id']
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _crypto_withdrawal_status_req(withdrawal_id):
    endpoint = f'/crypto/withdrawals/{withdrawal_id}'
    r = _req_get(endpoint)
    if r.status_code == 200:
        return _parse_withdrawal(r.json()[0])
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _crypto_withdrawal_confirm_req(withdrawal_id, totp_code):
    endpoint = '/crypto/withdrawals/confirm'
    r = _req_post(endpoint, params=dict(txId=withdrawal_id, token=totp_code))
    if r.status_code == 200:
        return True
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return False

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
    r = _req_put(endpoint, params=dict(reference=reference))
    if r.status_code == 200:
        return r.json()[0]
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return None

def _transfer_req(to_master, from_subaccount_id, to_subaccount_id, asset, amount):
    endpoint = '/transfer'
    r = _req_put(endpoint, params=dict(toMasterAccount=to_master, fromSubaccountId=from_subaccount_id, toSubaccountId=to_subaccount_id, symbol=asset, quantity=str(amount)))
    if r.status_code == 200:
        return True
    logger.error('request failed: %d, %s', r.status_code, r.content)
    return False

#
# Public functions
#

def crypto_deposit_completed(deposit):
    return deposit and deposit.status == 'COMPLETED'

#
# Public functions that rely on an exchange request
#

def bid_quote_amount(market, amount):
    assert isinstance(amount, decimal.Decimal)
    if amount < assets.MARKETS[market].min_order:
        return decimal.Decimal(-1), QuoteResult.AMOUNT_TOO_LOW

    order_book, _, broker_fee = order_book_req(market)

    filled = decimal.Decimal(0)
    total_price = decimal.Decimal(0)
    n = 0
    while amount > filled:
        if n >= len(order_book.asks):
            break
        rate = decimal.Decimal(order_book.asks[n]['rate'])
        quantity = decimal.Decimal(order_book.asks[n]['quantity'])
        quantity_to_use = quantity
        if quantity_to_use > amount - filled:
            quantity_to_use = amount - filled
        filled += quantity_to_use
        total_price += quantity_to_use * rate
        if filled == amount:
            return total_price * (decimal.Decimal(1) + broker_fee / decimal.Decimal(100)), QuoteResult.OK
        n += 1

    return decimal.Decimal(-1), QuoteResult.INSUFFICIENT_LIQUIDITY

def ask_quote_amount(market, amount):
    assert isinstance(amount, decimal.Decimal)
    if amount < assets.MARKETS[market].min_order:
        return decimal.Decimal(-1), QuoteResult.AMOUNT_TOO_LOW

    order_book, _, broker_fee = order_book_req(market)

    filled = decimal.Decimal(0)
    total_price = decimal.Decimal(0)
    n = 0
    while amount > filled:
        if n >= len(order_book.bids):
            break
        rate = decimal.Decimal(order_book.bids[n]['rate'])
        quantity = decimal.Decimal(order_book.bids[n]['quantity'])
        quantity_to_use = quantity
        if quantity_to_use > amount - filled:
            quantity_to_use = amount - filled
        filled += quantity_to_use
        total_price += quantity_to_use * rate
        if filled == amount:
            return total_price * (decimal.Decimal(1) - broker_fee / decimal.Decimal(100)), QuoteResult.OK
        n += 1

    return decimal.Decimal(-1), QuoteResult.INSUFFICIENT_LIQUIDITY

def account_balances(asset=None, subaccount_id=None):
    if _account_mock():
        balances = []
        for item in assets.ASSETS.values():
            if subaccount_id and assets.asset_is_fiat(item.symbol):
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
    if not order:
        return False
    return order.status == 'Completed'

def address_get_or_create(asset, subaccount_id):
    if _account_mock():
        return asset + '-XXX'
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
        return CRYPTO_WITHDRAWAL_STATUS_COMPLETED
    withdrawal = _crypto_withdrawal_status_req(withdrawal_id)
    if not withdrawal:
        return CRYPTO_WITHDRAWAL_STATUS_UNKNOWN
    if withdrawal.status == 'Completed':
        return CRYPTO_WITHDRAWAL_STATUS_COMPLETED
    if withdrawal.status == 'awaiting_mfa_confirmation':
        return CRYPTO_WITHDRAWAL_STATUS_2FA
    return CRYPTO_WITHDRAWAL_STATUS_UNKNOWN

def crypto_withdrawal_confirm(withdrawal_id):
    key = app.config['DASSET_TOTP_KEY']
    totp = pyotp.TOTP(key)
    code = totp.now()
    return _crypto_withdrawal_confirm_req(withdrawal_id, code)

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

def crypto_deposit_status_check(deposit_id):
    if _account_mock():
        return True
    deposit = _crypto_deposit_status_req(deposit_id)
    return crypto_deposit_completed(deposit)

def subaccount_create(reference):
    if _account_mock():
        return utils.generate_key()
    return _subaccount_req(reference)

def transfer(to_subaccount_id, from_subaccount_id, asset, amount):
    assert to_subaccount_id is None or from_subaccount_id is None
    assert isinstance(amount, decimal.Decimal)
    to_master = not to_subaccount_id
    return _transfer_req(to_master, from_subaccount_id, to_subaccount_id, asset, amount)

def funds_available_us(asset, amount):
    assert isinstance(amount, decimal.Decimal)
    for balance in account_balances(asset):
        if balance.symbol == asset:
            return balance.available >= amount
    return False
