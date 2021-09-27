import logging
import decimal
from enum import Enum

import bitcoin
import bitcoin.wallet
import base58
import web3
from munch import Munch
from stdnum.nz import bankaccount

from app_core import app

logger = logging.getLogger(__name__)

TESTNET = app.config['TESTNET']
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

def _base58_validate(address, mainnet_prefixes, testnet_prefixes):
    try:
        raw = base58.b58decode_check(address)
        prefix = raw[0]
        return not TESTNET and prefix in mainnet_prefixes or TESTNET and prefix in testnet_prefixes
    except ValueError:
        return False

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

def asset_recipient_validate(asset, recipient):
    result = False
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

def market_recipent_validate(market, side, recipient):
    base_asset, quote_asset = assets_from_market(market)
    if side is MarketSide.BID:
        asset = base_asset
    else:
        asset = quote_asset
    return asset_recipient_validate(asset, recipient)

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
