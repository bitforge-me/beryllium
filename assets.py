import logging
from decimal import Decimal as Dec
from enum import Enum
from typing import Union, Optional
from dataclasses import dataclass

import bitcoin
import bitcoin.wallet
import base58
import web3
from stdnum.nz import bankaccount

from app_core import app
from ln import LnRpc

logger = logging.getLogger(__name__)

@dataclass
class Asset:
    symbol: str
    name: str
    decimals: int
    withdraw_fee: Dec
    min_withdraw: Dec
    is_crypto: bool
    l2_network: Optional['Asset']

@dataclass
class Market:
    base_asset: str
    quote_asset: str

TESTNET = app.config['TESTNET']
NZD = Asset(symbol='NZD', name='New Zealand Dollar', decimals=2, withdraw_fee=Dec(7), min_withdraw=Dec(20), is_crypto=False, l2_network=None)
BTCLN = Asset(symbol='BTC-LN', name='Bitcoin (Lightning)', decimals=8, withdraw_fee=Dec('0'), min_withdraw=Dec('0.00000001'), is_crypto=True, l2_network=None)
BTC = Asset(symbol='BTC', name='Bitcoin', decimals=8, withdraw_fee=Dec('0.0003'), min_withdraw=Dec('0.001'), is_crypto=True, l2_network=BTCLN)
ETH = Asset(symbol='ETH', name='Ethereum', decimals=18, withdraw_fee=Dec('0.0052'), min_withdraw=Dec('0.01'), is_crypto=True, l2_network=None)
DOGE = Asset(symbol='DOGE', name='Dogecoin', decimals=8, withdraw_fee=Dec(5), min_withdraw=Dec(20), is_crypto=True, l2_network=None)
LTC = Asset(symbol='LTC', name='Litecoin', decimals=8, withdraw_fee=Dec('0.01'), min_withdraw=Dec('0.03'), is_crypto=True, l2_network=None)
WAVES = Asset(symbol='WAVES', name='Waves', decimals=8, withdraw_fee=Dec('0.001'), min_withdraw=Dec('0.003'), is_crypto=True, l2_network=None)
ASSETS = dict(NZD=NZD, BTC=BTC, ETH=ETH, DOGE=DOGE, LTC=LTC, WAVES=WAVES)
MARKETS = {'BTC-NZD': Market(base_asset=BTC, quote_asset=NZD), \
    'ETH-NZD': Market(base_asset=ETH, quote_asset=NZD), \
    'DOGE-NZD': Market(base_asset=DOGE, quote_asset=NZD), \
    'LTC-NZD': Market(base_asset=LTC, quote_asset=NZD), \
    'WAVES-BTC': Market(base_asset=WAVES, quote_asset=BTC)}

class MarketSide(Enum):
    BID = 'bid'
    ASK = 'ask'

    @classmethod
    def parse(cls, val: str):
        try:
            return cls(val)
        except: # pylint: disable=bare-except
            return None

#
# Helper functions
#

def _base58_validate(address: str, mainnet_prefixes: list[int], testnet_prefixes: list[int]) -> bool:
    try:
        raw = base58.b58decode_check(address)
        prefix = raw[0]
        return not TESTNET and prefix in mainnet_prefixes or TESTNET and prefix in testnet_prefixes
    except ValueError:
        return False

#
# Public functions
#

def market_side_is(have: Union[MarketSide, str], should_have: MarketSide) -> bool:
    assert isinstance(should_have, MarketSide)
    assert isinstance(have, (MarketSide, str))
    if isinstance(have, str):
        return have == should_have.value
    return have is should_have

def market_side_nice(side: Union[MarketSide, str]) -> str:
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

def assets_from_market(market: str) -> tuple[str, str]:
    return market.split('-')

def asset_decimals(asset: str) -> int:
    return ASSETS[asset].decimals

def asset_withdraw_fee(asset: str) -> Dec:
    return ASSETS[asset].withdraw_fee

def asset_min_withdraw(asset: str, l2_network: Optional[str]) -> Dec:
    ass = ASSETS[asset]
    if l2_network:
        assert ass.l2_network is not None and ass.l2_network.symbol == l2_network
        return ass.l2_network.min_withdraw
    return ass.min_withdraw

def asset_int_to_dec(asset: str, value: int) -> Dec:
    decimals = asset_decimals(asset)
    return Dec(value) / Dec(10**decimals)

def asset_dec_to_int(asset: str, value: Dec) -> int:
    decimals = asset_decimals(asset)
    return int(value * Dec(10**decimals))

def asset_dec_to_str(asset: str, value: Dec) -> str:
    decimals = asset_decimals(asset)
    return str(value.quantize(Dec(10) ** -decimals))

def asset_is_crypto(asset: str) -> bool:
    for item in ASSETS.values():
        if item.symbol == asset and item.is_crypto:
            return True
    return False

def asset_has_l2(asset: str, l2_network: str) -> bool:
    for item in ASSETS.values():
        if item.symbol == asset and item.l2_network is not None and item.l2_network.symbol == l2_network:
            return True
    return False

def asset_is_fiat(asset: str) -> bool:
    for item in ASSETS.values():
        if item.symbol == asset and not item.is_crypto:
            return True
    return False

def asset_recipient_extract_amount(asset: str, l2_network: Optional[str], recipient: str) -> Dec:
    if asset == BTC.symbol and l2_network == BTCLN.symbol:
        rpc = LnRpc()
        result = rpc.decode_pay(recipient)
        if not result:
            return Dec(0)
        return asset_int_to_dec(asset, result['amount_sat'])
    return Dec(0)

def asset_recipient_validate(asset: str, l2_network: Optional[str], recipient: str) -> bool:
    result = False
    if asset == NZD.symbol:
        result = bankaccount.is_valid(recipient)
    elif asset == BTC.symbol:
        if l2_network == BTCLN.symbol:
            # if a valid lightning invoice it should have a positive amount to send
            return asset_recipient_extract_amount(asset, l2_network, recipient) > 0
        bitcoin.SelectParams('testnet' if TESTNET else 'mainnet')
        try:
            bitcoin.wallet.CBitcoinAddress(recipient)
            result = True
        except: # pylint: disable=bare-except
            pass
    elif asset == ETH.symbol:
        result = web3.Web3.isAddress(recipient)
    elif asset == DOGE.symbol:
        result = _base58_validate(recipient, [0x1E], [0x71])
    elif asset == LTC.symbol:
        result = _base58_validate(recipient, [0x30], [0x6F])
    if not result:
        logger.error('failed to validate recipient "%s" (%s)', recipient, asset)
    return result

def crypto_uri(asset: str, address: str, amount_int: int) -> Optional[str]:
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
