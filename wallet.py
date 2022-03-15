from decimal import Decimal
from typing import Optional

import assets
from ln import LnRpc

def funds_available(asset: str, l2_network: Optional[str], amount_dec: Decimal) -> bool:
    if asset != assets.BTC.name or l2_network != assets.BTCLN.name:
        return False
    rpc = LnRpc()
    funds = rpc.list_funds()
    sats = assets.asset_dec_to_int(asset, amount_dec * Decimal('1.01')) # add a 1% buffer for fees
    return funds['sats_largest_channel'] > sats

def withdrawals_supported(asset: str, l2_network: Optional[str]):
    return asset == assets.BTC.name and l2_network == assets.BTCLN.name

def withdrawal_create(asset: str, l2_network: Optional[str], amount_dec: Decimal, recipient: str):
    assert withdrawals_supported(asset, l2_network)
    rpc = LnRpc()
    result = rpc.decode_pay(recipient)
    if not result:
        return None
    if assets.asset_int_to_dec(asset, result['amount_sat']) != amount_dec:
        return None
    result = rpc.pay(recipient)
    if not result:
        return None
    return result['payment_hash']

def withdrawal_completed(wallet_reference: str) -> bool:
    rpc = LnRpc()
    result = rpc.pay_status_from_hash(wallet_reference)
    if not result:
        return False
    return result['status'] == 'complete'
