from decimal import Decimal
from typing import Optional
import logging

import assets
from ln import LnRpc

logger = logging.getLogger(__name__)

def funds_available(asset: str, l2_network: Optional[str], amount_dec: Decimal) -> bool:
    if asset != assets.BTC.name or l2_network != assets.BTCLN.name:
        return False
    rpc = LnRpc()
    funds = rpc.list_funds()
    sats = assets.asset_dec_to_int(asset, amount_dec * Decimal('1.01')) # add a 1% buffer for fees
    logger.info('required: %d sats, largest channel: %d sats', sats, funds['sats_largest_channel'])
    return funds['sats_largest_channel'] > sats

def withdrawals_supported(asset: str, l2_network: Optional[str]):
    return asset == assets.BTC.name and l2_network == assets.BTCLN.name

def withdrawal_create(asset: str, l2_network: Optional[str], amount_dec: Decimal, recipient: str):
    assert withdrawals_supported(asset, l2_network)
    rpc = LnRpc()
    result = rpc.decode_pay(recipient)
    if not result:
        logger.error('ln pay not decoded: %s', recipient)
        return None
    amount_sat = assets.asset_dec_to_int(asset, amount_dec)
    if amount_sat != result['amount_sat']:
        logger.error('ln pay amount does not match: %d, %d', amount_sat, result['amount_sat'])
        return None
    result = rpc.pay(recipient)
    if not result:
        logger.error('ln pay failed: %s', recipient)
        return None
    logger.info('ln pay made: %s', result['payment_hash'])
    return result['payment_hash']

def withdrawal_completed(wallet_reference: str) -> bool:
    rpc = LnRpc()
    result = rpc.pay_status_from_hash(wallet_reference)
    if not result:
        logger.error('ln pay not found: %s', wallet_reference)
        return False
    complete = result['status'] == 'complete'
    logger.info('ln pay complete: %s', complete)
    return complete
