import os
import datetime
from typing import Optional

import pytz
from pyln.client import LightningRpc

def _msat_to_sat(msats):
    return int(int(msats) / 1000)

def _sat_to_msat(sats):
    return int(sats) * 1000

# pylint: disable=too-many-public-methods
class LnRpc():
    def __init__(self):
        if 'LN_RPC_FILE' in os.environ:
            self.instance = LightningRpc(os.environ['LN_RPC_FILE'])
        else:
            self.instance = LightningRpc("/etc/lightning/lightning-rpc")

    def get_info(self):
        return self.instance.getinfo()

    def list_nodes(self):
        return self.instance.listnodes()

    def connect_node(self, node_address):
        return self.instance.connect(node_address)

    def list_peers(self):
        return self.instance.listpeers()

    #
    # LN
    #

    def invoice(self, sats, label, msg):
        # create a LN invoice
        return self.instance.invoice(_sat_to_msat(sats), label, msg)

    def pay(self, bolt11: str) -> Optional[dict]:
        # pay a bolt11 invoice
        invoice_result = self.instance.pay(bolt11)
        if not invoice_result:
            return None
        invoice_result["sats_sent"] = _msat_to_sat(invoice_result["msatoshi_sent"].millisatoshis)
        return invoice_result

    def pay_status(self, bolt11: str) -> Optional[dict]:
        # show the status of a specific paid bolt11 invoice
        return self.instance.listpays(bolt11=bolt11)

    def pay_status_from_hash(self, payment_hash: str) -> Optional[dict]:
        # show the status of a specific payment hash
        return self.instance.listpays(payment_hash=payment_hash)

    def list_paid(self):
        # show the status of all paid bolt11 invoice
        results = []
        pays = self.instance.listpays()
        for pay in pays["pays"]:
            created_at = pay["created_at"]
            date = datetime.datetime.fromtimestamp(
                created_at, pytz.timezone('Pacific/Auckland'))
            status = pay["status"]
            amount_msat = pay["amount_sent_msat"].millisatoshis
            amount_sats = _msat_to_sat(amount_msat)
            results.append({"created_at": created_at,
                            "date": date,
                            "status": status,
                            "amount_msat": amount_msat,
                            "amount_sats": amount_sats})
        return results

    def decode_pay(self, bolt11: str) -> Optional[dict]:
        result = self.instance.decodepay(bolt11)
        sats = _msat_to_sat(result["amount_msat"].millisatoshis)
        result['amount_sat'] = sats
        return result

    def wait_any(self):
        invoice_list = self.list_paid()
        last_index = len(invoice_list)
        return self.instance.waitanyinvoice(lastpay_index=last_index)

    def list_channels(self):
        return self.instance.listchannels()

    def rebalance_channel(self, oscid, iscid, amount_sat):
        return self.instance.rebalance(oscid, iscid, _sat_to_msat(amount_sat))

    def fee_rates(self):
        # get fee rates in unit of sats per 1000 virtual bytes
        return self.instance.feerates("perkb")

    def key_send(self, node_id, sats):
        return self.instance.keysend(node_id, _sat_to_msat(sats))

    def list_forwards(self):
        return self.instance.listforwards()

    #
    # Onchain
    #

    def list_funds(self):
        funds_dict = self.instance.listfunds()
        msats_largest_channel = 0
        msats_channels = 0
        msats_onchain = 0
        sats_largest_channel = 0
        sats_channels = 0
        sats_onchain = 0
        # Only shows after the very first transaction otherwise errors.
        for chan in funds_dict["channels"]:
            msats_channel = chan["our_amount_msat"].millisatoshis
            if msats_channel > msats_largest_channel:
                msats_largest_channel = msats_channel
            msats_channels += msats_channel
        sats_largest_channel = _msat_to_sat(msats_largest_channel)
        sats_channels = _msat_to_sat(msats_channels)
        for output in funds_dict["outputs"]:
            if output["status"] == "confirmed":
                msats_onchain += output["amount_msat"].millisatoshis
        sats_onchain += _msat_to_sat(msats_onchain)
        return dict(msats_largest_channel=msats_largest_channel, msats_channels=msats_channels, msats_onchain=msats_onchain, sats_largest_channel=sats_largest_channel, sats_channels=sats_channels, sats_onchain=sats_onchain)

    #def open_channel(self, node_id, sats):
    #    return self.instance.fundchannel_start(node_id, _sat_to_msat(sats))

    def fund_channel(self, node_id, sats):
        return self.instance.fundchannel(node_id, _sat_to_msat(sats))

    def close_channel(self, peer_id):
        return self.instance.close(peer_id)

    def new_address(self):
        # return a bech32 address
        return self.instance.newaddr(addresstype='bech32')

    def list_txs(self):
        return self.instance.listtransactions()

    def multi_withdraw(self, outputs_dict):
        # outputs is in form {"address" : amount}
        return self.instance.multiwithdraw(outputs_dict)

    def prepare_psbt(self, outputs):
        return self.instance.txprepare(outputs)

    def sign_psbt(self, unsigned_psbt):
        return self.instance.signpsbt(unsigned_psbt)

    def send_psbt(self, signed_psbt):
        return self.instance.sendpsbt(signed_psbt)
