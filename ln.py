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

    def invoice_status(self, bolt11: str) -> bool:
        return self.instance.listinvoices(invstring=bolt11)

    def pay(self, bolt11: str) -> Optional[dict]:
        # pay a bolt11 invoice
        return self.instance.pay(bolt11)

    def pay_status(self, bolt11: str) -> list:
        # show the status of a specific paid bolt11 invoice
        return self.instance.listpays(bolt11=bolt11)

    def pay_status_from_hash(self, payment_hash: str) -> list:
        # show the status of a specific payment hash
        return self.instance.listpays(payment_hash=payment_hash)

    def lastpay_index(self):
        result = self.instance.listinvoices()
        invoices = result['invoices']
        current_pay_index = 0
        for invoice in invoices:
            if invoice['status'] == 'paid':
                pay_index = invoice['pay_index']
                if pay_index > current_pay_index:
                    current_pay_index = pay_index
        return current_pay_index

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

    def decode_bolt11(self, bolt11: str) -> Optional[dict]:
        result = self.instance.decodepay(bolt11)
        sats = _msat_to_sat(result["amount_msat"].millisatoshis)
        result['amount_sat'] = sats
        return result

    def wait_any_invoice(self, lastpay_index=0, timeout=None):
        return self.instance.waitanyinvoice(lastpay_index=lastpay_index, timeout=timeout)

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

    def list_invoices(self):
        results = []
        result_invoices = self.instance.listinvoices()
        for invoice in result_invoices["invoices"]:
            label = invoice["label"]
            description = invoice["description"]
            payment_hash = invoice["payment_hash"]
            expires_at = invoice["expires_at"]
            amount_msat = invoice["amount_msat"]
            amount_sats = _msat_to_sat(amount_msat)
            bolt11 = invoice["bolt11"]
            pay_index = None
            amount_received_msat = None
            paid_at = None
            paid_date = None
            payment_preimage = None
            status = invoice["status"]
            if status == 'paid':
                pay_index = invoice["pay_index"]
                amount_received_msat = invoice["amount_received_msat"]
                paid_at = invoice["paid_at"]
                paid_date = datetime.datetime.fromtimestamp(paid_at, pytz.timezone('Pacific/Auckland'))
                payment_preimage = invoice["payment_preimage"]
            results.append({"paid_date": paid_date, "description": description, "status": status, "amount_msat": amount_msat, "amount_sats": amount_sats, "pay_index": pay_index, "amount_received_msat": amount_received_msat, "payment_preimage": payment_preimage, "bolt11": bolt11, "expires_at": expires_at, "payment_hash": payment_hash, "label": label})
        return results

    #
    # Onchain
    #

    def list_funds(self):
        funds_dict = self.instance.listfunds()
        msats_largest_channel = 0
        msats_channels = 0
        msats_largest_channel_theirs = 0
        msats_channels_theirs = 0
        msats_onchain = 0
        sats_largest_channel = 0
        sats_channels = 0
        sats_largest_channel_theirs = 0
        sats_channels_theirs = 0
        sats_onchain = 0
        # Only shows after the very first transaction otherwise errors.
        for chan in funds_dict["channels"]:
            if chan["state"] == "CHANNELD_NORMAL":
                msats_channel = chan["our_amount_msat"].millisatoshis
                if msats_channel > msats_largest_channel:
                    msats_largest_channel = msats_channel
                msats_channels += msats_channel
                msats_channel_theirs = chan["amount_msat"].millisatoshis - chan["our_amount_msat"].millisatoshis
                if msats_channel_theirs > msats_largest_channel_theirs:
                    msats_largest_channel_theirs = msats_channel_theirs
                msats_channels_theirs += msats_channel_theirs
        sats_largest_channel = _msat_to_sat(msats_largest_channel)
        sats_channels = _msat_to_sat(msats_channels)
        sats_largest_channel_theirs = _msat_to_sat(msats_largest_channel_theirs)
        sats_channels_theirs = _msat_to_sat(msats_channels_theirs)
        for output in funds_dict["outputs"]:
            if output["status"] == "confirmed":
                msats_onchain += output["amount_msat"].millisatoshis
        sats_onchain += _msat_to_sat(msats_onchain)
        return dict(msats_largest_channel=msats_largest_channel, msats_channels=msats_channels, msats_largest_channel_theirs=msats_largest_channel_theirs, msats_channels_theirs=msats_channels_theirs, msats_onchain=msats_onchain, sats_largest_channel=sats_largest_channel, sats_channels=sats_channels, sats_channels_theirs=sats_channels_theirs, sats_largest_channel_theirs=sats_largest_channel_theirs, sats_onchain=sats_onchain)

    #def open_channel(self, node_id, sats):
    #    return self.instance.fundchannel_start(node_id, _sat_to_msat(sats))

    def fund_channel(self, node_id, sats):
        return self.instance.fundchannel(node_id, sats)

    def close_channel(self, channel_id):
        return self.instance.close(channel_id)

    def new_address(self, address_type):
        # return a bech32 address
        return self.instance.newaddr(addresstype=address_type)

    def list_txs(self):
        return self.instance.listtransactions()

    def multi_withdraw(self, outputs_dict):
        # outputs is in form {"address" : amount}
        return self.instance.multiwithdraw(outputs_dict)

    def prepare_psbt(self, outputs):
        return self.instance.txprepare(outputs)

    def send_invoice(self, bolt11):
        # pay a bolt11 invoice
        invoice_result = self.instance.pay(bolt11)
        invoice_result["sats_sent"] = _msat_to_sat(invoice_result["msatoshi_sent"])
        return invoice_result

    def sign_psbt(self, unsigned_psbt):
        return self.instance.signpsbt(unsigned_psbt)

    def send_psbt(self, signed_psbt):
        return self.instance.sendpsbt(signed_psbt)
