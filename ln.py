import os
import datetime
import pytz

from pyln.client import LightningRpc

# pylint: disable=too-many-public-methods
class LnRpc():
    def __init__(self):
        if 'LN_RPC_FILE' in os.environ:
            self.instance = LightningRpc(os.environ['LN_RPC_FILE'])
        else:
            self.instance = LightningRpc("/etc/lightning/lightning-rpc")

    def get_info(self):
        return self.instance.getinfo()

    def create_invoice(self, amount, label, msg):
        # create a LN invoice
        return self.instance.invoice(amount, label, msg)

    def send_invoice(self, bolt11):
        # pay a bolt11 invoice
        invoice_result = self.instance.pay(bolt11)
        invoice_result["sats_sent"] = int(invoice_result["msatoshi_sent"] / 1000)
        return invoice_result

    def payment_status(self, bolt11string):
        # show the status of a specific paid bolt11 invoice
        return self.instance.listpays(bolt11=bolt11string)

    def list_paid(self):
        # show the status of all paid bolt11 invoice
        results = []
        list_pays = self.instance.listpays()
        for list_pay in list_pays["pays"]:
            created_at = list_pay["created_at"]
            date = datetime.datetime.fromtimestamp(
                list_pay["created_at"], pytz.timezone('Pacific/Auckland'))
            status = list_pay["status"]
            amount_msat = list_pay["amount_sent_msat"]
            amount_sats = int(round(int(list_pay["amount_sent_msat"]) / 1000))
            results.append({"created_at": created_at,
                            "date": date,
                            "status": status,
                            "amount_msat": amount_msat,
                            "amount_sats": amount_sats})
        return results

    def list_nodes(self):
        return self.instance.listnodes()

    def connect_nodes(self, node_address):
        return self.instance.connect(node_address)

    def fund_channel(self, node_id, amount):
        return self.instance.fundchannel(node_id, amount)

    def list_peers(self):
        return self.instance.listpeers()

    def open_channel(self, node_id, amount):
        return self.instance.fundchannel_start(node_id, amount)

    def new_address(self):
        # return a bech32 address
        return self.instance.newaddr(addresstype='bech32')

    def list_txs(self):
        return self.instance.listtransactions()

    def multi_withdraw(self, outputs_dict):
        # outputs is in form {"address" : amount}
        return self.instance.multiwithdraw(outputs_dict)

    def list_funds(self):
        funds_dict = self.instance.listfunds()
        funds_channel = 0
        funds_onchain = 0
        sats_channel = 0
        sats_onchain = 0
        # Only shows after the very first transaction otherwise errors.
        for i in range(len(funds_dict["channels"])):
            funds_channel += int(str(funds_dict["channels"]
                                 [i]["our_amount_msat"]).split("msat", 1)[0])
        sats_channel += int(funds_channel / 1000)
        for i in range(len(funds_dict["outputs"])):
            if funds_dict["outputs"][i]["status"] == "confirmed":
                funds_onchain += int(str(funds_dict["outputs"]
                                     [i]["amount_msat"]).split("msat", 1)[0])
        sats_onchain += int(funds_onchain / 1000)
        return({"funds_channel": funds_channel, "funds_onchain": funds_onchain, "sats_channel": sats_channel, "sats_onchain": sats_onchain})

    def decode_pay(self, bolt11):
        bolt11_result = self.instance.decodepay(bolt11)
        amount_sats = int(
            int(str(bolt11_result["amount_msat"]).split("msat", 1)[0]) / 1000)
        return {
            "amount": amount_sats,
            "description": bolt11_result["description"],
            "payee": bolt11_result["payee"]}

    def wait_any(self):
        invoice_list = self.list_paid()
        last_index = len(invoice_list)
        return self.instance.waitanyinvoice(lastpay_index=last_index)

    def list_channels(self):
        return self.instance.listchannels()

    def rebalance_individual_channel(self, oscid, iscid, amountmillisatoshi):
        result = self.instance.rebalance(oscid, iscid, amountmillisatoshi)
        return result

    def close_channel(self, peer_id):
        return self.instance.close(peer_id)

    def fee_rates(self):
        # get fee rates in unit of sats per 1000 virtual bytes
        return self.instance.feerates("perkb")

    def prepare_psbt(self, outputs):
        return self.instance.txprepare(outputs)

    def send_psbt(self, signed_psbt):
        return self.instance.sendpsbt(signed_psbt)

    def sign_psbt(self, unsigned_psbt):
        return self.instance.signpsbt(unsigned_psbt)

    def key_send(self, node_id, msats):
        return self.instance.keysend(node_id, msats)

    def list_forwards(self):
        return self.instance.listforwards()
