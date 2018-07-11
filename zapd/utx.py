#!/usr/bin/python3

import sys
import struct
import random
import time
import binascii
import logging

import gevent
from gevent import socket
import base58

import utils

logger = logging.getLogger(__name__)

MAGIC = 305419896
CONTENT_ID_TX = 0x19
CONTENT_ID_BLOCK = 0x17
CONTENT_ID_SCORE = 0x18

def create_handshake(port):
    name = b"wavesT"
    name_len = len(name) 
    version_major = 0
    version_minor = 13
    version_patch = 2
    node_name = b"utx"
    node_name_len = len(node_name)
    node_nonce = random.randint(0, 10000)
    declared_address = 0x7f000001 #"127.0.0.1"
    declared_address_port = port
    declared_address_len = 8
    timestamp = int(time.time())
    fmt = ">B%dslllB%dsQlllQ" % (name_len, node_name_len)
    return struct.pack(fmt, name_len, name,
            version_major, version_minor, version_patch,
            node_name_len, node_name, node_nonce,
            declared_address_len, declared_address, declared_address_port,
            timestamp)

def decode_handshake(msg):
    l = msg[0]
    if l == 6 and msg[1:7] in (b"wavesT", b"wavesM"):
        chain = msg[1:7]
        msg = msg[7:]
        vmaj, vmin, vpatch = struct.unpack_from(">lll", msg)
        msg = msg[12:]
        l = msg[0]
        node_name = msg[1:1+l]
        msg = msg[1+l:]
        nonce, decl_addr_len, decl_addr, decl_addr_port, timestamp = struct.unpack_from(">QlllQ", msg)
        return (chain, vmaj, vmin, vpatch, node_name, nonce, decl_addr, decl_addr_port, timestamp)

def to_hex(data):
    s = ""
    for c in data:
        s += "%02X," % c
    return s

def parse_transfer_tx(payload):
    fmt_start = ">B64sB32sB"
    fmt_start_len = struct.calcsize(fmt_start)
    tx_type, sig, tx_type2, pubkey, asset_flag = \
        struct.unpack_from(fmt_start, payload)
    offset = fmt_start_len
    asset_id_len = 0
    asset_id = ""
    if asset_flag:
        asset_id_len = 32
        asset_id = payload[offset:offset+asset_id_len]
    offset += asset_id_len
    fee_asset_flag = payload[offset]
    offset += 1
    fee_asset_id_len = 0
    fee_asset_id = ""
    if fee_asset_flag:
        fee_asset_id_len = 32
        fee_asset_id = payload[offset:offset+fee_asset_id_len]
    offset += fee_asset_id_len
    fmt_mid = ">QQQ26sH"
    fmt_mid_len = struct.calcsize(fmt_mid)
    timestamp, amount, fee, recipient, attachment_len = \
        struct.unpack_from(fmt_mid, payload[offset:])
    offset += fmt_mid_len
    attachment = payload[offset:offset+attachment_len]

    return offset + attachment_len, tx_type, sig, tx_type2, pubkey, asset_flag, asset_id, fee_asset_flag, fee_asset_id, timestamp, amount, fee, recipient, attachment

def parse_block_txs(payload):
    ## Not sure if we will need to parse the block txs, it will require parsing each of the tx types
    ## because they have variable length fields.
    ## We could just RPC to the node and get the nicely formatted block txs as a shortcut.
    pass

def parse_block(payload):
    fmt_header = ">BQ64slQ32sl"
    fmt_header_len = struct.calcsize(fmt_header)
    version, timestamp, parent_sig, consensus_block_len, base_target, generation_sig, txs_len = \
        struct.unpack_from(fmt_header, payload)
    offset = fmt_header_len
    txs = parse_block_txs(payload[offset:offset + txs_len])

def transfer_asset_txid(pubkey, asset_id, fee_asset_id, timestamp, amount, fee, recipient, attachment):
    serialized_data = b'\4' + \
        pubkey + \
        (b'\1' + asset_id if asset_id else b'\0') + \
        (b'\1' + fee_asset_id if fee_asset_id else b'\0') + \
        struct.pack(">Q", timestamp) + \
        struct.pack(">Q", amount) + \
        struct.pack(">Q", fee) + \
        recipient + \
        struct.pack(">H", len(attachment)) + \
        attachment
    return utils.txid_from_txdata(serialized_data)

def parse_message(wutx, msg, on_transfer_utx=None):
    handshake = decode_handshake(msg)
    if handshake:
        logger.info(f"handshake: {handshake[0]} {handshake[1]}.{handshake[2]}.{handshake[3]} {handshake[4]}")
    else:
        while msg:
            fmt = ">llBl"
            if struct.calcsize(fmt) == len(msg):
                length, magic, content_id, payload_len \
                    = struct.unpack_from(fmt, msg)
                payload = ""
            else:
                fmt = ">llBll"
                fmt_size = struct.calcsize(fmt)
                if fmt_size > len(msg):
                    logger.error(f"msg too short - len {len(msg)}, fmt_size {fmt_size}")
                    break

                length, magic, content_id, payload_len, payload_checksum \
                    = struct.unpack_from(fmt, msg)
                payload = msg[fmt_size:fmt_size + payload_len]

            msg = msg[4 + length:]

            logger.debug(f"message: len {length:4}, magic {magic}, content_id: {content_id:#04x}, payload_len {payload_len:4}")

            if magic != MAGIC:
                logger.error("invalid magic")
                break

            if content_id == CONTENT_ID_TX:
                # transaction!
                tx_type = payload[0]
                logger.info(f"transaction type: {tx_type}")
                if tx_type == 4:
                    # transfer
                    tx_len, tx_type, sig, tx_type2, pubkey, asset_flag, asset_id, fee_asset_flag, fee_asset_id, timestamp, amount, fee, recipient, attachment = parse_transfer_tx(payload)
                    txid = transfer_asset_txid(pubkey, asset_id, fee_asset_id, timestamp, amount, fee, recipient, attachment)

                    logger.info(f"  txid: {txid}, senders pubkey: {base58.b58encode(pubkey)}, recipient: {base58.b58encode(recipient)}, amount: {amount}, fee: {fee}, asset id: {asset_id}, timestamp: {timestamp}, attachment: {attachment}")
                    if on_transfer_utx:
                        on_transfer_utx(wutx, txid, sig, pubkey, asset_id, timestamp, amount, fee, recipient, attachment)

            if content_id == CONTENT_ID_BLOCK:
                # block
                logger.debug(f"block: len {len(payload)}")
                parse_block(payload)

            if content_id == CONTENT_ID_SCORE:
                # score
                score = int(binascii.hexlify(payload), 16)
                logger.info(f"score: value {score}")

class WavesUTX():

    def __init__(self, on_msg, on_transfer_utx, addr="127.0.0.1", port=6863):
        self.on_msg = on_msg
        self.on_transfer_utx = on_transfer_utx
        self.addr = addr
        self.port = port

    def init_socket(self):
        while 1:
            try:
                # create an INET, STREAMing socket
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # now connect to the waves node on port 6863
                self.s.connect((self.addr, self.port))
                logger.info(f"socket opened: {self.addr}:{self.port}")
                # send handshake
                local_port = self.s.getsockname()[1]
                handshake = create_handshake(local_port)
                l = self.s.send(handshake)
                logger.info(f"handshake bytes sent: {l}")
                # success, exit loop!
                break
            except socket.error as e:
                logger.error(f"{e}")
                gevent.sleep(10)

    def start(self, group=None):
        def runloop():
            logger.info("WavesUTX runloop started")
            while 1:
                data = self.s.recv(1024)
                if data:
                    logger.debug(f"recv: {len(data)}")
                    if self.on_msg:
                        self.on_msg(self, data)
                    parse_message(self, data, self.on_transfer_utx)
                else:
                    # if data is empty the other side has closed the connection
                    logger.info("empty string from socket.recv(): the socket has been closed")
                    break

        def start_greenlet():
            logger.info("checking p2p socket")
            self.init_socket()
            logger.info("starting WavesUTX runloop...")
            self.runloop_greenlet.start()

        # create greenlet
        self.runloop_greenlet = gevent.Greenlet(runloop)
        if group != None:
            group.add(self.runloop_greenlet)
        # check socket and start greenlet
        gevent.spawn(start_greenlet)

    def stop(self):
        self.runloop_greenlet.kill()

def decode_test_msg():
    # tx msg
    comma_delim_hex = "00,00,00,A5,12,34,56,78,19,00,00,00,98,A1,D3,F9,48,04,0C,2B,4F,19,B5,09,23,F4,E5,A6,60,5C,A3,8B,E3,90,0D,A8,39,40,C6,56,FD,77,D7,10,18,2C,7A,0F,A4,B7,6C,B7,89,AC,1A,37,4F,2B,95,E8,FF,2D,B7,26,70,BF,C8,96,99,25,75,E4,E6,F1,F4,D5,CF,CF,5A,87,B1,8F,04,A9,D5,9F,EE,C5,51,43,8C,C7,43,7E,39,CD,75,32,8B,C0,C3,45,BF,C8,FC,91,88,43,C2,54,87,72,BA,26,40,00,00,00,00,01,64,15,54,57,A5,00,00,00,00,3B,9A,CA,00,00,00,00,00,00,01,86,A0,01,54,8D,98,AF,E7,34,F1,C1,88,CA,06,FB,6C,1F,C0,2B,49,FB,0C,2A,2A,E3,07,13,E9,00,00"
    # score msg
    comma_delim_hex = "00,00,00,17,12,34,56,78,18,00,00,00,0A,08,FA,BA,37,03,3D,C7,31,90,2C,FA,7A,08,EC"

    data = [chr(int(x, 16)) for x in comma_delim_hex.split(",")]
    data = "".join(data)

    parse_message(None, data)

def test_p2p():
    # setup logging
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('[%(name)s %(levelname)s] %(message)s'))
    logger.addHandler(ch)
    # clear loggers set by any imported modules
    logging.getLogger().handlers.clear()

    def on_msg(wutx, msg):
        print(to_hex(msg))
    def on_transfer_utx(wutx, txid, sig, pubkey, asset_id, timestamp, amount, fee, recipient, attachment):
        print(f"!transfer!: txid {txid}, recipient {base58.b58encode(recipient)}, amount {amount}")

    wutx = WavesUTX(on_msg, on_transfer_utx)
    wutx.start()
    while 1:
        gevent.sleep(1)
    wutx.stop()

if __name__ == "__main__":
    test_p2p()
    #decode_test_msg()
