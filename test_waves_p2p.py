import sys
import socket
import struct
import random
import time

def create_handshake(port):
    name = "wavesT"
    name_len = len(name) 
    version_major = 0
    version_minor = 13
    version_patch = 2
    node_name = "utx"
    node_name_len = len(node_name)
    node_nonce = random.randint(0, 10000)
    declared_address = 0x7f000001 #"127.0.0.1"
    declared_address_port = port
    declared_address_len = 8
    timestamp = int(time.time())
    fmt = ">B%dslllB%dsQlllQ" % (name_len, node_name_len)
    print struct.calcsize(fmt)
    return struct.pack(fmt, name_len, name,
            version_major, version_minor, version_patch,
            node_name_len, node_name, node_nonce,
            declared_address_len, declared_address, declared_address_port,
            timestamp)

def decode_handshake(msg):
    l = ord(msg[0])
    if l == 6 and msg[1:7] == "wavesT":
        msg = msg[7:]
        vmaj, vmin, vpatch = struct.unpack_from(">lll", msg)
        msg = msg[12:]
        l = ord(msg[0])
        node_name = msg[1:1+l]
        msg = msg[1+l:]
        nonce, decl_addr_len, decl_addr, decl_addr_port, timestamp = struct.unpack(">QlllQ", msg)
        return ("wavesT", vmaj, vmin, vpatch, node_name, nonce, decl_addr, decl_addr_port, timestamp)

def to_hex(data):
    s = ""
    for c in data:
        s += "%02X," % ord(c)
    return s

def parse_message(msg):
    handshake = decode_handshake(msg)
    if handshake:
        print "handshake:"
        for part in handshake:
            print "", part
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
                    print("msg too short", len(msg), fmt_size)
                    break

                length, magic, content_id, payload_len, payload_checksum \
                    = struct.unpack_from(fmt, msg)
                payload = msg[fmt_size:fmt_size + payload_len]

            msg = msg[4 + length:]

            print "message:"
            print "  length", length
            print "  magic", magic
            print "  content_id", "0x%02X" % content_id
            print "  payload_len", payload_len
            print "  payload:", to_hex(payload)

            if magic != 305419896:
                print "invalid magic"
                break

            if content_id == 0x19:
                # transaction!
                tx_type = ord(payload[0])
                print "transaction type:", tx_type

# create an INET, STREAMing socket
s = socket.socket(
    socket.AF_INET, socket.SOCK_STREAM)
# now connect to the waves node on port 6863
s.connect(("127.0.0.1", 6863))
local_port = s.getsockname()[1]

# send handshake
handshake = create_handshake(local_port)
print to_hex(handshake)
print s.send(handshake)

while 1:
    # read reply
    data = s.recv(1024)
    if data:
        print
        print len(data)
        print to_hex(data)
        parse_message(data)
    else:
        sys.stdout.write(".")

    time.sleep(1)
