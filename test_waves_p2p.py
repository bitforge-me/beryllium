import sys
import socket
import struct
import random
import time

def base58_encode(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    ####convert each digit into unicode
    buffer = [ord(each[0]) for each in str(data)]
    digits = [0]; i= 0; j = 0;
    while (i < len(buffer)):   #loop for as many digits are present
            j = 0
            while (j < len(digits)):
                    digits[j] <<= 8
                    j += 1
            digits[0] += buffer[i]
            carry = 0; j = 0;
            while(j < len(digits)):
                    digits[j] += carry
                    carry = (digits[j]/58) | 0
                    digits[j] %= 58;
                    j += 1
            while(carry):
                    digits.append(carry%58)
                    carry = (carry/58) | 0
            i += 1
    i = 0;
    while (buffer[i] == 0 and i < len(buffer) - 1):
            digits.push(0);
            i += 1;
    return "".join([alphabet[each] for each in digits][::-1])

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
    fee_asset_flag = ord(payload[offset])
    offset += 1
    fee_asset_id_len = 0
    fee_asset_id = ""
    if fee_asset_flag:
        fee_asset_id_len = 32
        fee_asset_id = payload[offset:offset+fee_asset_id_len]
    offset += fee_asset_id_len
    fmt_mid = ">QQQ26sH"
    fmt_mid_len = struct.calcsize(fmt_mid)
    timestamp, amount, fee, address, attachment_len = \
        struct.unpack_from(fmt_mid, payload[offset:])
    offset += fmt_mid_len
    attachment = payload[offset:offset+attachment_len]

    return tx_type, sig, tx_type2, pubkey, asset_flag, asset_id, timestamp, amount, fee, address, attachment

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
                if tx_type == 4:
                    # transfer
                    tx_type, sig, tx_type2, pubkey, asset_flag, asset_id, timestamp, amount, fee, address, attachment = parse_transfer_tx(payload)

                    print "  senders pubkey:", base58_encode(pubkey)
                    print "  addr:", base58_encode(address)
                    print "  amount:", amount
                    print "  fee:", fee
                    print "  asset id:", asset_id
                    print "  timestamp:", timestamp
                    print "  attachment:", attachment

def decode_test_tx():
    comma_delim_hex = "00,00,00,A5,12,34,56,78,19,00,00,00,98,A1,D3,F9,48,04,0C,2B,4F,19,B5,09,23,F4,E5,A6,60,5C,A3,8B,E3,90,0D,A8,39,40,C6,56,FD,77,D7,10,18,2C,7A,0F,A4,B7,6C,B7,89,AC,1A,37,4F,2B,95,E8,FF,2D,B7,26,70,BF,C8,96,99,25,75,E4,E6,F1,F4,D5,CF,CF,5A,87,B1,8F,04,A9,D5,9F,EE,C5,51,43,8C,C7,43,7E,39,CD,75,32,8B,C0,C3,45,BF,C8,FC,91,88,43,C2,54,87,72,BA,26,40,00,00,00,00,01,64,15,54,57,A5,00,00,00,00,3B,9A,CA,00,00,00,00,00,00,01,86,A0,01,54,8D,98,AF,E7,34,F1,C1,88,CA,06,FB,6C,1F,C0,2B,49,FB,0C,2A,2A,E3,07,13,E9,00,00"
    data = [chr(int(x, 16)) for x in comma_delim_hex.split(",")]
    data = "".join(data)

    parse_message(data)

def test_p2p():
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

if __name__ == "__main__":
    test_p2p()
    #decode_test_tx()
