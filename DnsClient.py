#!/usr/bin/env python3
# ECSE 316 - Assignment 1: DNS Client
# Author: Philippe Aprahamian (261073161)
# Author: Aerin Brown (???)

import sys
import socket
import struct
import time
import random
import re
from typing import Tuple, List, Dict, Any

# input parsing

def parse_args(argv: List[str]) -> Dict[str, Any]:
    # default values
    args = {
        "timeout": 5,
        "max_retries": 3,  # number of retransmissions allowed
        "port": 53,
        "qtype": "A",
        "server": None,
        "name": None,
    }

    # simple manual parsing to support the custom CLI syntax
    i = 0
    seen_type_flag = False
    while i < len(argv):
        tok = argv[i]
        if tok == "-t":
            i += 1
            if i >= len(argv):
                error_exit("Incorrect input syntax: -t requires an integer value")
            try:
                args["timeout"] = int(argv[i])
                if args["timeout"] <= 0:
                    raise ValueError()
            except:
                error_exit("Incorrect input syntax: timeout must be a positive integer")
        elif tok == "-r":
            i += 1
            if i >= len(argv):
                error_exit("Incorrect input syntax: -r requires an integer value")
            try:
                args["max_retries"] = int(argv[i])
                if args["max_retries"] < 0:
                    raise ValueError()
            except:
                error_exit("Incorrect input syntax: max-retries must be a non-negative integer")
        elif tok == "-p":
            i += 1
            if i >= len(argv):
                error_exit("Incorrect input syntax: -p requires an integer value")
            try:
                args["port"] = int(argv[i])
                if not (1 <= args["port"] <= 65535):
                    raise ValueError()
            except:
                error_exit("Incorrect input syntax: port must be in 1..65535")
        elif tok == "-mx":
            if seen_type_flag:
                error_exit("Incorrect input syntax: at most one of -mx or -ns can be provided")
            args["qtype"] = "MX"
            seen_type_flag = True
        elif tok == "-ns":
            if seen_type_flag:
                error_exit("Incorrect input syntax: at most one of -mx or -ns can be provided")
            args["qtype"] = "NS"
            seen_type_flag = True
        elif tok.startswith("@"):
            server_ip = tok[1:]
            if not is_valid_ipv4(server_ip):
                error_exit("Incorrect input syntax: server must be an IPv4 address (a.b.c.d)")
            args["server"] = server_ip
        else:
            # domain name (only one expected)
            if args["name"] is not None:
                error_exit("Incorrect input syntax: multiple domain names provided")
            args["name"] = tok
        i += 1

    if args["server"] is None or args["name"] is None:
        error_exit("Incorrect input syntax: must specify @server and name")

    return args


def is_valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4: 
            return False
        for p in parts:
            if not p.isdigit(): 
                return False
            v = int(p)
            if v < 0 or v > 255:
                return False
        return True
    except:
        return False


def error_exit(msg: str, *, prefix="ERROR"):
    # error lines start with "ERROR\t..."
    sys.stdout.write(f"ERROR\t{msg}\n")
    sys.exit(1)


# DNS packet building

TYPE_MAP = {"A": 1, "NS": 2, "MX": 15}
CLASS_IN = 1

def build_query(transaction_id: int, qname: str, qtype_str: str) -> bytes:
    # Header:
    # ID, Flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    # Flags: QR=0 (query), OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    flags = 0x0100  # RD=1
    header = struct.pack("!HHHHHH",
                         transaction_id,
                         flags,
                         1, 0, 0, 0)

    qname_bytes = encode_qname(qname)
    qtype = TYPE_MAP[qtype_str]
    question = qname_bytes + struct.pack("!HH", qtype, CLASS_IN)
    return header + question


def encode_qname(name: str) -> bytes:
    # Convert "www.mcgill.ca" -> 3 'w' 'w' 'w' 6 'm'... 2 'c' 'a' 0
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        if len(label) > 63:
            error_exit("Incorrect input syntax: label length exceeds 63")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


# response parsing

def parse_header(data: bytes) -> Dict[str, int]:
    if len(data) < 12:
        error_exit("Unexpected response: header too short")
    (tid, flags, qdcount, ancount, nscount, arcount) = struct.unpack("!HHHHHH", data[:12])
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    z  = (flags >> 4) & 0x7
    rcode = flags & 0xF
    return {
        "id": tid, "flags": flags, "qd": qdcount, "an": ancount, "ns": nscount, "ar": arcount,
        "qr": qr, "opcode": opcode, "aa": aa, "tc": tc, "rd": rd, "ra": ra, "z": z, "rcode": rcode
    }


def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a possibly compressed domain name.
    Returns (name, next_offset). If a pointer is used, the next_offset is after the original pointer.
    """
    labels = []
    o = offset
    jumped = False
    seen = set()
    while True:
        if o >= len(data):
            error_exit("Unexpected response: name pointer out of bounds")
        length = data[o]
        if (length & 0xC0) == 0xC0:
            # pointer
            if o + 1 >= len(data):
                error_exit("Unexpected response: truncated name pointer")
            ptr = ((length & 0x3F) << 8) | data[o+1]
            if ptr in seen:
                error_exit("Unexpected response: name pointer loop")
            seen.add(ptr)
            o += 2
            if not jumped:
                next_offset = o
                jumped = True
            o = ptr
            continue
        elif length == 0:
            o += 1
            break
        else:
            o += 1
            if o + length > len(data):
                error_exit("Unexpected response: truncated label")
            label = data[o:o+length].decode("ascii", errors="replace")
            labels.append(label)
            o += length
    name = ".".join(labels)
    return name, (next_offset if jumped else o)


def parse_question(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    qname, o = decode_name(data, offset)
    if o + 4 > len(data):
        error_exit("Unexpected response: truncated question")
    qtype, qclass = struct.unpack("!HH", data[o:o+4])
    o += 4
    return {"qname": qname, "qtype": qtype, "qclass": qclass}, o


def parse_rr(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, o = decode_name(data, offset)
    if o + 10 > len(data):
        error_exit("Unexpected response: truncated RR header")
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[o:o+10])
    o += 10
    if o + rdlength > len(data):
        error_exit("Unexpected response: truncated RDATA")
    rdata = data[o:o+rdlength]
    o += rdlength

    rr = {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdlength": rdlength,
        "rdata_raw": rdata,
    }

    # decode known types
    if rtype == 1 and rdlength == 4:  # A
        rr["rdata"] = socket.inet_ntoa(rdata)
    elif rtype in (2, 5):  # NS or CNAME
        target, _ = decode_name(data, o - rdlength)
        rr["rdata"] = target
    elif rtype == 15:  # MX
        if rdlength < 3:
            error_exit("Unexpected response: MX RDATA too short")
        pref = struct.unpack("!H", rdata[:2])[0]
        exch, _ = decode_name(data, (o - rdlength) + 2)
        rr["preference"] = pref
        rr["rdata"] = exch
    else:
        rr["rdata"] = None  # unsupported for printing

    return rr, o


# networking loop
def send_and_receive(server_ip: str, port: int, packet: bytes, timeout: int, max_retries: int, txid_expected: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        start = time.time()
        attempts = 0  # number of sends
        retries_used = 0
        while True:
            # send
            try:
                sock.sendto(packet, (server_ip, port))
            except Exception as e:
                error_exit(f"Network send error: {e}")

            attempts += 1

            # receive loop for this attempt (ignore mismatched IDs until timeout)
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    # retry if allowed
                    if retries_used < max_retries:
                        retries_used += 1
                        break  # break receive loop -> send again
                    else:
                        error_exit(f"Maximum number of retries {max_retries} exceeded")
                except Exception as e:
                    error_exit(f"Network receive error: {e}")

                # parse header to check transaction ID
                if len(data) < 12:
                    continue
                resp_id = struct.unpack("!H", data[:2])[0]
                if resp_id != txid_expected:
                    # ignore unrelated response
                    continue
                # matched
                elapsed = time.time() - start
                return data, elapsed, retries_used
            # loop continues to retransmit
    finally:
        sock.close()


# helpers
def print_request_summary(name: str, server: str, qtype: str):
    print(f"DnsClient sending request for {name}")
    print(f"Server: {server}")
    print(f"Request type: {qtype}")


def print_response(data: bytes, elapsed: float, retries_used: int):
    hdr = parse_header(data)
    if hdr["qr"] != 1:
        error_exit("Unexpected response: QR bit not set")
    if hdr["tc"] == 1:
        error_exit("Unexpected response: message truncated (TC=1)")
    rcode = hdr["rcode"]
    # 0: No error, 3: Name Error (NXDOMAIN)
    if rcode == 3:
        # even if NXDOMAIN, still print timing line before NOTFOUND? Spec isn't explicit.
        print(f"Response received after {elapsed:.3f} seconds ({retries_used} retries)")
        print("NOTFOUND")
        return
    elif rcode != 0:
        error_exit(f"Unexpected response RCODE={rcode}")

    # move past header
    o = 12
    # parse questions
    for _ in range(hdr["qd"]):
        _, o = parse_question(data, o)
    # parse answers
    answers = []
    for _ in range(hdr["an"]):
        rr, o = parse_rr(data, o)
        answers.append(rr)
    # parse authority (ignored for printing)
    authorities = []
    for _ in range(hdr["ns"]):
        rr, o = parse_rr(data, o)
        authorities.append(rr)
    # parse additional
    additionals = []
    for _ in range(hdr["ar"]):
        rr, o = parse_rr(data, o)
        additionals.append(rr)

    print(f"Response received after {elapsed:.3f} seconds ({retries_used} retries)")

    aa_str = "auth" if hdr["aa"] == 1 else "nonauth"

    # Answer Section
    printed_any = False
    if len(answers) > 0:
        print(f"***Answer Section ({len(answers)} records)***")
        for rr in answers:
            line = format_rr(rr, aa_str)
            if line:
                print(line)
                printed_any = True

    # Additional Section
    if len(additionals) > 0:
        print(f"***Additional Section ({len(additionals)} records)***")
        for rr in additionals:
            line = format_rr(rr, aa_str)
            if line:
                print(line)

    if not printed_any and len(additionals) == 0:
        print("NOTFOUND")


def format_rr(rr: Dict[str, Any], aa_str: str) -> str:
    rtype = rr["type"]
    ttl = rr["ttl"]
    if rtype == 1 and rr.get("rdata"):
        return f"IP\t{rr['rdata']}\t{ttl}\t{aa_str}"
    elif rtype == 5 and rr.get("rdata"):
        return f"CNAME\t{rr['rdata']}\t{ttl}\t{aa_str}"
    elif rtype == 15 and rr.get("rdata") is not None:
        pref = rr.get("preference", 0)
        return f"MX\t{rr['rdata']}\t{pref}\t{ttl}\t{aa_str}"
    elif rtype == 2 and rr.get("rdata"):
        return f"NS\t{rr['rdata']}\t{ttl}\t{aa_str}"
    else:
        return ""


def main():
    if len(sys.argv) < 3:
        error_exit("Incorrect input syntax: usage is python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name")

    # skip program name
    argv = sys.argv[1:]
    args = parse_args(argv)

    # print summary
    print_request_summary(args["name"], args["server"], args["qtype"])

    # build packet
    txid = random.randint(0, 0xFFFF)
    packet = build_query(txid, args["name"], args["qtype"])

    # send and receive
    try:
        data, elapsed, retries_used = send_and_receive(args["server"], args["port"], packet, args["timeout"], args["max_retries"], txid)
    except SystemExit:
        return

    # print response
    print_response(data, elapsed, retries_used)


if __name__ == "__main__":
    main()
