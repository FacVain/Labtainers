#!/usr/bin/env python3
"""DNS response monitor for the resolver (passive IDS sensor).

Sniffs DNS *responses* leaving the resolver and writes one CSV line per
response:

    ts,client,qname,qtype,rcode
    1731070000.123,172.30.0.103,qkzjfwta.lab,A,3

rcode 0 = NOERROR, 3 = NXDOMAIN, 2 = SERVFAIL, 5 = REFUSED.

  dns_monitor.py                       # eth0 -> /home/ubuntu/logs/dns_log.csv
  dns_monitor.py -i eth0 -o -          # print to stdout
"""
import argparse
import os
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4     # only packets this host sends
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
HEADER = "ts,client,qname,qtype,rcode" # The format of log we write

#The function which parse the qname from packet 
def parse_qname(packet, position):

    labels = []
    while position < len(packet):
        length = packet[position]
        if length == 0:
            name = ".".join(labels)
            return name, position + 1
        
        # Skip unsupported names without logging
        if length > 63:
            raise ValueError("unsupported name label")
        start = position + 1
        end = start + length
        if end > len(packet):
            raise ValueError("truncated name label")

        label = packet[start:end].decode("ascii", "replace")
        labels.append(label)
        position = end
    raise ValueError("truncated qname")


def parse_dns_response(dns):
    """Return (qname, qtype, rcode) for a DNS response, or None."""
    if len(dns) < 12:
        return None
    query_id, flags, question_count = struct.unpack("!HHH", dns[:6])

    # The highest bit is set when the packet is a DNS response.
    if (flags & 0x8000) == 0 or question_count < 1:
        return None
    
    rcode = flags & 0x000F
    qname, position = parse_qname(dns, 12)
    #If there are no 4 byte after name
    if position + 4 > len(dns):
        return None
    
    qtype_number = struct.unpack("!H", dns[position:position + 2])[0]
    qtype = QTYPES.get(qtype_number, str(qtype_number))
    return qname.lower(), qtype, rcode


def parse_frame(frame, port=53):

    """Ethernet/IPv4/UDP frame -> (client_ip, qname, qtype, rcode) or None."""
    #Ethernet 14 byte
    #IPv4 20 byte
    #UDP paketi 8 byte
    if len(frame) < 14 + 20 + 8:
        return None
    #If not IPv4 pass it
    if struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    
    ip = frame[14:]
    header_length = (ip[0] & 0x0F) * 4

    if ip[0] >> 4 != 4 or header_length < 20:
        return None
    total_length = struct.unpack("!H", ip[2:4])[0]
    if total_length > len(ip) or total_length < header_length + 8:
        return None
    
    fragment = struct.unpack("!H", ip[6:8])[0]
    if (fragment & 0x3FFF) != 0 or ip[9] != 17:      # UDP = 17
        return None
    
    client_ip = socket.inet_ntoa(ip[16:20])
    udp = ip[header_length:total_length]
    source_port = struct.unpack("!H", udp[0:2])[0]

    udp_length = struct.unpack("!H", udp[4:6])[0]

    if source_port != port or not (8 <= udp_length <= len(udp)):
        return None
    result = parse_dns_response(udp[8:udp_length])

    if result is None:
        return None
    
    qname, qtype, rcode = result

    return client_ip, qname, qtype, rcode


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--iface", default="eth0")
    parser.add_argument("-o", "--out", default="/home/ubuntu/logs/dns_log.csv",
                    help="CSV output file, or - for stdout")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--include-local", action="store_true",
                    help="also log answers to 127.0.0.1 (resolver's own lookups)")
    args = parser.parse_args()

    if args.out == "-":
        out = sys.stdout
    else:
        folder = os.path.dirname(args.out)
        if folder:
            os.makedirs(folder, exist_ok=True)
        new = not os.path.exists(args.out) or os.path.getsize(args.out) == 0
        out = open(args.out, "a", buffering=1)
        if new:
            out.write(HEADER + "\n")

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    raw_socket.bind((args.iface, 0))
    sys.stderr.write("dns_monitor: listening on {} -> {}\n".format(args.iface, args.out))

    while True:
        frame, address = raw_socket.recvfrom(65535)
        if address[2] != PACKET_OUTGOING:
            continue
        try:
            record = parse_frame(frame, args.port)
        except (ValueError, IndexError, struct.error):
            continue
        if record is None:
            continue
        client, qname, qtype, rcode = record
        if client.startswith("127.") and not args.include_local:
            continue
        out.write("{:.3f},{},{},{},{}\n".format(time.time(), client, qname, qtype, rcode))


if __name__ == "__main__":
    main()
