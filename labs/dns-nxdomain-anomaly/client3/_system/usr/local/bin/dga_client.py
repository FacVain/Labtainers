#!/usr/bin/env python3
"""Simulated DGA malware (client3).

Walks the DGA sequence and looks up one generated name after another until
one of them resolves (the registered C2 name). It sends no other traffic:
the only observable behaviour is DNS, which is what the lab is about.

Settings come from /etc/nxlab/lab.conf; command-line options override them.
Events are logged to /home/ubuntu/logs/dga.log:
    <ts> QUERY <i> <name> rcode=<n>
    <ts> C2_RESOLVED <i> <name> <ip>
    <ts> QUARANTINED?   (the resolver started answering NXDOMAIN for the C2)
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, "/usr/local/bin")
from nxdga import dga  # noqa: E402

CONF = "/etc/nxlab/lab.conf"
LOG = "/home/ubuntu/logs/dga.log"


def load_conf(path):
    conf = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    return conf


def build_query(name, qid):
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)       # RD=1
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return hdr + q + b"\x00" + struct.pack("!HH", 1, 1)          # A, IN


def lookup(name, server, port=53, timeout=2.0):
    """Send one A query (absolute name, no search list). Return (rcode, ip)."""
    qid = random.randint(0, 0xFFFF)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_query(name, qid), (server, port))
        data, _ = s.recvfrom(4096)
    except OSError:          # timeout, or resolver unreachable (e.g. BIND restarting)
        return None, None
    finally:
        s.close()
    try:
        return parse_answer(data, qid)
    except (IndexError, struct.error):   # truncated or malformed answer
        return None, None


def parse_answer(data, qid):
    """Return (rcode, first A address or None) from a DNS response."""
    rid, flags, qd, an = struct.unpack("!HHHH", data[:8])
    if rid != qid:
        return None, None
    rcode = flags & 0x0F
    off = 12
    for _ in range(qd):                     # skip question
        while data[off] != 0:
            off += 1 + data[off]
        off += 5
    for _ in range(an):                     # first A record in the answer
        if data[off] & 0xC0:
            off += 2
        else:
            while data[off] != 0:
                off += 1 + data[off]
            off += 1
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            return rcode, socket.inet_ntoa(data[off:off + 4])
        off += rdlen
    return rcode, None


def main():
    conf = load_conf(CONF)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", default=conf.get("DGA_SEED", "12345"))
    ap.add_argument("--mode", default=conf.get("DGA_MODE", "random"),
                    choices=["random", "dictionary"])
    ap.add_argument("--rate", type=float, default=float(conf.get("DGA_RATE", 30)),
                    help="lookups per minute")
    ap.add_argument("--ramp-to", type=float, default=None,
                    help="slow drip: increase the rate linearly from --rate to this")
    ap.add_argument("--ramp-minutes", type=float, default=20.0)
    ap.add_argument("--delay", type=float, default=float(conf.get("DGA_START_DELAY", 0)),
                    help="seconds to wait before starting")
    ap.add_argument("--server", default=conf.get("RESOLVER", "172.30.0.10"))
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--max", type=int, default=100000, help="max DGA index")
    ap.add_argument("--keep-alive", default=conf.get("DGA_KEEP_ALIVE", "yes"))
    ap.add_argument("--log", default=LOG)
    a = ap.parse_args()

    d = os.path.dirname(a.log)
    if d:
        os.makedirs(d, exist_ok=True)
    log = open(a.log, "a", buffering=1)

    def emit(msg):
        log.write("{:.3f} {}\n".format(time.time(), msg))

    emit("START seed={} mode={} rate={}/min delay={}s".format(a.seed, a.mode, a.rate, a.delay))
    time.sleep(a.delay)
    t0 = time.time()
    c2 = None
    for i in range(a.max):
        name = dga(a.seed, i, a.mode)
        rcode, ip = lookup(name, a.server, a.port)
        emit("QUERY {} {} rcode={}".format(i, name, rcode))
        if rcode == 0 and ip:
            c2 = (i, name, ip)
            emit("C2_RESOLVED {} {} {}".format(i, name, ip))
            break
        rate = a.rate
        if a.ramp_to is not None:
            frac = min(1.0, (time.time() - t0) / (a.ramp_minutes * 60.0))
            rate = a.rate + frac * (a.ramp_to - a.rate)
        # small jitter so the timing is not perfectly regular
        time.sleep(60.0 / rate * random.uniform(0.8, 1.2))

    if c2 is None:
        emit("GAVE_UP")
        return
    # Beacon phase: re-resolve the C2 name once a minute (no C2 traffic).
    while a.keep_alive == "yes":
        time.sleep(60)
        rcode, ip = lookup(c2[1], a.server, a.port)
        emit("BEACON {} rcode={} ip={}".format(c2[1], rcode, ip))
        if rcode == 3:
            emit("QUARANTINED {}".format(c2[1]))


if __name__ == "__main__":
    main()
