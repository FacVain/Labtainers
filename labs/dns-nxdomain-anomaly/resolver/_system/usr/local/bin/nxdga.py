#!/usr/bin/env python3
"""Deterministic domain generator used by the lab's simulated malware.

The same file is installed on client3 (to generate names) and on the
resolver (to register exactly one of them as the C2 name).

  nxdga.py --seed 12345 --index 80            -> prints name #80
  nxdga.py --seed 12345 --index 80 --mode dictionary
  nxdga.py --seed 12345 --count 5             -> prints names #0..#4
"""
import argparse
import hashlib

TLD = "lab"

# Small word list for the optional "dictionary" mode (names look like words,
# so name-based detectors struggle, but they still fail -> NXDOMAIN).
WORDS = [
    "cloud", "secure", "data", "portal", "update", "service", "online", "net",
    "smart", "mobile", "account", "center", "global", "access", "system",
    "media", "store", "file", "share", "login", "web", "app", "sync", "home",
]


def _digest(seed, i):
    return hashlib.sha256("{}-{}".format(seed, i).encode()).hexdigest()


def dga_random(seed, i):
    """7-12 random-looking lowercase letters + .lab"""
    raw = bytes.fromhex(_digest(seed, i))
    letters = "".join(chr(97 + b % 26) for b in raw[:12])
    length = 7 + raw[12] % 6
    return "{}.{}".format(letters[:length], TLD)


def dga_dictionary(seed, i):
    """two dictionary words + .lab, e.g. securesync.lab"""
    h = _digest(seed, i)
    a = WORDS[int(h[0:4], 16) % len(WORDS)]
    b = WORDS[int(h[4:8], 16) % len(WORDS)]
    if a == b:
        b = WORDS[(int(h[4:8], 16) + 1) % len(WORDS)]
    return "{}{}.{}".format(a, b, TLD)


def dga(seed, i, mode="random"):
    if mode == "dictionary":
        return dga_dictionary(seed, i)
    return dga_random(seed, i)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", required=True)
    ap.add_argument("--index", type=int, default=None)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--mode", choices=["random", "dictionary"], default="random")
    a = ap.parse_args()
    if a.index is not None:
        print(dga(a.seed, a.index, a.mode))
    else:
        for i in range(a.count):
            print(dga(a.seed, i, a.mode))


if __name__ == "__main__":
    main()
