#!/usr/bin/env python3
"""
Benign DNS activity for the lab clients.

Uses the system resolver (socket.gethostbyname -> /etc/resolv.conf),
so the "search corp.lab" suffix behaviour is real, not simulated.

Behaviours (enable with --profile or BENIGN_PROFILE in /etc/nxlab/lab.conf):
  browse   visit the lab sites with pauses; fetch the page over HTTP
  typo     sometimes mistype a site name           (rate: TYPO_RATE)
  probe    browser-style random probes: 3 random 7-15 letter single-label
           names every 5-15 minutes (like Chromium's intranet redirect check)
  stale    misconfigured app polling a deleted hostname every STALE_PERIOD s

Each lookup is logged to /home/ubuntu/logs/benign.log:
    <ts> <behaviour> <name> ok|fail
"""
import argparse
import os
import random
import socket
import string
import threading
import time
import urllib.request

CONF = "/etc/nxlab/lab.conf"
LOG = "/home/ubuntu/logs/benign.log"
SITES = ["shop.lab", "news.lab", "mail.lab", "wiki.lab", "intranet", "files"]
# short names ("intranet", "files") rely on the search list -> intranet.corp.lab

_lock = threading.Lock()


def load_conf(path):
    conf = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    return conf


class Gen(object):
    def __init__(self, a):
        self.a = a
        self.rng = random.Random(a.seed)
        d = os.path.dirname(a.log)
        if d:
            os.makedirs(d, exist_ok=True)
        self.log = open(a.log, "a", buffering=1)

    def emit(self, kind, name, ok):
        with _lock:
            self.log.write("{:.3f} {} {} {}\n".format(time.time(), kind, name,
                                                      "ok" if ok else "fail"))

    def resolve(self, kind, name):
        try:
            ip = socket.gethostbyname(name)
            self.emit(kind, name, True)
            return ip
        except (socket.gaierror, socket.herror):
            self.emit(kind, name, False)
            return None

    def typo(self, name):
        rng = self.rng
        host, dot, rest = name.partition(".")
        if len(host) < 3:
            return name + "x"
        i = rng.randrange(len(host) - 1)
        op = rng.choice(["swap", "drop", "double", "replace"])
        if op == "swap":
            host = host[:i] + host[i + 1] + host[i] + host[i + 2:]
        elif op == "drop":
            host = host[:i] + host[i + 1:]
        elif op == "double":
            host = host[:i] + host[i] + host[i:]
        else:
            host = host[:i] + rng.choice(string.ascii_lowercase) + host[i + 1:]
        return host + dot + rest

    # --- behaviours -------------------------------------------------------
    def browse_loop(self):
        while True:
            site = self.rng.choice(SITES)
            if "typo" in self.a.profile and self.rng.random() < self.a.typo_rate:
                self.resolve("typo", self.typo(site))
                time.sleep(self.rng.uniform(2, 6))        # user notices, retypes
            ip = self.resolve("browse", site)
            if ip and self.a.http:
                try:
                    urllib.request.urlopen("http://{}/".format(ip), timeout=3).read()
                except Exception:
                    pass
            time.sleep(self.rng.uniform(self.a.think_min, self.a.think_max))

    def probe_loop(self):
        time.sleep(self.rng.uniform(5, 60))
        while True:
            for _ in range(3):
                n = "".join(self.rng.choice(string.ascii_lowercase)
                            for _ in range(self.rng.randint(7, 15)))
                self.resolve("probe", n)
            time.sleep(self.rng.uniform(300, 900))

    def stale_loop(self):
        while True:
            self.resolve("stale", self.a.stale_name)
            time.sleep(self.a.stale_period)

    def run(self):
        threads = []
        if "browse" in self.a.profile:
            threads.append(self.browse_loop)
        if "probe" in self.a.profile:
            threads.append(self.probe_loop)
        if "stale" in self.a.profile:
            threads.append(self.stale_loop)
        for t in threads:
            th = threading.Thread(target=t)
            th.daemon = True
            th.start()
        while True:
            time.sleep(3600)


def main():
    c = load_conf(CONF)
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default=c.get("BENIGN_PROFILE", "browse,typo,probe"),
                    help="comma list: browse,typo,probe,stale")
    ap.add_argument("--typo-rate", type=float, default=float(c.get("TYPO_RATE", 0.05)))
    ap.add_argument("--think-min", type=float, default=float(c.get("THINK_MIN", 8)))
    ap.add_argument("--think-max", type=float, default=float(c.get("THINK_MAX", 40)))
    ap.add_argument("--stale-name", default=c.get("STALE_NAME", "oldbackup.corp.lab"))
    ap.add_argument("--stale-period", type=float, default=float(c.get("STALE_PERIOD", 30)))
    ap.add_argument("--no-http", dest="http", action="store_false")
    ap.add_argument("--seed", default=c.get("BENIGN_SEED", None))
    ap.add_argument("--log", default=LOG)
    a = ap.parse_args()
    a.profile = a.profile.split(",")
    Gen(a).run()


if __name__ == "__main__":
    main()
