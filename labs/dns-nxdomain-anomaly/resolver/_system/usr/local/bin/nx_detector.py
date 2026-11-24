#!/usr/bin/env python3
"""Count NXDOMAIN responses in a sliding window for each client.

DNS responses -> dns_monitor.py -> dns_log.csv -> nx_detector.py
    -> count NXDOMAINs per client in the time window
    -> if count >= threshold -> terminal + alerts.log

Usage:
  nx_detector.py --mode threshold
  nx_detector.py --window 60 --nx-threshold 20
  nx_detector.py --follow
  nx_detector.py --stats
"""
import argparse
import csv
import math
import os
import time

DEFAULT_LOG = "/home/ubuntu/logs/dns_log.csv"
DEFAULT_ALERTS = "/home/ubuntu/logs/alerts.log"
NXDOMAIN = 3


def parse_row(line):
    # Skip the header and empty lines.
    if not line.strip() or line.startswith("ts,"):
        return None
    try:
        parts = next(csv.reader([line], strict=True))
        if len(parts) != 5:
            return None
        ts = float(parts[0])
        ip = parts[1]
        code = int(parts[4])
    except (ValueError, csv.Error):
        return None

    if not math.isfinite(ts) or not (0 <= code <= 15):
        return None
    return ts, ip, code


def update_window(rows, ts, code, seconds):
    # Remove old records.
    rows.append((ts, code))
    while rows and rows[0][0] < ts - seconds:
        rows.pop(0)

    # Count NXDOMAIN responses.
    nx_count = 0

    for old_ts, old_code in rows:
        if old_code == NXDOMAIN:
            nx_count += 1
    return len(rows), nx_count


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log", nargs="?", default=DEFAULT_LOG)
    parser.add_argument("--mode", choices=["threshold"], default="threshold")
    parser.add_argument("--window", type=float, default=60.0, help="window length in seconds")
    parser.add_argument("--nx-threshold", type=int, default=20)
    parser.add_argument("--follow", action="store_true", help="keep reading new log entries")
    parser.add_argument("--alerts-file", default=DEFAULT_ALERTS)
    parser.add_argument("--append", action="store_true", help="keep alerts from earlier runs")
    parser.add_argument("--stats", action="store_true", help="show peak counts without writing alerts")
    parser.add_argument("--ignore", default="172.30.0.10,172.30.0.20",
                        help="comma-separated server IPs to exclude")
    args = parser.parse_args()

    if not math.isfinite(args.window) or args.window <= 0 or args.nx_threshold < 1:
        parser.error("window and NXDOMAIN threshold must be positive")

    if args.stats and args.follow:
        parser.error("use --stats on a saved log without --follow")

    if not args.stats and os.path.realpath(args.log) == os.path.realpath(args.alerts_file):
        parser.error("the DNS log and alerts file must be different files")

    if not os.path.exists(args.log):
        if not args.follow:
            parser.error("log file not found: " + args.log)
        print("Waiting for " + args.log, flush=True)
        while not os.path.exists(args.log):
            time.sleep(0.5)

    skip_ips = []
    for ip in args.ignore.split(","):
        skip_ips.append(ip.strip())

    client_rows = {}
    max_counts = {}
    alert_ips = []
    alert_file = None
    try:
        if not args.stats:
            folder = os.path.dirname(args.alerts_file)

            if folder:
                os.makedirs(folder, exist_ok=True)

            mode = "w"
            if args.append:
                mode = "a"
            alert_file = open(args.alerts_file, mode, encoding="utf-8", buffering=1)

        with open(args.log, encoding="utf-8") as log_file:
            while True:
                pos = log_file.tell()
                line = log_file.readline()

                # In live mode, wait for a complete line.
                if not line or (args.follow and not line.endswith("\n")):
                    if not args.follow:
                        break
                    log_file.seek(pos)
                    time.sleep(0.5)
                    continue

                row = parse_row(line)
                if row is None:
                    continue
                ts, ip, code = row
                if ip in skip_ips:
                    continue

                if ip not in client_rows:
                    client_rows[ip] = []
                total, nx_count = update_window(client_rows[ip], ts, code, args.window)

                if ip not in max_counts or nx_count > max_counts[ip][1]:
                    max_counts[ip] = (total, nx_count)

                # Write one alert per client.
                if args.stats or nx_count < args.nx_threshold or ip in alert_ips:
                    continue
                text = ("ALERT ts={:.3f} client={} mode=threshold total={} nx={}").format(
                    ts, ip, total, nx_count)
                print(text, flush=True)
                alert_file.write(text + "\n")
                alert_ips.append(ip)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if alert_file is not None:
            alert_file.close()

    print("\nClient counts:")
    for ip in sorted(max_counts):

        total, nx_count = max_counts[ip]
        result = "no alert"

        if args.stats:
            result = "-"
        elif ip in alert_ips:
            result = "ALERT"

        print(ip, "total:", total, "NXDOMAIN:", nx_count, "result:", result)

    print("Counts come from each client's window with the most NXDOMAINs.")


if __name__ == "__main__":
    main()
