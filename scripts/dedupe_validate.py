#!/usr/bin/env python3
"""
Merge, deduplicate and DNS-validate all collected subdomains.
Usage: python3 dedupe_validate.py --inputs f1.txt,f2.txt --domain target.com \
         --output all_unique.txt
"""

import argparse
import re
import socket
import threading
from queue import Queue, Empty

# Bound DNS resolution so a hung lookup can't wedge a worker (and thus queue.join()).
socket.setdefaulttimeout(5)

found_lock = threading.Lock()
live = []

def resolve(subdomain):
    try:
        socket.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
        return True
    except socket.gaierror:
        return False

def worker(queue):
    while True:
        try:
            sub = queue.get_nowait()
        except Empty:
            return
        if resolve(sub):
            with found_lock:
                live.append(sub)
        queue.task_done()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    subs = set()

    for path in args.inputs.split(","):
        path = path.strip()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    # Strip wildcards
                    line = line.lstrip("*.")
                    if line.endswith("." + domain) or line == domain:
                        subs.add(line)
        except FileNotFoundError:
            print(f"[!] File not found: {path} (skipping)")

    print(f"[*] Total unique before validation: {len(subs)}")

    # DNS-validation always runs — it confirms which discovered names actually
    # resolve, so the final list isn't padded with dead entries.
    if subs:
        print(f"[*] DNS-validating {len(subs)} subdomains (100 threads)...", flush=True)
        queue = Queue()
        for s in subs:
            queue.put(s)
        threads = []
        for _ in range(min(100, len(subs))):
            t = threading.Thread(target=worker, args=(queue,), daemon=True)
            t.start()
            threads.append(t)
        queue.join()
        final = sorted(live)
        print(f"[+] DNS-live: {len(final)}")
    else:
        final = []

    with open(args.output, "w") as f:
        for s in final:
            f.write(s + "\n")

    print(f"[+] Written {len(final)} subdomains → {args.output}")

if __name__ == "__main__":
    main()
