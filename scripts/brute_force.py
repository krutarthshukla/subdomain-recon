#!/usr/bin/env python3
"""
DNS brute-force subdomain discovery.
Uses dnsx if available, falls back to pure Python DNS resolution.
Usage: python3 brute_force.py --domain target.com --wordlist wordlist.txt --output out.txt
"""

import argparse
import socket
import subprocess
import sys
import threading
from queue import Queue, Empty

THREAD_COUNT = 100

# Bound DNS resolution so a hung lookup can't wedge a worker (and thus queue.join()).
socket.setdefaulttimeout(5)

found = []
found_lock = threading.Lock()

def resolve(subdomain):
    try:
        socket.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
        return True
    except socket.gaierror:
        return False

def worker(queue, domain):
    while True:
        try:
            word = queue.get_nowait()
        except Empty:
            return
        subdomain = f"{word}.{domain}"
        if resolve(subdomain):
            with found_lock:
                found.append(subdomain)
                print(f"  [+] {subdomain}", flush=True)
        queue.task_done()

def brute_with_dnsx(domain, wordlist_path, output_path):
    """Use dnsx for faster brute-forcing if available.

    Returns True when dnsx actually RAN (even if it found zero) — a clean run
    that finds nothing is a valid result, not a reason to fall back to the slow
    pure-Python scan over a multi-million-word list.
    """
    import os
    recon_dnsx = os.path.expanduser("~/.recon-tools/bin/dnsx")
    for dnsx_path in [recon_dnsx, "dnsx"]:
        try:
            result = subprocess.run(
                [dnsx_path, "-d", domain, "-w", wordlist_path,
                 "-silent", "-t", "200"],
                capture_output=True, text=True, timeout=300
            )
            subs = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            with open(output_path, "w") as f:
                f.write("\n".join(subs) + ("\n" if subs else ""))
            print(f"  [+] dnsx brute-force: {len(subs)} found")
            return True
        except FileNotFoundError:
            continue  # this dnsx path doesn't exist — try the next
        except subprocess.TimeoutExpired:
            print("  [!] dnsx timed out — falling back to Python resolver", flush=True)
            return False
    return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--wordlist", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=THREAD_COUNT)
    args = parser.parse_args()

    print(f"[*] Brute-forcing subdomains of {args.domain}...", flush=True)

    # Try dnsx first (faster)
    if brute_with_dnsx(args.domain, args.wordlist, args.output):
        return

    # Fallback: Python socket resolution
    print(f"[*] Using Python socket resolution ({args.threads} threads)...", flush=True)

    try:
        with open(args.wordlist) as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError as e:
        print(f"[!] Cannot read wordlist {args.wordlist}: {e}", file=sys.stderr)
        open(args.output, "w").close()  # leave an empty output so callers don't break
        sys.exit(1)

    print(f"[*] Wordlist size: {len(words)}", flush=True)

    queue = Queue()
    for w in words:
        queue.put(w)

    threads = []
    for _ in range(min(args.threads, len(words))):
        t = threading.Thread(target=worker, args=(queue, args.domain), daemon=True)
        t.start()
        threads.append(t)

    queue.join()

    with open(args.output, "w") as f:
        for s in sorted(found):
            f.write(s + "\n")

    print(f"[+] Brute-force complete: {len(found)} found → {args.output}")

if __name__ == "__main__":
    main()
