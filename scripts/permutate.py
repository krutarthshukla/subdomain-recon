#!/usr/bin/env python3
"""
permutate.py — Data-driven subdomain permutation generator.

Key principle (from bug bounty research):
  Permutations must be learned FROM the target's own discovered subdomains,
  not from hardcoded org-specific patterns. An org using blue/green deployments
  will have blue/green in passive recon results — we extract those words and
  permutate on them. An org using red/black/gold naming will have those words.
  Hardcoding color names only works for one org.

Approach:
  1. Extract all unique "words" from discovered subdomains (the vocabulary
     the target org actually uses in naming their infrastructure).
  2. Use that extracted vocabulary as the permutation seed.
  3. Supplement with a small set of truly universal environment prefixes
     (dev, staging, prod, test) that research shows appear in all orgs.
  4. Generate permutations: prefix-word, word-prefix, word+N, sub.word.domain.
  5. Resolve via dnsx (fast) or Python socket fallback.

Usage:
  python3 permutate.py --input known.txt --domain target.com --output perms.txt
"""

import argparse
import re
import socket
import subprocess
import sys
import threading
from queue import Queue, Empty

# Bound DNS resolution so a hung lookup can't wedge a worker (and thus queue.join()).
socket.setdefaulttimeout(5)

# ── Universal environment words — research-backed, appear in ALL orgs ─────────
# Source: substats (1M+ subdomains / 3000 bug bounty companies), SecLists,
#         jhaddix DNS research. These are the ONLY hardcoded patterns.
# Deliberately small — org-specific patterns come from the data, not here.
UNIVERSAL_ENVS = [
    "dev", "development", "staging", "stage", "stg",
    "test", "testing", "qa", "uat", "sandbox",
    "beta", "alpha", "preview", "demo",
    "prod", "production", "live", "preprod", "pre-prod",
    "internal", "int", "ext", "external",
    "new", "old", "legacy", "next",
    "v1", "v2", "v3",
    "api", "admin", "app", "web",
]

# ── Word extraction ────────────────────────────────────────────────────────────

def extract_words(subdomains, domain):
    """
    Pull all meaningful words from the target's own subdomain names.
    This is the vocabulary the target org actually uses — e.g. if they use
    'blue/green/white', those words appear here. If they use 'primary/secondary',
    those appear here. We permutate on what they actually use.
    """
    words = set()
    for sub in subdomains:
        # Strip the root domain
        if sub.endswith("." + domain):
            prefix = sub[: -(len(domain) + 1)]
        elif sub == domain:
            continue
        else:
            prefix = sub

        # Split on dots and hyphens — each segment is a potential word
        parts = re.split(r'[.\-]', prefix)
        for part in parts:
            part = part.strip().lower()
            # Keep only alphabetic words 2-20 chars — skip pure numbers and UUIDs
            if part and re.match(r'^[a-z]{2,20}$', part):
                words.add(part)

    return words

# ── Permutation generation ────────────────────────────────────────────────────

def generate_permutations(subdomains, domain):
    """
    Generate subdomain candidates by combining:
    - Extracted org vocabulary (from their own subdomains)
    - Universal env prefixes/suffixes
    """
    known_set = set(subdomains)
    org_words = extract_words(subdomains, domain)

    # Combine org vocabulary with universal envs for permutation seeds
    all_seeds = org_words | set(UNIVERSAL_ENVS)

    candidates = set()

    # For each known subdomain, generate variations
    for sub in subdomains:
        if not sub.endswith("." + domain):
            continue
        prefix = sub[: -(len(domain) + 1)]
        parts = prefix.split(".")
        leftmost = parts[0]  # immediate subdomain word

        for seed in all_seeds:
            # prefix-word and word-prefix combinations
            candidates.add(f"{seed}-{leftmost}.{domain}")
            candidates.add(f"{leftmost}-{seed}.{domain}")
            candidates.add(f"{seed}.{leftmost}.{domain}")

            # Multi-level: seed.existing-sub.domain
            if len(parts) > 1:
                candidates.add(f"{seed}.{prefix}.{domain}")

        # Numeric variants (N=1-5): api1, api2, etc.
        for n in range(1, 6):
            candidates.add(f"{leftmost}{n}.{domain}")
            candidates.add(f"{leftmost}-{n}.{domain}")
            candidates.add(f"{leftmost}0{n}.{domain}")

    # Also generate bare env words at the apex (dev.domain.com, staging.domain.com, ...)
    for seed in all_seeds:
        candidates.add(f"{seed}.{domain}")

    # Remove already-known subdomains
    candidates -= known_set
    return candidates

# ── DNS resolution ────────────────────────────────────────────────────────────

found_lock = threading.Lock()
found = []

def resolve(subdomain):
    try:
        socket.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
        return True
    except (socket.gaierror, OSError):
        return False

def worker(queue):
    while True:
        try:
            sub = queue.get_nowait()
        except Empty:
            return
        if resolve(sub):
            with found_lock:
                found.append(sub)
                print(f"  [+] {sub}", flush=True)
        queue.task_done()

def resolve_with_dnsx(candidates_file, output_file):
    import os
    recon_dnsx = os.path.expanduser("~/.recon-tools/bin/dnsx")
    for dnsx_path in [recon_dnsx, "dnsx"]:
        try:
            result = subprocess.run(
                [dnsx_path, "-l", candidates_file, "-silent", "-t", "200"],
                capture_output=True, text=True, timeout=300
            )
            subs = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if subs:
                with open(output_file, "w") as f:
                    f.write("\n".join(subs) + "\n")
                print(f"[+] dnsx permutation resolve: {len(subs)} found")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Known subdomains file")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=100)
    args = parser.parse_args()

    try:
        with open(args.input) as f:
            known = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
    except OSError as e:
        print(f"[!] Cannot read input {args.input}: {e}", file=sys.stderr)
        open(args.output, "w").close()
        sys.exit(1)

    org_vocab = extract_words(known, args.domain)
    print(f"[*] Org vocabulary extracted: {len(org_vocab)} unique words", flush=True)
    print(f"[*] Sample: {sorted(org_vocab)[:15]}", flush=True)
    print(f"[*] Generating permutations from {len(known)} known subdomains...", flush=True)

    candidates = generate_permutations(known, args.domain)
    print(f"[*] {len(candidates)} permutation candidates to test", flush=True)

    tmp = f"/tmp/perms_{args.domain}.txt"
    with open(tmp, "w") as f:
        for c in sorted(candidates):
            f.write(c + "\n")

    if resolve_with_dnsx(tmp, args.output):
        return

    # Fallback: Python socket resolution
    queue = Queue()
    for c in candidates:
        queue.put(c)

    threads = []
    for _ in range(min(args.threads, len(candidates))):
        t = threading.Thread(target=worker, args=(queue,), daemon=True)
        t.start()
        threads.append(t)

    queue.join()

    with open(args.output, "w") as f:
        for s in sorted(found):
            f.write(s + "\n")

    print(f"[+] Permutation done: {len(found)} new subdomains → {args.output}")

if __name__ == "__main__":
    main()
