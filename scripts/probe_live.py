#!/usr/bin/env python3
"""
probe_live.py — Reliable httpx wrapper that works in all subprocess contexts.

Problem it solves:
  When httpx is called via the Bash tool, its output gets intercepted by the
  tool's subprocess layer before shell redirects (>, tee) can capture it.
  This Python wrapper uses subprocess.Popen to capture output directly from
  the httpx process, bypassing the Bash tool's stream interception entirely.

Usage:
  python3 probe_live.py --input /tmp/all.txt --output /tmp/live.txt \
      [--threads 300] [--timeout 5]
"""

import argparse, os, subprocess, sys

HTTPX = os.path.expanduser("~/.recon-tools/bin/httpx")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",   required=True, help="File with hosts to probe")
    parser.add_argument("--output",  required=True, help="Output file for live hosts")
    parser.add_argument("--threads", type=int, default=300)
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()

    if not os.path.isfile(HTTPX):
        print(f"[!] httpx not found at {HTTPX}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"[!] input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as _fh:
        total = sum(1 for _ in _fh if _.strip())
    if total == 0:
        print("[!] input has no hosts — nothing to probe", flush=True)
        open(args.output, "w").close()
        return
    print(f"[*] Probing {total} hosts (threads={args.threads}, timeout={args.timeout}s)…",
          flush=True)

    cmd = [
        HTTPX,
        "-l", args.input,
        "-threads", str(args.threads),
        "-timeout", str(args.timeout),
        "-status-code",
        "-title",
        "-silent",   # suppress banner
    ]

    # Stream httpx stdout line-by-line and persist each result the instant it
    # arrives. This is the key reliability fix: httpx prints every live host as
    # it finds it, so even if the wall-clock watchdog has to kill a slow run
    # (e.g. behind a corporate proxy that delays every probe), everything found
    # up to that point is already on disk. The previous approaches — capturing
    # stdout via communicate(), or httpx -o — lost all results on a kill because
    # the buffer/file was only flushed at the very end.
    import threading
    wall_cap = max(300, int(total * args.timeout / max(args.threads, 1)) + 300)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1)
    timed_out = {"v": False}
    def _kill():
        timed_out["v"] = True
        try:
            proc.kill()
        except Exception:
            pass
    watchdog = threading.Timer(wall_cap, _kill)
    watchdog.start()

    results = []
    try:
        with open(args.output, "w") as out:
            for line in proc.stdout:        # ends when httpx exits or is killed
                line = line.strip()
                if line.startswith(("http://", "https://")):
                    out.write(line + "\n")
                    out.flush()             # persist immediately, survive a kill
                    results.append(line)
    finally:
        watchdog.cancel()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass

    if timed_out["v"]:
        print(f"[!] httpx exceeded {wall_cap}s wall-clock cap — "
              f"kept {len(results)} live hosts found so far", flush=True)

    print(f"[+] Live hosts: {len(results)} / {total}")
    print(f"[+] Written to: {args.output}")

    # Print status code summary
    from collections import Counter
    import re
    codes = Counter(re.search(r'\[(\d+)\]', l).group(1)
                    for l in results if re.search(r'\[(\d+)\]', l))
    for code, count in sorted(codes.items()):
        print(f"    {code}: {count}")

if __name__ == "__main__":
    main()
