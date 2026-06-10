#!/usr/bin/env python3
"""
Write the final organized report file.
Usage: python3 write_report.py --org "Acme Corp" \
         --domain-map "acme.com:Primary,acquired-co.com:Acquisition 2023" \
         --subdomain-files /tmp/all.txt \
         --output ~/Desktop/AcmeCorp_domains.txt
"""

import argparse
import os
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True)
    parser.add_argument("--domain-map", required=True,
                        help="domain:label pairs, comma-separated")
    parser.add_argument("--subdomain-files", required=True,
                        help="Comma-separated paths to subdomain files")
    parser.add_argument("--rejected-file", default="",
                        help="Optional 'domain<TAB>reason' file from "
                             "validate_ownership.py — listed as NOT OWNED")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Roots that ownership validation rejected (parked/for-sale) — reported, not scanned.
    rejected = {}
    if args.rejected_file:
        try:
            with open(args.rejected_file) as rf:
                for line in rf:
                    line = line.rstrip("\n")
                    if not line.strip() or line.startswith("#"):
                        continue
                    d, _, reason = line.partition("\t")
                    rejected[d.strip().lower()] = reason.strip() or "not owned"
        except FileNotFoundError:
            pass

    # Build domain → label map
    domain_meta = {}
    for pair in args.domain_map.split(","):
        pair = pair.strip()
        if ":" in pair:
            d, label = pair.split(":", 1)
            domain_meta[d.strip().lower()] = label.strip()

    # Load all subdomains
    all_subs = set()
    for path in args.subdomain_files.split(","):
        path = path.strip()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        all_subs.add(line.lstrip("*."))
        except FileNotFoundError:
            pass

    # Group by root domain
    grouped = {d: [] for d in domain_meta}
    ungrouped = []
    for sub in sorted(all_subs):
        matched = False
        for d in domain_meta:
            if sub.endswith("." + d) or sub == d:
                grouped[d].append(sub)
                matched = True
                break
        if not matched:
            ungrouped.append(sub)

    output = os.path.expanduser(args.output)
    with open(output, "w") as f:
        f.write(f"# {args.org} — Domain & Subdomain Recon\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Techniques attempted:\n")
        for t in (
            "domain discovery (slug x TLD sweep, crt.sh org search, reverse WHOIS,",
            "  GitHub org, Wayback apex, NS-existence)",
            "acquisition/brand-domain research (web search)",
            "ownership validation (NS / redirect / page-title / CGNAT)",
            "passive enum: crt.sh, CertSpotter, Merklemap, Columbus, LeakIX, Netlas,",
            "  host.io, C99.nl, HackerTarget, RapidDNS, JLDC/Anubis, AlienVault OTX,",
            "  VirusTotal, Wayback CDX, subfinder, uncover (18 engines), asnmap+PTR",
            "advanced: favicon-hash pivot, .well-known, source maps, Azure tenant enum,",
            "  SaaS patterns, Postman search, BBOT, katana JS crawl, subwiz ML, JARM,",
            "  BadDNS takeover detection",
            "active: zone transfer, DNS brute-force (n0kovo 3M), alterx -enrich perms,",
            "  tlsx SAN-on-CIDR",
            "live HTTP probe (httpx)",
        ):
            f.write((f"#     {t[2:]}\n") if t.startswith("  ") else f"#   - {t}\n")
        total = sum(len(v) for v in grouped.values()) + len(ungrouped)
        f.write(f"# Total: {total} subdomains across {len(domain_meta)} root domains "
                f"({len(rejected)} root(s) rejected as not-owned)\n")
        f.write("\n")

        for domain, label in domain_meta.items():
            subs = grouped.get(domain, [])
            f.write("=" * 70 + "\n")
            f.write(f"# {domain}  |  {label}\n")
            f.write(f"# Subdomains: {len(subs)}\n")
            f.write("=" * 70 + "\n")
            for s in sorted(subs):
                f.write(s + "\n")
            f.write("\n")

        if ungrouped:
            f.write("=" * 70 + "\n")
            f.write(f"# [Ungrouped / Other]  |  {len(ungrouped)} entries\n")
            f.write("=" * 70 + "\n")
            for s in sorted(ungrouped):
                f.write(s + "\n")
            f.write("\n")

        if rejected:
            f.write("=" * 70 + "\n")
            f.write(f"# NOT OWNED — excluded from scan  ({len(rejected)})\n")
            f.write("# (resolves, but parked/for-sale — review before acting)\n")
            f.write("=" * 70 + "\n")
            for d in sorted(rejected):
                f.write(f"{d:<35} {rejected[d]}\n")
            f.write("\n")

        # Summary table
        f.write("=" * 70 + "\n")
        f.write("# SUMMARY\n")
        f.write("=" * 70 + "\n")
        f.write(f"{'Root Domain':<35} {'Count':>8}  Label\n")
        f.write("-" * 70 + "\n")
        for domain, label in domain_meta.items():
            f.write(f"{domain:<35} {len(grouped.get(domain,[]))  :>8}  {label}\n")
        f.write("-" * 70 + "\n")
        f.write(f"{'TOTAL':<35} {total:>8}\n")

    print(f"[+] Report written: {output}")
    print(f"[+] Total subdomains: {total}")

    # Print summary to stdout too
    print(f"\n{'Root Domain':<35} {'Count':>8}  Label")
    print("-" * 60)
    for domain, label in domain_meta.items():
        print(f"{domain:<35} {len(grouped.get(domain,[]))  :>8}  {label}")
    print("-" * 60)
    print(f"{'TOTAL':<35} {total:>8}")

if __name__ == "__main__":
    main()
