#!/usr/bin/env python3
"""
domain_discovery.py — Find ALL root domains owned by an org.

Strategy (all run in parallel):
  A. TLD sweep        — every entity name × 25 TLDs, DNS-confirmed
  B. crt.sh org name  — certs issued to the org reveal domains
  C. Reverse WHOIS    — whoxy.com: other domains by same registrant email
  D. GitHub org       — repos + README often contain production domain names
  E. Wayback apex     — CDX API for apex domains, not just subdomains

Usage:
  python3 domain_discovery.py \
    --org "Acme Corp" \
    --acquisitions "Acquired Co One,Acquired Co Two,Acquired Co Three" \
    --abbreviations "acme,ac" \
    --output /tmp/confirmed_domains.txt
"""

import argparse, json, os, re, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Bound raw DNS lookups so a hung resolver can't wedge a pool worker.
socket.setdefaulttimeout(8)

try:
    import requests as _req
    _SESSION = _req.Session()
    _SESSION.headers.update({"User-Agent": "Mozilla/5.0 (compatible; recon/1.0)"})
    def fetch(url, timeout=15):
        try:
            return _SESSION.get(url, timeout=timeout).text
        except Exception:
            return ""
except ImportError:
    from urllib.request import urlopen, Request
    def fetch(url, timeout=15):
        try:
            with urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception:
            return ""

# ── TLD list — global, org-agnostic ──────────────────────────────────────────
# Covers all industries and regions. Ordered by global registration frequency.
TLDS = [
    # Universal — appear in every region and industry
    "com", "net", "org", "io", "co", "ai",
    # Country codes with heavy commercial use (global, not region-biased)
    "us", "uk", "de", "fr", "ca", "au", "br", "nl", "jp", "in",
    # Modern tech/startup TLDs
    "app", "dev", "tech", "cloud", "digital",
    # Business/commerce
    "store", "shop", "online", "biz", "info",
    # Misc common
    "me", "xyz", "co.uk", "co.in",
]

# ── Slugification ─────────────────────────────────────────────────────────────

_DROP_WORDS = {
    # Legal suffixes (universal across all countries)
    "technologies", "technology", "solutions", "labs",
    "software", "systems", "platforms", "platform",
    "services", "service", "group", "holdings", "ventures",
    "private", "public", "limited", "unlimited",
    "pvt", "ltd", "llc", "llp", "inc", "corp", "co",
    "gmbh", "ag", "sa", "bv", "nv", "plc", "pty",
    # Generic descriptors that add no domain signal
    "tech", "digital", "global", "international", "worldwide",
    "online", "network", "networks", "cloud", "data",
    "hq", "official",
    # Country names (the script tests country TLDs separately)
    "india", "america", "usa", "europe", "asia",
}

def slugify(name: str) -> set:
    """Return all plausible domain slug variants for a company/product name."""
    name = name.strip().lower()
    slugs = set()

    # 1. Raw: strip everything non-alphanumeric
    raw = re.sub(r'[^a-z0-9]', '', name)
    if raw: slugs.add(raw)

    # 2. Hyphenated
    hyph = re.sub(r'[^a-z0-9]+', '-', name).strip('-')
    if hyph: slugs.add(hyph)

    # 3. Strip drop-words, then re-slug
    words = re.split(r'[^a-z0-9]+', name)
    kept = [w for w in words if w and w not in _DROP_WORDS]
    if kept:
        slugs.add(''.join(kept))
        slugs.add('-'.join(kept))
        slugs.add(kept[0])           # first word only

    # 4. Abbreviation: first letter of each meaningful word
    abbrev = ''.join(w[0] for w in kept if w)
    if len(abbrev) >= 2:
        slugs.add(abbrev)

    # 5. Common prefix variants
    for base in list(slugs):
        slugs.add(f"get{base}")
        slugs.add(f"my{base}")
        slugs.add(f"{base}hq")
        slugs.add(f"{base}app")
        slugs.add(f"{base}pay")
        slugs.add(f"{base}x")

    return {s for s in slugs if 2 <= len(s) <= 30}


def candidates(entity_name: str) -> list:
    slugs = slugify(entity_name)
    return sorted({f"{s}.{tld}" for s in slugs for tld in TLDS})


# ── DNS resolution ────────────────────────────────────────────────────────────

def resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        return True
    except (socket.gaierror, OSError):
        return False


def ns_exists(domains, verbose=False) -> set:
    """Apexes that are NS-delegated even if they have no apex A record.

    A TLD sweep that only keeps A-resolving names silently drops real roots that
    serve only via subdomains / a redirect (e.g. acme.in is NS-delegated to
    Route 53 but has no apex A). dnsx if installed, else threaded `dig +short NS`.
    Ownership validation downstream prunes the parked ones."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    found = set()
    if not domains:
        return found
    import os as _os
    from shutil import which as _which
    dnsx = (_os.path.expanduser("~/.recon-tools/bin/dnsx")
            if _os.path.isfile(_os.path.expanduser("~/.recon-tools/bin/dnsx"))
            else _which("dnsx"))
    if dnsx:
        import tempfile as _tf
        with _tf.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            tmp = f.name
        try:
            r = subprocess.run([dnsx, "-l", tmp, "-ns", "-silent", "-json",
                                "-t", "150"], capture_output=True, text=True,
                               timeout=max(60, len(domains) // 5))
            for line in r.stdout.splitlines():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = (obj.get("host") or obj.get("input") or "").lower()
                if host and (obj.get("ns") or []):
                    found.add(host)
        except (subprocess.SubprocessError, OSError):
            pass
        finally:
            try:
                _os.unlink(tmp)
            except OSError:
                pass
    else:
        def dig_ns(d):
            try:
                r = subprocess.run(["dig", "+short", "NS", d], capture_output=True,
                                   text=True, timeout=8)
                return d, bool(r.stdout.strip())
            except (subprocess.SubprocessError, OSError):
                return d, False
        with ThreadPoolExecutor(max_workers=40) as pool:
            for f in as_completed({pool.submit(dig_ns, d) for d in domains}):
                d, ok = f.result()
                if ok:
                    found.add(d)
    if verbose and found:
        print(f"  [+] NS-existence: {len(found)} extra NS-only root(s)", flush=True)
    return found


def live_from_candidates(entity_name: str, verbose=False):
    cands = candidates(entity_name)
    live = []
    with ThreadPoolExecutor(max_workers=60) as pool:
        futures = {pool.submit(resolves, d): d for d in cands}
        for f in as_completed(futures):
            if f.result():
                live.append(futures[f])
    if verbose and live:
        print(f"  [+] {entity_name}: {sorted(live)}", flush=True)
    return sorted(live)


# ── Source B: crt.sh org-name certificate search ─────────────────────────────

def crtsh_by_org(org_name: str, verbose=False) -> set:
    """Search crt.sh for certs issued to this org — reveals all their domains."""
    found = set()
    import urllib.parse
    for query in [org_name, org_name.split()[0]]:   # try full name and first word
        for attempt in range(3):
            try:
                data = fetch(f"https://crt.sh/?q={urllib.parse.quote(query)}&output=json", timeout=40)
                for entry in json.loads(data):
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if not name or '.' not in name:
                            continue
                        parts = name.split('.')
                        # Extract apex domain (handle .co.in etc.)
                        if parts[-2] in ('co', 'com', 'net', 'org', 'gov', 'edu'):
                            apex = '.'.join(parts[-3:]) if len(parts) >= 3 else name
                        else:
                            apex = '.'.join(parts[-2:])
                        found.add(apex)
                break
            except (json.JSONDecodeError, Exception):
                if attempt < 2:
                    time.sleep(4)
    if verbose and found:
        print(f"  [+] crt.sh org search ({org_name}): {len(found)} apex domains", flush=True)
    return found


# ── Source C: Reverse WHOIS ───────────────────────────────────────────────────

def reverse_whois(primary_domain: str, org_slug: str, verbose=False) -> set:
    found = set()
    try:
        out = subprocess.run(["whois", primary_domain], capture_output=True,
                             text=True, timeout=10).stdout
        emails = [e for e in re.findall(r'[\w.+-]+@[\w.-]+\.\w{2,}', out)
                  if not any(x in e.lower() for x in
                             ['privacy', 'proxy', 'protect', 'redacted', 'noreply'])]
        for email in emails[:3]:
            data = fetch(f"https://www.whoxy.com/whois-history/domains-by-email/{email}", timeout=15)
            for d in re.findall(r'([a-zA-Z0-9_-]+\.[a-zA-Z]{2,})', data):
                d = d.lower()
                # Only keep domains that share the org slug root
                if org_slug[:4] in d:
                    found.add(d)
    except Exception:
        pass
    if verbose and found:
        print(f"  [+] reverse WHOIS: {sorted(found)}", flush=True)
    return found


# ── Source D: GitHub org search ───────────────────────────────────────────────

def github_org_domains(org_name: str, verbose=False) -> set:
    """Fetch GitHub org profile + repos README snippets for domain references."""
    found = set()
    slug = re.sub(r'[^a-z0-9-]', '', org_name.lower().replace(' ', '-'))
    org_slug_root = re.sub(r'[^a-z0-9]', '', org_name.lower())[:6]

    for gh_org in [slug, org_slug_root]:
        data = fetch(f"https://api.github.com/orgs/{gh_org}", timeout=10)
        try:
            obj = json.loads(data)
            blog = obj.get("blog", "")
            if blog:
                m = re.search(r'(?:https?://)?([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', blog)
                if m:
                    found.add(m.group(1).lower())
        except Exception:
            pass

        # Also search repos for domain patterns
        repos_data = fetch(f"https://api.github.com/orgs/{gh_org}/repos?per_page=50", timeout=10)
        try:
            for repo in json.loads(repos_data):
                hp = repo.get("homepage", "") or ""
                m = re.search(r'(?:https?://)?([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', hp)
                if m:
                    d = m.group(1).lower()
                    if org_slug_root[:4] in d:
                        found.add(d)
        except Exception:
            pass

    if verbose and found:
        print(f"  [+] GitHub ({org_name}): {sorted(found)}", flush=True)
    return found


# ── Source E: Wayback apex domains ───────────────────────────────────────────

def wayback_apex(org_slug: str, verbose=False) -> set:
    """CDX API broad search for any URL containing org slug → extract apex domains."""
    found = set()
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{org_slug}.*&output=text&fl=original&collapse=urlkey&limit=5000")
    data = fetch(url, timeout=30)
    for line in data.splitlines():
        m = re.search(r'https?://(?:[^/]+\.)?([a-zA-Z0-9_-]*' + re.escape(org_slug[:5])
                      + r'[a-zA-Z0-9_-]*\.[a-zA-Z]{2,})', line, re.IGNORECASE)
        if m:
            found.add(m.group(1).lower())
    if verbose and found:
        print(f"  [+] Wayback apex: {sorted(found)}", flush=True)
    return found


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--org", required=True)
    parser.add_argument("--acquisitions", default="",
                        help="Comma-separated acquired company names")
    parser.add_argument("--abbreviations", default="",
                        help="Comma-separated known abbreviations/shortcuts e.g. amzn,aws for Amazon")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    args.verbose = True  # verbose output is always on

    # Build full entity list
    entities = [args.org]
    entities += [a.strip() for a in args.acquisitions.split(",") if a.strip()]
    entities += [a.strip() for a in args.abbreviations.split(",") if a.strip()]

    org_slug = re.sub(r'[^a-z0-9]', '', args.org.lower())
    primary_domain = f"{org_slug}.com"

    print(f"[*] Domain discovery for: {args.org}", flush=True)
    print(f"[*] Entities ({len(entities)}): {', '.join(entities)}", flush=True)
    print(f"[*] TLDs tested per entity: {len(TLDS)}", flush=True)
    print(f"[*] Total DNS probes: ~{len(entities) * len(TLDS) * 6} (with slug variants)\n",
          flush=True)

    confirmed = set()

    # ── A. TLD sweep (parallel across all entities) ───────────────────────────
    print("[*] A — TLD sweep...", flush=True)
    with ThreadPoolExecutor(max_workers=len(entities)) as pool:
        futures = {pool.submit(live_from_candidates, e, args.verbose): e for e in entities}
        for f in as_completed(futures):
            confirmed.update(f.result())
    print(f"    → {len(confirmed)} domains after TLD sweep", flush=True)

    # ── B–E run in parallel ───────────────────────────────────────────────────
    before = len(confirmed)
    cert_domains = set()
    whois_domains = set()
    github_domains = set()
    wayback_domains = set()

    print("[*] B-E — cert search, reverse WHOIS, GitHub, Wayback...", flush=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_cert    = pool.submit(crtsh_by_org, args.org, args.verbose)
        f_whois   = pool.submit(reverse_whois, primary_domain, org_slug, args.verbose)
        f_github  = pool.submit(github_org_domains, args.org, args.verbose)
        f_wayback = pool.submit(wayback_apex, org_slug, args.verbose)

        cert_domains    = f_cert.result(timeout=60)
        whois_domains   = f_whois.result(timeout=30)
        github_domains  = f_github.result(timeout=30)
        wayback_domains = f_wayback.result(timeout=40)

    # DNS-confirm B-E results (they may include false positives)
    candidates_bce = (cert_domains | whois_domains | github_domains | wayback_domains) - confirmed
    print(f"    → {len(candidates_bce)} new candidates from B-E, confirming via DNS...",
          flush=True)
    with ThreadPoolExecutor(max_workers=60) as pool:
        futures = {pool.submit(resolves, d): d for d in candidates_bce}
        for f in as_completed(futures):
            if f.result():
                d = futures[f]
                confirmed.add(d)
                if args.verbose:
                    print(f"  [+] confirmed: {d}", flush=True)

    print(f"    → {len(confirmed) - before} new domains from B-E", flush=True)

    # ── F. NS-existence — keep NS-delegated roots with no apex A (recall) ──────
    before_ns = len(confirmed)
    all_cands = set()
    for e in entities:
        all_cands.update(candidates(e))
    leftover = sorted((all_cands | candidates_bce) - confirmed)[:3000]
    if leftover:
        print(f"[*] F — NS-existence check on {len(leftover)} unresolved candidate(s)...",
              flush=True)
        confirmed |= ns_exists(leftover, args.verbose)
        print(f"    → {len(confirmed) - before_ns} NS-only root(s) kept", flush=True)

    # ── Write output ─────────────────────────────────────────────────────────
    with open(args.output, "w") as out:
        for d in sorted(confirmed):
            out.write(d + "\n")

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  {len(confirmed)} confirmed live domains → {args.output}")
    print(f"{'='*55}")

    # Group by entity for readability
    entity_map = defaultdict(list)
    for d in sorted(confirmed):
        root_slug = re.sub(r'[^a-z0-9]', '', d.split('.')[0])
        matched = False
        for entity in entities:
            e_slug = re.sub(r'[^a-z0-9]', '', entity.lower().split()[0])
            if e_slug[:5] in root_slug or root_slug in e_slug[:8]:
                entity_map[entity].append(d)
                matched = True
                break
        if not matched:
            entity_map["other"].append(d)

    for entity, domains in sorted(entity_map.items()):
        print(f"  {entity}")
        for d in sorted(domains):
            print(f"    → {d}")

if __name__ == "__main__":
    main()
