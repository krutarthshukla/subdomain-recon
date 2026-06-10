#!/usr/bin/env python3
"""
validate_ownership.py — Decide which discovered root domains are actually OWNED.

"Resolves" is not "owned". A brand-named domain can be parked, squatted, or a
redirect to a registrar's for-sale page (e.g. acme.us → Afternic parking,
acme.uk → "for sale | spaceship.com").

DESIGN (positive-signal-only):
  Maintaining a denylist of parking nameservers is whack-a-mole — there's always
  another registrar/broker whose NS isn't in the list, and "uncertain" defaulting
  to "keep" let squatter brand-look-alike domains waste hours of a real scan.

  The new model requires AFFIRMATIVE proof of ownership. Signals (any one wins):
    1. RDAP registrant org name matches --org-aliases  (strongest)
    2. TLS cert subject.O matches --org-aliases        (strong)
    3. HTTP redirect to a known-owned brand domain      (strong)
    4. NS matches --trusted-ns-pattern (e.g. awsdns-)   (medium — narrow allowlist)
    5. Brand label exact-match + live serving content   (weak; legacy heuristic)

  Without ANY positive signal → REJECTED (default). Pass --include-uncertain
  to restore the old "include unjudged domains in enumeration" behavior.

  PARKING_NS + PARKING_TITLE remain as a fast first-pass reject, not the primary
  mechanism.

Usage:
  python3 validate_ownership.py \
    --input /tmp/confirmed_domains.txt \
    --trusted acme.com,acme.io \
    --org-aliases "Acme,Acme Software Private Limited,Acme Subsidiary" \
    --trusted-ns-pattern "awsdns|cloudflare" \
    --slugs acme,acm,acmex \
    --output /tmp/owned_domains.txt \
    --rejected /tmp/rejected_domains.txt
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import ssl
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Bound raw DNS lookups so a hung resolver can't wedge a pool worker.
socket.setdefaulttimeout(8)

# Registrant organisations that mean "this domain is for sale or parked",
# regardless of NS. RDAP returns these as the org name on broker-held domains.
# Stable across years — broker companies rebrand much less often than they
# spin up new parking nameservers, so this denylist doesn't go stale the way
# PARKING_NS does.
#
# IMPORTANT: WHOIS-PRIVACY services are NOT included here. "Domains By Proxy",
# "WhoisGuard", "Withheld for Privacy", "Contact Privacy Inc.", "Perfect
# Privacy, LLC", "REDACTED FOR PRIVACY" are all used by LEGITIMATE owners to
# hide their personal details. Treating them as squatters would cause every
# privacy-protected real defensive registration by the target org to be wrongly
# rejected. Privacy → "no positive signal" → fall through to other signals
# (NS allowlist, cert, etc.) rather than auto-reject.
SQUATTER_ORGS = (
    # Pure brokers (their business IS selling parked inventory)
    "huge domains", "hugedomains",
    "namebright",  "name bright",
    "buydomains",  "buy domains",
    "sedo gmbh",   "sedo holding",
    "afternic",
    "dropcatch",   "drop catch",
    "namejet",     "snapnames",
    "domain capital",
    "dan.com",
    "uniregistry",
    "efty",
    "namepros",
    "fabulous",
    "park.io",
    "registrar otc",
    "internet domain service",
    "domainmarket",  "domain market",
    "above.com",
)

# ── Ownership signals (kept in sync with recon_tool.py) ──────────────────────
# Nameservers that mean "parked / for sale / not operated by the owner". High
# confidence only — registrars that also host live sites are left out so a real
# owned domain is never mis-rejected. Matched as exact host or any subdomain.
# Fast first-pass nameserver denylist. NOT the primary mechanism — the RDAP
# registrant check (SQUATTER_ORGS above) is far more stable. Kept short and
# focused on well-known parking infra; new squatter NS are caught by RDAP
# without needing to be added here.
PARKING_NS = (
    "afternic.com", "parkingcrew.net", "parkingcrew.com", "sedoparking.com",
    "sedo.com", "bodis.com", "dan.com", "above.com", "hugedomains.com",
    "voodoo.com", "namedrive.com", "parklogic.com", "fabulous.com",
    "dnsdiy.com", "uniregistrymarket.link", "domainmarket.com", "cashparking.com",
    "parkingpage.namecheap.com", "undeveloped.com", "skenzo.com", "rookdns.com",
    "namebrightdns.com", "dns-parking.com",
)

PARKING_TITLE = (
    "for sale", "is for sale", "buy this domain", "domain is parked",
    "domain parking", "this domain may be for sale", "purchase this domain",
    "domain for sale", "parked free", "this domain has expired",
    "available for purchase", "domain expired",
)

# RFC 6598 shared address space — internal-asset convention at some orgs.
CGNAT = ipaddress.ip_network("100.64.0.0/10")

_BIN = os.path.expanduser("~/.recon-tools/bin")


def _have(name):
    cand = os.path.join(_BIN, name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    from shutil import which
    return which(name)


def _url_host(u):
    if not u:
        return ""
    u = re.sub(r"^[a-z]+://", "", str(u).strip().lower())
    return u.split("/")[0].split("?")[0].split(":")[0].rstrip(".")


def _is_parking_ns(ns_set):
    for ns in ns_set:
        ns = ns.strip().lower().rstrip(".")
        for p in PARKING_NS:
            if ns == p or ns.endswith("." + p):
                return p
    return ""


# ── DNS: nameservers + A records ─────────────────────────────────────────────
def ns_lookup(domains):
    """{apex: {nameservers}} — dnsx if present, else `dig +short NS`."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    out = {}
    if not domains:
        return out
    dnsx = _have("dnsx")
    if dnsx:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            tmp = f.name
        # Stream dnsx output line-by-line via Popen so we get every NS as it's
        # produced — subprocess.run + capture_output buffers everything until
        # process exit, so a hung dnsx (observed: 2+ minutes on certain parking
        # NS) loses ALL results when the timeout kicks in. Reading the pipe as
        # we go means partial coverage survives the kill.
        import threading
        deadline = max(30, len(domains) // 4 + 30)
        proc = subprocess.Popen(
            [dnsx, "-l", tmp, "-ns", "-silent", "-json",
             "-t", "100", "-wt", "3", "-retry", "1"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1,
        )
        killer = threading.Timer(deadline, lambda: proc.kill())
        killer.start()
        try:
            for line in proc.stdout:                # streams as dnsx prints
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = (obj.get("host") or obj.get("input") or "").lower()
                ns = {n.strip().lower().rstrip(".") for n in (obj.get("ns") or []) if n}
                if host and ns:
                    out[host] = ns
        finally:
            killer.cancel()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
            try: os.unlink(tmp)
            except OSError: pass
        return out

    def dig_ns(d):
        try:
            r = subprocess.run(["dig", "+short", "NS", d], capture_output=True,
                               text=True, timeout=8)
            ns = {ln.strip().lower().rstrip(".") for ln in r.stdout.splitlines()
                  if ln.strip()}
            return d, ns
        except (subprocess.SubprocessError, OSError):
            return d, set()

    with ThreadPoolExecutor(max_workers=max(1, min(40, len(domains)))) as pool:
        for f in as_completed({pool.submit(dig_ns, d) for d in domains}):
            d, ns = f.result()
            if ns:
                out[d] = ns
    return out


def a_lookup(domains):
    """{apex: [ips]} via getaddrinfo (good enough for the CGNAT check)."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    out = {}

    def one(d):
        try:
            infos = socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
            return d, sorted({i[4][0] for i in infos})
        except (socket.gaierror, OSError):
            return d, []

    if not domains:
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(60, len(domains)))) as pool:
        for f in as_completed({pool.submit(one, d) for d in domains}):
            d, ips = f.result()
            if ips:
                out[d] = ips
    return out


# ── HTTP: status / redirect / title ──────────────────────────────────────────
def http_meta(domains, timeout=10):
    """{apex: (status, redirect_host, title_lower)} — httpx if present, else a
    threaded requests/urllib fallback."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    out = {}
    if not domains:
        return out
    httpx = _have("httpx")
    if httpx:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            tmp = f.name
        try:
            r = subprocess.run([httpx, "-l", tmp, "-json", "-silent",
                                "-status-code", "-title", "-location",
                                "-timeout", str(timeout), "-threads", "50"],
                               capture_output=True, text=True,
                               timeout=max(120, len(domains)))
            for line in r.stdout.splitlines():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = _url_host(obj.get("input") or obj.get("host") or "")
                if not host:
                    continue
                final = _url_host(obj.get("url") or "")
                redirect = _url_host(obj.get("location") or "")
                if not redirect and final and final != host:
                    redirect = final
                out[host] = (obj.get("status_code"),
                             redirect, (obj.get("title") or "").strip().lower())
        except (subprocess.SubprocessError, OSError):
            pass
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return out

    # Fallback: requests (follow redirects, read final host + title).
    try:
        import requests
        sess = requests.Session()
        sess.headers.update({"User-Agent": "Mozilla/5.0 (compatible; recon/2.0)"})
    except ImportError:
        sess = None

    def one(d):
        for scheme in ("https", "http"):
            try:
                if sess is not None:
                    resp = sess.get(f"{scheme}://{d}", timeout=timeout,
                                    allow_redirects=True, verify=False)
                    final = _url_host(resp.url)
                    m = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "",
                                  re.IGNORECASE | re.DOTALL)
                    title = (m.group(1).strip().lower()[:120] if m else "")
                    redirect = final if final and final != d else ""
                    return d, (resp.status_code, redirect, title)
                from urllib.request import urlopen, Request
                req = Request(f"{scheme}://{d}", headers={"User-Agent": "Mozilla/5.0"})
                with urlopen(req, timeout=timeout) as resp:
                    final = _url_host(resp.geturl())
                    body = resp.read(65536).decode("utf-8", "ignore")
                    m = re.search(r"<title[^>]*>(.*?)</title>", body,
                                  re.IGNORECASE | re.DOTALL)
                    title = (m.group(1).strip().lower()[:120] if m else "")
                    redirect = final if final and final != d else ""
                    return d, (getattr(resp, "status", 200), redirect, title)
            except Exception:
                continue
        return d, (None, "", "")

    with ThreadPoolExecutor(max_workers=max(1, min(40, len(domains)))) as pool:
        for f in as_completed({pool.submit(one, d) for d in domains}):
            d, meta = f.result()
            out[d] = meta
    return out


# ── RDAP registrant lookup ────────────────────────────────────────────────────
def _rdap_one(domain):
    """Return the registrant organisation name for `domain`, or "" on failure.

    Uses rdap.org's free bootstrap service (no key, supports most TLDs). Looks
    for the entity with role 'registrant' and extracts vcard 'org' or 'fn'.
    """
    try:
        req = Request(f"https://rdap.org/domain/{domain}",
                      headers={"User-Agent": "subdomain-recon/2.0"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except (URLError, HTTPError, json.JSONDecodeError, socket.timeout, OSError):
        return ""
    for ent in data.get("entities", []):
        roles = [r.lower() for r in ent.get("roles", [])]
        if "registrant" not in roles:
            continue
        vcard = ent.get("vcardArray", [])
        if len(vcard) < 2:
            continue
        # vcardArray[1] is a list of [name, params, type, value] entries
        org = ""
        fn = ""
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            key, _, _, val = item[0], item[1], item[2], item[3]
            if key == "org":
                org = val if isinstance(val, str) else (val[0] if val else "")
            elif key == "fn":
                fn = val if isinstance(val, str) else ""
        if org:
            return org.strip()
        if fn:
            return fn.strip()
    return ""


def rdap_lookup(domains):
    """{apex: registrant_org_name_lowercased} for each resolvable domain."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    out = {}
    if not domains:
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(20, len(domains)))) as pool:
        futs = {pool.submit(_rdap_one, d): d for d in domains}
        for f in as_completed(futs):
            d = futs[f]
            try:
                org = f.result()
            except Exception:
                org = ""
            if org:
                out[d] = org.lower()
    return out


# ── TLS cert organisation lookup ─────────────────────────────────────────────
def _cert_org_one(domain, timeout=6):
    """Return the cert subject's Organization (O) field, lowercased, or ""."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we just want the cert, not to validate
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except (socket.timeout, socket.gaierror, ConnectionError, ssl.SSLError, OSError):
        return ""
    subject = dict(x[0] for x in cert.get("subject", ()) if x)
    return (subject.get("organizationName") or "").lower().strip()


def cert_org_lookup(domains, timeout=6):
    """{apex: cert_subject_O_lowercased} for HTTPS-reachable domains."""
    domains = sorted({d.strip().lower() for d in domains if d.strip()})
    out = {}
    if not domains:
        return out
    with ThreadPoolExecutor(max_workers=max(1, min(40, len(domains)))) as pool:
        futs = {pool.submit(_cert_org_one, d, timeout): d for d in domains}
        for f in as_completed(futs):
            d = futs[f]
            try:
                org = f.result()
            except Exception:
                org = ""
            if org:
                out[d] = org
    return out


def _org_matches_aliases(org_string, aliases):
    """Word-boundary match: every alias word must appear as a whole token in the
    org string. Prevents 'TERA Finlabs' from matching any 'TERA'-containing
    third-party org (e.g. teraflop-byte LLC) — that was a false-positive
    source in the legacy substring match.

    Examples (alias → org → result):
      'Acme' → 'Acme Software Private Limited' → match
      'TERA Finlabs' → 'Tera Finlabs Pvt Ltd' → match
      'TERA Finlabs' → 'Teraflop Software' → NO match (no 'finlabs' token)
      'Acme' → 'Acmepayments LLC' → NO match (no whole 'acme' word)
    """
    if not org_string or not aliases:
        return None
    org_tokens = re.findall(r"[a-z0-9]+", org_string.lower())
    org_set = set(org_tokens)
    for a in aliases:
        a_tokens = re.findall(r"[a-z0-9]+", a.lower())
        if not a_tokens:
            continue
        if all(t in org_set for t in a_tokens):
            return a
    return None


def _org_is_squatter(org_string):
    if not org_string:
        return None
    s = org_string.lower()
    for sq in SQUATTER_ORGS:
        if sq in s:
            return sq
    return None


# ── Classification — positive-signal-only ─────────────────────────────────────
def classify_root(apex, owned_roots, owned_labels, org_aliases,
                  trusted_ns_re, trusted_ns_set,
                  ns_map, http_map, a_map, rdap_map, cert_map):
    """Decide owned / rejected / uncertain for one root.

    Returns (status, reason). With positive-signal-only policy, "uncertain"
    means no signal at all — caller decides whether to keep these via the
    --include-uncertain flag.
    """
    label = apex.split(".")[0]
    ns = ns_map.get(apex, set())
    status, redirect, title = http_map.get(apex, (None, "", ""))
    ips = a_map.get(apex, [])
    registrant = rdap_map.get(apex, "")
    cert_o = cert_map.get(apex, "")

    # === Hard rejects (cheap, run first) ===
    parker = _is_parking_ns(ns)
    if parker:
        return "rejected", f"parked: nameserver *.{parker}"
    for frag in PARKING_TITLE:
        if frag in title:
            return "rejected", f"for-sale/parked landing page (title: {frag!r})"
    sq = _org_is_squatter(registrant)
    if sq:
        return "rejected", f"registrant is squatter/broker ({sq!r} in {registrant!r})"

    # === Strong positive signals — RDAP / TLS cert ===
    if registrant:
        m = _org_matches_aliases(registrant, org_aliases)
        if m:
            return "owned", f"RDAP registrant matches '{m}' (org={registrant!r})"
    if cert_o:
        m = _org_matches_aliases(cert_o, org_aliases)
        if m:
            return "owned", f"TLS cert subject.O matches '{m}' (O={cert_o!r})"

    # === Strong positive — HTTP redirect to owned brand ===
    if redirect:
        rlabel = redirect.split(".")[0]
        for r in sorted(owned_roots, key=len, reverse=True):
            if redirect == r or redirect.endswith("." + r):
                return "owned", f"HTTP redirect to owned domain {r}"
        if rlabel in owned_labels:
            return "owned", f"HTTP redirect to brand domain {redirect}"

    # === Strong positive — NS overlaps the trusted set's nameservers ===
    # For Route 53, each AWS hosted zone gets a unique 4-NS delegation set;
    # NS overlap between two domains is a strong signal they share an AWS
    # account/owner. Same logic works for Cloudflare (unique NS pair per zone)
    # and Gandi, name.com, etc. The trusted_ns_set is auto-derived from the
    # NS of --trusted domains (computed in main()), so the user only has to
    # name their primary domains; the allowlist falls out for free.
    if trusted_ns_set and ns:
        overlap = ns & trusted_ns_set
        if overlap:
            return "owned", f"NS overlaps trusted delegation set ({sorted(overlap)[0]})"

    # === Medium positive — NS matches user-supplied regex pattern ===
    # Backward-compat opt-in. Looser than the NS-overlap above (regex like
    # 'awsdns' matches all Route 53 zones, not just the user's account).
    if trusted_ns_re:
        for n in ns:
            if trusted_ns_re.search(n):
                return "owned", f"NS matches trusted pattern ({n})"

    # === Medium positive — CGNAT (internal-only asset) ===
    for ip in ips:
        try:
            if ipaddress.ip_address(ip) in CGNAT:
                return "owned", f"resolves to internal IP {ip} (RFC6598 100.64/10)"
        except ValueError:
            continue

    # === Weak positive — brand label EXACT MATCH + serving content ===
    # Tightened from prior 'label in owned_labels' (substring) to exact match,
    # so 'myrazorx' no longer satisfies the 'razorx' slug.
    if label in owned_labels:
        if status and 200 <= status < 400 and title:
            return "owned", (f"brand label '{label}' serving live content "
                             f"(HTTP {status})")

    # === No positive signal ===
    return "uncertain", "no positive ownership signal (no RDAP/cert/redirect/NS match)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="File of confirmed root domains")
    ap.add_argument("--trusted", default="",
                    help="Comma-separated known-owned roots (pass through as owned)")
    ap.add_argument("--slugs", default="",
                    help="Comma-separated brand labels owned by the org "
                         "(e.g. acme,acme). Defaults to the trusted roots' labels.")
    ap.add_argument("--org-aliases", default="",
                    help="Comma-separated organisation-name strings to match "
                         "against RDAP registrant + TLS cert subject.O. "
                         "Examples: 'Acme,Acme Software Private Limited'. "
                         "This is the strongest positive ownership signal.")
    ap.add_argument("--trusted-ns-pattern", default="",
                    help="Regex applied to nameservers. Any NS matching is a "
                         "positive ownership signal — pass your org's known DNS "
                         "infrastructure pattern, e.g. 'awsdns|cloudflare' if "
                         "your org's domains are all on AWS Route 53 + CF.")
    ap.add_argument("--include-uncertain", action="store_true",
                    help="Include domains with no positive ownership signal in "
                         "the output (legacy behavior). Default: exclude them "
                         "(treat as rejected for enumeration purposes).")
    ap.add_argument("--output", required=True,
                    help="Owned roots (and uncertain, if --include-uncertain). "
                         "These continue to subdomain enumeration.")
    ap.add_argument("--rejected", default="",
                    help="Optional file for rejected roots ('domain<TAB>reason')")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()
    args.verbose = True  # verbose output is always on

    with open(args.input) as f:
        roots = sorted({ln.strip().lower().lstrip("*.") for ln in f
                        if ln.strip() and not ln.startswith("#") and "." in ln})
    if not roots:
        print("[!] No roots to validate", file=sys.stderr)
        sys.exit(1)

    trusted = {d.strip().lower() for d in args.trusted.split(",") if d.strip()}
    slugs = {s.strip().lower() for s in args.slugs.split(",") if s.strip()}
    slugs |= {r.split(".")[0] for r in trusted}
    org_aliases = [a.strip() for a in args.org_aliases.split(",") if a.strip()]
    trusted_ns_re = re.compile(args.trusted_ns_pattern, re.I) if args.trusted_ns_pattern else None

    to_check = [r for r in roots if r not in trusted]
    print(f"[*] Ownership validation: {len(roots)} root(s) "
          f"({len(trusted)} trusted pass through, {len(to_check)} to judge)",
          flush=True)
    if not org_aliases and not trusted_ns_re:
        print("[!] WARNING: no --org-aliases and no --trusted-ns-pattern given. "
              "Falling back to slug-match heuristic + NS-overlap from --trusted. "
              "Pass --org-aliases to get the strong RDAP/cert positive-signal "
              "checks.", flush=True)

    # Derive the trusted NS allowlist from the --trusted domains' actual NS.
    # This is the strongest available NS signal: if a candidate root shares
    # any NS with a known-owned domain, they share a hosted-zone owner.
    trusted_ns_set = set()
    if trusted:
        trusted_ns_map = ns_lookup(sorted(trusted))
        for d, ns_set in trusted_ns_map.items():
            trusted_ns_set |= ns_set
        if trusted_ns_set:
            print(f"[*] Derived {len(trusted_ns_set)} trusted nameserver(s) "
                  f"from --trusted: {sorted(trusted_ns_set)[:3]}…", flush=True)

    ns_map = ns_lookup(to_check)
    http_map = http_meta(to_check, args.timeout)
    a_map = a_lookup(to_check)
    print(f"[*] RDAP registrant lookups ({len(to_check)} domains)…", flush=True)
    rdap_map = rdap_lookup(to_check)
    print(f"[*] TLS cert subject.O lookups…", flush=True)
    cert_map = cert_org_lookup(to_check, timeout=min(args.timeout, 6))

    owned_roots = set(trusted)
    owned_labels = set(slugs)
    owned, uncertain, rejected = {}, {}, {}
    for r in trusted:
        owned[r] = "explicit / trusted"

    bucket = {"owned": owned, "uncertain": uncertain, "rejected": rejected}
    for r in to_check:
        status, reason = classify_root(r, owned_roots, owned_labels, org_aliases,
                                       trusted_ns_re, trusted_ns_set,
                                       ns_map, http_map, a_map,
                                       rdap_map, cert_map)
        bucket[status][r] = reason
        if args.verbose:
            print(f"  [{status:9}] {r:<22} {reason}", flush=True)

    # Default policy flip: uncertain is EXCLUDED unless --include-uncertain.
    # Uncertain domains are still reported (written to --rejected with a
    # distinct reason) so a human can override.
    if args.include_uncertain:
        keep = sorted(set(owned) | set(uncertain))
    else:
        keep = sorted(set(owned))
    with open(args.output, "w") as f:
        f.write("\n".join(keep) + ("\n" if keep else ""))
    if args.rejected:
        with open(args.rejected, "w") as f:
            for d in sorted(rejected):
                f.write(f"{d}\t{rejected[d]}\n")
            if not args.include_uncertain:
                for d in sorted(uncertain):
                    f.write(f"{d}\tuncertain (no positive signal): {uncertain[d]}\n")

    print(f"\n{'='*60}")
    print(f"  {len(owned)} owned | {len(uncertain)} uncertain (kept) | "
          f"{len(rejected)} rejected")
    print(f"  → {len(keep)} roots continue to enumeration: {args.output}")
    if rejected:
        print(f"  → {len(rejected)} NOT-owned roots logged"
              + (f" to {args.rejected}" if args.rejected else "") + ":")
        for d in sorted(rejected):
            print(f"      {d:<22} {rejected[d]}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
