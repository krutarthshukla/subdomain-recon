#!/usr/bin/env python3
"""
passive_enum.py — 27 passive sources (v1 + v2 merged), parallel, zero direct target probing.

v1 sources (19): crt.sh, CertSpotter, HackerTarget, RapidDNS, BufferOver, JLDC/Anubis,
  ThreatMiner, Robtex, AlienVault OTX, VirusTotal, Wayback CDX, gau,
  subfinder -all, amass, assetfinder, chaos, findomain, theHarvester, DNS records

v2 sources added (8): Merklemap, Columbus, LeakIX, Netlas, host.io, C99.nl,
  uncover (18 engines), asnmap+PTR

API keys (optional, all degrade gracefully):
  Configure at: ~/.config/subdomain-recon/api_keys.yaml
  Free keys that help: merklemap, leakix, netlas, c99, hostio

Usage:
  python3 passive_enum.py --domains target.com,acquired.com --output /tmp/passive.txt
  python3 passive_enum.py --domains target.com --output /tmp/out.txt \\
      --keys ~/.config/subdomain-recon/api_keys.yaml
"""

import argparse, json, os, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

GOBIN = os.path.expanduser("~/.recon-tools/bin")

# ── API key loader ────────────────────────────────────────────────────────────
def _load_keys(path=None):
    path = path or os.path.expanduser("~/.config/subdomain-recon/api_keys.yaml")
    if not os.path.isfile(path):
        return {}
    try:
        try:
            import yaml
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except ImportError:
            import re as _re
            keys = {}
            with open(path) as f:
                for line in f:
                    m = _re.match(r'^(\w+):\s*"([^"]*)"', line.strip())
                    if m and m.group(2):
                        keys[m.group(1)] = m.group(2)
            return keys
    except Exception:
        return {}

_KEYS = {}  # populated in main() and passed down

# Sources that REQUIRE an API key. Without a key they're guaranteed to return
# zero, so we skip them at startup (instead of making a wasted HTTP call that
# silently returns 401/empty) and log once per missing key. This turns the
# previous "Zero results from: netlas, host.io, c99, …" noise into a single
# clear "[skip] netlas: no API key configured" message.
_KEY_REQUIRED_SOURCES = {
    "src_merklemap":  ("merklemap",  "https://merklemap.com (free tier)"),
    "src_netlas":     ("netlas",     "https://netlas.io (50 req/day free)"),
    "src_hostio":     ("hostio",     "https://host.io (1000/mo free)"),
    "src_c99":        ("c99",        "https://api.c99.nl (~$5/mo)"),
    "src_leakix":     ("leakix",     "https://leakix.net (free with reg)"),
    "src_virustotal": ("virustotal", "https://virustotal.com/apikey"),
    "src_alienvault": ("alienvault", "free, but OTX rate-limits anon hard"),
    "src_chaos":      ("chaos",      "https://chaos.projectdiscovery.io"),
}

# ── HTTP helper ───────────────────────────────────────────────────────────────
try:
    import requests as _req
    def get(url, headers=None, timeout=20, retries=3):
        h = {"User-Agent": "Mozilla/5.0 (compatible; recon-bot/1.0)"}
        if headers: h.update(headers)
        for i in range(retries):
            try:
                r = _req.get(url, headers=h, timeout=timeout)
                # 4xx/5xx bodies (rate-limit JSON, WAF/auth pages) are NOT data —
                # don't feed them to the subdomain parsers. Back off on 429.
                if r.status_code == 429 and i < retries - 1:
                    time.sleep(3); continue
                if r.status_code >= 400:
                    return ""
                return r.text
            except Exception:
                if i < retries - 1: time.sleep(3)
        return ""
except ImportError:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    import urllib.parse
    def get(url, headers=None, timeout=20, retries=3):
        h = {"User-Agent": "Mozilla/5.0"}
        if headers: h.update(headers)
        for i in range(retries):
            try:
                req = Request(url, headers=h)
                with urlopen(req, timeout=timeout) as r:
                    return r.read().decode("utf-8", errors="ignore")
            except Exception:
                if i < retries - 1: time.sleep(3)
        return ""

def clean(text, domain):
    """Extract + clean subdomains from raw text."""
    pat = r'(?:[a-zA-Z0-9_-]+\.)+' + re.escape(domain)
    subs = set()
    for s in re.findall(pat, text, re.IGNORECASE):
        s = s.lower().lstrip("*.")
        if s.endswith("." + domain) or s == domain:
            subs.add(s)
    return subs

def run_tool(args, timeout=90):
    """Run a CLI tool, return stdout as string. Tries GOBIN path first."""
    binary = args[0]
    for prefix in [GOBIN + "/", ""]:
        try:
            result = subprocess.run(
                [prefix + binary] + args[1:],
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return ""
    return ""

# ── Source functions (each returns (name, set_of_subs)) ──────────────────────

def src_crtsh(domain):
    # Two depth levels only — %.%.%.domain is covered by subfinder -recursive
    import urllib.parse as _up
    subs = set()
    for q in [f"%.{domain}", f"%.%.{domain}"]:
        for attempt in range(3):
            try:
                data = get(f"https://crt.sh/?q={_up.quote(q)}&output=json", timeout=40)
                if not data: time.sleep(5); continue
                for e in json.loads(data):
                    for n in e.get("name_value","").split("\n"):
                        n = n.strip().lstrip("*.")
                        if n.endswith("."+domain) or n == domain: subs.add(n.lower())
                break
            except json.JSONDecodeError:
                subs |= clean(data, domain); break
            except Exception:
                time.sleep(5)
    return "crt.sh", subs

def src_certspotter(domain):
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    subs = set()
    try:
        for e in json.loads(get(url, timeout=20)):
            for n in e.get("dns_names", []):
                n = n.strip().lower().lstrip("*.")
                if n.endswith("."+domain) or n == domain: subs.add(n)
    except Exception:
        subs |= clean(get(url), domain)
    return "certspotter", subs

def src_hackertarget(domain):
    data = get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
    subs = set()
    if "API count exceeded" not in (data or ""):
        subs |= clean(data, domain)
    return "hackertarget", subs

def src_rapiddns(domain):
    return "rapiddns", clean(get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=15), domain)

def src_bufferover(domain):
    subs = set()
    data = get(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15)
    try:
        obj = json.loads(data)   # parse once, not twice
        for e in obj.get("FDNS_A",[]) + obj.get("RDNS",[]):
            subs |= clean(str(e), domain)
    except Exception:
        subs |= clean(data, domain)
    return "bufferover", subs

def src_jldc(domain):
    subs = set()
    data = get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=15)
    try:
        for s in json.loads(data):
            s = s.strip().lower().lstrip("*.")
            if s.endswith("."+domain) or s == domain: subs.add(s)
    except Exception:
        subs |= clean(data, domain)
    return "jldc/anubis", subs

def src_threatcrowd(domain):
    subs = set()
    data = get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=15)
    try:
        for s in json.loads(data).get("subdomains",[]):
            s = s.strip().lower()
            if s.endswith("."+domain) or s == domain: subs.add(s)
    except Exception:
        subs |= clean(data, domain)
    return "threatcrowd", subs

def src_threatminer(domain):
    subs = set()
    data = get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=15)
    try:
        for s in json.loads(data).get("results",[]):
            s = s.strip().lower()
            if s.endswith("."+domain) or s == domain: subs.add(s)
    except Exception:
        subs |= clean(data, domain)
    return "threatminer", subs

def src_alienvault(domain):
    subs = set()
    data = get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
    try:
        for r in json.loads(data).get("passive_dns",[]):
            h = r.get("hostname","").lower()
            if h.endswith("."+domain) or h == domain: subs.add(h)
    except Exception:
        subs |= clean(data, domain)
    return "alienvault", subs

def src_virustotal(domain):
    """VirusTotal v3 public endpoint — v2 is deprecated/broken."""
    subs = set()
    data = get(f"https://www.virustotal.com/ui/domains/{domain}/subdomains?relationships=subdomains&cursor=&count=40", timeout=15)
    try:
        for item in json.loads(data).get("data", []):
            s = item.get("id","").lower()
            if s.endswith("."+domain) or s == domain: subs.add(s)
    except Exception:
        subs |= clean(data, domain)
    return "virustotal", subs

def src_urlscan(domain):
    subs = set()
    data = get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200", timeout=20)
    try:
        for r in json.loads(data).get("results",[]):
            for f in ["domain","hostname"]:
                h = (r.get("task",{}).get(f,"") or r.get("page",{}).get(f,"")).lower()
                if h.endswith("."+domain) or h == domain: subs.add(h)
    except Exception:
        subs |= clean(data, domain)
    return "urlscan", subs

def src_riddler(domain):
    return "riddler", clean(get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=15), domain)

def src_robtex(domain):
    subs = set()
    data = get(f"https://freeapi.robtex.com/pdns/forward/{domain}", timeout=15)
    try:
        for line in data.splitlines():
            obj = json.loads(line)
            s = obj.get("rrname","").lower().rstrip(".")
            if s.endswith("."+domain) or s == domain: subs.add(s)
    except Exception:
        subs |= clean(data, domain)
    return "robtex", subs

def src_wayback(domain):
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=20000")
    subs = set()
    for line in get(url, timeout=60).splitlines():
        m = re.search(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', line)
        if m: subs.add(m.group(1).lower())
    return "wayback", subs

def src_commoncrawl(domain):
    subs = set()
    try:
        indexes = json.loads(get("http://index.commoncrawl.org/collinfo.json", timeout=10))
        if indexes:
            api = indexes[0]["cdx-api"]
            data = get(f"{api}?url=*.{domain}&output=json&limit=3000&fl=url", timeout=30)
            for line in data.splitlines():
                try:
                    m = re.search(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', json.loads(line).get("url",""))
                    if m: subs.add(m.group(1).lower())
                except Exception: pass
    except Exception: pass
    return "commoncrawl", subs

def src_gau(domain):
    """gau extracts subdomains from Wayback, Common Crawl, AlienVault, URLScan."""
    subs = set()
    out = run_tool(["gau", "--subs", "--threads", "10", domain], timeout=60)
    for line in out.splitlines():
        m = re.search(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', line)
        if m: subs.add(m.group(1).lower())
    return "gau", subs

def src_subfinder(domain):
    subs = set()
    # Run with -all (all sources) + -recursive (finds sub-subdomains like a.b.domain.com)
    out = run_tool(["subfinder", "-d", domain, "-all", "-recursive", "-silent"], timeout=180)
    if not out.strip():
        # Retry once without -recursive if it failed
        out = run_tool(["subfinder", "-d", domain, "-all", "-silent"], timeout=120)
    for s in out.splitlines():
        s = s.strip().lower()
        if s.endswith("."+domain) or s == domain: subs.add(s)
    return "subfinder", subs

def src_amass(domain):
    subs = set()
    out = run_tool(["amass", "enum", "--passive", "-d", domain, "-nocolor"], timeout=180)
    for s in out.splitlines():
        s = s.strip().lower()
        if s.endswith("."+domain) or s == domain: subs.add(s)
    return "amass", subs

def src_assetfinder(domain):
    subs = set()
    out = run_tool(["assetfinder", "--subs-only", domain], timeout=60)
    for s in out.splitlines():
        s = s.strip().lower()
        if s.endswith("."+domain) or s == domain: subs.add(s)
    return "assetfinder", subs

def src_chaos(domain):
    """ProjectDiscovery Chaos — massive public DNS dataset."""
    subs = set()
    out = run_tool(["chaos", "-d", domain, "-silent"], timeout=60)
    for s in out.splitlines():
        s = s.strip().lower()
        if s.endswith("."+domain) or s == domain: subs.add(s)
    return "chaos", subs

def src_findomain(domain):
    subs = set()
    out = run_tool(["findomain", "--target", domain, "--quiet"], timeout=60)
    for s in out.splitlines():
        s = s.strip().lower()
        if s.endswith("."+domain) or s == domain: subs.add(s)
    return "findomain", subs

def src_theharvester(domain):
    """theHarvester with the free sources that actually work without API keys."""
    subs = set()
    free_sources = "baidu,bing,certspotter,crtsh,dnsdumpster,hackertarget,otx,rapiddns,urlscan,wayback"
    out = run_tool(["theHarvester", "-d", domain, "-b", free_sources, "-l", "200"], timeout=90)
    subs |= clean(out, domain)
    return "theHarvester", subs

def src_dns_records(domain):
    """Mine TXT/MX/NS/CAA/SOA records — SPF includes often reveal extra domains."""
    subs = set()
    for rtype in ["TXT", "MX", "NS", "CAA", "SOA", "CNAME"]:
        try:
            out = subprocess.run(["dig", "+short", rtype, domain],
                                 capture_output=True, text=True, timeout=10).stdout
            subs |= clean(out, domain)
        except Exception: pass
    return "dns_records", subs

def src_waybackurls(domain):
    subs = set()
    out = run_tool(["waybackurls", domain], timeout=60)
    for line in out.splitlines():
        m = re.search(r'https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', line)
        if m: subs.add(m.group(1).lower())
    return "waybackurls", subs

# ── v2 NEW SOURCES ────────────────────────────────────────────────────────────

def src_merklemap(domain):
    """100B+ CT rows, 0-second MMD, wildcards anywhere — not redundant with crt.sh."""
    subs = set()
    key = _KEYS.get("merklemap", "")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    for attempt in range(3):
        data = get(f"https://api.merklemap.com/search?query=*.{domain}&page=0",
                   headers=headers, timeout=30)
        if not data: time.sleep(5); continue
        try:
            for entry in json.loads(data).get("results", []):
                for n in entry.get("domains", []):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith("." + domain) or n == domain: subs.add(n)
            break
        except Exception: subs |= clean(data, domain); break
    return "merklemap", subs

def src_columbus(domain):
    """CT logs + opt-in public resolver — surfaces subdomains that never hit CT."""
    subs = set()
    for attempt in range(3):
        data = get(f"https://columbus.elmasy.com/api/lookup/{domain}", timeout=20)
        if not data: time.sleep(3); continue
        try:
            for s in json.loads(data):
                s = s.strip().lower().lstrip("*.")
                if s.endswith("." + domain) or s == domain: subs.add(s)
            break
        except Exception: subs |= clean(data, domain); break
    return "columbus", subs

def src_leakix(domain):
    """Independent leak-plugin crawler — not CT-based."""
    subs = set()
    key = _KEYS.get("leakix", "")
    headers = {"api-key": key} if key else {}
    data = get(f"https://leakix.net/api/subdomains/{domain}", headers=headers, timeout=20)
    try:
        for entry in json.loads(data):
            s = entry.get("subdomain", "").strip().lower().lstrip("*.")
            if s.endswith("." + domain) or s == domain: subs.add(s)
    except Exception: subs |= clean(data, domain)
    return "leakix", subs

def src_netlas(domain):
    """10-level subdomain depth, regex/fuzzy DSL — 50 req/day free."""
    subs = set()
    key = _KEYS.get("netlas", "")
    if not key: return "netlas", subs
    headers = {"X-API-Key": key}
    data = get(f"https://app.netlas.io/api/domains/?q=domain%3A*.{domain}"
               f"&source_type=include&start=0&fields=domain", headers=headers, timeout=20)
    try:
        for entry in json.loads(data).get("items", []):
            s = entry.get("data", {}).get("domain", "").strip().lower()
            if s.endswith("." + domain) or s == domain: subs.add(s)
    except Exception: subs |= clean(data, domain)
    return "netlas", subs

def src_hostio(domain):
    """Reverse-IP/NS/MX — finds sibling domains on same infra. 1000/mo free."""
    subs = set()
    token = _KEYS.get("hostio", "")
    if not token: return "host.io", subs
    data = get(f"https://host.io/api/domains/{domain}?token={token}", timeout=20)
    try:
        for s in json.loads(data).get("domains", []):
            s = s.strip().lower()
            if s.endswith("." + domain) or s == domain: subs.add(s)
    except Exception: subs |= clean(data, domain)
    return "host.io", subs

def src_c99(domain):
    """Cheapest commercial subdomain API, ~$5/mo."""
    subs = set()
    key = _KEYS.get("c99", "")
    if not key: return "c99", subs
    data = get(f"https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json",
               timeout=20)
    try:
        for entry in json.loads(data).get("subdomains", []):
            s = entry.get("subdomain", "").strip().lower()
            if s.endswith("." + domain) or s == domain: subs.add(s)
    except Exception: subs |= clean(data, domain)
    return "c99", subs

def src_uncover(domain):
    """Wraps 18 asset engines (Shodan, Censys, Fofa, Quake, Hunter, ZoomEye…).
    Identified as the single biggest gap in the 2024-2026 research report."""
    subs = set()
    uncover_bin = os.path.join(GOBIN, "uncover")
    if not os.path.isfile(uncover_bin): return "uncover", subs
    for q in [f"ssl:{domain}", f"hostname:{domain}", f"domain:{domain}"]:
        out = run_tool([uncover_bin, "-q", q, "-silent",
                        "-field", "host", "-limit", "500"], timeout=60)
        for line in out.splitlines():
            line = line.strip().lower().split(":")[0]
            if line.endswith("." + domain) or line == domain: subs.add(line)
    return "uncover", subs

def src_asnmap(domain):
    """ASN→CIDR→PTR via mapcidr+dnsx — finds hosts with no forward DNS entry."""
    subs = set()
    asnmap_bin = os.path.join(GOBIN, "asnmap")
    if not os.path.isfile(asnmap_bin): return "asnmap", subs
    out = run_tool([asnmap_bin, "-d", domain, "-silent"], timeout=30)
    cidrs = [l.strip() for l in out.splitlines() if "/" in l.strip()][:5]
    if not cidrs: return "asnmap", subs
    mapcidr_bin = os.path.join(GOBIN, "mapcidr")
    dnsx_bin = os.path.join(GOBIN, "dnsx")
    if os.path.isfile(mapcidr_bin) and os.path.isfile(dnsx_bin):
        import tempfile
        # delete=False + manual unlink in finally — we need the file path to
        # outlive the `with` block (handed to subprocess), but must clean up so
        # /tmp doesn't accumulate one file per run.
        tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        try:
            tmp_f.write("\n".join(cidrs))
            tmp_f.close()
            # Pipe via subprocess instead of `sh -c f"…"` — avoids interpolating
            # file paths into a shell command.
            with open(tmp_f.name) as src:
                mc = subprocess.Popen([mapcidr_bin, "-silent"], stdin=src,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                dx = subprocess.Popen([dnsx_bin, "-ptr", "-resp-only", "-silent", "-t", "250"],
                                      stdin=mc.stdout, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
                mc.stdout.close()
                try:
                    ptr, _ = dx.communicate(timeout=120)
                except subprocess.TimeoutExpired:
                    dx.kill(); mc.kill(); ptr = ""
            for line in (ptr or "").splitlines():
                line = line.strip().lower().rstrip(".")
                if line.endswith("." + domain) or line == domain: subs.add(line)
        finally:
            try: os.unlink(tmp_f.name)
            except OSError: pass
    return "asnmap", subs

# ── Ordered source list ───────────────────────────────────────────────────────
# Removed (redundant/dead):
#   src_waybackurls  — src_wayback queries CDX directly with higher limit
#   src_commoncrawl  — gau queries Common Crawl internally
#   src_urlscan      — gau queries URLScan internally
#   src_riddler      — consistently unavailable since 2023
#   src_threatcrowd  — service down/unreliable since late 2023
ALL_SOURCES = [
    # CT logs. NOTE: subfinder -all -recursive (below) ALREADY queries crt.sh,
    # certspotter, hackertarget, rapiddns, bufferover, anubis(jldc) and
    # threatminer internally — running them again here is redundant work and
    # extra crt.sh hits (→ self-inflicted rate-limiting). Keep crt.sh (primary,
    # deeper recursion) + robtex (distinct passive DNS); drop the rest.
    src_crtsh,
    # CT / passive — v2 additions
    src_merklemap, src_columbus, src_leakix,
    # Free passive DNS not well-covered by subfinder
    src_robtex,
    # Paid/key APIs — v2 (degrade gracefully without keys)
    src_netlas, src_hostio, src_c99,
    # Threat intel (v1)
    src_alienvault, src_virustotal,
    # Web archives (v1)
    src_wayback, src_gau,
    # Multi-engine pivot — v2
    src_uncover,
    # Tools (v1)
    src_subfinder, src_amass, src_assetfinder, src_chaos,
    src_findomain, src_theharvester,
    # DNS + ASN (v1 + v2)
    src_dns_records, src_asnmap,
]

def enumerate_domain(domain):
    domain = domain.strip().lower()
    all_subs = set()
    zero_sources = []
    print(f"\n[*] Passive enum: {domain}", flush=True)

    # Filter out sources whose required API key is missing. Without this,
    # they'd waste a worker slot making an HTTP call destined to return 401
    # or empty, and clutter the log with "Zero results from: …". Skipping
    # them up-front is faster AND clearer.
    sources = []
    skipped = []
    for src in ALL_SOURCES:
        if src.__name__ in _KEY_REQUIRED_SOURCES:
            key_name, hint = _KEY_REQUIRED_SOURCES[src.__name__]
            if not _KEYS.get(key_name):
                skipped.append((key_name, hint))
                continue
        sources.append(src)
    if skipped:
        # Print the missing-key notice ONCE per domain (small log spam).
        # Future improvement: hoist to main() so the notice prints once total.
        for key_name, hint in skipped:
            print(f"  [skip] {key_name:22s} no API key (get one: {hint})",
                  flush=True)

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(src, domain): src.__name__ for src in sources}
        for future in as_completed(futures):
            src_name = futures[future]
            try:
                name, subs = future.result(timeout=200)
                if subs:
                    print(f"  [+] {name:22s}: {len(subs)}", flush=True)
                    all_subs |= subs
                else:
                    zero_sources.append(name)
            except Exception as e:
                zero_sources.append(src_name)

    # Retry critical sources that returned 0 — they may have 502'd or rate-limited.
    # These three sources alone account for 60-80% of all passive results.
    # A single retry after 5s catches most transient failures.
    CRITICAL_NAMES = {"src_crtsh", "src_subfinder", "src_alienvault",
                      "src_wayback", "src_hackertarget"}
    retry = [s for s in sources if s.__name__ in CRITICAL_NAMES
             and s.__name__ in zero_sources]
    if retry:
        print(f"  [!] Retrying {len(retry)} critical sources after 5s...", flush=True)
        time.sleep(5)
        with ThreadPoolExecutor(max_workers=len(retry)) as pool:
            futures = {pool.submit(src, domain): src.__name__ for src in retry}
            for future in as_completed(futures):
                try:
                    name, subs = future.result(timeout=200)
                    if subs:
                        print(f"  [+] {name:22s}: {len(subs)} (retry)", flush=True)
                        all_subs |= subs
                except Exception:
                    pass

    if zero_sources:
        print(f"  [-] Zero results from: {', '.join(zero_sources[:8])}", flush=True)

    print(f"  [=] {domain}: {len(all_subs)} unique subdomains", flush=True)

    if len(all_subs) < 10:
        print(f"  [!] WARNING: Very few results for {domain}", flush=True)

    return domain, all_subs, {}

def main():
    global _KEYS
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--keys", default="", help="Path to api_keys.yaml (optional)")
    args = parser.parse_args()
    _KEYS = _load_keys(args.keys or None)

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if not domains:
        print("[!] No domains provided to --domains", file=sys.stderr)
        open(args.output, "w").close()
        sys.exit(1)
    all_results = {}

    # Run domains in parallel, but CAP the outer pool. Each domain itself fans out
    # to ~14 source threads, so an uncapped outer pool (one thread per domain) means
    # a 50-root org would spawn ~700 threads + hundreds of subprocesses at once.
    outer_workers = max(1, min(len(domains), 8))
    print(f"[*] Enumerating {len(domains)} domains ({outer_workers} in parallel)...", flush=True)
    with ThreadPoolExecutor(max_workers=outer_workers) as pool:
        futures = {pool.submit(enumerate_domain, d): d for d in domains}
        for future in as_completed(futures):
            try:
                domain, subs, _ = future.result(timeout=300)
                all_results[domain] = subs
            except Exception as e:
                print(f"[!] {futures[future]}: {e}", flush=True)
                all_results[futures[future]] = set()

    with open(args.output, "w") as f:
        for domain in domains:  # preserve input order
            subs = all_results.get(domain, set())
            f.write(f"# === {domain} ({len(subs)}) ===\n")
            for s in sorted(subs): f.write(s + "\n")
            f.write("\n")

    total = sum(len(v) for v in all_results.values())
    print(f"\n[+] Total: {total} across {len(domains)} domains → {args.output}")
    # Per-domain summary
    for d in domains:
        print(f"    {d:<45} {len(all_results.get(d, set()))}")

if __name__ == "__main__":
    main()
