#!/usr/bin/env python3
"""
advanced_techniques.py — All advanced subdomain discovery techniques (v1 + v2 merged).

v1 techniques (15):
  1. HTTP Header Mining (CSP/CORS)        9.  NSEC zone walking
  2. robots.txt + sitemap crawl          10.  Google CT Transparency
  3. SPF/DKIM/DMARC chain walk           11.  ESP DKIM discovery
  4. JavaScript analysis                 12.  Google Analytics reverse
  5. TLS SAN pivot                       13.  Reverse IP lookup
  6. Certificate org-name match         14.  CNAME takeover detection
  7. Cloud bucket probe                  15.  ASN → IP range → PTR scan
  8. Reverse WHOIS

v2 techniques added (10) — from 2024-2026 gap analysis:
 16. Favicon hash pivot (MurmurHash3 → Shodan/uncover)
 17. .well-known enum (apple-app-site-association, assetlinks.json)
 18. Source map extraction (reconstructs frontend tree)
 19. Azure tenant enum + SaaS subdomain patterns
 20. Postman public workspace search
 21. BBOT runner (finds 20-50% more per README)
 22. Katana JS crawler (-jc -jsl -xhr -f fqdn)
 23. subwiz ML prediction (+10.4% new subdomains per Hadrian 2025)
 24. BadDNS takeover check (auto-syncs Nuclei+dnsReaper signatures)
 25. JARM fingerprint pivot

Usage:
  python3 advanced_techniques.py --domain target.com --org "Acme Corp" \\
      --output /tmp/advanced.txt [--probe-ips 1.2.3.4] [--known-subs /tmp/known.txt]
"""

import argparse, json, os, re, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Bound every raw socket operation (gethostbyname/getaddrinfo/gethostbyaddr).
# Without this a single unresponsive DNS server can hang a worker thread, which
# blocks pool shutdown and stalls the whole backgrounded run.
socket.setdefaulttimeout(8)

try:
    import requests as _req
    def get(url, headers=None, timeout=15, allow_redirects=True, verify=True):
        h = {"User-Agent": "Mozilla/5.0 (compatible; recon-bot/1.0)"}
        if headers: h.update(headers)
        try:
            r = _req.get(url, headers=h, timeout=timeout,
                         allow_redirects=allow_redirects, verify=verify)
            return r.text, r.headers, r.status_code
        except Exception:
            return "", {}, 0
    def get_text(url, **kw): return get(url, **kw)[0]
except ImportError:
    from urllib.request import urlopen, Request
    def get(url, headers=None, timeout=15, **kw):
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0", **(headers or {})})
            with urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", errors="ignore")
                return text, dict(r.headers), r.status
        except Exception:
            return "", {}, 0
    def get_text(url, **kw): return get(url, **kw)[0]

def extract_domains(text, domain):
    pat = r'(?:[a-zA-Z0-9_-]+\.)+' + re.escape(domain)
    subs = set()
    for s in re.findall(pat, text, re.IGNORECASE):
        s = s.lower().lstrip("*.")
        if s.endswith("." + domain) or s == domain: subs.add(s)
    return subs

def _dns_txt(name):
    try:
        out = subprocess.run(["dig", "+short", "TXT", name],
                             capture_output=True, text=True, timeout=8).stdout
        return out
    except Exception: return ""

# ── 1. HTTP Header Mining ────────────────────────────────────────────────────

def http_header_mining(domain):
    """Fetch headers from www + apex, extract subdomains from CSP/CORS/HSTS."""
    subs = set()
    probed = set()

    for target in [f"https://{domain}", f"https://www.{domain}",
                   f"http://{domain}", f"http://www.{domain}"]:
        _, headers, status = get(target, timeout=12)
        if not headers: continue

        header_text = " ".join(f"{k}: {v}" for k, v in headers.items())

        # CSP header — goldmine for subdomains
        for csp_key in ["Content-Security-Policy", "X-Content-Security-Policy",
                         "X-Webkit-CSP", "content-security-policy"]:
            csp = headers.get(csp_key, "")
            subs |= extract_domains(csp, domain)

        # CORS allowed origins
        cors = headers.get("Access-Control-Allow-Origin", "") or headers.get("access-control-allow-origin", "")
        subs |= extract_domains(cors, domain)

        # Set-Cookie domain attribute
        for ck in headers.get("Set-Cookie", "").split(";"):
            if "domain=" in ck.lower():
                ck_domain = re.search(r'domain=([^\s;,]+)', ck, re.IGNORECASE)
                if ck_domain:
                    d = ck_domain.group(1).strip().lstrip(".")
                    if d.endswith(domain): subs.add(d.lower())

        # Location redirects
        loc = headers.get("Location","") or headers.get("location","")
        subs |= extract_domains(loc, domain)

        # HSTS includeSubDomains just confirms wildcard — note it but don't add subs
        # X-Frame-Options, Referrer-Policy may also have domain refs
        subs |= extract_domains(header_text, domain)

    print(f"  [+] http_headers: {len(subs)} found", flush=True)
    return "http_headers", subs

# ── 2. robots.txt + sitemap.xml ──────────────────────────────────────────────

def robots_and_sitemap(domain):
    subs = set()
    base = f"https://{domain}"

    # robots.txt
    robots = get_text(f"{base}/robots.txt", timeout=10)
    subs |= extract_domains(robots, domain)

    # Extract sitemap URLs from robots.txt
    sitemap_urls = re.findall(r'Sitemap:\s*(https?://[^\s]+)', robots, re.IGNORECASE)
    sitemap_urls += [
        f"{base}/sitemap.xml", f"{base}/sitemap_index.xml",
        f"{base}/sitemap-index.xml", f"{base}/sitemaps.xml",
        f"{base}/news-sitemap.xml",
    ]

    visited = set()
    def crawl_sitemap(url, depth=0):
        if url in visited or depth > 3: return
        visited.add(url)
        data = get_text(url, timeout=10)
        subs |= extract_domains(data, domain)
        # Follow sub-sitemaps
        for nested in re.findall(r'<loc>\s*(https?://[^\s<]+sitemap[^\s<]*)\s*</loc>', data):
            crawl_sitemap(nested, depth + 1)

    for url in sitemap_urls[:10]:
        crawl_sitemap(url)

    print(f"  [+] robots+sitemap: {len(subs)} found", flush=True)
    return "robots_sitemap", subs

# ── 3. SPF Deep Parsing ───────────────────────────────────────────────────────

def spf_deep_parse(domain):
    """Follow SPF include: chains recursively → find all referenced domains."""
    subs = set()
    new_domains = set()
    visited = set()

    def parse_spf(d, depth=0):
        if d in visited or depth > 5: return
        visited.add(d)
        txt = _dns_txt(d)
        subs |= extract_domains(txt, domain)
        for inc in re.findall(r'include:([a-zA-Z0-9._-]+)', txt):
            new_domains.add(inc)
            parse_spf(inc, depth + 1)
        for redirect in re.findall(r'redirect=([a-zA-Z0-9._-]+)', txt):
            parse_spf(redirect, depth + 1)

    parse_spf(domain)

    # Also parse DMARC
    dmarc = _dns_txt(f"_dmarc.{domain}")
    subs |= extract_domains(dmarc, domain)
    for d in re.findall(r'rua=mailto:[^@]+@([a-zA-Z0-9._-]+)', dmarc):
        if domain in d: subs.add(d)

    # DKIM selector probing — expand beyond 7 common selectors
    for selector in ["default", "google", "mail", "mail2", "dkim", "k1", "k2",
                     "smtp", "email", "s1", "s2", "sg", "mg", "pm", "nc",
                     "selector1", "selector2", "mimecast"]:
        dkim = _dns_txt(f"{selector}._domainkey.{domain}")
        subs |= extract_domains(dkim, domain)

    # Use ESP domains discovered in SPF chain to generate targeted subdomain patterns.
    # e.g. if SPF includes netcorecloud.net → try email-nc.<domain>
    # This is the connection between "who sends email" and "what subdomains they use".
    ESP_DOMAIN_TO_PATTERNS = {
        "netcore":      [f"email-nc.{domain}", f"emails.{domain}", f"nc.{domain}"],
        "sendgrid":     [f"email-sg.{domain}", f"email.{domain}", f"em.{domain}",
                         f"em1.{domain}", f"em2.{domain}", f"em3.{domain}"],
        "mailgun":      [f"email-mg.{domain}", f"email.{domain}", f"mg.{domain}"],
        "postmark":     [f"email-pm.{domain}", f"pm.{domain}", f"bounce.{domain}"],
        "sparkpost":    [f"email-sp.{domain}", f"sp.{domain}", f"links.{domain}"],
        "freshemail":   [f"email-fe.{domain}", f"email.{domain}"],
        "salesforce":   [f"email-sf.{domain}", f"et.{domain}"],
        "amazonses":    [f"email-aws.{domain}", f"email-ses.{domain}"],
        "mailjet":      [f"email-mj.{domain}", f"mj.{domain}"],
        "sendinblue":   [f"email-sb.{domain}", f"sb.{domain}"],
    }
    for esp_domain, patterns in ESP_DOMAIN_TO_PATTERNS.items():
        if any(esp_domain in nd for nd in new_domains):
            for p in patterns:
                try:
                    socket.getaddrinfo(p, None, proto=socket.IPPROTO_TCP)
                    subs.add(p.lower())
                except (socket.gaierror, OSError):
                    pass

    print(f"  [+] spf_dmarc_dkim: {len(subs)} found (+ {len(new_domains)} 3rd-party ESP domains)", flush=True)
    return "spf_dmarc_dkim", subs

# ── 4. Cloud Bucket Probing ───────────────────────────────────────────────────

def cloud_bucket_probe(domain, org_name):
    """Check for org-named S3/GCS/Azure buckets. Returns accessible bucket URLs."""
    org_slug = re.sub(r'[^a-z0-9-]', '-', org_name.lower()).strip('-')
    root = domain.split('.')[0]  # e.g. "acme" from "acme.com"

    patterns = set()
    for base in [root, org_slug]:
        for suffix in ["", "-dev", "-staging", "-prod", "-test", "-backup",
                        "-assets", "-static", "-media", "-uploads", "-data",
                        "-cdn", "-logs", "-archive", "-public", "-private"]:
            patterns.add(f"{base}{suffix}")

    found = set()

    def check_s3(name):
        for region in ["", ".s3.", ".s3-us-east-1.", ".s3-us-west-2.", ".s3-ap-south-1.",
                        ".s3-eu-west-1.", ".s3.ap-southeast-1.", ".s3.ap-south-1."]:
            if region:
                url = f"https://{name}{region}amazonaws.com"
            else:
                url = f"https://{name}.s3.amazonaws.com"
            _, _, status = get(url, timeout=5, verify=False)
            if status in [200, 403]:  # 403 means bucket exists but restricted
                found.add(f"[S3-BUCKET] {url} (HTTP {status})")
                return

    def check_gcs(name):
        url = f"https://storage.googleapis.com/{name}"
        _, _, status = get(url, timeout=5)
        if status in [200, 403]:
            found.add(f"[GCS-BUCKET] {url} (HTTP {status})")

    def check_azure(name):
        for suffix in [".blob.core.windows.net", ".azureedge.net", ".azurewebsites.net"]:
            url = f"https://{name}{suffix}"
            _, _, status = get(url, timeout=5)
            if status in [200, 403, 400]:
                found.add(f"[AZURE] {url} (HTTP {status})")

    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = []
        for p in list(patterns)[:40]:  # cap at 40 patterns
            futs.append(pool.submit(check_s3, p))
            futs.append(pool.submit(check_gcs, p))
            futs.append(pool.submit(check_azure, p))
        for f in as_completed(futs): f.result()

    print(f"  [+] cloud_buckets: {len(found)} accessible/existing", flush=True)
    return "cloud_buckets", found  # returns URLs not subdomains

# ── 5. JavaScript Analysis ───────────────────────────────────────────────────

def js_analysis(domain):
    """Fetch homepage JS files, extract hardcoded subdomains."""
    subs = set()
    base = f"https://{domain}"

    html, _, _ = get(base, timeout=12)
    js_urls = set()

    # Inline JS
    subs |= extract_domains(html, domain)

    # External JS files
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        if not src.startswith("http"):
            src = base + "/" + src.lstrip("/")
        if domain in src or src.startswith("/") or src.startswith(base):
            js_urls.add(src)

    # Also check common JS paths
    for path in ["/app.js", "/main.js", "/bundle.js", "/webpack.js", "/vendor.js",
                 "/static/js/main.chunk.js", "/assets/index.js"]:
        js_urls.add(base + path)

    for url in list(js_urls)[:20]:
        try:
            content = get_text(url, timeout=10)
            subs |= extract_domains(content, domain)
            # Find API endpoint patterns
            for match in re.findall(r'["\']https?://([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')["\'/]', content):
                subs.add(match.lower())
        except Exception: pass

    print(f"  [+] js_analysis: {len(subs)} found", flush=True)
    return "js_analysis", subs

# ── 6. Reverse WHOIS ─────────────────────────────────────────────────────────

def reverse_whois(domain):
    """whoxy.com free reverse WHOIS — find all domains by same registrant email."""
    subs = set()
    new_domains = set()
    try:
        # Get registrant email from WHOIS
        whois_out = subprocess.run(["whois", domain],
                                   capture_output=True, text=True, timeout=10).stdout
        emails = re.findall(r'[\w.-]+@[\w.-]+\.\w+', whois_out)
        # Filter for org-related emails
        org_emails = [e for e in emails if any(x in e.lower() for x in [domain.split('.')[0], 'registrant'])]

        for email in org_emails[:3]:
            data = get_text(f"https://www.whoxy.com/whois-history/domains-by-email/{email}")
            found = re.findall(r'([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', data)
            for d in found:
                if domain.split('.')[0].lower() in d.lower():
                    new_domains.add(d.lower())
    except Exception: pass

    print(f"  [+] reverse_whois: {len(new_domains)} related domains found", flush=True)
    return "reverse_whois", new_domains  # returns root domains, not subdomains

# ── 7. TLS SAN Pivot ─────────────────────────────────────────────────────────

def tls_san_pivot(domain, ips=None):
    """Get TLS cert from known IPs/domain, extract all SANs."""
    subs = set()
    targets = list(ips or [])
    # Always try the domain itself
    targets.insert(0, domain)

    for target in targets[:10]:
        try:
            out = subprocess.run(
                ["openssl", "s_client", "-connect", f"{target}:443", "-servername", domain,
                 "-showcerts"],
                input=b"", capture_output=True, timeout=8
            ).stdout.decode("utf-8", errors="ignore")
            subs |= extract_domains(out, domain)
            # Extract all SANs
            for san in re.findall(r'DNS:([a-zA-Z0-9._*-]+)', out):
                san = san.lstrip("*.").lower()
                if san.endswith("."+domain) or san == domain: subs.add(san)
        except Exception: pass

    # Also use tlsx if available
    gobin = os.path.expanduser("~/.recon-tools/bin")
    for tlsx_path in [gobin + "/tlsx", "tlsx"]:
        try:
            out = subprocess.run([tlsx_path, "-host", domain, "-san", "-silent"],
                                 capture_output=True, text=True, timeout=20).stdout
            subs |= extract_domains(out, domain)
            break
        except FileNotFoundError: continue

    print(f"  [+] tls_san_pivot: {len(subs)} found", flush=True)
    return "tls_san", subs

# ── 8. Certificate Org Match (crt.sh by org name) ────────────────────────────

def cert_org_match(domain, org_name):
    """Search crt.sh by organization name — finds certs not indexed under the domain."""
    subs = set()
    for org_query in [org_name, org_name.replace(" ", "%20"), org_name.lower()]:
        try:
            import urllib.parse
            url = f"https://crt.sh/?q={urllib.parse.quote(org_query)}&output=json"
            data = get_text(url, timeout=30)
            for e in json.loads(data):
                for n in e.get("name_value","").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith("."+domain) or n == domain: subs.add(n)
        except Exception: pass

    print(f"  [+] cert_org_match: {len(subs)} found", flush=True)
    return "cert_org_match", subs

# ── 9. NSEC Zone Walking ─────────────────────────────────────────────────────

def nsec_walk(domain):
    """Attempt DNSSEC NSEC record walking to enumerate all names in zone."""
    subs = set()
    try:
        # Check if DNSSEC is enabled
        check = subprocess.run(["dig", "+short", "DNSKEY", domain],
                                capture_output=True, text=True, timeout=8).stdout
        if not check.strip(): return "nsec_walk", subs

        # Walk NSEC records
        current = domain
        visited = set()
        for _ in range(200):  # cap iterations
            if current in visited: break
            visited.add(current)
            out = subprocess.run(["dig", "+short", "NSEC", current],
                                 capture_output=True, text=True, timeout=5).stdout
            if not out.strip(): break
            # First field is the next domain in zone
            next_name = out.split()[0].rstrip(".").lower() if out.split() else ""
            if not next_name or next_name == domain: break
            if next_name.endswith("."+domain): subs.add(next_name)
            current = next_name
    except Exception: pass

    print(f"  [+] nsec_walk: {len(subs)} found", flush=True)
    return "nsec_walk", subs

# ── 10. Google Transparency Report ───────────────────────────────────────────

def google_transparency(domain):
    """Query Google's CT transparency report for certs."""
    subs = set()
    url = f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=true&domain={domain}"
    data = get_text(url, timeout=20)
    subs |= extract_domains(data, domain)
    print(f"  [+] google_transparency: {len(subs)} found", flush=True)
    return "google_transparency", subs


# ── 11. Google Analytics ID reverse lookup ───────────────────────────────────

def google_analytics_reverse(domain):
    """
    Find all domains sharing the same Google Analytics tracking ID.

    Organisations use the same GA property (UA-XXXXXXX or G-XXXXXXX) across
    all their subdomains AND sometimes across acquired/sister domains.
    Reverse-searching that ID reveals related domains the org owns.

    Sources: HackerTarget Reverse Analytics (free), osint.sh (free).
    """
    subs = set()
    new_domains = set()

    # Step 1: Extract GA ID from the homepage
    html = get_text(f"https://{domain}", timeout=12)
    if not html:
        html = get_text(f"http://{domain}", timeout=12)

    ga_ids = set(re.findall(r'(?:UA-\d+-\d+|G-[A-Z0-9]{8,})', html))
    if not ga_ids:
        print(f"  [+] ga_reverse: no GA ID found on {domain}", flush=True)
        return "ga_reverse", subs

    for ga_id in list(ga_ids)[:3]:
        # HackerTarget reverse analytics (free, no key)
        data = get_text(f"https://api.hackertarget.com/reverseanalytics/?q={ga_id}", timeout=15)
        if data and "API count" not in data:
            for line in data.splitlines():
                line = line.strip().lower()
                if "." in line:
                    if line.endswith("." + domain) or line == domain:
                        subs.add(line)
                    else:
                        new_domains.add(line)

        # osint.sh reverse analytics
        data2 = get_text(f"https://osint.sh/analytics/?q={ga_id}", timeout=15)
        subs |= extract_domains(data2, domain)

    if new_domains:
        print(f"  [+] ga_reverse: GA IDs found: {ga_ids} → {len(new_domains)} related domains", flush=True)
    print(f"  [+] ga_reverse: {len(subs)} subdomains + {len(new_domains)} related domains", flush=True)
    return "ga_reverse", subs


# ── 12. Reverse IP lookup ─────────────────────────────────────────────────────

def reverse_ip_lookup(domain):
    """
    Find other domains/subdomains hosted on the same IP address.

    Useful for shared hosting and multi-tenant CDN environments where an org
    runs several subdomains on one IP. HackerTarget provides this free.
    """
    subs = set()
    try:
        ip = socket.gethostbyname(domain)
        data = get_text(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
        if data and "API count" not in data:
            for line in data.splitlines():
                line = line.strip().lower()
                if line.endswith("." + domain) or line == domain:
                    subs.add(line)
    except Exception:
        pass
    print(f"  [+] reverse_ip: {len(subs)} found", flush=True)
    return "reverse_ip", subs


# ── 13. CNAME → Subdomain takeover detection ─────────────────────────────────

def cname_takeover_check(domain):
    """
    Check all subdomains for dangling CNAMEs pointing to unclaimed services.

    A CNAME pointing to a deprovisioned S3 bucket, GitHub Pages, Heroku app,
    Azure site etc. is claimable by anyone → subdomain takeover.
    We flag these as cloud_findings (not subdomains).

    Sources: nuclei (if available), manual CNAME dig check.
    """
    vulnerable = set()

    # Services whose NXDOMAIN/specific response patterns indicate takeover potential
    TAKEOVER_SIGNATURES = {
        "s3.amazonaws.com":              "NoSuchBucket",
        "github.io":                     "There isn't a GitHub Pages site here",
        "herokuapp.com":                 "No such app",
        "azurewebsites.net":             "404 Web Site not found",
        "cloudapp.net":                  "404",
        "trafficmanager.net":            "404",
        "ghostio.ghost.io":              "The thing you were looking for is no longer here",
        "myshopify.com":                 "Sorry, this shop is currently unavailable",
        "zendesk.com":                   "Help Center Closed",
        "desk.com":                      "Sorry, We Couldn't Find That Page",
        "helpjuice.com":                 "We could not find what you're looking for",
        "helpscoutdocs.com":             "No settings were found",
        "cargo.site":                    "404",
        "bitbucket.io":                  "Repository not found",
        "launchrock.com":                "It looks like you may have taken a wrong turn",
        "surge.sh":                      "project not found",
        "readme.io":                     "Project doesnt exist",
    }

    # Get known subdomains from a quick crt.sh query
    import urllib.parse as _up
    try:
        data = get_text(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        known = set()
        for e in json.loads(data):
            for n in e.get("name_value","").split("\n"):
                n = n.strip().lstrip("*.")
                if n.endswith("."+domain): known.add(n)
    except Exception:
        known = set()

    for sub in list(known)[:200]:  # cap at 200 to keep it fast
        try:
            cname_out = subprocess.run(
                ["dig", "+short", "CNAME", sub, "+time=3", "+tries=1"],
                capture_output=True, text=True, timeout=5
            ).stdout.strip().rstrip(".")
            if not cname_out:
                continue
            for svc, sig in TAKEOVER_SIGNATURES.items():
                if svc in cname_out:
                    # Check if the CNAME target actually returns the takeover signature
                    content = get_text(f"https://{sub}", timeout=5)
                    if not content:
                        content = get_text(f"http://{sub}", timeout=5)
                    if sig.lower() in content.lower():
                        vulnerable.add(f"[TAKEOVER-RISK] {sub} → CNAME {cname_out} ({svc})")
        except Exception:
            pass

    if vulnerable:
        print(f"  [!] cname_takeover: {len(vulnerable)} POTENTIAL TAKEOVERS FOUND", flush=True)
        for v in sorted(vulnerable):
            print(f"      {v}", flush=True)
    else:
        print(f"  [+] cname_takeover: no obvious takeover risks found", flush=True)

    return "cname_takeover", vulnerable  # returns findings, not subdomains


# ── 14. ASN-based subdomain discovery ────────────────────────────────────────

def asn_ptr_discovery(domain, org_name):
    """
    Find subdomains via ASN → IP range → PTR (reverse DNS) scan.

    How it works:
    1. Look up the org's ASN from bgp.he.net or whois
    2. Get all IP prefixes the org announces
    3. Do PTR reverse DNS on each IP → returns hostnames
    4. Filter to hostnames ending in the target domain

    Finds subdomains INVISIBLE to all passive sources because they may never
    have had a forward DNS entry or SSL cert indexed anywhere.
    """
    subs = set()
    org_slug = re.sub(r'[^a-z0-9]', '', org_name.lower())[:10]

    try:
        # Try to get ASN from bgp.he.net (plain text query)
        asn_data = get_text(f"https://bgp.he.net/dns/{domain}", timeout=10)
        asns = re.findall(r'AS(\d+)', asn_data)

        if not asns:
            # Fallback: whois
            try:
                whois_out = subprocess.run(
                    ["whois", "-h", "whois.cymru.com", f" -v {socket.gethostbyname(domain)}"],
                    capture_output=True, text=True, timeout=10
                ).stdout
                asns = re.findall(r'\|\s*(\d+)\s*\|', whois_out)
            except Exception:
                pass

        if not asns:
            print(f"  [+] asn_ptr: no ASN found for {domain}", flush=True)
            return "asn_ptr", subs

        # For each ASN get IP prefixes (limit to first 3 ASNs, max 5 prefixes each)
        ip_ranges = []
        for asn in asns[:3]:
            prefix_data = get_text(f"https://bgp.he.net/AS{asn}#_prefixes", timeout=10)
            prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', prefix_data)
            ip_ranges.extend(prefixes[:5])  # cap: 5 prefixes per ASN = max 15 ranges

        if not ip_ranges:
            print(f"  [+] asn_ptr: no IP ranges found for ASN(s) {asns[:3]}", flush=True)
            return "asn_ptr", subs

        # PTR scan each range using dnsx if available
        GOBIN = os.path.expanduser("~/.recon-tools/bin")
        dnsx_bin = os.path.join(GOBIN, "dnsx")
        mapcidr_bin = os.path.join(GOBIN, "mapcidr")

        if os.path.isfile(dnsx_bin) and os.path.isfile(mapcidr_bin):
            # Use NamedTemporaryFile so concurrent runs (parallel domains) don't
            # clobber each other's /tmp/asn_ranges_<domain>.txt, and so the file
            # is unlinked in finally even on early exit. The previous version
            # also passed `domain` through shell=True, which made the command
            # injectable via any shell metachar in --domain.
            import tempfile
            tmp_f = tempfile.NamedTemporaryFile(mode='w', prefix=f'asn_ranges_', suffix='.txt', delete=False)
            try:
                tmp_f.write("\n".join(ip_ranges[:10]))  # max 10 ranges
                tmp_f.close()
                with open(tmp_f.name) as src:
                    mc = subprocess.Popen([mapcidr_bin, "-silent"], stdin=src,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    dx = subprocess.Popen([dnsx_bin, "-ptr", "-resp-only", "-silent", "-t", "250"],
                                          stdin=mc.stdout, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, text=True)
                    mc.stdout.close()
                    try:
                        ptr_result, _ = dx.communicate(timeout=120)
                    except subprocess.TimeoutExpired:
                        dx.kill(); mc.kill(); ptr_result = ""
                for line in (ptr_result or "").splitlines():
                    line = line.strip().lower().rstrip(".")
                    if line.endswith("." + domain) or line == domain:
                        subs.add(line)
            finally:
                try: os.unlink(tmp_f.name)
                except OSError: pass
        else:
            # Fallback: manual PTR for first 256 IPs of first range
            first_range = ip_ranges[0] if ip_ranges else None
            if first_range and "/" in first_range:
                base_ip = first_range.split("/")[0]
                parts = base_ip.split(".")
                if len(parts) == 4:
                    for last in range(1, 255):
                        ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{last}"
                        try:
                            hostname = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
                            if hostname.endswith("." + domain) or hostname == domain:
                                subs.add(hostname)
                        except Exception:
                            pass

    except Exception as e:
        pass

    print(f"  [+] asn_ptr: {len(subs)} subdomains from PTR scan", flush=True)
    return "asn_ptr", subs


def esp_dkim_discovery(domain):
    """
    Email Service Provider infrastructure discovery.

    WHY THIS EXISTS:
    Subdomains like email-nc.acme.com (Netcore Cloud) are INVISIBLE to
    all passive sources because:
    - They have no SSL cert under the parent domain (cert is *.netcorecloud.net)
    - They're never crawled by Wayback/GAU (not web-facing URLs)
    - They resolve to CGNAT/private IPs (100.64.x.x range)
    - The vendor abbreviation ('nc' = Netcore) is not in standard wordlists

    This technique:
    1. Probes known DKIM selectors for common ESPs
       (DKIM selectors are discoverable because they're TXT records at
        <selector>._domainkey.<domain>)
    2. From found DKIM selectors, infers which ESP is used
    3. Generates and resolves ESP-specific tracking subdomains

    Common ESP patterns: email-nc (Netcore), email-sg (SendGrid),
    em1-em9 (SendGrid), email-mg (Mailgun), email-pm (Postmark)
    """
    subs = set()

    # DKIM selectors by ESP — discovering these reveals which ESP is in use
    DKIM_SELECTORS = {
        "netcore":    ["netcore", "nc", "ncemail", "ncmail"],
        "sendgrid":   ["s1", "s2", "sg", "sendgrid", "smtpapi"],
        "mailgun":    ["mg", "mailgun", "k1", "k2"],
        "postmark":   ["pm", "postmark", "k1"],
        "sparkpost":  ["sp", "sparkpost", "s1"],
        "mailjet":    ["mailjet", "mj", "s1", "s2"],
        "sendinblue": ["sendinblue", "sb", "mail"],
        "ses":        ["amazonses", "ses"],
        "freshworks": ["freshemail", "fdemail", "freshworks"],
        "salesforce": ["salesforce", "sfmc", "exacttarget"],
        "hubspot":    ["hubspot", "hs"],
        "marketo":    ["marketo", "mkt"],
        "klaviyo":    ["klaviyo", "k1"],
        "generic":    ["default", "mail", "email", "dkim", "key1", "key2"],
    }

    # ESP → typical tracking subdomain patterns
    ESP_SUBDOMAINS = {
        "netcore":    [f"email-nc.{domain}", f"track-nc.{domain}",
                       f"click-nc.{domain}", f"nc.{domain}"],
        "sendgrid":   [f"email-sg.{domain}", f"em.{domain}",
                       f"em1.{domain}", f"em2.{domain}", f"em3.{domain}",
                       f"em4.{domain}", f"em5.{domain}", f"em6.{domain}",
                       f"email.{domain}", f"sg.{domain}"],
        "mailgun":    [f"email-mg.{domain}", f"mg.{domain}",
                       f"email.{domain}", f"reply.{domain}"],
        "postmark":   [f"email-pm.{domain}", f"pm.{domain}",
                       f"bounce.{domain}", f"track.{domain}"],
        "sparkpost":  [f"email-sp.{domain}", f"sp.{domain}",
                       f"links.{domain}", f"email.{domain}"],
        "mailjet":    [f"email-mj.{domain}", f"mj.{domain}"],
        "sendinblue": [f"email-sb.{domain}", f"sb.{domain}"],
        "ses":        [f"email-aws.{domain}", f"email-ses.{domain}",
                       f"ses.{domain}"],
        "freshworks": [f"email-fw.{domain}", f"email-fe.{domain}"],
        "salesforce": [f"email-sf.{domain}", f"et.{domain}"],
        "generic":    [f"track.{domain}", f"click.{domain}", f"open.{domain}",
                       f"bounce.{domain}", f"reply.{domain}", f"pixel.{domain}",
                       f"links.{domain}", f"mailer.{domain}", f"email.{domain}",
                       f"emails.{domain}", f"email2.{domain}", f"email3.{domain}",
                       f"email-nc.{domain}", f"email-sg.{domain}", f"email-mg.{domain}",
                       f"email-pm.{domain}", f"email-sp.{domain}", f"email-aws.{domain}",
                       f"email-mj.{domain}", f"email-sb.{domain}",
                       f"mail2.{domain}", f"mail3.{domain}",
                       f"transactional.{domain}", f"bulk.{domain}",
                       f"outbound.{domain}", f"mta.{domain}", f"relay.{domain}"],
    }

    found_esps = set()

    # Step 1: probe DKIM selectors to identify ESPs in use
    for esp, selectors in DKIM_SELECTORS.items():
        for sel in selectors:
            dkim_host = f"{sel}._domainkey.{domain}"
            try:
                result = subprocess.run(
                    ["dig", "+short", "TXT", dkim_host, "+time=3", "+tries=1"],
                    capture_output=True, text=True, timeout=8
                ).stdout.strip()
                if result and "p=" in result:  # valid DKIM record has p= (public key)
                    found_esps.add(esp)
                    break
            except Exception:
                pass

    # Step 2: resolve ALL ESP patterns directly via DNS — don't depend on DKIM detection.
    # DNS lookup is fast (no HTTP) and has zero false positives (either resolves or not).
    # We always probe all patterns so subdomains like email-nc.domain.com are found
    # even when the Netcore DKIM selector times out or uses an unusual selector name.
    all_candidates = set()
    for patterns in ESP_SUBDOMAINS.values():
        all_candidates.update(patterns)

    from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac
    def _resolve(h):
        try:
            socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
            return h
        except (socket.gaierror, OSError):
            return None

    with _TPE(max_workers=30) as pool:
        for result in pool.map(_resolve, sorted(all_candidates)):
            if result:
                subs.add(result.lower())

    if found_esps:
        print(f"  [+] esp_dkim: ESPs found: {', '.join(sorted(found_esps))}", flush=True)
    print(f"  [+] esp_dkim: {len(subs)} email infrastructure subdomains found", flush=True)
    return "esp_dkim", subs


# ── v2 Techniques (2024-2026 gap analysis) ────────────────────────────────────

def favicon_hash_pivot(domain):
    """MurmurHash3 of favicon → Shodan/uncover pivot for shared-infra discovery."""
    subs = set()
    try:
        import mmh3, base64 as _b64
    except ImportError:
        return "favicon_hash", subs
    for favicon_url in [f"https://{domain}/favicon.ico", f"https://www.{domain}/favicon.ico"]:
        raw_text, _, _ = get(favicon_url, timeout=8)
        if not raw_text: continue
        raw = raw_text.encode("latin-1", errors="ignore")
        b64 = _b64.encodebytes(raw).decode("utf-8")
        fav_hash = mmh3.hash(b64)
        uncover = os.path.join(GOBIN, "uncover")
        if os.path.isfile(uncover):
            out = subprocess.run(
                [uncover, "-q", f"http.favicon.hash:{fav_hash}",
                 "-e", "shodan,fofa,censys", "-silent", "-field", "host", "-limit", "200"],
                capture_output=True, text=True, timeout=60
            ).stdout
            for line in out.splitlines():
                line = line.strip().lower().split(":")[0]
                if line.endswith("." + domain) or line == domain: subs.add(line)
        print(f"  [+] favicon_hash: hash={fav_hash}, {len(subs)}", flush=True)
        break
    return "favicon_hash", subs


def well_known_enum(domain):
    """apple-app-site-association + assetlinks.json + security.txt — lists iOS/Android deep-link subdomains."""
    subs = set()
    for path in ["/.well-known/apple-app-site-association",
                 "/.well-known/assetlinks.json",
                 "/.well-known/security.txt", "/security.txt",
                 "/.well-known/openid-configuration", "/humans.txt", "/app-ads.txt"]:
        for scheme in ["https", "http"]:
            content = get_text(f"{scheme}://{domain}{path}", timeout=8)
            if content:
                subs |= extract_domains(content, domain)
                try:
                    data = json.loads(content)
                    for item in data.get("applinks", {}).get("details", []):
                        for p in item.get("paths", []) + item.get("components", []):
                            subs |= extract_domains(str(p), domain)
                except Exception:
                    pass
                break
    print(f"  [+] well_known:         {len(subs)}", flush=True)
    return "well_known", subs


def sourcemap_extraction(domain):
    """.map file reconstruction → grep internal URLs hardcoded in frontend source."""
    subs = set()
    html = get_text(f"https://{domain}", timeout=12)
    js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
    base = f"https://{domain}"
    js_files = [f if f.startswith("http") else f"{base}/{f.lstrip('/')}" for f in js_files[:10]]
    for js_url in js_files:
        map_content = get_text(js_url + ".map", timeout=8)
        if map_content and "sourcesContent" in map_content:
            subs |= extract_domains(map_content, domain)
    print(f"  [+] sourcemap:          {len(subs)}", flush=True)
    return "sourcemap", subs


def azure_saas_enum(domain, org_name):
    """Azure tenant probe + 17 SaaS subdomain patterns (atlassian, okta, vercel etc.)."""
    subs = set()
    # Microsoft tenant probe
    realm = get_text(
        f"https://login.microsoftonline.com/getuserrealm.srf?login=user@{domain}&xml=1",
        timeout=10)
    subs |= extract_domains(realm, domain)

    slug = re.sub(r'[^a-z0-9-]', '-', (org_name or domain.split(".")[0]).lower()).strip('-')[:30]
    patterns = [
        f"{slug}.azurewebsites.net", f"{slug}.blob.core.windows.net",
        f"{slug}.azureedge.net", f"{slug}.trafficmanager.net", f"{slug}.vault.azure.net",
        f"{slug}.scm.azurewebsites.net", f"{slug}.atlassian.net", f"{slug}.zendesk.com",
        f"{slug}.okta.com", f"{slug}.auth0.com", f"{slug}.workers.dev",
        f"{slug}.pages.dev", f"{slug}.vercel.app", f"{slug}.netlify.app",
        f"{slug}.onrender.com", f"{slug}.fly.dev", f"{slug}.servicenow.com",
        f"{slug}.my.salesforce.com", f"{slug}.force.com", f"{slug}.notion.site",
    ]
    from concurrent.futures import ThreadPoolExecutor as _T
    def _r(h):
        try: socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP); return h
        except: return None
    with _T(max_workers=30) as p:
        for r in p.map(_r, patterns):
            if r: subs.add(r.lower())
    print(f"  [+] azure_saas:         {len(subs)}", flush=True)
    return "azure_saas", subs


def postman_search(domain, org_name):
    """Postman public workspaces leak internal subdomain URLs (30K+ workspaces, CloudSEK Dec 2024)."""
    subs = set()
    query = org_name or domain.split(".")[0]
    data = get_text(f"https://www.postman.com/search?q={query}&scope=all&type=all", timeout=15)
    subs |= extract_domains(data, domain)
    print(f"  [+] postman:            {len(subs)}", flush=True)
    return "postman", subs


def bbot_runner(domain):
    """BBOT subdomain-enum preset — finds 20-50% more subdomains per README."""
    subs = set()
    import tempfile, shutil
    bbot_bin = shutil.which("bbot") or os.path.join(GOBIN, "bbot")
    if not os.path.isfile(bbot_bin) and not shutil.which("bbot"):
        return "bbot", subs
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            out = subprocess.run(
                [bbot_bin, "-t", domain, "-p", "subdomain-enum",
                 "-o", tmpdir, "-y", "--allow-deadly"],
                capture_output=True, text=True, timeout=600
            )
            for root, _, files in os.walk(tmpdir):
                for fn in files:
                    if fn.endswith(".ndjson"):
                        with open(os.path.join(root, fn)) as f:
                            for line in f:
                                try:
                                    ev = json.loads(line)
                                    if ev.get("type") == "DNS_NAME":
                                        s = ev.get("data","").lower().strip()
                                        if s.endswith("."+domain) or s == domain: subs.add(s)
                                except Exception: pass
            subs |= extract_domains(out.stdout, domain)
        except Exception:
            pass
    print(f"  [+] bbot:               {len(subs)}", flush=True)
    return "bbot", subs


def katana_crawl(domain):
    """Headless JS-aware crawler with -jc -jsl -xhr -f fqdn for subdomain harvest."""
    subs = set()
    katana_bin = os.path.join(GOBIN, "katana")
    if not os.path.isfile(katana_bin): return "katana", subs
    try:
        out = subprocess.run(
            [katana_bin, "-u", f"https://{domain}", "-hl", "-jc", "-jsl",
             "-xhr", "-f", "fqdn", "-d", "3", "-c", "20", "-silent"],
            capture_output=True, text=True, timeout=120
        ).stdout
        for line in out.splitlines():
            line = line.strip().lower()
            if line.endswith("."+domain) or line == domain: subs.add(line)
    except Exception: pass
    print(f"  [+] katana_crawl:       {len(subs)}", flush=True)
    return "katana", subs


def subwiz_predict(domain, known_subs_file=None):
    """nanoGPT 17.3M params trained on 26M tokens — finds +10.4% new subdomains (Hadrian Apr 2025)."""
    subs = set()
    if not known_subs_file or not os.path.isfile(known_subs_file):
        # Announce the skip so it doesn't look like one of the 25 techniques
        # silently disappeared from output. subwiz needs a seed file to predict
        # from — without it, this technique simply can't run.
        print(f"  [+] subwiz_ml:          skipped (no --known-subs file)", flush=True)
        return "subwiz", subs
    try:
        out = subprocess.run(
            ["subwiz", "-i", known_subs_file, "-n", "500", "-t", "0.0"],
            capture_output=True, text=True, timeout=60
        ).stdout
        predictions = [l.strip() for l in out.splitlines() if l.strip()]
        if predictions:
            import tempfile
            # delete=False + manual unlink in finally so the file outlives the
            # `with` block (we hand its path to dnsx) but doesn't pile up in /tmp.
            tmp_f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            try:
                tmp_f.write("\n".join(predictions))
                tmp_f.close()
                dnsx_bin = os.path.join(GOBIN, "dnsx")
                if os.path.isfile(dnsx_bin):
                    resolved = subprocess.run(
                        [dnsx_bin, "-l", tmp_f.name, "-silent", "-t", "150"],
                        capture_output=True, text=True, timeout=120
                    ).stdout
                    for line in resolved.splitlines():
                        line = line.strip().lower()
                        if line.endswith("."+domain) or line == domain: subs.add(line)
            finally:
                try: os.unlink(tmp_f.name)
                except OSError: pass
    except Exception: pass
    print(f"  [+] subwiz_ml:          {len(subs)}", flush=True)
    return "subwiz", subs


def baddns_check(domain):
    """BadDNS (Feb 2025) — auto-syncs Nuclei+dnsReaper signatures; checks cname/ns/mx/references."""
    findings = set()
    try:
        result = subprocess.run(
            ["baddns", "-m", "cname,ns,mx,references", domain],
            capture_output=True, text=True, timeout=60
        )
        out = result.stdout + result.stderr
        for line in out.splitlines():
            if any(k in line for k in ["VULNERABLE", "Vulnerable", "takeover", "TAKEOVER"]):
                findings.add(f"[BADDNS] {domain}: {line.strip()[:120]}")
    except FileNotFoundError: pass
    except Exception: pass
    if findings: print(f"  [!] baddns: {len(findings)} RISKS", flush=True)
    else: print(f"  [+] baddns:             0 takeover risks", flush=True)
    return "baddns", findings


def jarm_pivot(domain):
    """Active TLS fingerprint (62-byte) → uncover search for matching infrastructure."""
    subs = set()
    tlsx_bin = os.path.join(GOBIN, "tlsx")
    if not os.path.isfile(tlsx_bin): return "jarm", subs
    try:
        out = subprocess.run(
            [tlsx_bin, "-host", domain, "-jarm", "-silent"],
            capture_output=True, text=True, timeout=20
        ).stdout
        jarm_m = re.search(r'"jarm"\s*:\s*"([a-f0-9]{62})"', out)
        if jarm_m:
            jarm = jarm_m.group(1)
            uncover = os.path.join(GOBIN, "uncover")
            if os.path.isfile(uncover):
                res = subprocess.run(
                    [uncover, "-q", f'ssl.jarm:"{jarm}"', "-e", "shodan,censys",
                     "-silent", "-field", "host", "-limit", "100"],
                    capture_output=True, text=True, timeout=60
                ).stdout
                for line in res.splitlines():
                    line = line.strip().lower().split(":")[0]
                    if line.endswith("."+domain) or line == domain: subs.add(line)
    except Exception: pass
    print(f"  [+] jarm_pivot:         {len(subs)}", flush=True)
    return "jarm", subs


# ── Main ──────────────────────────────────────────────────────────────────────

def run_all(domain, org_name, known_ips=None, known_subs_file=None):
    domain = domain.strip().lower()
    all_subs = set()
    cloud_findings = set()
    new_root_domains = set()

    print(f"\n[*] Advanced techniques: {domain} (25 techniques)", flush=True)

    tasks = [
        # ── v1 techniques (15) ──────────────────────────────────────────────
        lambda: http_header_mining(domain),
        lambda: robots_and_sitemap(domain),
        lambda: spf_deep_parse(domain),
        lambda: js_analysis(domain),
        lambda: tls_san_pivot(domain, known_ips),
        lambda: cert_org_match(domain, org_name),
        lambda: nsec_walk(domain),
        lambda: google_transparency(domain),
        lambda: reverse_whois(domain),
        lambda: esp_dkim_discovery(domain),
        lambda: cloud_bucket_probe(domain, org_name),
        lambda: google_analytics_reverse(domain),
        lambda: reverse_ip_lookup(domain),
        lambda: cname_takeover_check(domain),
        lambda: asn_ptr_discovery(domain, org_name),
        # ── v2 techniques (10) — 2024-2026 gap analysis ─────────────────────
        lambda: favicon_hash_pivot(domain),
        lambda: well_known_enum(domain),
        lambda: sourcemap_extraction(domain),
        lambda: azure_saas_enum(domain, org_name),
        lambda: postman_search(domain, org_name),
        lambda: katana_crawl(domain),
        lambda: jarm_pivot(domain),
        lambda: baddns_check(domain),
        # Slower v2 techniques — higher timeout
        lambda: bbot_runner(domain),
        lambda: subwiz_predict(domain, known_subs_file),
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(t): t.__name__ if hasattr(t, '__name__') else str(i)
                   for i, t in enumerate(tasks)}
        for future in as_completed(futures):
            try:
                name, results = future.result(timeout=700)
                if name in ("cloud_buckets",):
                    cloud_findings |= results
                elif name == "reverse_whois":
                    new_root_domains |= results
                elif name in ("cname_takeover", "baddns"):
                    cloud_findings |= results
                else:
                    all_subs |= results
            except Exception:
                pass

    return all_subs, cloud_findings, new_root_domains

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", required=True)
    parser.add_argument("--org", default="", help="Organisation name")
    parser.add_argument("--output", required=True)
    parser.add_argument("--probe-ips", default="", help="Comma-separated known IPs for TLS pivot")
    parser.add_argument("--known-subs", default="", help="Known subdomains file for subwiz ML")
    args = parser.parse_args()

    known_ips = [ip.strip() for ip in args.probe_ips.split(",") if ip.strip()]
    subs, cloud, root_domains = run_all(
        args.domain, args.org or args.domain,
        known_ips, args.known_subs or None
    )

    with open(args.output, "w") as f:
        for s in sorted(subs): f.write(s + "\n")

    if cloud:
        print("\n[!] Cloud buckets found (check manually):")
        for c in sorted(cloud): print(f"    {c}")

    if root_domains:
        print("\n[!] Potential additional root domains via reverse WHOIS:")
        for d in sorted(root_domains): print(f"    {d}")

    print(f"\n[+] Advanced: {len(subs)} subdomains → {args.output}")

if __name__ == "__main__":
    main()
