# subdomain-recon

Give it an organisation name and a few seed domains, and it maps out the whole external footprint: all the root domains the org owns, every subdomain it can find, and which of those are actually live. It pulls from passive sources first, then layers on the more aggressive techniques, and finishes by probing what's up and writing a report.

In practice it tends to surface noticeably more than running `subfinder` or `amass` on their own, mostly because it doesn't stop at certificate transparency — it also pivots on favicons, TLS certs, source maps, ASN ranges, and a few ML and brute-force passes.

## What it does

- **Finds the root domains, not just subdomains.** Starts from the org name and expands into acquisitions, brand domains, and ccTLD variants. It also keeps domains that only have NS records (no A record), which a naive sweep would throw away.
- **Checks ownership before enumerating.** A domain resolving doesn't mean the org owns it — plenty are parked or squatted. This step sorts roots into owned / uncertain / rejected so you don't waste time enumerating someone else's parking page. Rejected domains are logged, not silently dropped.
- **27 passive sources.** Merklemap, crt.sh, Columbus, LeakIX, Netlas, host.io, C99.nl, `uncover` (which itself wraps 18 engines), asnmap + PTR, and more.
- **25 advanced techniques.** Favicon-hash pivoting, `.well-known` app-association files, source-map extraction, Azure tenant enumeration, SaaS-platform patterns, Postman workspace search, BBOT, the katana JS crawler, `subwiz` ML prediction, BadDNS takeover checks, and JARM/TLS-SAN pivoting.
- **Active enumeration.** DNS brute-force against the n0kovo 3M wordlist, permutation enrichment with `alterx`, and TLS SAN-on-CIDR.
- **Live probing and a report.** Probes everything it found and writes a text report grouped by source domain.
- **Continuous monitoring (optional).** Subscribe to CT logs and get alerted when new subdomains show up.

## Requirements

- Python 3.9 or newer
- The tooling the installer sets up (full list below)
- API keys are optional — free tiers are plenty. Worth getting: Merklemap, LeakIX, Netlas, Validin, host.io, C99.nl

`install_tools.sh` is idempotent and cross-platform (macOS + Linux), and `run_all.sh` calls it automatically if anything is missing — so you don't have to run it by hand. Tools already on your system are detected and never reinstalled.

### Tools it installs / uses

| Group | Tools |
|-------|-------|
| Passive enumeration | `subfinder`, `assetfinder`, `chaos`, `findomain`, `amass`, `theHarvester`, `uncover` |
| DNS resolution / brute | `dnsx`, `puredns`, `massdns`, `shuffledns`, `alterx` |
| Cert / TLS / ASN pivots | `tlsx`, `asnmap`, `mapcidr`, `cdncheck`, `cero` |
| Crawl / archive | `katana`, `gau`, `waybackurls`, `sourcemapper` |
| Probe / utility | `httpx`, `anew` |
| CT monitoring | `gungnir` |
| ML / takeover (Python) | `bbot`, `subwiz`, `baddns` |
| Python libs | `requests`, `mmh3`, `pyyaml` |
| Wordlist | n0kovo 3M subdomains |

If a tool can't be installed on a given host, that technique is skipped and the rest of the run continues.

## Installation

You don't have to run this — `run_all.sh` auto-installs anything missing. But to set up (or refresh) the toolchain by hand:

```bash
bash scripts/install_tools.sh
source ~/.recon-tools/activate.sh

# Optional, but recommended — add free API keys
nano ~/.config/subdomain-recon/api_keys.yaml
```

If you only add a few keys, these give the most back for the least effort:

| Key | Cost | Why it's worth it |
|-----|------|-------------------|
| Merklemap | Free tier | 100B+ CT rows, near-instant |
| LeakIX | Free (register) | Independent crawler, not just CT |
| Netlas | 50 req/day free | Deep nesting, regex search |
| Validin | Free community | The best free RiskIQ replacement |
| C99.nl | ~$5/mo | Cheapest commercial subdomain API |
| host.io | 1000/mo free | Reverse IP / NS / MX lookups |

Merklemap, Validin, LeakIX, and Netlas together cost under $100/mo and cover more than SecurityTrails alone.

## Quick start

One command runs the whole thing:

```bash
bash scripts/run_all.sh "Acme Corp" "acme.com,acquired-co.com,product.io"

# Or point the output somewhere specific
bash scripts/run_all.sh "Acme Corp" "acme.com,acquired-co.com" /custom/output.txt
```

By default the report lands at `~/Desktop/<OrgName>_domains.txt`, with live hosts listed under a `# LIVE HOSTS` section at the bottom.

## How it works

There are eight stages. Each one feeds the next, and you can run any of them on their own if you only need part of the pipeline.

```
        org name + seed domains
                  │
   ┌──────────────▼───────────────┐
   │ Phase 1   Domain Discovery    │  expand org → acquisitions/brands/ccTLDs
   │                               │  + NS-existence sweep
   └──────────────┬───────────────┘
                  │ confirmed roots
   ┌──────────────▼───────────────┐
   │ Phase 1.5 Ownership Validation│  owned / uncertain / rejected (parked)
   │                               │  rejected logged, never silently dropped
   └──────────────┬───────────────┘
                  │ owned roots
   ┌──────────────▼───────────────┐
   │ Phase 2   Passive Enumeration │  27 CT/API sources, no target contact
   │                               │
   └──────────────┬───────────────┘
                  │ passive subdomains
   ┌──────────────▼───────────────┐
   │ Phase 3   Advanced Techniques │  25 asset-pivot techniques
   │                               │  (favicon/JARM/sourcemap/BBOT/ML…)
   └──────────────┬───────────────┘
                  │ advanced subdomains
   ┌──────────────▼───────────────┐
   │ Phase 4   Active Enumeration  │  brute-force (n0kovo 3M),
   │                               │  permutation, TLS SAN-on-CIDR
   └──────────────┬───────────────┘
                  │ brute / permuted subdomains
   ┌──────────────▼───────────────┐
   │ Phase 5   Merge + Dedupe      │  union all sources, normalise, cache
   │                               │
   └──────────────┬───────────────┘
                  │ merged subdomains
   ┌──────────────▼───────────────┐
   │ Phase 6   Live Probe          │  concurrent HTTP probe + tech detect
   │                               │
   └──────────────┬───────────────┘
                  │ live hosts
   ┌──────────────▼───────────────┐
   │ Phase 7   Report              │  grouped report → ~/Desktop
   │                               │
   └───────────────────────────────┘
```

| Phase | Takes | Produces | What happens |
|-------|-------|----------|--------------|
| **1 — Domain Discovery** | org name, acquisitions, abbreviations | confirmed root domains | Turns the org into a list of candidate roots — brands, ccTLD variants, acquisitions — and holds onto anything with live NS records even if it has no A record, since those are easy to miss. |
| **1.5 — Ownership Validation** | confirmed roots | owned roots, rejected roots | Decides whether each root really belongs to the org. Owned (trusted or with a clear ownership signal) and uncertain (no signal, but kept just in case) both move on; parked or for-sale domains get set aside and logged. |
| **2 — Passive Enumeration** | owned roots | passive subdomains | Queries 27 passive sources (Merklemap, crt.sh, Columbus, LeakIX, Netlas, host.io, C99.nl, `uncover`'s 18 engines, asnmap + PTR, and so on). Never touches the target directly. |
| **3 — Advanced Techniques** | roots + passive results | advanced subdomains | Runs 25 pivoting techniques: favicon hashes, `.well-known` app-association, source maps, Azure tenants, 17 SaaS patterns, Postman search, BBOT, katana JS crawling, `subwiz` ML prediction, BadDNS takeover checks, and JARM/TLS-SAN pivots. |
| **4 — Active Enumeration** | owned roots + passive results | brute / permuted subdomains | DNS brute-force against the n0kovo 3M wordlist, permutation enrichment, and TLS SAN-on-CIDR. Wildcards are tested first so you don't drown in false positives. |
| **5 — Merge + Dedupe** | everything above | merged subdomain set | Combines all the sources, normalises case, removes duplicates, and updates the per-org cache. |
| **6 — Live Probe** | merged subdomains | live hosts | Probes everything over HTTP/HTTPS (300 threads) and records status, title, and detected tech. |
| **7 — Report** | merged subdomains + rejected roots | `~/Desktop/<Org>_domains.txt` | Writes the final report grouped by source domain, with live hosts at the end. |

If you want ongoing coverage, you can also subscribe to CT logs and diff against the last run to catch new subdomains as they appear — see [Continuous monitoring](#continuous-monitoring).

### Running a single phase

```bash
# Phase 1 — root domain discovery
python3 scripts/domain_discovery.py \
  --org "Acme Corp" \
  --acquisitions "SubsidiaryA,SubsidiaryB,SubsidiaryC" \
  --abbreviations "acme,acmex" \
  --output /tmp/confirmed_domains.txt

# Phase 1.5 — ownership validation
python3 scripts/validate_ownership.py \
  --input /tmp/confirmed_domains.txt \
  --trusted acme.com \
  --slugs "acme,acmex" \
  --output /tmp/owned_domains.txt \
  --rejected /tmp/rejected_domains.txt

# Phase 2 — passive enumeration
python3 scripts/passive_enum.py \
  --domains "acme.com,acquired-co.com" \
  --output /tmp/passive.txt \
  --keys ~/.config/subdomain-recon/api_keys.yaml

# Phase 3 — advanced techniques (one domain at a time)
python3 scripts/advanced_techniques.py \
  --domain acme.com --org "Acme Corp" \
  --known-subs /tmp/passive.txt \
  --output /tmp/advanced.txt

# Phase 6 — live probe
python3 scripts/probe_live.py \
  --input /tmp/all.txt --output /tmp/live.txt --threads 300 --timeout 5

# Phase 7 — report
python3 scripts/write_report.py \
  --org "Acme Corp" \
  --domain-map "acme.com:Primary,acquired-co.com:Acquisition 2023" \
  --subdomain-files /tmp/all.txt \
  --rejected-file /tmp/rejected_domains.txt \
  --output ~/Desktop/Acme_domains.txt
```

## Options reference

<details>
<summary><code>domain_discovery.py</code></summary>

| Flag | Required | Description |
|------|----------|-------------|
| `--org` | yes | Organisation name |
| `--acquisitions` | no | Comma-separated subsidiary/brand names |
| `--abbreviations` | no | Comma-separated short labels to expand |
| `--output` | yes | Output file of confirmed root domains |
</details>

<details>
<summary><code>validate_ownership.py</code></summary>

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | yes | File of confirmed root domains |
| `--trusted` | no | Comma-separated roots treated as definitely owned |
| `--slugs` | no | Brand labels for ownership signals (defaults to trusted roots' labels) |
| `--output` | yes | Owned + uncertain roots |
| `--rejected` | no | File for parked/for-sale rejects (logged, not deleted) |
| `--timeout` | no | Per-request timeout (default 10s) |
</details>

<details>
<summary><code>passive_enum.py</code></summary>

| Flag | Required | Description |
|------|----------|-------------|
| `--domains` | yes | Comma-separated domains |
| `--output` | yes | Output file |
| `--keys` | no | Path to `api_keys.yaml` |
</details>

<details>
<summary><code>advanced_techniques.py</code></summary>

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | yes | Target domain |
| `--org` | no | Organisation name |
| `--output` | yes | Output file |
| `--probe-ips` | no | Known IPs for TLS pivot |
| `--known-subs` | no | Known subdomains file for `subwiz` ML |
</details>

<details>
<summary><code>probe_live.py</code> / <code>write_report.py</code></summary>

`probe_live.py`: `--input` `--output` `--threads` (300) `--timeout` (5)
`write_report.py`: `--org` `--domain-map` `--subdomain-files` `--rejected-file` `--output`
</details>

## Continuous monitoring

```bash
# Watch CT logs and get told about new subdomains
gungnir -d acme.com -o /tmp/ct_stream.txt &

# See what's new since the last scan
comm -13 <(sort /tmp/previous.txt) <(sort /tmp/all.txt) > /tmp/new_subdomains.txt
```

## Things to know

- The n0kovo 3M wordlist is slow over a home connection. Run it with `--wildcard-batch 1000000`.
- JARM makes real TLS connections (10 hellos per host), so mind the rate limits.
- Postman workspace scraping returns less than it used to since mid-2025, but it still finds things.
- Merklemap doesn't cover Sunlight CT (the 2025 split). If that matters to you, add `certstream-server-rust`.
- Cloud IP takeover signals (like EC2) are usually low impact — worth flagging, not worth chasing.

## A note on scope

Only run this against assets you own or have explicit permission to test. Scanning systems you're not authorised to touch can be illegal where you live.

## Author

Krutarth Shukla · krutarth.ce@gmail.com
