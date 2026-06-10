---
name: subdomain-recon
owner: Krutarth Shukla
email: krutarth.ce@gmail.com
description: >
  World-class subdomain & domain reconnaissance implementing 2024-2026 SOTA gap analysis.
  20-50% more subdomains than v1 via bbot, uncover (18 engines), Merklemap CT, ML prediction (subwiz),
  Azure tenant enum, .well-known, source maps, JARM pivoting, BadDNS takeover detection.
  Use for: "recon X", "find all subdomains", "map attack surface", or any serious recon engagement.
---

# Subdomain Recon — 2024-2026 SOTA

Three structural gaps from research report, now fixed:
1. Asset-pivot engines — uncover wraps 18 engines; favicon/JARM/cert-graph finds hosts never in CT
2. 2024-era toolchain — bbot (20-50% more), BadDNS, subwiz ML, katana, sourcemapper
3. Continuous monitoring — gungnir CT subscription + delta detection

## Phase 0 — Install

```bash
bash ~/.claude/skills/subdomain-recon/scripts/install_tools.sh
source ~/.recon-tools/activate.sh
nano ~/.config/subdomain-recon/api_keys.yaml  # add Merklemap, LeakIX (free)
```

## Phase 1 — Domain Discovery

Use `domain_discovery.py` + acquisition research. Two things drive ROOT-domain
recall (find domains, not just subs):

1. **NS-existence** (now built into `domain_discovery.py`, source F): a TLD sweep
   that only keeps A-resolving apexes silently drops NS-delegated roots with no
   apex A (e.g. `acme.in` is on Route 53 but serves only via subdomains / a
   redirect). The script now unions in any swept candidate that has live NS.

2. **Broaden acquisition research beyond acquisitions** — when you research the
   org, also collect its own PRODUCT/BRAND domains, SHORT/VANITY domains (link
   shorteners, redirect domains), and REGIONAL ccTLD variants, then pass them via
   `--acquisitions` / `--abbreviations` (or curate them into the Phase 7
   `--domain-map`). For **Acme**, the non-obvious owned roots a plain
   "acme" sweep misses include: `acmex.com`, `acme.io`, `acme.in`,
   `acmepay.in`, `getacmepay.com`, `acmepay.io`, `acmeclub.co`,
   `subsidiary-a.com`, `subsidiary-b.in`, `subsidiary-c.com`.

```bash
python3 ~/.claude/skills/subdomain-recon/scripts/domain_discovery.py \
  --org "$ORG" --acquisitions "SubsidiaryA,SubsidiaryB,SubsidiaryC" \
  --abbreviations "acme,acmex,acmepay,acmeclub" \
  --output /tmp/confirmed_domains.txt
```

## Phase 1.5 — Ownership Validation (run BEFORE enumeration)

"Resolves" ≠ "owned". Brand-named domains are routinely parked or squatted
(`acme.us` → Afternic parking, `acme.uk` → "for sale | spaceship.com").
Validate the confirmed roots so enumeration only runs on real assets — but never
blindly delete: rejected roots are still reported, with the reason, for review.

```bash
python3 ~/.claude/skills/subdomain-recon/scripts/validate_ownership.py \
  --input /tmp/confirmed_domains.txt \
  --trusted "$(echo $ORG | tr 'A-Z' 'a-z').com" \
  --slugs "acme,acmex" \
  --output /tmp/owned_domains.txt \
  --rejected /tmp/rejected_domains.txt

DOMAINS="$(paste -sd, /tmp/owned_domains.txt)"   # feed owned+uncertain to Phase 2+
```

Buckets: **owned** (trusted, or a positive signal — redirect-to-brand /
internal-CGNAT / brand label serving live content / brand label present on live
non-parked DNS) and **uncertain** (no brand label and no positive signal) both
continue to enumeration; **rejected** (parking NS or for-sale page title) is
excluded but logged to `/tmp/rejected_domains.txt`. Rationale: once the parked/
for-sale gate is passed, a brand-labelled root on real DNS is treated as ours.

## Phase 2 — Passive Enumeration (27 sources)

```bash
python3 ~/.claude/skills/subdomain-recon/scripts/passive_enum.py \
  --domains "$DOMAINS" --output /tmp/sr_passive.txt \
  --keys ~/.config/subdomain-recon/api_keys.yaml
```

New sources over v1: Merklemap, Columbus, LeakIX, Netlas, host.io, C99.nl, uncover (18 engines), asnmap+PTR

## Phase 3 — Advanced (25 techniques)

```bash
# One script, 25 techniques
> /tmp/sr_advanced.txt
pids=()
for domain in $(echo "$DOMAINS" | tr ',' '\n'); do
  python3 ~/.claude/skills/subdomain-recon/scripts/advanced_techniques.py \
    --domain "$domain" --org "$ORG" \
    --known-subs "/tmp/sr_passive.txt" \
    --output "/tmp/sr_adv_${domain}.txt" 2>/dev/null &
  pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
cat /tmp/sr_adv_*.txt >> /tmp/sr_advanced.txt 2>/dev/null || true
```

Techniques: favicon hash pivot, .well-known/apple-app-site-association + assetlinks.json,
source map extraction, Azure tenant enum, SaaS patterns (17 platforms), Postman workspace search,
BBOT (80+ modules), katana JS crawler (-jc -jsl -xhr), subwiz ML (+10.4%), BadDNS takeover, JARM pivot

## Phase 4 — Active Enumeration

Zone transfer (same as v1), then:

```bash
# n0kovo 3M wordlist (upgraded from SecLists 110k)
WORDLIST="$HOME/.recon-tools/wordlists/n0kovo_subdomains_3M.txt"
[ ! -f "$WORDLIST" ] && WORDLIST="$HOME/.recon-tools/wordlists/subdomains-top110k.txt"

for domain in $(echo "$DOMAINS" | tr ',' '\n'); do
  rand="xyzrnd$(date +%s%N | tail -c 6).${domain}"
  [ -n "$(dig +short $rand A 2>/dev/null)" ] && echo "  $domain: skip (wildcard)" && continue
  echo -n "  $domain (brute)... "
  "$HOME/.recon-tools/bin/puredns" bruteforce "$WORDLIST" "$domain" \
    -r "$HOME/.recon-tools/wordlists/resolvers.txt" \
    --resolvers-trusted "$HOME/.recon-tools/wordlists/trusted_resolvers.txt" \
    --wildcard-tests 5 -q 2>/dev/null \
    | tee "/tmp/sr_brute_${domain}.txt" > /dev/null
  echo "$(wc -l < "/tmp/sr_brute_${domain}.txt") found"
done
cat /tmp/sr_brute_*.txt >> /tmp/sr_brute.txt 2>/dev/null || true
```

```bash
# alterx -enrich (target-specific word enrichment)
for domain in $(echo "$DOMAINS" | tr ',' '\n'); do
  grep "\.${domain}$" /tmp/sr_passive.txt | head -300 > "/tmp/sr_known_${domain}.txt"
  "$HOME/.recon-tools/bin/alterx" -l "/tmp/sr_known_${domain}.txt" \
    -enrich -silent 2>/dev/null | head -50000 \
    | "$HOME/.recon-tools/bin/dnsx" -silent -t 150 2>/dev/null >> /tmp/sr_perms.txt
done
```

```bash
# tlsx SAN-on-CIDR (highest yield per research report)
"$HOME/.recon-tools/bin/asnmap" -d "$(echo $DOMAINS | cut -d, -f1)" -silent 2>/dev/null \
  | "$HOME/.recon-tools/bin/mapcidr" -silent \
  | "$HOME/.recon-tools/bin/tlsx" -san -cn -silent -resp-only 2>/dev/null \
  | "$HOME/.recon-tools/bin/dnsx" -silent 2>/dev/null >> /tmp/sr_tls_san.txt
```

## Phase 5 — Merge + Cache

```bash
cat /tmp/sr_passive.txt /tmp/sr_advanced.txt /tmp/sr_brute.txt \
    /tmp/sr_perms.txt /tmp/sr_tls_san.txt 2>/dev/null \
  | grep -v "^#\|^\*\.\|^$" | tr '[:upper:]' '[:lower:]' | grep "\." | sort -u \
  > /tmp/sr_all.txt

# Persistent cache
CACHE="$HOME/.recon-cache/$(echo "$ORG" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_')_subdomains.txt"
[ -f "$CACHE" ] && cat "$CACHE" >> /tmp/sr_all.txt && sort -u /tmp/sr_all.txt -o /tmp/sr_all.txt
cp /tmp/sr_all.txt "$CACHE"
echo "Total: $(wc -l < /tmp/sr_all.txt)"
```

## Phase 6 — Live Probe

```bash
python3 ~/.claude/skills/subdomain-recon/scripts/probe_live.py \
  --input /tmp/sr_all.txt --output /tmp/sr_live.txt --threads 300 --timeout 5
```

## Phase 7 — Report

```bash
python3 ~/.claude/skills/subdomain-recon/scripts/write_report.py \
  --org "$ORG" \
  --domain-map "domain.com:Primary,acquired.com:Acquisition 2023" \
  --subdomain-files /tmp/sr_all.txt \
  --rejected-file /tmp/rejected_domains.txt \
  --output ~/Desktop/${ORG}_domains.txt
{ echo ""; echo "# LIVE HOSTS"; cat /tmp/sr_live.txt; } >> ~/Desktop/${ORG}_domains.txt
```

## API Keys — ROI Ranking (from research report)

Fill in `~/.config/subdomain-recon/api_keys.yaml`:

| Key | Cost | Why |
|-----|------|-----|
| Merklemap | Free tier | 100B+ CT rows, 0-second MMD |
| LeakIX | Free (register) | Independent crawler, not CT |
| Netlas | 50 req/day free | 10-level depth, regex DSL |
| Validin | Free community | Best free RiskIQ replacement |
| C99.nl | ~$5/mo | Cheapest commercial subdomain API |
| host.io | 1000/mo free | Reverse-IP/NS/MX relationships |

Merklemap + Validin + LeakIX + Netlas together < $100/mo and beat SecurityTrails alone.

## Continuous Monitoring (Phase 3 optional)

```bash
# Subscribe to CT logs — alert on new subdomains for your domains
gungnir -d target.com -o /tmp/ct_stream.txt &

# Delta: what's new since last scan
comm -13 <(sort /tmp/previous.txt) <(sort /tmp/sr_all.txt) > /tmp/new_subdomains.txt
```

## Caveats

- n0kovo 3M is slow on home connections — use with --wildcard-batch 1000000
- JARM is active (10 TLS hellos per host) — respect rate limits
- Postman workspace scraping shrinking since mid-2025, still valuable
- Merklemap won't support Sunlight CT (2025 split) — supplement with certstream-server-rust
- EC2 IP takeover: low-impact, flag only
