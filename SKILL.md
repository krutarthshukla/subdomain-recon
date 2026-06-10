---
name: subdomain-recon
Author: Krutarth Shukla
description: >
  Automated subdomain & domain reconnaissance. The user gives ONLY an org name
  or one/more domains; the skill discovers owned root domains (including
  acquisitions and subsidiaries), validates ownership, and enumerates
  subdomains end-to-end (passive sources, advanced
  techniques, brute/permutation/TLS-SAN active enum, live probing) and writes a
  report. Use for: "recon X", "find all subdomains", "map attack surface",
  "find domains and subdomains of <org>", or any serious recon engagement.
---

# Subdomain Recon

## First run (one-time, per machine)

Before running the engine, check the onboarding marker:

```bash
test -f ~/.recon-tools/.onboarded_subdomain && echo onboarded || echo first-run
```

If it prints `first-run`, this is the user's first time on this machine —
**pause, tell them the following, and ask whether to proceed** (don't launch yet):
- The toolchain (subfinder, httpx, dnsx, puredns, …) **auto-installs on this first
  run** — a few minutes, one time only.
- *Optional, improves recall:* add free API keys to
  `~/.config/subdomain-recon/api_keys.yaml` (Merklemap, LeakIX, Netlas).
- *Optional:* for bbot's extra coverage, run once (needs sudo):
  `bbot --install-all-deps`.

Once they confirm, record it so this never prompts again, then run the engine:

```bash
mkdir -p ~/.recon-tools && touch ~/.recon-tools/.onboarded_subdomain
```

If the marker already exists, skip all of this and run the engine directly.

## How to run it

The user gives you **one thing** — an org name, a single domain, or a comma-list
of domains. Take that input verbatim and run the engine. It does everything
else automatically; do **not** step through phases yourself.

```bash
bash ~/.claude/skills/subdomain-recon/scripts/run_all.sh "<the user's input>"
```

Examples — pass exactly what the user said:

```bash
bash ~/.claude/skills/subdomain-recon/scripts/run_all.sh "Acme"                       # org name
bash ~/.claude/skills/subdomain-recon/scripts/run_all.sh "acme.com"                    # one domain
bash ~/.claude/skills/subdomain-recon/scripts/run_all.sh "acme.com,acme.io,acmex.in"   # several domains
```

**Mode is auto-detected from the input:**

| Input | What the engine does |
|-------|----------------------|
| **Org name** (e.g. `Acme`) | Discovers candidate root domains, validates which are actually owned, then enumerates subdomains for **every owned root**. |
| **One domain** (e.g. `acme.com`) | Enumerates subdomains of **that domain only** — no sibling-root discovery. |
| **Several domains** (comma-separated) | Enumerates subdomains of **exactly those domains** — no discovery. |

First run on a fresh machine auto-installs the toolchain (`install_tools.sh`) —
this can take a few minutes; let it finish. Subsequent runs skip it.

## Reading the output

Everything for a run lands in one self-contained directory:
`~/Desktop/<Org>_<timestamp>/`

- `run.log` — full stdout/stderr of every phase (debug a run end-to-end here).
- `<Org>_domains.txt` — the report: subdomains grouped by root, plus a
  `# LIVE HOSTS` section at the bottom.
- `rejected_domains.txt` — (org mode) roots excluded by ownership validation,
  with the reason each was rejected.
- `work/` — per-phase intermediates (passive/advanced/brute/perms/tls_san/…).

When the engine finishes, summarize for the user: mode, owned roots enumerated,
total unique subdomains, live-host count, and the report path. Surface anything
the log flagged as `LOW` or skipped.

## Pipeline (reference only — the engine runs all of this; you don't)

- **Phase 0 — Tools.** Verify/auto-install the toolchain at `~/.recon-tools/bin`.
- **Phase 1 — Domain discovery** *(org mode only)*: `domain_discovery.py` casts a
  wide net (cert/whois/wayback/GitHub/NS sweeps) for candidate roots.
- **Phase 1.5 — Ownership validation** *(org mode only)*: `validate_ownership.py`
  keeps only roots with a positive ownership signal (RDAP / cert-SAN /
  MX-SPF-DMARC / NS-overlap / redirect / same-IP), so enumeration isn't wasted
  on parked or squatted look-alikes.
- **Phase 2 — Passive.** `passive_enum.py` across many CT/DNS/crawler sources.
- **Phase 3 — Advanced.** `advanced_techniques.py` (favicon-hash pivot,
  `.well-known`, source maps, Azure/SaaS patterns, BBOT, katana, subwiz ML,
  BadDNS, ASN→PTR, ESP/DKIM, JARM, …) — parallel per domain.
- **Phase 4 — Active.** Zone transfers, then parallel (watchdog-bounded)
  puredns brute-force (tiered wordlist), alterx permutations resolved through
  puredns, and tlsx SAN-on-CIDR.
- **Phase 5 — Merge + cache.** ANSI-cleaned dedupe → canonical result for the
  run. The `~/.recon-cache/` history is kept separately for delta detection and
  is **not** merged into the report.
- **Phase 6 — Live probe.** `probe_live.py` (httpx) marks which hosts are live.
- **Phase 7 — Report.** `write_report.py` writes the grouped report.

## API keys (optional, improves passive recall)

`~/.config/subdomain-recon/api_keys.yaml` (created by the installer). Free tiers
worth adding: Merklemap, LeakIX, Netlas, Validin, host.io. The skill runs fine
without them — they just add passive sources.

## Notes

- Run only against assets you're authorized to test.
- `n0kovo` 3M wordlist is opt-in (Phase 4 defaults to top110k); it adds hours for
  little extra recall.
- JARM/active probes respect rate limits; an interrupted run still salvages
  partial results to `partial_subdomains.txt`.
