#!/usr/bin/env bash
# run_all.sh — Single autopilot engine for the subdomain-recon skill.
#
# The user provides ONE thing — an org name OR domain(s). Everything else runs
# automatically end-to-end. SKILL.md just fires this with the user's input; no
# manual phase-stepping by the model.
#
#   bash run_all.sh "Acme"                       # org   → discover+validate+enum
#   bash run_all.sh "acme.com"                   # domain→ enumerate that domain
#   bash run_all.sh "acme.com,acme.io,acmex.in"  # domains→ enumerate exactly those
#
# IMPORTANT — file-writing rules (hard-won):
#   NEVER use tool flags like -o/-w to write output files from a backgrounded
#   subprocess — they fail silently. ALWAYS use a shell stdout redirect:
#   `tool ... > file.txt`. Applies to puredns/dnsx/httpx/alterx/tlsx.

set -euo pipefail

# ── Input — the ONLY thing the user provides ─────────────────────────────────
# A single field: an ORG NAME, or one/many DOMAINS. Mode is auto-detected:
#   • bare org name   ("Acme")             → MODE=org:    discover roots →
#                                            validate ownership → enumerate every
#                                            owned root's subdomains.
#   • one domain      ("acme.com")         → MODE=domain: subdomains of that
#                                            domain only (NO root discovery).
#   • many domains    ("acme.com,acme.io") → MODE=domain: subdomains of exactly
#                                            those, no discovery.
RAW="${1:?Usage: run_all.sh \"<org name | domain | domain1,domain2,...>\"}"

# "domainish" = label(.label)+ with no whitespace (a real domain, not "Acme Corp").
is_domainish() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9-]+)+$ ]]; }

MODE="org"; DOMAINS=""
IFS=',' read -ra _RAWTOKS <<< "$RAW"
_any=0; _all_dom=1
for _t in "${_RAWTOKS[@]}"; do
    _t="$(echo "$_t" | xargs)"; [ -z "$_t" ] && continue; _any=1
    is_domainish "$_t" || { _all_dom=0; break; }
done
if [ "$_any" -eq 1 ] && [ "$_all_dom" -eq 1 ]; then
    MODE="domain"
    # NB: tr -d ' \t' (NOT [:space:], which also eats the newlines we just split on).
    DOMAINS="$(echo "$RAW" | tr 'A-Z' 'a-z' | tr ',' '\n' | tr -d ' \t' | grep . | sort -u | paste -sd, -)"
    # Display label from the first domain's registrable part (handles co.uk/co.in
    # double-TLDs). Used only for the run-dir name + report title, never for recon.
    _label="$(echo "${DOMAINS%%,*}" | awk -F. '{ n=NF;
        if (n>=3 && ($(n-1)=="co"||$(n-1)=="com"||$(n-1)=="net"||$(n-1)=="org"||$(n-1)=="gov"||$(n-1)=="edu"||$(n-1)=="ac")) print $(n-2); else print $(n-1) }')"
    ORG="$(echo "${_label:0:1}" | tr 'a-z' 'A-Z')${_label:1}"        # "acme.com" → "Acme"
else
    MODE="org"
    ORG="$RAW"
fi

# ── Per-run output dir on Desktop: <Org>_<timestamp> (report + full log) ──────
TS="$(date +%Y%m%d_%H%M%S)"
# SR_RUNDIR lets a caller (e.g. bounty-recon) nest this run under its own dir and
# consume the outputs; default is a fresh timestamped dir on the Desktop.
RUNDIR="${SR_RUNDIR:-$HOME/Desktop/${ORG// /_}_${TS}}"
mkdir -p "$RUNDIR"
LOG="$RUNDIR/run.log"
# Mirror EVERYTHING (stdout+stderr, every phase + tool) into the run log while
# still printing to the console — single file for debugging a run end-to-end.
exec > >(tee -a "$LOG") 2>&1

# Diagnosis: if any command trips set -e, log exactly where before exiting, so a
# failure is never silent in the log. errtrace makes the trap fire in functions too.
set -o errtrace
trap 'rc=$?; echo "[FATAL] run_all.sh aborted at line ${LINENO} (exit ${rc})"' ERR

OUTPUT="$RUNDIR/${ORG// /_}_domains.txt"

# ── Paths ─────────────────────────────────────────────────────────────────────
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
REFS="$SKILL_DIR/references"
TOOLS_DIR="$HOME/.recon-tools"
WORDLIST="${TOOLS_DIR}/wordlists/subdomains-top110k.txt"
BUNDLED_WORDLIST="$REFS/wordlist.txt"
RESOLVERS="${TOOLS_DIR}/wordlists/resolvers.txt"
TRUSTED_RESOLVERS="${TOOLS_DIR}/wordlists/trusted_resolvers.txt"

# Explicit binary paths — never rely on PATH for these.
# macOS brew installs Python 'httpx' at /opt/homebrew/bin/httpx which is a
# completely different tool. Always use full paths from TOOLS_DIR.
HTTPX="$TOOLS_DIR/bin/httpx"
PUREDNS="$TOOLS_DIR/bin/puredns"
DNSX="$TOOLS_DIR/bin/dnsx"
ALTERX="$TOOLS_DIR/bin/alterx"
SUBFINDER="$TOOLS_DIR/bin/subfinder"

[ -f "$TOOLS_DIR/activate.sh" ] && source "$TOOLS_DIR/activate.sh" || true
export PATH="$TOOLS_DIR/bin:$PATH"

# ── Kill lingering processes from prior runs ──────────────────────────────────
# Multiple old puredns/dnsx/httpx processes competing on the same network and
# writing to the same output files causes empty results. Always clean first.
pkill -9 -f "$TOOLS_DIR/bin/httpx"   2>/dev/null || true
pkill -9 -f "$TOOLS_DIR/bin/puredns" 2>/dev/null || true
pkill -9 -f "$TOOLS_DIR/bin/dnsx"    2>/dev/null || true
pkill -9 -f "$TOOLS_DIR/bin/alterx"  2>/dev/null || true
sleep 1

# All intermediates live under the run dir (auditable, survives /tmp GC).
WORKDIR="$RUNDIR/work"
mkdir -p "$WORKDIR"

# On Ctrl-C / kill: take down backgrounded children AND salvage whatever
# subdomains were gathered so an interrupted run still leaves usable output +
# the full log in the run dir (instead of losing everything).
cleanup() {
    pkill -P $$ 2>/dev/null || true
    if [ -n "${WORKDIR:-}" ] && ls "$WORKDIR"/*.txt >/dev/null 2>&1; then
        cat "$WORKDIR"/*.txt 2>/dev/null \
            | grep -v "^#\|^\*\.\|^$" | tr '[:upper:]' '[:lower:]' \
            | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.+$//' \
            | grep "\." | sort -u > "$RUNDIR/partial_subdomains.txt" 2>/dev/null || true
        echo "[!] Saved partial results → $RUNDIR/partial_subdomains.txt"
    fi
}
trap 'echo; echo "[!] Interrupted — salvaging partial results…"; cleanup; exit 130' INT TERM

# ── Helpers ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
banner() { echo -e "\n${CYAN}══════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}══════════════════════════════════════════════${NC}"; }
ok()     { echo -e "${GREEN}[✓]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
info()   { echo -e "    $*"; }

# ── Phase 0: Tools check + auto-install ───────────────────────────────────────
# Portable across machines: if ANY required tool is missing, run the installer
# once, then continue. Tools that still can't install (rare/optional) just
# degrade — they don't block the run.
banner "Phase 0 — Tools"
REQUIRED_BINS=(subfinder httpx dnsx puredns alterx tlsx asnmap mapcidr uncover \
               katana gau waybackurls assetfinder amass chaos)
# These five are invoked elsewhere via hard-coded $TOOLS_DIR/bin/<name> and
# must exist at that exact path. Accepting a generic PATH match (e.g. pyenv's
# Python `httpx` HTTP client shadowing ProjectDiscovery httpx) lets Phase 0
# claim "all tools present" while later phases silently skip. Treat these as
# strict-path tools.
STRICT_BINS=(httpx subfinder dnsx puredns alterx)
REQUIRED_PY=(bbot subwiz baddns)

is_strict() {
    local x; for x in "${STRICT_BINS[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1
}

list_missing() {
    local m=()
    local b
    for b in "${REQUIRED_BINS[@]}"; do
        if is_strict "$b"; then
            # must exist at $TOOLS_DIR/bin/$b — generic PATH is not enough
            [ -x "$TOOLS_DIR/bin/$b" ] || m+=("$b")
        else
            [ -f "$TOOLS_DIR/bin/$b" ] || command -v "$b" &>/dev/null || m+=("$b")
        fi
    done
    for b in "${REQUIRED_PY[@]}"; do
        [ -e "$TOOLS_DIR/bin/$b" ] || command -v "$b" &>/dev/null || python3 -c "import $b" 2>/dev/null || m+=("$b")
    done
    echo "${m[*]:-}"
}

# Attempt-marker: only run the installer when the missing set CHANGES. This
# avoids re-running the (slow) installer every time for an optional tool that
# simply can't install on this host, while still self-healing if a tool that
# was present later goes missing.
MARKER="$TOOLS_DIR/.install_attempted"
MISSING="$(list_missing)"
if [ -z "$MISSING" ]; then
    ok "all required tools present"
    rm -f "$MARKER" 2>/dev/null || true
elif [ "$MISSING" = "$(cat "$MARKER" 2>/dev/null || true)" ]; then
    warn "Optional tools unavailable (install already attempted): $MISSING — continuing degraded"
else
    warn "Missing tool(s): $MISSING"
    echo "[*] Auto-installing via install_tools.sh (one-time, may take a few minutes)…"
    bash "$SCRIPTS/install_tools.sh" || warn "installer reported errors — continuing with what's available"
    source "$TOOLS_DIR/activate.sh" 2>/dev/null || true
    export PATH="$TOOLS_DIR/bin:$PATH"
    list_missing > "$MARKER" 2>/dev/null || true   # record what's still missing post-attempt
    STILL_MISSING="$(list_missing)"
    [ -n "$STILL_MISSING" ] && warn "Still unavailable (run will degrade): $STILL_MISSING" \
                            || { ok "all required tools present"; rm -f "$MARKER" 2>/dev/null || true; }
fi
[ -f "$RESOLVERS" ] && ok "resolvers: $(wc -l < "$RESOLVERS") entries" || warn "resolvers missing"
[ -f "$WORDLIST"  ] && ok "wordlist: $(wc -l < "$WORDLIST") words" || warn "wordlist missing"

# ── Phase 1 + 1.5: Domain discovery + ownership validation (ORG MODE only) ────
# Org mode: the user gave only a name, so we have to FIND the owned roots before
# we can enumerate. domain_discovery.py casts the wide net (cert/whois/wayback/
# github/NS sweeps); validate_ownership.py then keeps only roots with a positive
# ownership signal, so enumeration isn't wasted on parked/squatted look-alikes.
# Domain mode: the user named exact targets — trust them, skip discovery.
if [ "$MODE" = "org" ]; then
    banner "Phase 1 — Domain Discovery (org: $ORG)"
    ORG_SLUG="$(echo "$ORG" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9')"
    CONFIRMED="$WORKDIR/confirmed_domains.txt"

    # Curated acquisitions/subsidiary hint — deterministic coverage for the
    # differently-branded subsidiaries free OSINT can't auto-discover (e.g. an
    # org's acquisitions on unrelated brand names). Optional file:
    #   ~/.config/subdomain-recon/acquisitions.yaml
    #   <org>:               # matched by slug, case/space-insensitive
    #     domains: [a.com, b.io]
    #     names:   [BrandA, BrandB]
    HINT_FILE="$HOME/.config/subdomain-recon/acquisitions.yaml"
    HINT_DOMAINS=""; HINT_NAMES=""
    if [ -f "$HINT_FILE" ]; then
        HINT_OUT="$(python3 - "$HINT_FILE" "$ORG" <<'PY' 2>/dev/null
import sys, re
try:
    import yaml
except Exception:
    sys.exit(0)
try:
    data = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    sys.exit(0)
slug = re.sub(r'[^a-z0-9]', '', sys.argv[2].lower())
entry = None
if isinstance(data, dict):
    for k, v in data.items():
        if re.sub(r'[^a-z0-9]', '', str(k).lower()) == slug:
            entry = v; break
doms, names = [], []
if isinstance(entry, dict):
    doms = entry.get('domains') or []; names = entry.get('names') or []
elif isinstance(entry, list):
    doms = entry
j = lambda xs: ','.join(str(x).strip() for x in xs if str(x).strip())
print("HINT_DOMAINS='%s'" % j(doms))
print("HINT_NAMES='%s'" % j(names))
PY
)"
        eval "$HINT_OUT" 2>/dev/null || true
        [ -n "$HINT_DOMAINS" ] && ok "acquisitions hint: $HINT_DOMAINS"
    fi

    # Hint names join the slug-sweep entity list; the org slug is always included.
    ABBR="$ORG_SLUG"; [ -n "$HINT_NAMES" ] && ABBR="$ORG_SLUG,$HINT_NAMES"
    python3 "$SCRIPTS/domain_discovery.py" --org "$ORG" \
        --abbreviations "$ABBR" --output "$CONFIRMED" 2>&1 || : > "$CONFIRMED"
    # Seed the canonical apex + any curated acquisition domains as candidates.
    printf '%s\n' "${ORG_SLUG}.com" >> "$CONFIRMED"
    [ -n "$HINT_DOMAINS" ] && printf '%s\n' "$HINT_DOMAINS" | tr ',' '\n' | grep . >> "$CONFIRMED"
    sort -u "$CONFIRMED" -o "$CONFIRMED"
    ok "discovery: $(wc -l < "$CONFIRMED" | xargs) candidate root(s)"

    banner "Phase 1.5 — Ownership Validation"
    OWNED="$WORKDIR/owned_domains.txt"
    REJECTED="$RUNDIR/rejected_domains.txt"
    # Curated acquisition domains pass through as trusted-owned (operator asserts
    # ownership); hint names extend --org-aliases so their RDAP/cert matches too.
    TRUSTED="${ORG_SLUG}.com"; [ -n "$HINT_DOMAINS" ] && TRUSTED="${ORG_SLUG}.com,$HINT_DOMAINS"
    ALIASES="$ORG"; [ -n "$HINT_NAMES" ] && ALIASES="$ORG,$HINT_NAMES"
    python3 "$SCRIPTS/validate_ownership.py" \
        --input "$CONFIRMED" \
        --trusted "$TRUSTED" \
        --org-aliases "$ALIASES" \
        --slugs "$ORG_SLUG" \
        --output "$OWNED" --rejected "$REJECTED" 2>&1 || : > "$OWNED"
    DOMAINS="$(grep -vE '^#|^$' "$OWNED" 2>/dev/null | paste -sd, - || true)"
    [ -z "$DOMAINS" ] && DOMAINS="${ORG_SLUG}.com"
    ok "owned roots → enumeration: $DOMAINS"
else
    info "domain mode — enumerating exactly: $DOMAINS  (no root discovery)"
fi
IFS=',' read -ra DOMAIN_ARR <<< "$DOMAINS"
# Emit the enumerated roots so a caller (e.g. bounty-recon) can pick up the scope.
printf '%s\n' "$DOMAINS" | tr ',' '\n' | grep . > "$RUNDIR/owned_roots.txt" 2>/dev/null || true

# ── Phase 2: Passive enumeration ──────────────────────────────────────────────
banner "Phase 2 — Passive Enumeration (× ${#DOMAIN_ARR[@]} domains)"
PASSIVE_OUT="$WORKDIR/passive.txt"
python3 "$SCRIPTS/passive_enum.py" --domains "$DOMAINS" --output "$PASSIVE_OUT"
ok "Passive: $(grep -cv "^#" "$PASSIVE_OUT" 2>/dev/null || echo 0) subdomains"

# ── Phase 3: Advanced techniques — parallel ────────────────────────────────────
banner "Phase 3 — Advanced Techniques (parallel)"
ADVANCED_OUT="$WORKDIR/advanced.txt"
> "$ADVANCED_OUT"
pids=()
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    # Pass the Phase 2 passive output as --known-subs so subwiz_predict (ML
    # subdomain prediction) has a seed to work from. Without it, subwiz
    # early-returns silently and the ML technique never runs.
    python3 "$SCRIPTS/advanced_techniques.py" \
        --domain "$domain" --org "$ORG" \
        --known-subs "$PASSIVE_OUT" \
        --output "$WORKDIR/adv_${domain}.txt" 2>/dev/null &
    pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
cat "$WORKDIR"/adv_*.txt >> "$ADVANCED_OUT" 2>/dev/null || true
ok "Advanced: $(grep -c "." "$ADVANCED_OUT" 2>/dev/null || echo 0) subdomains"

# ── Phase 4: Active enumeration ───────────────────────────────────────────────
banner "Phase 4 — Active Enumeration"

BRUTE_OUT="$WORKDIR/brute.txt"
PERM_OUT="$WORKDIR/perms.txt"
ZONE_OUT="$WORKDIR/zonetransfer.txt"
TLS_OUT="$WORKDIR/tls_san.txt"
> "$BRUTE_OUT"; > "$PERM_OUT"; > "$ZONE_OUT"; > "$TLS_OUT"

# Build tiered wordlists (generated once from the main 110k list)
WL_LARGE="${WORDLIST}"
WL_MEDIUM="${TOOLS_DIR}/wordlists/subdomains-top20k.txt"
WL_SMALL="${TOOLS_DIR}/wordlists/subdomains-top5k.txt"
if [ -f "$WORDLIST" ]; then
    [ ! -f "$WL_MEDIUM" ] && head -20000 "$WORDLIST" > "$WL_MEDIUM"
    [ ! -f "$WL_SMALL"  ] && head -5000  "$WORDLIST" > "$WL_SMALL"
elif [ -f "$BUNDLED_WORDLIST" ]; then
    WL_LARGE="$BUNDLED_WORDLIST"; WL_MEDIUM="$BUNDLED_WORDLIST"; WL_SMALL="$BUNDLED_WORDLIST"
else
    WL_LARGE=""; WL_MEDIUM=""; WL_SMALL=""
fi

# Pick wordlist tier based on passive count (more passive = larger org = worth full scan)
_pick_wordlist() {
    local domain="$1"
    local c
    c=$(grep -cE "(^|\.)${domain//./\\.}$" "$PASSIVE_OUT" 2>/dev/null || echo 0)
    if   [ "$c" -gt 100 ]; then echo "$WL_LARGE"
    elif [ "$c" -gt 30  ]; then echo "$WL_MEDIUM"
    else                        echo "$WL_SMALL"
    fi
}

# ── Wildcard DNS detection (informational) ───────────────────────────────────
# Wildcard DNS means *.domain.com resolves for ANY name. We do NOT skip these
# domains — that throws away real subdomains. Instead, brute-force and
# permutations are resolved through puredns, whose wildcard-detection algorithm
# filters out the catch-all false positives while keeping genuine hosts (the
# methodology used by puredns/shuffledns + NahamSec-style recon pipelines).
# The list below is only used to fall back to a skip when puredns is unavailable
# (plain dnsx/socket resolution cannot filter wildcards).
echo "[*] Checking wildcard DNS..."
WILDCARD_DOMAINS=()
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    rand_host="xyzrnd$(date +%s%N | tail -c 6).${domain}"
    # `|| true` guards against SIGPIPE (141) when head closes the pipe early.
    wc_result=$(dig +short "$rand_host" A 2>/dev/null | head -1 || true)
    if [ -n "$wc_result" ]; then
        WILDCARD_DOMAINS+=("$domain")
        warn "$domain: wildcard DNS detected → puredns wildcard filtering will be used"
    fi
done

# Helper: is this domain a wildcard? (used to gate non-filtering fallbacks)
is_wildcard_domain() {
    local d="$1" w
    for w in "${WILDCARD_DOMAINS[@]:-}"; do [ "$w" = "$d" ] && return 0; done
    return 1
}

# ── Zone transfers ────────────────────────────────────────────────────────────
# Wrap dig in `timeout` (gtimeout on brew, falls back to perl). dig's `+time=5`
# is unreliable for AXFR over TCP — observed hangs of 20+ minutes on a single
# transfer against AWS NS on a large multi-domain scan. A hard process
# kill is the only reliable bound for the whole zone-transfer phase.
TO_CMD="$(command -v timeout || command -v gtimeout || true)"
zt_dig() {
    local ns="$1" dom="$2"
    if [ -n "$TO_CMD" ]; then
        "$TO_CMD" 8 dig axfr "$dom" "@$ns" +time=5 +tries=1 2>/dev/null
    else
        # Pure-bash fallback: background dig, kill after 8s if still running.
        ( dig axfr "$dom" "@$ns" +time=5 +tries=1 2>/dev/null ) & local p=$!
        ( sleep 8 && kill -9 $p 2>/dev/null ) & local k=$!
        wait $p 2>/dev/null
        kill -9 $k 2>/dev/null || true
    fi
}
echo "[*] Zone transfers..."
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    for ns in $(dig NS "$domain" +short +time=3 +tries=1 2>/dev/null | head -2 || true); do
        zt_dig "$ns" "$domain" | grep -v "^[;$]" >> "$ZONE_OUT" || true
    done
done
ok "Zone transfers: $(wc -l < "$ZONE_OUT") records"

# ── Brute-force — PARALLEL per domain, per-domain watchdog, tiered wordlist ──
# Each domain runs in its own subshell so one slow/dead domain can't wedge the
# rest (the earlier sequential loop could hang the whole phase on domain #1 if a
# resolver stalled). A 10-minute watchdog hard-kills a brute that overruns.
# Wildcards are still filtered by puredns; tiering still picks the wordlist size
# from the passive count; --resolvers-trusted keeps wildcard detection sane
# against the 16k-resolver list.
echo "[*] Brute-force (parallel, per-domain 10-min watchdog) — $(date)"
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    (
        # On a wildcard domain we rely on puredns to filter catch-all responses;
        # only skip when puredns is unavailable (dnsx/python can't filter them).
        if is_wildcard_domain "$domain" && ! [ -f "$PUREDNS" ]; then
            echo "  $domain: brute-force skipped (wildcard + puredns unavailable)"
            exit 0
        fi
        wl=$(_pick_wordlist "$domain")
        if [ -z "$wl" ] || [ ! -f "$wl" ]; then exit 0; fi

        TRUSTED_ARGS=""
        [ -f "$TRUSTED_RESOLVERS" ] && TRUSTED_ARGS="--resolvers-trusted $TRUSTED_RESOLVERS"

        if [ -f "$PUREDNS" ] && [ -f "$RESOLVERS" ]; then
            "$PUREDNS" bruteforce "$wl" "$domain" \
                -r "$RESOLVERS" $TRUSTED_ARGS \
                --wildcard-tests 5 -q 2>/dev/null \
                > "$WORKDIR/brute_${domain}.txt" &
        elif [ -f "$DNSX" ]; then
            "$DNSX" -d "$domain" -w "$wl" -silent -t 200 2>/dev/null \
                > "$WORKDIR/brute_${domain}.txt" &
        else
            python3 "$SCRIPTS/brute_force.py" --domain "$domain" \
                --wordlist "$wl" --output "$WORKDIR/brute_${domain}.txt" --threads 100 &
        fi
        BRUTE_PID=$!
        ( sleep 600 && kill -9 $BRUTE_PID 2>/dev/null ) & WATCH_PID=$!
        wait $BRUTE_PID 2>/dev/null
        kill -9 $WATCH_PID 2>/dev/null   # cancel watchdog if brute finished cleanly
        echo "  $domain: $(wc -l < "$WORKDIR/brute_${domain}.txt" 2>/dev/null || echo 0) brute hits"
    ) &
done
wait
cat "$WORKDIR"/brute_*.txt >> "$BRUTE_OUT" 2>/dev/null || true
ok "Brute-force total: $(wc -l < "$BRUTE_OUT") subdomains"

# ── Permutations — PARALLEL per domain, per-domain 5-min watchdog ────────────
# alterx generates candidates, resolved through puredns (wildcard-aware: keeps
# real permutation hits, drops catch-all false positives). Plain dnsx is NOT
# wildcard-aware, so it's only a fallback on NON-wildcard domains. Each domain
# writes its OWN file (no concurrent appends to a shared file), merged after.
#   altered names | puredns resolve   (never feed permutations straight to httpx)
echo "[*] Permutations (parallel, per-domain 5-min watchdog) — $(date)"
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    (
        grep -E "(^|\.)${domain//./\\.}$" "$PASSIVE_OUT" 2>/dev/null | head -300 \
            > "$WORKDIR/known_${domain}.txt" || true
        if [ ! -s "$WORKDIR/known_${domain}.txt" ]; then exit 0; fi

        TRUSTED_ARGS=""
        [ -f "$TRUSTED_RESOLVERS" ] && TRUSTED_ARGS="--resolvers-trusted $TRUSTED_RESOLVERS"

        (
            if [ -f "$ALTERX" ] && [ -f "$PUREDNS" ] && [ -f "$RESOLVERS" ]; then
                # Wildcard-aware resolution — correct on wildcard AND normal domains.
                "$ALTERX" -l "$WORKDIR/known_${domain}.txt" -silent 2>/dev/null \
                    | head -30000 \
                    | "$PUREDNS" resolve -r "$RESOLVERS" $TRUSTED_ARGS \
                        --wildcard-tests 5 -q 2>/dev/null \
                    > "$WORKDIR/perm_${domain}.txt" || true
            elif ! is_wildcard_domain "$domain" && [ -f "$ALTERX" ] && [ -f "$DNSX" ]; then
                # dnsx has no wildcard filtering — safe only because NOT a wildcard domain.
                "$ALTERX" -l "$WORKDIR/known_${domain}.txt" -silent 2>/dev/null \
                    | head -30000 \
                    | "$DNSX" -silent -t 250 2>/dev/null \
                    > "$WORKDIR/perm_${domain}.txt" || true
            elif is_wildcard_domain "$domain"; then
                echo "  $domain: permutation skipped (wildcard + puredns unavailable)"
            else
                python3 "$SCRIPTS/permutate.py" \
                    --input "$WORKDIR/known_${domain}.txt" \
                    --domain "$domain" \
                    --output "$WORKDIR/perm_${domain}.txt" || true
            fi
        ) &
        INNER_PID=$!
        ( sleep 300 && kill -9 $INNER_PID 2>/dev/null ) & WATCH_PID=$!
        wait $INNER_PID 2>/dev/null
        kill -9 $WATCH_PID 2>/dev/null
    ) &
done
wait
cat "$WORKDIR"/perm_*.txt >> "$PERM_OUT" 2>/dev/null || true
ok "Permutations: $(wc -l < "$PERM_OUT") subdomains"

# ── tlsx SAN-on-CIDR — highest-yield active technique per the research report ──
# For each owned root: resolve ASN → announced CIDRs → pull cert SANs/CNs across
# the range → resolve. Fans out across ALL roots in parallel (per-domain files,
# merged after). Skips cleanly when asnmap/tlsx aren't installed.
if [ -x "$TOOLS_DIR/bin/asnmap" ] && [ -x "$TOOLS_DIR/bin/tlsx" ]; then
    echo "[*] tlsx CIDR-SAN (parallel per domain) — $(date)"
    for domain in "${DOMAIN_ARR[@]}"; do
        domain=$(echo "$domain" | xargs)
        (
            "$TOOLS_DIR/bin/asnmap" -d "$domain" -silent 2>/dev/null \
                | "$TOOLS_DIR/bin/mapcidr" -silent 2>/dev/null \
                | "$TOOLS_DIR/bin/tlsx" -san -cn -silent -resp-only 2>/dev/null \
                | "$DNSX" -silent 2>/dev/null \
                > "$WORKDIR/tls_san_${domain}.txt" || true
        ) &
    done
    wait
    cat "$WORKDIR"/tls_san_*.txt >> "$TLS_OUT" 2>/dev/null || true
    ok "tlsx CIDR-SAN: $(wc -l < "$TLS_OUT") subdomains"
else
    info "tlsx CIDR-SAN skipped (asnmap/tlsx not installed)"
fi

# ── Phase 5: Merge + cache (cache is HISTORICAL ONLY, never merged into output) ─
banner "Phase 5 — Merge + Cache"
MERGED="$WORKDIR/all_unique.txt"

# Strip ANSI escape sequences some tools (bbot/katana) leak when their stdout is
# captured into a pipe — otherwise "\x1b[36mwww.example.com" becomes
# "36mwww.example.com" in the report.
ANSI='s/\x1b\[[0-9;]*[a-zA-Z]//g'
# Canonical result = what enumeration found THIS run. The persistent cache is a
# SEPARATE historical record and is deliberately NOT merged in here — blind
# cache-merge was the source of long-decommissioned subdomains reappearing in
# every report.
cat "$PASSIVE_OUT" "$ADVANCED_OUT" "$BRUTE_OUT" "$PERM_OUT" "$TLS_OUT" "$ZONE_OUT" 2>/dev/null \
    | sed -E "$ANSI" \
    | grep -v "^#\|^\*\.\|^$" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.+$//' \
    | grep "\." \
    | sort -u > "$MERGED" || true
[ -f "$MERGED" ] || : > "$MERGED"
TOTAL=$(wc -l < "$MERGED" | xargs)

# Persistent cache — union of historical + this-run, tagged with a first-seen
# date so a future run can age out anything not seen in N consecutive scans.
# Used for delta detection only; never blindly merged into the result above.
CACHE_DIR="$HOME/.recon-cache"
mkdir -p "$CACHE_DIR"
CACHE_SLUG=$(echo "$ORG" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_')
CACHE_FILE="$CACHE_DIR/${CACHE_SLUG}_subdomains.txt"
{
    date_iso=$(date -u +%Y-%m-%d)
    awk -v d="$date_iso" '{print $0"\t"d}' "$MERGED"
    [ -f "$CACHE_FILE" ] && cat "$CACHE_FILE"
} | awk '!seen[$1]++' > "$CACHE_FILE.new" 2>/dev/null && mv "$CACHE_FILE.new" "$CACHE_FILE" || true
ok "Total unique this run: $TOTAL  |  cache: $(wc -l < "$CACHE_FILE" 2>/dev/null | xargs || echo 0)"

echo ""
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    count=$(grep -cE "(^|\.)${domain//./\\.}$" "$MERGED" 2>/dev/null || echo 0)
    if [ "$count" -lt 5 ]; then
        warn "$domain: $count — LOW (passive sources may have been rate-limited)"
    else
        ok "$domain: $count"
    fi
done

# ── Phase 6: Live probe ───────────────────────────────────────────────────────
banner "Phase 6 — Live Probe"
LIVE_OUT="$WORKDIR/live.txt"
LIVE_COUNT=0
if [ -f "$HTTPX" ]; then
    # Use probe_live.py — Python subprocess.Popen bypasses the Bash tool's
    # stream interception that causes httpx output to disappear.
    # NON-FATAL: the live probe must never abort the run, or the report (Phase 7)
    # would be lost even though all subdomains were already gathered.
    if python3 "$SCRIPTS/probe_live.py" \
        --input "$MERGED" --output "$LIVE_OUT" \
        --threads 300 --timeout 5; then
        LIVE_COUNT=$(wc -l < "$LIVE_OUT" 2>/dev/null | xargs || echo 0)
        ok "Live: $LIVE_COUNT / $TOTAL"
    else
        warn "live probe failed — continuing to report with subdomains only"
    fi
else
    warn "httpx not at $HTTPX — skipping live probe"
fi

# ── Phase 7: Write report ─────────────────────────────────────────────────────
banner "Phase 7 — Report → $OUTPUT"
DOMAIN_MAP=""
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    DOMAIN_MAP+="$domain:$ORG,"
done
DOMAIN_MAP="${DOMAIN_MAP%,}"

# Include the rejected-roots file in org mode (validate_ownership wrote it) so
# the report shows what was excluded and why.
if [ -n "${REJECTED:-}" ] && [ -f "${REJECTED:-}" ]; then
    python3 "$SCRIPTS/write_report.py" \
        --org "$ORG" --domain-map "$DOMAIN_MAP" \
        --subdomain-files "$MERGED" --rejected-file "$REJECTED" --output "$OUTPUT"
else
    python3 "$SCRIPTS/write_report.py" \
        --org "$ORG" --domain-map "$DOMAIN_MAP" \
        --subdomain-files "$MERGED" --output "$OUTPUT"
fi

if [ -f "$LIVE_OUT" ] && [ -s "$LIVE_OUT" ]; then
    { echo ""; echo "# LIVE HOSTS ($LIVE_COUNT)"; cat "$LIVE_OUT"; } >> "$OUTPUT"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
banner "Complete"
echo -e "  Mode:       ${CYAN}$MODE${NC}"
echo -e "  Org:        ${CYAN}$ORG${NC}"
echo -e "  Roots:      ${CYAN}$DOMAINS${NC}"
echo -e "  Subdomains: ${CYAN}$TOTAL${NC}"
echo -e "  Live:       ${CYAN}$LIVE_COUNT${NC}"
echo ""
echo -e "  ${GREEN}✔ Output dir:${NC} $RUNDIR"
echo -e "  ${CYAN}Main outputs:${NC}"
echo -e "     • $(basename "$OUTPUT")  — the report (subdomains grouped by root + live hosts)"
echo -e "     • run.log  — full run log (every phase + tool)"
echo -e "  Everything else in the dir (work/, owned_roots.txt, rejected_domains.txt) is supporting/debug output."
echo ""
