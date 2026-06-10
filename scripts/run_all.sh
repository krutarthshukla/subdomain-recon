#!/usr/bin/env bash
# run_all.sh — Master orchestrator for subdomain-recon skill
#
# Usage:
#   bash run_all.sh "Acme Corp" "acme.com,acquired-co.com,product.io"
#   bash run_all.sh "Acme Corp" "acme.com,acquired-co.com" /custom/output.txt
#
# IMPORTANT — file writing rules (hard-won lessons):
#   NEVER use tool flags like -o, -w to write output files.
#   They fail silently when the tool runs as a background subprocess.
#   ALWAYS use shell stdout redirect: tool ... > file.txt
#   This applies to: puredns, dnsx, httpx, alterx

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────
ORG="${1:?Usage: run_all.sh <OrgName> <domain1,domain2,...> [output.txt]}"
DOMAINS="${2:?Provide comma-separated domains}"

# ── Per-run output dir on Desktop: <Org>_<timestamp> (report + full log) ──────
TS="$(date +%Y%m%d_%H%M%S)"
RUNDIR="$HOME/Desktop/${ORG// /_}_${TS}"
mkdir -p "$RUNDIR"
LOG="$RUNDIR/run.log"
# Mirror EVERYTHING (stdout+stderr, every phase + tool) into the run log while
# still printing to the console — single file for debugging a run end-to-end.
exec > >(tee -a "$LOG") 2>&1

# Diagnosis: if any command trips set -e, log exactly where before exiting, so a
# failure is never silent in the log. errtrace makes the trap fire in functions too.
set -o errtrace
trap 'rc=$?; echo "[FATAL] run_all.sh aborted at line ${LINENO} (exit ${rc})"' ERR

OUTPUT="${3:-$RUNDIR/${ORG// /_}_domains.txt}"

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

WORKDIR="/tmp/recon_${ORG// /_}_$$"
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

IFS=',' read -ra DOMAIN_ARR <<< "$DOMAINS"

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
        command -v "$b" &>/dev/null || python3 -c "import $b" 2>/dev/null || m+=("$b")
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

# ── Phase 1: Passive enumeration ──────────────────────────────────────────────
banner "Phase 1 — Passive Enumeration (19 sources × ${#DOMAIN_ARR[@]} domains)"
PASSIVE_OUT="$WORKDIR/passive.txt"
python3 "$SCRIPTS/passive_enum.py" --domains "$DOMAINS" --output "$PASSIVE_OUT"
ok "Passive: $(grep -cv "^#" "$PASSIVE_OUT" 2>/dev/null || echo 0) subdomains"

# ── Phase 2: Advanced techniques — parallel ────────────────────────────────────
banner "Phase 2 — Advanced Techniques (parallel)"
ADVANCED_OUT="$WORKDIR/advanced.txt"
> "$ADVANCED_OUT"
pids=()
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    # Pass the Phase 1 passive output as --known-subs so subwiz_predict (ML
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

# ── Phase 3: Active enumeration ───────────────────────────────────────────────
banner "Phase 3 — Active Enumeration"

BRUTE_OUT="$WORKDIR/brute.txt"
PERM_OUT="$WORKDIR/perms.txt"
ZONE_OUT="$WORKDIR/zonetransfer.txt"
> "$BRUTE_OUT"; > "$PERM_OUT"; > "$ZONE_OUT"

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

# ── Brute-force — sequential per domain, tiered wordlist ─────────────────────
# KEY FIX: puredns with 16k resolvers has false wildcard detection.
# Pass --resolvers-trusted with 36 known-good resolvers for wildcard detection only.
# The 16k resolvers are still used for speed; trusted resolvers prevent false detection.
echo "[*] Brute-force..."
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)

    # On a wildcard domain we rely on puredns to filter the catch-all responses.
    # Only skip when puredns is unavailable, since the dnsx/python fallbacks
    # cannot filter wildcards and would flood the results with false positives.
    if is_wildcard_domain "$domain" && ! [ -f "$PUREDNS" ]; then
        echo "  $domain: brute-force skipped (wildcard + puredns unavailable for filtering)"
        continue
    fi

    wl=$(_pick_wordlist "$domain")
    passive_c=$(grep -cE "(^|\.)${domain//./\\.}$" "$PASSIVE_OUT" 2>/dev/null || echo 0)
    tier="5k"; [ "$passive_c" -gt 30 ] && tier="20k"; [ "$passive_c" -gt 100 ] && tier="110k"
    [ -z "$wl" ] || [ ! -f "$wl" ] && continue

    echo -n "  $domain ($tier, passive=$passive_c)... "
    if [ -f "$PUREDNS" ] && [ -f "$RESOLVERS" ]; then
        # --resolvers-trusted: use only reliable resolvers for wildcard detection
        # This prevents 16k unreliable resolvers from causing false wildcard detection
        TRUSTED_ARGS=""
        [ -f "$TRUSTED_RESOLVERS" ] && TRUSTED_ARGS="--resolvers-trusted $TRUSTED_RESOLVERS"

        # Use tee (not >) — tee writes to file via its own handle, bypassing
        # the Bash tool's stdout interception
        "$PUREDNS" bruteforce "$wl" "$domain" \
            -r "$RESOLVERS" $TRUSTED_ARGS \
            --wildcard-tests 5 -q 2>/dev/null \
            | tee "$WORKDIR/brute_${domain}.txt" > /dev/null || true
    elif [ -f "$DNSX" ]; then
        "$DNSX" -d "$domain" -w "$wl" -silent -t 200 2>/dev/null \
            | tee "$WORKDIR/brute_${domain}.txt" > /dev/null || true
    else
        python3 "$SCRIPTS/brute_force.py" --domain "$domain" \
            --wordlist "$wl" --output "$WORKDIR/brute_${domain}.txt" --threads 100 || true
    fi
    echo "$(wc -l < "$WORKDIR/brute_${domain}.txt" 2>/dev/null || echo 0) found"
done
cat "$WORKDIR"/brute_*.txt >> "$BRUTE_OUT" 2>/dev/null || true
ok "Brute-force total: $(wc -l < "$BRUTE_OUT") subdomains"

# Permutations — alterx generates candidates, resolved through puredns.
# puredns is wildcard-aware: it keeps real permutation hits and drops catch-all
# false positives. Plain dnsx is NOT wildcard-aware, so it's only used as a
# fallback on NON-wildcard domains. This is the NahamSec-style pipeline:
#   altered names | puredns resolve  (never feed permutations straight to httpx).
echo "[*] Permutations..."
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)

    grep -E "(^|\.)${domain//./\\.}$" "$PASSIVE_OUT" 2>/dev/null | head -300 \
        > "$WORKDIR/known_${domain}.txt" || true
    [ ! -s "$WORKDIR/known_${domain}.txt" ] && continue

    TRUSTED_ARGS=""
    [ -f "$TRUSTED_RESOLVERS" ] && TRUSTED_ARGS="--resolvers-trusted $TRUSTED_RESOLVERS"

    if [ -f "$ALTERX" ] && [ -f "$PUREDNS" ] && [ -f "$RESOLVERS" ]; then
        # Wildcard-aware resolution — works correctly on wildcard AND normal domains.
        "$ALTERX" -l "$WORKDIR/known_${domain}.txt" -silent 2>/dev/null \
            | head -30000 \
            | "$PUREDNS" resolve -r "$RESOLVERS" $TRUSTED_ARGS \
                --wildcard-tests 5 -q 2>/dev/null \
            >> "$PERM_OUT" || true
    elif ! is_wildcard_domain "$domain" && [ -f "$ALTERX" ] && [ -f "$DNSX" ]; then
        # dnsx has no wildcard filtering — safe only because this is NOT a wildcard domain.
        "$ALTERX" -l "$WORKDIR/known_${domain}.txt" -silent 2>/dev/null \
            | head -30000 \
            | "$DNSX" -silent -t 150 2>/dev/null \
            >> "$PERM_OUT" || true
    elif is_wildcard_domain "$domain"; then
        echo "  $domain: permutation skipped (wildcard + puredns unavailable for filtering)"
    else
        python3 "$SCRIPTS/permutate.py" \
            --input "$WORKDIR/known_${domain}.txt" \
            --domain "$domain" \
            --output "$WORKDIR/perm_${domain}.txt" || true
        cat "$WORKDIR"/perm_*.txt >> "$PERM_OUT" 2>/dev/null || true
    fi
done
ok "Permutations: $(wc -l < "$PERM_OUT") subdomains"

# ── Phase 4: Deduplicate + persistent cache ───────────────────────────────────
banner "Phase 4 — Deduplicate"
MERGED="$WORKDIR/all_unique.txt"

# Persistent cache: accumulates subdomains across ALL runs for this org.
# Passive APIs have rate limits — results vary run to run. The cache ensures
# a subdomain found in ANY run is never lost in future runs.
CACHE_DIR="$HOME/.recon-cache"
mkdir -p "$CACHE_DIR"
ORG_SLUG=$(echo "$ORG" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_')
CACHE_FILE="$CACHE_DIR/${ORG_SLUG}_subdomains.txt"
[ -f "$CACHE_FILE" ] && ok "Cache: $(wc -l < "$CACHE_FILE") previously found subdomains"

# Self-heal a poisoned cache. If any domain has wildcard DNS, re-validate the
# cached entries through puredns BEFORE merging them, so stale wildcard false
# positives (e.g. left by an older/buggy run or another tool) can't silently
# inflate this run. puredns keeps only entries that genuinely resolve and aren't
# catch-all wildcards. Only runs for wildcard domains, so normal caches (which
# may legitimately hold currently-dead historical subs) are left untouched.
if [ -f "$CACHE_FILE" ] && [ "${#WILDCARD_DOMAINS[@]}" -gt 0 ] && [ -f "$PUREDNS" ] && [ -f "$RESOLVERS" ]; then
    _ct=""; [ -f "$TRUSTED_RESOLVERS" ] && _ct="--resolvers-trusted $TRUSTED_RESOLVERS"
    _before=$(wc -l < "$CACHE_FILE" | xargs)
    if "$PUREDNS" resolve "$CACHE_FILE" -r "$RESOLVERS" $_ct --wildcard-tests 5 -q \
            2>/dev/null > "$CACHE_FILE.clean"; then
        mv "$CACHE_FILE.clean" "$CACHE_FILE"
        warn "cache re-validated through puredns (wildcard filter): $_before → $(wc -l < "$CACHE_FILE" | xargs)"
    else
        rm -f "$CACHE_FILE.clean"
    fi
fi

# Build the source list — include the cache ONLY if it exists. Passing a
# nonexistent cache path to `cat` makes it exit 1, which under `set -o pipefail`
# aborted the whole run on the very first scan of any org (no cache yet).
MERGE_SRCS=("$PASSIVE_OUT" "$ADVANCED_OUT" "$BRUTE_OUT" "$PERM_OUT" "$ZONE_OUT")
[ -f "$CACHE_FILE" ] && MERGE_SRCS+=("$CACHE_FILE")
# `|| true`: an empty result set makes `grep` exit 1 — that's not a failure here.
cat "${MERGE_SRCS[@]}" 2>/dev/null \
    | grep -v "^#\|^\*\.\|^$" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.+$//' \
    | grep "\." \
    | sort -u > "$MERGED" || true
[ -f "$MERGED" ] || : > "$MERGED"
TOTAL=$(wc -l < "$MERGED" | xargs)

# Update cache with everything found this run + all previous runs
cp "$MERGED" "$CACHE_FILE"
ok "Total unique: $TOTAL (cache updated: $CACHE_FILE)"

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

# ── Phase 5: Live probe ───────────────────────────────────────────────────────
banner "Phase 5 — Live Probe"
LIVE_OUT="$WORKDIR/live.txt"
LIVE_COUNT=0
if [ -f "$HTTPX" ]; then
    # Use probe_live.py — Python subprocess.Popen bypasses the Bash tool's
    # stream interception that causes httpx output to disappear.
    # NON-FATAL: the live probe must never abort the run, or the report (Phase 6)
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

# ── Phase 6: Write report ─────────────────────────────────────────────────────
banner "Phase 6 — Report → $OUTPUT"
DOMAIN_MAP=""
for domain in "${DOMAIN_ARR[@]}"; do
    domain=$(echo "$domain" | xargs)
    DOMAIN_MAP+="$domain:$ORG,"
done
DOMAIN_MAP="${DOMAIN_MAP%,}"

python3 "$SCRIPTS/write_report.py" \
    --org "$ORG" \
    --domain-map "$DOMAIN_MAP" \
    --subdomain-files "$MERGED" \
    --output "$OUTPUT"

if [ -f "$LIVE_OUT" ] && [ -s "$LIVE_OUT" ]; then
    { echo ""; echo "# LIVE HOSTS ($LIVE_COUNT)"; cat "$LIVE_OUT"; } >> "$OUTPUT"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
banner "Complete"
echo -e "  Org:        ${CYAN}$ORG${NC}"
echo -e "  Subdomains: ${CYAN}$TOTAL${NC}"
echo -e "  Live:       ${CYAN}$LIVE_COUNT${NC}"
echo -e "  Report:     ${GREEN}$OUTPUT${NC}"
echo -e "  Log:        ${GREEN}$LOG${NC}"
echo ""
echo -e "  ${GREEN}✔ Report and full log saved in: $RUNDIR${NC}"
echo ""
