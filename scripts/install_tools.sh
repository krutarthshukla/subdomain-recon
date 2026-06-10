#!/usr/bin/env bash
# install_tools.sh — Install ALL tools from gap analysis
# Extends v1 installer with: uncover, asnmap, cdncheck, shuffledns, bbot,
#   badDNS, subwiz, sourcemapper, mmh3, pyyaml, bbot presets

set -euo pipefail

TOOLS_DIR="$HOME/.recon-tools"
GOBIN="$TOOLS_DIR/bin"
mkdir -p "$GOBIN"
export GOPATH="$TOOLS_DIR"
export GOBIN="$GOBIN"
export PATH="$GOBIN:$PATH"

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()     { echo -e "${GREEN}[✓]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
info()   { echo -e "    $*"; }
banner() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# ── Auto-add to shell RCs ─────────────────────────────────────────────────────
PATH_LINE='export PATH="$HOME/.recon-tools/bin:$PATH"'
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    [ -f "$rc" ] && grep -qF "recon-tools" "$rc" 2>/dev/null || \
        printf '\n# subdomain-recon tools\n%s\n' "$PATH_LINE" >> "$rc" 2>/dev/null
done

go_install() {
    local name="$1" pkg="$2"
    # IMPORTANT: only trust $GOBIN/$name — never `command -v $name`. On many
    # systems, an unrelated binary on PATH can shadow the Go tool with the same
    # name (e.g. pyenv's Python `httpx` HTTP client shadows ProjectDiscovery
    # httpx; brew's GNU find shadows Go's `find`). run_all.sh hard-codes
    # $TOOLS_DIR/bin paths and will skip phases if the Go tool isn't there,
    # so the install MUST land in $GOBIN.
    [ -x "$GOBIN/$name" ] && { ok "$name already installed"; return; }
    info "Installing $name..."
    # If caller already pinned a version (pkg contains '@'), use it as-is.
    # Otherwise default to @latest.
    local target="$pkg"
    [[ "$pkg" != *@* ]] && target="${pkg}@latest"
    GOBIN="$GOBIN" go install "$target" 2>/tmp/go_err_$name \
        && ok "$name installed" \
        || warn "Failed: $name ($(tail -1 /tmp/go_err_$name 2>/dev/null))"
}

# Python CLI installer. Prefer pipx (isolated venv, the upstream-recommended
# path for bbot / baddns / theHarvester). Fall back through pip variants for
# PEP 668 environments where the system Python refuses installs.
ensure_pipx() {
    command -v pipx &>/dev/null && return 0
    if   command -v brew    &>/dev/null; then brew install pipx -q 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then sudo apt-get install -y -qq pipx 2>/dev/null || true
    elif command -v dnf     &>/dev/null; then sudo dnf install -y -q pipx 2>/dev/null || true
    elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm python-pipx 2>/dev/null || true
    fi
    command -v pipx &>/dev/null || python3 -m pip install --user pipx -q 2>/dev/null \
        || python3 -m pip install --user pipx -q --break-system-packages 2>/dev/null || true
    command -v pipx &>/dev/null && pipx ensurepath &>/dev/null || true
    command -v pipx &>/dev/null
}

pipx_install() {
    ensure_pipx || return 1
    pipx install "$@" 2>/dev/null \
      || pipx install --force "$@" 2>/dev/null
}

pip_install() {
    pip3 install "$@" -q 2>/dev/null \
      || pip3 install "$@" -q --break-system-packages 2>/dev/null \
      || python3 -m pip install "$@" -q --break-system-packages 2>/dev/null \
      || pip3 install "$@" -q --user 2>/dev/null
}

# ── Check Go (portable across macOS / Linux distros) ──────────────────────────
[ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
if ! command -v go &>/dev/null; then
    info "Go not found — attempting install for this platform…"
    if   command -v brew    &>/dev/null; then brew install go 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then sudo apt-get update -qq && sudo apt-get install -y -qq golang-go 2>/dev/null || true
    elif command -v dnf     &>/dev/null; then sudo dnf install -y -q golang 2>/dev/null || true
    elif command -v yum     &>/dev/null; then sudo yum install -y -q golang 2>/dev/null || true
    elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm go 2>/dev/null || true
    elif command -v zypper  &>/dev/null; then sudo zypper install -y go 2>/dev/null || true
    fi
fi
[ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
command -v go &>/dev/null || { warn "Go unavailable — install from https://go.dev/dl/ then re-run"; exit 1; }
ok "Go $(go version | awk '{print $3}')"

# ── Run v1 installer first ────────────────────────────────────────────────────
# ── All tools (full toolchain) ───────────────────────────────────────
banner "ProjectDiscovery core tools"
go_install "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
go_install "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx"
go_install "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx"
go_install "alterx"      "github.com/projectdiscovery/alterx/cmd/alterx"
go_install "chaos"       "github.com/projectdiscovery/chaos-client/cmd/chaos"
go_install "tlsx"        "github.com/projectdiscovery/tlsx/cmd/tlsx"
go_install "katana"      "github.com/projectdiscovery/katana/cmd/katana"
go_install "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
go_install "mapcidr"     "github.com/projectdiscovery/mapcidr/cmd/mapcidr"

banner "tomnomnom tools"
go_install "assetfinder" "github.com/tomnomnom/assetfinder"
go_install "anew"        "github.com/tomnomnom/anew"
go_install "waybackurls" "github.com/tomnomnom/waybackurls"

banner "Archive / URL tools"
go_install "gau"         "github.com/lc/gau/v2/cmd/gau"

banner "DNS resolution"
go_install "puredns"     "github.com/d3mondev/puredns/v2"
# amass: v4 main module ships under /v4 with `master` branch (no tag yet).
# Pass the version inside pkg so go_install doesn't double-append @latest.
if ! command -v amass &>/dev/null && [ ! -f "$GOBIN/amass" ]; then
    go_install "amass" "github.com/owasp-amass/amass/v4/...@master" \
        || go_install "amass" "github.com/owasp-amass/amass/v3/...@master" \
        || { command -v brew &>/dev/null && brew install amass -q 2>/dev/null && ok "amass (brew)"; }
fi

banner "Other Go tools (v1)"
# findomain is a Rust binary, not Go — `go install` cannot build it.
# Prefer brew on macOS; otherwise download the prebuilt release binary.
if ! command -v findomain &>/dev/null && [ ! -f "$GOBIN/findomain" ]; then
    info "Installing findomain (Rust binary)..."
    installed=0
    if command -v brew &>/dev/null; then
        brew install findomain -q 2>/dev/null && installed=1
    fi
    if [ "$installed" -eq 0 ]; then
        case "$(uname -s)-$(uname -m)" in
            Darwin-arm64|Darwin-x86_64) url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-osx.zip" ;;
            Linux-x86_64)               url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip" ;;
            Linux-aarch64|Linux-arm64)  url="https://github.com/Findomain/Findomain/releases/latest/download/findomain-aarch64.zip" ;;
            *)                          url="" ;;
        esac
        if [ -n "$url" ]; then
            tmpzip="$(mktemp -t findomain.XXXXXX.zip)"
            if curl -sL "$url" -o "$tmpzip" 2>/dev/null && unzip -oq "$tmpzip" -d "$GOBIN" 2>/dev/null; then
                chmod +x "$GOBIN/findomain" 2>/dev/null && installed=1
            fi
            rm -f "$tmpzip"
        fi
    fi
    [ "$installed" -eq 1 ] && ok "findomain installed" || warn "findomain install failed (optional)"
fi

# massdns
if [ ! -f "$GOBIN/massdns" ] && ! command -v massdns &>/dev/null; then
    command -v brew &>/dev/null && brew install massdns -q 2>/dev/null || true
    [ ! -f "$GOBIN/massdns" ] && {
        git clone --depth=1 https://github.com/blechschmidt/massdns.git /tmp/_massdns 2>/dev/null
        (cd /tmp/_massdns && make -s 2>/dev/null && cp bin/massdns "$GOBIN/") || true
    }
fi
[ -f "$GOBIN/massdns" ] || command -v massdns &>/dev/null && ok "massdns" || warn "massdns (optional)"

# theHarvester — prefer pipx for clean isolated install (PEP 668 friendly)
if ! command -v theHarvester &>/dev/null && [ ! -f "$GOBIN/theHarvester" ]; then
    pipx_install theHarvester &>/dev/null || pip_install theHarvester || {
        git clone --depth=1 https://github.com/laramies/theHarvester.git "$TOOLS_DIR/theHarvester" 2>/dev/null
        pip_install -r "$TOOLS_DIR/theHarvester/requirements/base.txt"
        ln -sf "$TOOLS_DIR/theHarvester/theHarvester.py" "$GOBIN/theHarvester"
    }
fi
command -v theHarvester &>/dev/null && ok "theHarvester" || warn "theHarvester"

# Python base
python3 -c "import requests" 2>/dev/null || pip_install requests

# ── ProjectDiscovery 2024 toolchain ───────────────────────────────────
banner "ProjectDiscovery 2024 toolchain"
go_install "uncover"    "github.com/projectdiscovery/uncover/cmd/uncover"
go_install "asnmap"     "github.com/projectdiscovery/asnmap/cmd/asnmap"
go_install "cdncheck"   "github.com/projectdiscovery/cdncheck/cmd/cdncheck"
go_install "shuffledns" "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
go_install "naabu"      "github.com/projectdiscovery/naabu/v2/cmd/naabu"

# ── Other Go tools ────────────────────────────────────────────────────
banner "Other new tools"
go_install "cero"       "github.com/glebarez/cero"
go_install "gungnir"    "github.com/g0ldencybersec/gungnir/cmd/gungnir"

# ── sourcemapper ─────────────────────────────────────────────────────
banner "sourcemapper"
if [ -f "$GOBIN/sourcemapper" ] || command -v sourcemapper &>/dev/null; then
    ok "sourcemapper already installed"
else
    info "Building sourcemapper..."
    git clone --depth=1 https://github.com/denandz/sourcemapper /tmp/_srcmapper 2>/dev/null || true
    ( cd /tmp/_srcmapper && go build -o "$GOBIN/sourcemapper" . 2>/dev/null ) \
        && ok "sourcemapper installed" \
        || warn "sourcemapper build failed (optional)"
fi

# ── BBOT ─────────────────────────────────────────────────────────────
# bbot/baddns/subwiz: upstream-recommended install path is pipx (isolated venv),
# which sidesteps PEP 668 "externally-managed-environment" failures on
# Homebrew/system Python. Fall back to plain pip with break-system-packages.
banner "BBOT — dominant 2024-2026 framework"
if command -v bbot &>/dev/null || [ -f "$GOBIN/bbot" ]; then
    ok "bbot already installed"
else
    info "Installing bbot via pipx (finds 20-50% more subdomains per README)..."
    if pipx_install bbot &>/dev/null || pip_install bbot; then
        ok "bbot installed"
    else
        warn "bbot install failed — try: pipx install bbot  (or)  pip3 install bbot --break-system-packages"
    fi
fi

# ── BadDNS ────────────────────────────────────────────────────────────
# BadDNS depends on `blasthttp`, a Rust extension that links against openssl-sys.
# Without rustc/cargo + openssl headers on PATH, the maturin build fails. Make
# sure both are present and OPENSSL_DIR is exported so openssl-sys can find them.
banner "BadDNS — modern takeover detection"
if command -v baddns &>/dev/null; then
    ok "BadDNS already installed"
else
    info "Installing BadDNS (Feb 2025 release, auto-syncs Nuclei templates)..."
    if ! command -v cargo &>/dev/null; then
        info "Rust toolchain missing — installing for blasthttp build..."
        if   command -v brew    &>/dev/null; then brew install rust -q 2>/dev/null || true
        elif command -v apt-get &>/dev/null; then sudo apt-get install -y -qq rustc cargo 2>/dev/null || true
        elif command -v dnf     &>/dev/null; then sudo dnf install -y -q rust cargo 2>/dev/null || true
        elif command -v pacman  &>/dev/null; then sudo pacman -Sy --noconfirm rust 2>/dev/null || true
        fi
    fi
    if command -v brew &>/dev/null && brew --prefix openssl@3 &>/dev/null; then
        export OPENSSL_DIR="$(brew --prefix openssl@3)"
        export OPENSSL_LIB_DIR="$OPENSSL_DIR/lib"
        export OPENSSL_INCLUDE_DIR="$OPENSSL_DIR/include"
    fi
    if pipx_install baddns &>/dev/null || pip_install baddns; then
        ok "BadDNS installed"
    else
        warn "BadDNS install failed — needs rustc + openssl headers; try: pipx install baddns"
    fi
fi

# ── subwiz (ML prediction) ────────────────────────────────────────────
banner "subwiz — ML subdomain prediction"
if command -v subwiz &>/dev/null; then
    ok "subwiz already installed"
else
    info "Installing subwiz (nanoGPT, finds +10.4% subdomains per Hadrian 2025)..."
    if pipx_install subwiz &>/dev/null || pip_install subwiz; then
        ok "subwiz installed"
    else
        warn "subwiz install failed — try: pipx install subwiz  (or)  pip3 install subwiz --break-system-packages"
    fi
fi

# ── Python libraries ──────────────────────────────────────────────────
banner "Python libraries"
for lib in mmh3 pyyaml; do
    python3 -c "import $lib" 2>/dev/null \
        && ok "$lib available" \
        || { pip_install $lib && ok "$lib installed"; }
done

# ── Wordlists + resolvers ─────────────────────────────────────────────
banner "Wordlists & resolvers"
WLDIR="$TOOLS_DIR/wordlists"
mkdir -p "$WLDIR"

# trickest/resolvers — actively maintained ~30k public DNS resolvers
RESOLVERS="$WLDIR/resolvers.txt"
if [ -s "$RESOLVERS" ]; then
    ok "resolvers.txt: $(wc -l < "$RESOLVERS") resolvers"
else
    info "Downloading resolvers list (trickest/resolvers)..."
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o "$RESOLVERS" 2>/dev/null \
        && ok "resolvers downloaded ($(wc -l < "$RESOLVERS") resolvers)" \
        || warn "resolvers download failed (brute will fall back to system DNS)"
fi

# Trusted resolvers for puredns wildcard validation (Cloudflare/Google/Quad9/OpenDNS)
TRUSTED="$WLDIR/trusted_resolvers.txt"
if [ -s "$TRUSTED" ]; then
    ok "trusted_resolvers.txt: $(wc -l < "$TRUSTED") resolvers"
else
    cat > "$TRUSTED" <<'EOF'
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
    ok "trusted_resolvers.txt seeded ($(wc -l < "$TRUSTED") resolvers)"
fi

# SecLists top-110k fallback wordlist (used when n0kovo 3M is too slow)
SECLIST="$WLDIR/subdomains-top110k.txt"
if [ -s "$SECLIST" ]; then
    ok "subdomains-top110k.txt: $(wc -l < "$SECLIST") words"
else
    info "Downloading SecLists top-110k wordlist..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
        -o "$SECLIST" 2>/dev/null \
        && ok "SecLists 110k downloaded ($(wc -l < "$SECLIST") words)" \
        || warn "SecLists 110k download failed (optional)"
fi

N0KOVO="$WLDIR/n0kovo_subdomains_3M.txt"
if [ -f "$N0KOVO" ]; then
    ok "n0kovo 3M wordlist: $(wc -l < "$N0KOVO") words"
else
    info "Downloading n0kovo 3M subdomain wordlist (from TLS-cert SAN scans)..."
    curl -sL "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt" \
        -o "$N0KOVO" 2>/dev/null \
        && ok "n0kovo 3M downloaded ($(wc -l < "$N0KOVO") words)" \
        || warn "n0kovo download failed (optional — using SecLists 110k)"
fi

# Assetnote 10M wordlist (large — optional, skipped by default for home use)
# Uncomment to download:
# ASSETNOTE="$WLDIR/assetnote_best_dns_10M.txt"
# curl -sL "https://wordlistscdn.assetnote.io/data/manual/best-dns-wordlist.txt" -o "$ASSETNOTE"

# ── API key config template ────────────────────────────────────────────────
CONFIG_DIR="$HOME/.config/subdomain-recon"
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/api_keys.yaml" ]; then
    cat > "$CONFIG_DIR/api_keys.yaml" << 'EOF'
# subdomain-recon API keys
# Free sources that dramatically improve results:

# Merklemap — 100B+ CT rows, 0s MMD (free tier, cheap paid)
# Get key: https://merklemap.com/
merklemap: ""

# LeakIX — independent crawler (free with registration)
# Get key: https://leakix.net/
leakix: ""

# Netlas — 10-level subdomain depth, 50 req/day free
# Get key: https://app.netlas.io/
netlas: ""

# Validin — passive DNS + cert history (free community 10/day)
# Get key: https://app.validin.com/
validin: ""

# C99.nl — cheapest commercial subdomain API (~$5/mo)
# Get key: https://api.c99.nl/
c99: ""

# host.io — reverse-IP/NS/MX (1000/mo free)
# Get key: https://host.io/
hostio: ""

# uncover engines (optional — uncover uses its own config at ~/.config/uncover/)
# Configure via: uncover -auth
EOF
    ok "API keys template: $CONFIG_DIR/api_keys.yaml"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD} Tool Inventory${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
for t in subfinder httpx dnsx alterx chaos tlsx katana nuclei \
          assetfinder anew waybackurls gau mapcidr asnmap cdncheck \
          uncover shuffledns puredns massdns cero gungnir sourcemapper; do
    [ -f "$GOBIN/$t" ] || command -v "$t" &>/dev/null \
        && echo -e "  ${GREEN}✓${NC} $t" \
        || echo -e "  ${YELLOW}?${NC} $t"
done
for py in bbot baddns subwiz; do
    command -v "$py" &>/dev/null \
        && echo -e "  ${GREEN}✓${NC} $py (Python)" \
        || echo -e "  ${YELLOW}?${NC} $py (Python)"
done
echo ""
echo -e "  API keys: ${CYAN}$CONFIG_DIR/api_keys.yaml${NC}"
echo -e "  PATH added to ~/.zshrc and ~/.bashrc"
echo -e "  Activate now: ${CYAN}source ~/.recon-tools/activate.sh${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
