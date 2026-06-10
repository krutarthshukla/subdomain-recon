# Complete Subdomain Enumeration Techniques Reference

## PASSIVE (no direct contact with target)

### Certificate Transparency Logs
| Source | Endpoint | Key? |
|--------|----------|------|
| crt.sh | `https://crt.sh/?q=%.{domain}&output=json` | No |
| CertSpotter | `https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true` | No (limited) |
| Facebook CT | `https://graph.facebook.com/certificates?query={domain}&fields=domains` | Yes (App ID+Secret) |
| Censys | `https://search.censys.io/api/v2/certificates/search` | Yes |

### Free DNS / Passive DNS APIs
| Source | Endpoint | Key? |
|--------|----------|------|
| HackerTarget | `https://api.hackertarget.com/hostsearch/?q={domain}` | No (100/day) |
| RapidDNS | `https://rapiddns.io/subdomain/{domain}?full=1` | No |
| BufferOver.run | `https://dns.bufferover.run/dns?q=.{domain}` | No |
| JLDC/Anubis | `https://jldc.me/anubis/subdomains/{domain}` | No |
| ThreatCrowd | `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}` | No |
| Riddler.io | `https://riddler.io/search/exportcsv?q=pld:{domain}` | No |
| Robtex | `https://freeapi.robtex.com/pdns/forward/{domain}` | No |
| ThreatMiner | `https://api.threatminer.org/v2/domain.php?q={domain}&rt=5` | No |
| DNSdb (Farsight) | `https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{domain}` | Yes |

### Threat Intel APIs
| Source | Notes | Key? |
|--------|-------|------|
| AlienVault OTX | `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` | No |
| VirusTotal | `https://www.virustotal.com/api/v3/domains/{domain}/subdomains` | Yes (free 4/min) |
| URLScan.io | `https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200` | No (limited) |
| SecurityTrails | `https://api.securitytrails.com/v1/domain/{domain}/subdomains` | Yes |
| PassiveTotal/RiskIQ | `https://api.riskiq.net/pt/v2/dns/passive?query={domain}` | Yes |
| Shodan | `https://api.shodan.io/dns/domain/{domain}` | Yes |
| Censys | `https://search.censys.io/api/v2/hosts/search` | Yes |
| BinaryEdge | `https://api.binaryedge.io/v2/query/domains/subdomain/{domain}` | Yes |
| FullHunt | `https://fullhunt.io/api/v1/domain/{domain}/subdomains` | Yes |
| IntelX | `https://2.intelx.io/intelligent/search` | Yes |
| Netlas | `https://app.netlas.io/api/responses` | Yes |
| ZoomEye | `https://api.zoomeye.org/domain/search?q={domain}` | Yes |
| FOFA | `https://fofa.info/api/v1/search/all` | Yes |

### Web Archives
| Source | Endpoint |
|--------|----------|
| Wayback CDX | `http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey` |
| Common Crawl | Latest index API: `http://index.commoncrawl.org/collinfo.json` → query latest |
| URLScan.io | (also in threat intel above) |

### subfinder (aggregates all of the above + more)
```bash
# Free sources only:
subfinder -d {domain} -silent

# All sources (slower, uses API keys from ~/.config/subfinder/provider-config.yaml):
subfinder -d {domain} -all -silent

# With recursive enabled:
subfinder -d {domain} -all -recursive -silent
```

### Search Engine Dorking
Run these via WebSearch tool and extract subdomains from results:
```
site:*.{domain} -www
site:{domain} inurl:admin
site:{domain} inurl:dev OR staging OR test
site:{domain} inurl:api
site:{domain} inurl:beta
"{domain}" filetype:pdf
"{domain}" filetype:xlsx
```

### GitHub Dorking
Search GitHub for leaks of internal hostnames:
```
"{domain}" in:code language:yaml
"{domain}" filename:.env
"{domain}" filename:config.json
"{domain}" filename:docker-compose.yml
"{domain}" in:code "internal"
"{domain}" in:code "staging"
```
Tool: `github-subdomains -d {domain} -t {GITHUB_TOKEN}`

### DNS Record Mining
Extract subdomains from DNS records:
```bash
dig TXT {domain}       # SPF, DKIM, DMARC, others
dig MX {domain}        # Mail servers
dig NS {domain}        # Nameservers (may hint at subdomains)
dig CNAME www.{domain} # CNAME chains
dig CAA {domain}       # Certificate authority authorization
dig SOA {domain}       # Start of Authority
```

### JavaScript / HTML Analysis
- SubDomainizer: scans JS files for subdomain references, cloud buckets
- xnLinkFinder / getallurls (GAU): crawls live pages for subdomain links

---

## ACTIVE (direct DNS queries)

### DNS Brute-Force
```bash
# With dnsx (fast):
dnsx -d {domain} -w wordlist.txt -t 200 -silent

# With puredns (wildcard-aware):
puredns brute wordlist.txt {domain} -r resolvers.txt

# With shuffledns:
shuffledns -d {domain} -w wordlist.txt -r resolvers.txt
```
Recommended wordlists (in order of preference):
1. `SecLists/Discovery/DNS/subdomains-top1million-110000.txt` (110k words)
2. `SecLists/Discovery/DNS/dns-Jhaddix.txt` (trusted community list)
3. `SecLists/Discovery/DNS/subdomains-top1million-20000.txt` (fast, good coverage)

### Zone Transfer Attempt
```bash
# Get nameservers first:
dig NS {domain} +short

# Try AXFR on each:
dig axfr {domain} @ns1.{domain}
dig axfr {domain} @ns2.{domain}
# Most will fail — rare but worth trying
```

### Permutation / Mutation Scanning
Tools (use multiple — each uses different algorithms):
```bash
# alterx (ProjectDiscovery — best for known-pattern extension):
cat known_subs.txt | alterx | dnsx -silent

# dnsgen (intelligent permutations):
cat known_subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S

# gotator:
gotator -sub known_subs.txt -perm permutation_wordlist.txt -depth 1 -numbers 10

# altdns:
altdns -i known_subs.txt -o altdns_out.txt -w altdns_wordlist.txt
```

### Reverse DNS / IP Range Scanning
```bash
# Get ASN for org:
# whois -h whois.radb.net -- '-i origin AS{num}'
# or: curl https://bgp.he.net/AS{num}

# Reverse DNS entire netblock:
for ip in $(seq 1 254); do
  host 10.10.10.$ip 2>/dev/null | grep "{domain}"
done
```

### Virtual Host Discovery
```bash
# ffuf vhost fuzzing (finds apps not in DNS):
ffuf -w subdomains.txt -u http://{ip}/ -H "Host: FUZZ.{domain}" \
  -fs {default_size} -t 100

# gobuster vhost:
gobuster vhost -u http://{ip} -w subdomains.txt --append-domain
```

### ASN-Based Discovery
1. Find ASN: `whois {domain}` or `https://bgp.he.net/`
2. Get IP ranges: `whois -h whois.radb.net -- '-i origin AS{num}'`
3. Reverse DNS scan ranges
4. Check Shodan/Censys for org name

---

## ACQUISITION RESEARCH METHODOLOGY

1. **Crunchbase**: `site:crunchbase.com/organization/{org}/acquisitions`
2. **Tracxn**: `site:tracxn.com "{org}" acquisitions`
3. **Wikipedia**: Search `{org}` page, Acquisitions section
4. **News**: `"{org}" acquired "{company}" site:techcrunch.com OR site:yourstory.com`
5. **Company blog**: `site:{domain}/blog "acquired" OR "acquisition" OR "joining"`
6. For each acquired company → find domain → verify DNS → enumerate

---

## TOOLS PRIORITY ORDER

For maximum coverage with minimum setup:
1. `passive_enum.py` — 14 sources, no API keys needed
2. `subfinder -all` — 50+ sources
3. DNS brute-force (skill wordlist + SecLists)
4. `permutate.py` / `alterx` — extends known subdomains
5. Zone transfer attempt
6. Google/GitHub dorks via WebSearch

With API keys, add: VirusTotal, SecurityTrails, Shodan, Censys, BinaryEdge
