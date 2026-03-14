# did_finder

<p align="center">
<b>Advanced Subdomain Discovery Engine</b><br>
<i>Faster. Deeper. Smarter than subfinder.</i>
</p>

---

`did_finder` is an elite-tier subdomain enumeration tool written in Go. It combines **11+ passive sources** with powerful **active intelligence modules** — DNS bruteforce, subdomain takeover detection, WAF fingerprinting, SSL/TLS cert analysis, recursive enumeration, and more — all in a single binary.

## Features

### Passive Sources (11+)
| Source | Auth Required |
|--------|:---:|
| crt.sh | ✗ |
| HackerTarget | ✗ |
| AlienVault OTX | ✗ |
| Wayback Machine | ✗ |
| CertSpotter | ✗ |
| AnubisDB | ✗ |
| ThreatCrowd | ✗ |
| RapidDNS | ✗ |
| URLScan | ✗ |
| VirusTotal | API Key |
| SecurityTrails | API Key |

### Active Intelligence Modules
| Module | Flag | Description |
|--------|------|-------------|
| DNS Resolution | `-resolve` | Mass resolve subdomains, auto wildcard filtering |
| HTTP Probing | `-probe` | Status codes, titles, server headers, **technology fingerprinting** |
| DNS Bruteforce | `-brute` | Built-in 200+ word wordlist targeting modern infra |
| Subdomain Takeover | `-takeover` | **35+ service fingerprints** (GitHub, S3, Heroku, Azure, Netlify...) |
| WAF Detection | `-waf` | **15+ WAF signatures** (Cloudflare, AWS, Akamai, Imperva...) |
| SSL/TLS Certs | `-certs` | Grab certs, extract SANs for hidden subdomains |
| DNS Enumeration | `-dns-enum` | Full A/AAAA/CNAME/MX/NS/TXT records |
| Permutations | `-permute` | Smart subdomain permutation engine |
| Web Scraping | `-scrape` | Crawl live hosts, extract subdomains from HTML/JS |
| Recursive | `-recursive` | Enumerate subs-of-subs with configurable depth |
| Zone Transfer | `-zt` | AXFR zone transfer testing |
| CIDR Reverse DNS | `-cidr` | Reverse DNS scan of the /24 IP range |
| **All-in-One** | `-all` | Enable resolve + probe + takeover + waf + certs + brute + permute |

### Output & Operations
| Feature | Flag |
|---------|------|
| JSON output | `-json` |
| CSV output | `-csv` |
| File output | `-o file` |
| HTML Report | `-report file.html` |
| Silent mode | `-silent` |
| Multi-domain file | `-dL file` |
| Stdin pipe | `cat domains.txt \| did_finder` |
| Proxy support | `-proxy socks5://...` |
| Rate limiting | `-rate N` |
| Config file | `-config path` |
| Verbose | `-v` |
| Threads | `-t N` |
| Timeout | `-timeout N` |

## Installation

```bash
git clone https://github.com/yel-joul/did_finder.git
cd did_finder
go build -o did_finder ./cmd/did_finder/
sudo mv did_finder /usr/local/bin/
```

## Usage

```bash
# Basic passive scan
did_finder -d example.com

# Full arsenal scan (the nuclear option)
did_finder -d example.com -all -v -report report.html

# Resolve + probe + takeover check
did_finder -d example.com -resolve -probe -takeover

# Bruteforce + resolve
did_finder -d example.com -brute -resolve -v

# Deep recursive scan
did_finder -d example.com -recursive -depth 3 -resolve -probe

# Multiple targets with JSON output
did_finder -dL targets.txt -resolve -json -o results.jsonl

# Pipe from stdin, output only subs
cat domains.txt | did_finder -resolve -silent

# Through Tor
did_finder -d example.com -proxy socks5://127.0.0.1:9050

# Custom bruteforce wordlist
did_finder -d example.com -brute -w /path/to/wordlist.txt -resolve
```

## Configuration

Create `~/.config/did_finder/config.yaml`:

```yaml
virustotal: "YOUR_VT_API_KEY"
securitytrails: "YOUR_ST_API_KEY"

webhook:
  discord: "https://discord.com/api/webhooks/..."
  slack: "https://hooks.slack.com/services/..."
```

## Output Examples

### Terminal (colored)
```
    ____  _ ____    _____           __
   / __ \(_) __ \  / __(_)___  ____/ /__  _____
  / / / / / / / / / /_/ / __ \/ __  / _ \/ ___/
 / /_/ / / /_/ / / __/ / / / / /_/ /  __/ /
/_____/_/_____/ /_/ /_/_/ /_/\__,_/\___/_/

[INF] Loaded 11 passive sources
[INF] Active modules: DNS Resolution, HTTP Probing, Takeover Detection, WAF Detection
api.example.com [hackertarget]
dev.example.com [anubisdb]
[TAKEOVER] old.example.com → old.example.com.s3.amazonaws.com (AWS S3) [POTENTIALLY VULNERABLE]
[WAF] api.example.com → Cloudflare
```

### HTML Report
Beautiful dark-themed report with gradient cards, vulnerability alerts, and per-source statistics. Generated with `-report output.html`.

## License

MIT
