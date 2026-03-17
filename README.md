<p align="center">
  <h1 align="center">🔍 did_finder</h1>
  <p align="center">Advanced Subdomain Discovery Engine — Fast, modular, and feature-rich</p>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#modules">Modules</a>
</p>

---

## Features

**did_finder** is an advanced subdomain enumeration tool built in Go. It combines **15 passive sources** with **12 active modules** for comprehensive subdomain discovery and security analysis.

### Passive Sources
| Source | API Key Required |
|---|---|
| crt.sh, HackerTarget, AlienVault OTX, Wayback Machine | ❌ |
| CertSpotter, Anubis, ThreatCrowd, RapidDNS, URLScan | ❌ |
| BufferOver, CommonCrawl | ❌ |
| VirusTotal, SecurityTrails, Shodan, GitHub | ✅ |

### Active Modules
- 🔍 **DNS Resolution** — Filter alive subdomains
- 🌐 **HTTP Probing** — Status codes, titles, server headers, tech fingerprinting
- 💣 **DNS Bruteforce** — Built-in wordlist + custom wordlists
- 🔄 **Permutations** — Intelligent subdomain permutation
- 🕸️ **Web Scraping** — Discover subdomains from live page content
- 🔐 **SSL/TLS Cert Grabbing** — Extract SANs for new subdomains
- 📡 **DNS Enumeration** — Full record types (A, AAAA, CNAME, MX, TXT)
- ⚡ **Zone Transfer** — AXFR attempt on nameservers
- 🌀 **CIDR Reverse DNS** — Reverse lookup across IP ranges
- 🎯 **Subdomain Takeover** — 35+ service fingerprints
- 🛡️ **WAF Detection** — 15+ WAF signatures
- 🔌 **Port Scanning** — Top 100 ports TCP connect scan
- 🔓 **CORS Misconfiguration** — Reflected origin, null origin, wildcard+creds
- ↪️ **Open Redirect** — 30+ redirect parameters tested
- 📸 **Screenshots** — Headless Chrome/Chromium capture
- 🔁 **Recursive Enumeration** — Configurable depth

### Output & Reporting
- 📊 **HTML Report** — Beautiful dark-themed report with all findings
- 📝 **JSON / CSV / Plain** — Machine-readable output formats
- 💾 **Resume** — Checkpoint and resume interrupted scans
- 📣 **Webhooks** — Discord & Slack notifications
- 📈 **Progress Bar** — Real-time scan progress

---

## Installation

### From Source
```bash
go install github.com/yel-joul/did_finder/cmd/did_finder@latest
```

### Build Locally
```bash
git clone https://github.com/yel-joul/did_finder.git
cd did_finder
go build -o did_finder ./cmd/did_finder
```

---

## Usage

### Basic
```bash
# Single domain
did_finder -d example.com

# Multiple domains from file
did_finder -dL domains.txt

# Pipe from stdin
echo "example.com" | did_finder
```

### Full Scan
```bash
# Enable ALL modules
did_finder -d example.com -all -report report.html

# Custom combination
did_finder -d example.com -resolve -probe -takeover -cors -ports -v
```

### Output
```bash
# JSON output
did_finder -d example.com -json -o results.json

# CSV output
did_finder -d example.com -csv -o results.csv

# Silent mode (subdomains only, great for piping)
did_finder -d example.com -silent | httpx
```

### Advanced
```bash
# Custom resolvers
did_finder -d example.com -resolve -r 8.8.8.8
did_finder -d example.com -resolve -rL resolvers.txt

# Exclude patterns
did_finder -d example.com -exclude "*.staging.*,*.dev.*"

# Resume interrupted scan
did_finder -d example.com -all    # Ctrl+C to interrupt
did_finder -d example.com -all -resume

# Custom wordlist + bruteforce
did_finder -d example.com -brute -w /path/to/wordlist.txt

# Screenshots (requires Chrome/Chromium)
did_finder -d example.com -resolve -screenshot -oD ./results
```

---

## Flags

| Flag | Description | Default |
|---|---|---|
| `-d` | Target domain | |
| `-dL` | File containing domains | |
| `-t` | Concurrent threads | `30` |
| `-timeout` | Timeout in seconds | `30` |
| `-o` | Output file path | |
| `-oD` | Output directory | `output` |
| `-v` | Verbose output | `false` |
| `-silent` | Only print subdomains | `false` |
| `-json` | JSONL output | `false` |
| `-csv` | CSV output | `false` |
| `-all` | Enable all modules | `false` |
| `-resolve` | DNS resolution | `false` |
| `-probe` | HTTP probing | `false` |
| `-brute` | DNS bruteforce | `false` |
| `-w` | Custom wordlist | |
| `-permute` | Permutation generation | `false` |
| `-scrape` | Web scraping | `false` |
| `-recursive` | Recursive enumeration | `false` |
| `-depth` | Recursion depth | `2` |
| `-certs` | SSL/TLS cert grabbing | `false` |
| `-dns-enum` | DNS record enumeration | `false` |
| `-zt` | Zone transfer attempt | `false` |
| `-cidr` | CIDR reverse DNS | `false` |
| `-takeover` | Subdomain takeover check | `false` |
| `-waf` | WAF detection | `false` |
| `-ports` | Port scanning (top 100) | `false` |
| `-cors` | CORS misconfig check | `false` |
| `-redirect` | Open redirect check | `false` |
| `-screenshot` | Screenshot capture | `false` |
| `-r` | Custom DNS resolver | |
| `-rL` | Resolver list file | |
| `-exclude` | Exclude patterns (comma-sep) | |
| `-resume` | Resume interrupted scan | `false` |
| `-report` | Generate HTML report | |
| `-config` | Config file path | |
| `-proxy` | HTTP/SOCKS5 proxy | |
| `-nc` | Disable colors | `false` |

---

## Configuration

Create `~/.config/did_finder/config.yaml` or `~/.did_finder.yaml`:

```yaml
# API Keys
virustotal: "YOUR_VT_KEY"
securitytrails: "YOUR_ST_KEY"
shodan: "YOUR_SHODAN_KEY"
github: "YOUR_GITHUB_TOKEN"

# Custom resolvers
resolvers:
  - "8.8.8.8"
  - "1.1.1.1"
  - "9.9.9.9"

# Webhook notifications
webhook:
  discord: "https://discord.com/api/webhooks/..."
  slack: "https://hooks.slack.com/services/..."
```

---

## Modules

### Subdomain Takeover Detection
Checks 35+ services including: GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, Netlify, Vercel, Cloudflare, and more.

### WAF Detection
Identifies 15+ WAFs: Cloudflare, AWS WAF/CloudFront, Akamai, Sucuri, Imperva, ModSecurity, F5 BIG-IP, Barracuda, FortiWeb, and more.

### Technology Fingerprinting
Detects frameworks and technologies from HTTP headers and body content: WordPress, React, Angular, Vue.js, Next.js, Laravel, Django, Rails, and more.

### CORS Misconfiguration
Tests for:
- **Reflected Origin** — Server reflects attacker origin
- **Null Origin** — Server allows `null` origin
- **Wildcard + Credentials** — `*` with `Access-Control-Allow-Credentials: true`
- **Prefix Bypass** — Bypass via `evil-target.com`

### Open Redirect
Tests 30+ common redirect parameters (`url`, `redirect`, `next`, `dest`, `return_to`, etc.)

---

## License

MIT License

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/yel-joul">yel-joul</a>
</p>
