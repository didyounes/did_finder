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
- 🧪 **Vulnerability Scanning** — Open-source Nuclei templates for CVEs, exposures, misconfigs, and tech-specific checks
- 🧵 **Advanced Curl Fingerprints** — Open-source curl metrics, redirects, remote IPs, content types, and replay scripts
- 📸 **Screenshots** — Headless Chrome/Chromium capture
- 🔁 **Recursive Enumeration** — Configurable depth

### Output & Reporting
- 📊 **HTML Report** — Beautiful dark-themed report with all findings
- 📝 **JSON / CSV / Plain** — Machine-readable output formats
- 🤖 **Local Ollama Analysis** — Optional AI triage and next-step recommendations
- 🧰 **Bug Bounty Tool Catalog** — Embedded `awesome-bugbounty-tools` search, recommendations, and PATH checks
- 💾 **Resume** — Checkpoint and resume interrupted scans
- 📣 **Webhooks** — Discord & Slack notifications
- 📈 **Progress Bar** — Real-time scan progress

---

## Installation

### From Source
```bash
go install github.com/yel-joul/did_finder/cmd/did_finder@latest
```

If your shell cannot find `did_finder` after install, add your Go bin directory to `PATH`:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Build Locally
```bash
git clone https://github.com/yel-joul/did_finder.git
cd did_finder
go build -o did_finder ./cmd/did_finder
```

### Workstation Setup
```bash
# Build and install did_finder into your Go bin directory
make install

# Pull the default local AI model
make ollama-pull

# Install and update the open-source Nuclei scanner/templates
make nuclei-install
make nuclei-update

# Check Go, did_finder, Ollama, Nuclei, config, and screenshot dependencies
make doctor
```

---

## Usage

### Basic
```bash
# Single domain
did_finder -d example.com

# Multiple domains from file
did_finder -dL domains.txt

# Lists may contain domains, subdomains, URLs, blank lines, and # comments
did_finder -dL targets.txt

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

# Passive source control and confidence filtering
did_finder -list-sources
did_finder -d example.com -sources crtsh,certspotter,urlscan
did_finder -d example.com -exclude-sources commoncrawl,wayback -min-sources 2
did_finder -d example.com -interesting -json

# Resume interrupted scan
did_finder -d example.com -all    # Ctrl+C to interrupt
did_finder -d example.com -all -resume

# Custom wordlist + bruteforce
did_finder -d example.com -brute -w /path/to/wordlist.txt

# Screenshots (requires Chrome/Chromium)
did_finder -d example.com -resolve -screenshot -oD ./results

# Local AI analysis with Ollama (requires a pulled model)
did_finder -d example.com -all -ollama -ollama-model llama3.2:1b -report report.html
did_finder -d example.com -takeover -cors -redirect -ollama -ollama-out output/example-ai.md

# Open-source vulnerability scanning with Nuclei
did_finder -d example.com -resolve -probe -vuln -report report.html
did_finder -d example.com -all -vuln-all -vuln-update -vuln-output output/example-nuclei.jsonl
did_finder -d example.com -vuln -vuln-tags cve,rce -vuln-severity critical,high

# Advanced curl fingerprints and replay commands
did_finder -d example.com -resolve -probe -curl -report report.html
did_finder -d example.com -all -curl-export output/{domain}-replay.sh
did_finder -d example.com -curl -curl-headers "X-Bug-Bounty: did_finder"

# Merged awesome-bugbounty-tools catalog
did_finder -tools
did_finder -tools-search takeover -tools-check
did_finder -tools-recommend -all -tools-check
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
| `-rate` | Passive source request rate limit | `5` |
| `-list-sources` | List passive source names and exit | `false` |
| `-sources` | Comma-separated passive sources to include | |
| `-exclude-sources` | Comma-separated passive sources to skip | |
| `-min-sources` | Keep only hosts found by at least N sources | `1` |
| `-interesting` | Keep only high-signal hosts based on labels/source confidence | `false` |
| `-ollama` | Analyze findings with local Ollama | `false` |
| `-ollama-host` | Ollama host URL | `http://127.0.0.1:11434` |
| `-ollama-model` | Ollama model name | `llama3.2:1b` |
| `-ollama-out` | Write Ollama Markdown analysis to file | |
| `-vuln` | Run open-source Nuclei vulnerability scanning | `false` |
| `-vuln-all` | Run all default Nuclei template severities | `false` |
| `-vuln-templates` | Comma-separated Nuclei template paths | |
| `-vuln-severity` | Nuclei severity filter | `low,medium,high,critical` |
| `-vuln-tags` | Nuclei tags to include | |
| `-vuln-exclude-tags` | Nuclei tags to exclude | `dos,fuzz,intrusive` |
| `-vuln-rate` | Nuclei maximum requests per second | `50` |
| `-vuln-concurrency` | Nuclei template concurrency | `25` |
| `-vuln-output` | Write Nuclei JSONL findings to file | |
| `-vuln-update` | Update Nuclei templates before scanning | `false` |
| `-vuln-headless` | Enable Nuclei headless templates | `false` |
| `-vuln-code` | Enable Nuclei code protocol templates | `false` |
| `-vuln-dast` | Enable Nuclei DAST/fuzz templates | `false` |
| `-vuln-include-aggressive` | Do not exclude dos/fuzz/intrusive tags | `false` |
| `-nuclei-bin` | Path/name of nuclei binary | `nuclei` |
| `-curl` | Run advanced curl HTTP fingerprinting | `false` |
| `-curl-export` | Write replayable curl commands to a shell script | |
| `-curl-bin` | Path/name of curl binary | `curl` |
| `-curl-user-agent` | User-Agent for curl requests | `did_finder/3.0` |
| `-curl-headers` | Comma-separated extra curl headers | |
| `-curl-timeout` | Curl max time and connect timeout | `15` |
| `-curl-follow` | Follow redirects with curl | `true` |
| `-tools` | Show embedded awesome-bugbounty-tools catalog | `false` |
| `-tools-category` | Filter tool catalog by category | |
| `-tools-search` | Search tool catalog | |
| `-tools-check` | Check whether listed tools are installed in PATH | `false` |
| `-tools-json` | Print tool catalog as JSON | `false` |
| `-tools-recommend` | Recommend companion tools for enabled modules | `false` |
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

# Local Ollama analysis
ollama:
  enabled: false
  host: "http://127.0.0.1:11434"
  model: "llama3.2:1b"
  output: ""

# Open-source Nuclei vulnerability scanning
nuclei:
  enabled: false
  binary: "nuclei"
  templates: []
  severity: "low,medium,high,critical"
  tags: ""
  exclude_tags: "dos,fuzz,intrusive"
  rate_limit: 50
  concurrency: 25
  output: ""
  update_templates: false
  headless: false
  code: false
  dast: false
  include_aggressive: false

# Advanced curl fingerprints and replay script export
curl:
  enabled: false
  binary: "curl"
  output: ""
  user_agent: "did_finder/3.0"
  headers: []
  timeout: 15
  follow_redirects: true
```

The embedded tool catalog is imported from [`vavkamil/awesome-bugbounty-tools`](https://github.com/vavkamil/awesome-bugbounty-tools), which is released under CC0-1.0.

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

### Open-Source Vulnerability Scanning
Runs Nuclei against discovered targets and folds JSONL findings into terminal output, `-json`, `-vuln-output`, HTML reports, and optional Ollama triage. By default it scans `low,medium,high,critical` findings and excludes `dos,fuzz,intrusive` tags; `-vuln-all`, `-vuln-headless`, `-vuln-code`, `-vuln-dast`, and `-vuln-include-aggressive` expose broader Nuclei modes when you want them.

### Advanced Curl Mode
Runs `curl` against live targets with compression, path-preserving requests, TLS ignore for recon, timing metrics, redirect counts, remote IPs, content types, and status codes. `-curl-export` writes a replayable shell script for live targets, Nuclei findings, and open redirect checks so manual validation can start from exact commands.

---

## License

MIT License

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/yel-joul">yel-joul</a>
</p>
