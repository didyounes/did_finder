package output

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

// HTMLReportData holds all data for report generation
type HTMLReportData struct {
	Domain           string
	Subdomains       []SubdomainEntry
	TakeoverVulns    []TakeoverEntry
	WAFDetections    []WAFEntry
	CertInfos        []CertEntry
	PortResults      []PortEntry
	CORSFindings     []CORSEntry
	RedirectFindings []RedirectEntry
	VulnFindings     []VulnEntry
	CurlResults      []CurlEntry
	AIAnalysis       string
	AIModel          string
	Stats            *Stats
	ScanTime         time.Time
}

type SubdomainEntry struct {
	Name   string
	Source string
	IPs    string
	Status int
	Title  string
	Techs  string
}

type TakeoverEntry struct {
	Subdomain string
	CNAME     string
	Service   string
	Vuln      bool
}

type WAFEntry struct {
	Subdomain string
	WAF       string
	Evidence  string
}

type CertEntry struct {
	Subdomain string
	Subject   string
	Issuer    string
	SANCount  int
	Expired   bool
}

type PortEntry struct {
	Subdomain string
	OpenPorts []int
}

type CORSEntry struct {
	Subdomain string
	Origin    string
	Type      string
	WithCreds bool
}

type RedirectEntry struct {
	Subdomain string
	URL       string
	Parameter string
	Location  string
}

type VulnEntry struct {
	Target     string
	TemplateID string
	Name       string
	Severity   string
	Type       string
	MatchedAt  string
	Tags       string
	CVEs       string
}

type CurlEntry struct {
	Target       string
	EffectiveURL string
	Status       int
	ContentType  string
	RemoteIP     string
	Redirects    int
	TimeTotal    float64
	Error        string
}

func GenerateHTMLReport(data HTMLReportData, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>did_finder Report — %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0e17;color:#e0e6ed;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:2rem}
h1{font-size:2.5rem;background:linear-gradient(135deg,#00f2fe,#4facfe,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:0.5rem}
h2{font-size:1.5rem;color:#4facfe;margin:2rem 0 1rem;padding-bottom:0.5rem;border-bottom:1px solid #1e293b}
.meta{color:#64748b;margin-bottom:2rem;font-size:0.9rem}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:linear-gradient(135deg,#111827,#1e293b);border:1px solid #374151;border-radius:12px;padding:1.5rem;text-align:center}
.stat-card .number{font-size:2.5rem;font-weight:700;background:linear-gradient(135deg,#00f2fe,#4facfe);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-card .label{color:#94a3b8;font-size:0.85rem;margin-top:0.25rem}
table{width:100%%;border-collapse:collapse;margin:1rem 0;background:#111827;border-radius:12px;overflow:hidden;border:1px solid #1e293b}
th{background:#1e293b;color:#4facfe;padding:12px 16px;text-align:left;font-weight:600;font-size:0.85rem;text-transform:uppercase;letter-spacing:0.05em}
td{padding:10px 16px;border-bottom:1px solid #1e293b;font-size:0.9rem}
tr:hover td{background:#1a2332}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:0.75rem;font-weight:600}
.badge-red{background:#7f1d1d;color:#fca5a5}
.badge-green{background:#14532d;color:#86efac}
.badge-yellow{background:#713f12;color:#fde047}
.badge-blue{background:#1e3a5f;color:#93c5fd}
.badge-purple{background:#4c1d95;color:#c4b5fd}
.badge-orange{background:#7c2d12;color:#fdba74}
.vuln-alert{background:linear-gradient(135deg,#450a0a,#7f1d1d);border:1px solid #991b1b;border-radius:12px;padding:1rem 1.5rem;margin:0.5rem 0}
.vuln-alert strong{color:#fca5a5}
.ai-analysis{background:#101826;border:1px solid #334155;border-radius:12px;padding:1rem 1.25rem;white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:0.9rem;color:#dbeafe}
.footer{text-align:center;margin-top:3rem;padding-top:1.5rem;border-top:1px solid #1e293b;color:#475569;font-size:0.8rem}
</style>
</head>
<body>
<div class="container">
<h1>🔍 did_finder v3.0</h1>
<p class="meta">Scan Report for <strong>%s</strong> — Generated %s</p>

<div class="stats-grid">
<div class="stat-card"><div class="number">%d</div><div class="label">Subdomains Found</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Takeover Checks</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">WAF Detected</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Certificates</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Port Scans</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">CORS Vulns</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Open Redirects</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Nuclei Findings</div></div>
<div class="stat-card"><div class="number">%d</div><div class="label">Curl Fingerprints</div></div>
</div>
`

	fmt.Fprintf(f, tmpl,
		html.EscapeString(data.Domain),
		html.EscapeString(data.Domain),
		data.ScanTime.Format("2006-01-02 15:04:05 UTC"),
		len(data.Subdomains),
		len(data.TakeoverVulns),
		len(data.WAFDetections),
		len(data.CertInfos),
		len(data.PortResults),
		len(data.CORSFindings),
		len(data.RedirectFindings),
		len(data.VulnFindings),
		len(data.CurlResults),
	)

	// Takeover section
	if len(data.TakeoverVulns) > 0 {
		fmt.Fprintln(f, `<h2>🚨 Subdomain Takeover</h2>`)
		for _, t := range data.TakeoverVulns {
			if t.Vuln {
				fmt.Fprintf(f, `<div class="vuln-alert"><strong>VULNERABLE:</strong> %s → %s (%s)</div>`+"\n",
					html.EscapeString(t.Subdomain), html.EscapeString(t.CNAME), html.EscapeString(t.Service))
			}
		}
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>CNAME</th><th>Service</th><th>Status</th></tr>`)
		for _, t := range data.TakeoverVulns {
			status := `<span class="badge badge-yellow">Check</span>`
			if t.Vuln {
				status = `<span class="badge badge-red">VULNERABLE</span>`
			}
			fmt.Fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(t.Subdomain), html.EscapeString(t.CNAME), html.EscapeString(t.Service), status)
		}
		fmt.Fprintln(f, `</table>`)
	}

	// CORS section
	if len(data.CORSFindings) > 0 {
		fmt.Fprintln(f, `<h2>🔓 CORS Misconfigurations</h2>`)
		for _, c := range data.CORSFindings {
			fmt.Fprintf(f, `<div class="vuln-alert"><strong>CORS:</strong> %s — %s (credentials: %v)</div>`+"\n",
				html.EscapeString(c.Subdomain), html.EscapeString(c.Type), c.WithCreds)
		}
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>Type</th><th>Origin</th><th>Credentials</th></tr>`)
		for _, c := range data.CORSFindings {
			creds := `<span class="badge badge-green">No</span>`
			if c.WithCreds {
				creds = `<span class="badge badge-red">Yes</span>`
			}
			fmt.Fprintf(f, "<tr><td>%s</td><td><span class=\"badge badge-orange\">%s</span></td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(c.Subdomain), html.EscapeString(c.Type),
				html.EscapeString(c.Origin), creds)
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Open Redirect section
	if len(data.RedirectFindings) > 0 {
		fmt.Fprintln(f, `<h2>↪️ Open Redirects</h2>`)
		for _, r := range data.RedirectFindings {
			fmt.Fprintf(f, `<div class="vuln-alert"><strong>REDIRECT:</strong> %s — param: %s → %s</div>`+"\n",
				html.EscapeString(r.Subdomain), html.EscapeString(r.Parameter), html.EscapeString(r.Location))
		}
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>Parameter</th><th>Redirect To</th></tr>`)
		for _, r := range data.RedirectFindings {
			fmt.Fprintf(f, "<tr><td>%s</td><td><span class=\"badge badge-yellow\">%s</span></td><td>%s</td></tr>\n",
				html.EscapeString(r.Subdomain), html.EscapeString(r.Parameter), html.EscapeString(r.Location))
		}
		fmt.Fprintln(f, `</table>`)
	}

	// WAF section
	if len(data.WAFDetections) > 0 {
		fmt.Fprintln(f, `<h2>🛡️ WAF Detection</h2>`)
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>WAF</th><th>Evidence</th></tr>`)
		for _, w := range data.WAFDetections {
			fmt.Fprintf(f, "<tr><td>%s</td><td><span class=\"badge badge-purple\">%s</span></td><td>%s</td></tr>\n",
				html.EscapeString(w.Subdomain), html.EscapeString(w.WAF), html.EscapeString(w.Evidence))
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Port scan section
	if len(data.PortResults) > 0 {
		fmt.Fprintln(f, `<h2>🔌 Open Ports</h2>`)
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>Open Ports</th><th>Count</th></tr>`)
		for _, p := range data.PortResults {
			portStrs := make([]string, len(p.OpenPorts))
			for i, port := range p.OpenPorts {
				portStrs[i] = fmt.Sprintf("%d", port)
			}
			fmt.Fprintf(f, "<tr><td>%s</td><td>%s</td><td><span class=\"badge badge-blue\">%d</span></td></tr>\n",
				html.EscapeString(p.Subdomain), html.EscapeString(strings.Join(portStrs, ", ")), len(p.OpenPorts))
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Nuclei vulnerability section
	if len(data.VulnFindings) > 0 {
		fmt.Fprintln(f, `<h2>🧪 Nuclei Vulnerability Findings</h2>`)
		for _, v := range data.VulnFindings {
			if strings.EqualFold(v.Severity, "critical") || strings.EqualFold(v.Severity, "high") {
				fmt.Fprintf(f, `<div class="vuln-alert"><strong>%s:</strong> %s — %s</div>`+"\n",
					html.EscapeString(strings.ToUpper(v.Severity)), html.EscapeString(v.Target), html.EscapeString(v.Name))
			}
		}
		fmt.Fprintln(f, `<table><tr><th>Severity</th><th>Target</th><th>Name</th><th>Template</th><th>CVEs</th><th>Tags</th></tr>`)
		for _, v := range data.VulnFindings {
			color := "badge-blue"
			switch strings.ToLower(v.Severity) {
			case "critical", "high":
				color = "badge-red"
			case "medium":
				color = "badge-yellow"
			case "low":
				color = "badge-green"
			}
			fmt.Fprintf(f, "<tr><td><span class=\"badge %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				color, html.EscapeString(strings.ToUpper(v.Severity)),
				html.EscapeString(v.Target), html.EscapeString(v.Name),
				html.EscapeString(v.TemplateID), html.EscapeString(v.CVEs),
				html.EscapeString(v.Tags))
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Curl fingerprint section
	if len(data.CurlResults) > 0 {
		fmt.Fprintln(f, `<h2>🧵 Curl Fingerprints</h2>`)
		fmt.Fprintln(f, `<table><tr><th>Target</th><th>Effective URL</th><th>Status</th><th>Type</th><th>Remote IP</th><th>Redirects</th><th>Total Time</th><th>Error</th></tr>`)
		for _, c := range data.CurlResults {
			statusBadge := ""
			if c.Status > 0 {
				color := "badge-green"
				if c.Status >= 400 {
					color = "badge-red"
				} else if c.Status >= 300 {
					color = "badge-yellow"
				}
				statusBadge = fmt.Sprintf(`<span class="badge %s">%d</span>`, color, c.Status)
			}
			fmt.Fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%.3fs</td><td>%s</td></tr>\n",
				html.EscapeString(c.Target), html.EscapeString(c.EffectiveURL), statusBadge,
				html.EscapeString(c.ContentType), html.EscapeString(c.RemoteIP),
				c.Redirects, c.TimeTotal, html.EscapeString(c.Error))
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Subdomains table
	fmt.Fprintln(f, `<h2>📋 Discovered Subdomains</h2>`)
	fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>Source</th><th>IPs</th><th>Status</th><th>Title</th><th>Technologies</th></tr>`)
	for _, s := range data.Subdomains {
		statusBadge := ""
		if s.Status > 0 {
			color := "badge-green"
			if s.Status >= 400 {
				color = "badge-red"
			} else if s.Status >= 300 {
				color = "badge-yellow"
			}
			statusBadge = fmt.Sprintf(`<span class="badge %s">%d</span>`, color, s.Status)
		}
		fmt.Fprintf(f, "<tr><td>%s</td><td><span class=\"badge badge-blue\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(s.Name), html.EscapeString(s.Source),
			html.EscapeString(s.IPs), statusBadge,
			html.EscapeString(s.Title), html.EscapeString(s.Techs))
	}
	fmt.Fprintln(f, `</table>`)

	// Certs section
	if len(data.CertInfos) > 0 {
		fmt.Fprintln(f, `<h2>🔐 SSL/TLS Certificates</h2>`)
		fmt.Fprintln(f, `<table><tr><th>Subdomain</th><th>Subject</th><th>Issuer</th><th>SANs</th><th>Status</th></tr>`)
		for _, c := range data.CertInfos {
			status := `<span class="badge badge-green">Valid</span>`
			if c.Expired {
				status = `<span class="badge badge-red">Expired</span>`
			}
			fmt.Fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>\n",
				html.EscapeString(c.Subdomain), html.EscapeString(c.Subject),
				html.EscapeString(c.Issuer), c.SANCount, status)
		}
		fmt.Fprintln(f, `</table>`)
	}

	// Local AI analysis
	if data.AIAnalysis != "" {
		title := "Local AI Analysis"
		if data.AIModel != "" {
			title = "Local AI Analysis - " + data.AIModel
		}
		fmt.Fprintf(f, `<h2>🤖 %s</h2>`+"\n", html.EscapeString(title))
		fmt.Fprintf(f, `<div class="ai-analysis">%s</div>`+"\n", html.EscapeString(data.AIAnalysis))
	}

	// Source breakdown
	if data.Stats != nil {
		fmt.Fprintln(f, `<h2>📊 Source Breakdown</h2>`)
		fmt.Fprintln(f, `<table><tr><th>Source</th><th>Count</th></tr>`)
		data.Stats.mu.Lock()
		for source, count := range data.Stats.SourceCounts {
			fmt.Fprintf(f, "<tr><td>%s</td><td>%d</td></tr>\n", html.EscapeString(source), count)
		}
		data.Stats.mu.Unlock()
		fmt.Fprintln(f, `</table>`)
	}

	footer := `
<div class="footer">
Generated by <strong>did_finder v3.0</strong> — Advanced Subdomain Discovery Engine<br>
` + strings.Repeat("─", 40) + `
</div>
</div>
</body>
</html>`
	fmt.Fprintln(f, footer)

	return nil
}
