package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yel-joul/did_finder/internal/active"
	"github.com/yel-joul/did_finder/internal/ai"
	"github.com/yel-joul/did_finder/internal/output"
	"github.com/yel-joul/did_finder/internal/sources"
	"github.com/yel-joul/did_finder/internal/sources/alienvault"
	"github.com/yel-joul/did_finder/internal/sources/anubis"
	"github.com/yel-joul/did_finder/internal/sources/bufferover"
	"github.com/yel-joul/did_finder/internal/sources/certspotter"
	"github.com/yel-joul/did_finder/internal/sources/commoncrawl"
	"github.com/yel-joul/did_finder/internal/sources/crtsh"
	"github.com/yel-joul/did_finder/internal/sources/github"
	"github.com/yel-joul/did_finder/internal/sources/hackertarget"
	"github.com/yel-joul/did_finder/internal/sources/rapiddns"
	"github.com/yel-joul/did_finder/internal/sources/securitytrails"
	"github.com/yel-joul/did_finder/internal/sources/shodan"
	"github.com/yel-joul/did_finder/internal/sources/threatcrowd"
	"github.com/yel-joul/did_finder/internal/sources/urlscan"
	"github.com/yel-joul/did_finder/internal/sources/virustotal"
	"github.com/yel-joul/did_finder/internal/sources/wayback"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Runner struct {
	options  *Options
	stats    *output.Stats
	progress *output.Progress
	outFile  *os.File
	config   *utils.Config

	// Collected data for HTML report
	reportSubdomains []output.SubdomainEntry
	reportTakeovers  []output.TakeoverEntry
	reportWAFs       []output.WAFEntry
	reportCerts      []output.CertEntry
	reportPorts      []output.PortEntry
	reportCORS       []output.CORSEntry
	reportRedirects  []output.RedirectEntry
	reportVulns      []output.VulnEntry
	reportCurl       []output.CurlEntry
	reportAIAnalysis string
}

func NewRunner(options *Options) (*Runner, error) {
	if len(options.Domains) == 0 {
		return nil, errors.New("no domains specified. Use -d, -dL, or pipe via stdin")
	}

	config, err := utils.LoadConfig(options.ConfigPath)
	if err != nil && options.Verbose {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
	}
	if config == nil {
		config = &utils.Config{}
	}

	// Merge resolvers from config if none provided via CLI
	if len(options.Resolvers) == 0 && len(config.Resolvers) > 0 {
		options.Resolvers = config.Resolvers
	}
	if config.Ollama.Enabled {
		options.Ollama = true
	}
	if options.OllamaHost == "" {
		if config.Ollama.Host != "" {
			options.OllamaHost = config.Ollama.Host
		} else {
			options.OllamaHost = ai.DefaultOllamaHost
		}
	}
	if options.OllamaModel == "" {
		if config.Ollama.Model != "" {
			options.OllamaModel = config.Ollama.Model
		} else {
			options.OllamaModel = ai.DefaultOllamaModel
		}
	}
	if options.OllamaOutput == "" {
		options.OllamaOutput = config.Ollama.Output
	}
	if config.Nuclei.Enabled {
		options.VulnScan = true
	}
	if options.NucleiBinary == "" || options.NucleiBinary == active.DefaultNucleiBinary {
		if config.Nuclei.Binary != "" {
			options.NucleiBinary = config.Nuclei.Binary
		} else if options.NucleiBinary == "" {
			options.NucleiBinary = active.DefaultNucleiBinary
		}
	}
	if options.VulnTemplates == "" && len(config.Nuclei.Templates) > 0 {
		options.VulnTemplates = strings.Join(config.Nuclei.Templates, ",")
	}
	if options.VulnSeverity == "low,medium,high,critical" && config.Nuclei.Severity != "" {
		options.VulnSeverity = config.Nuclei.Severity
	}
	if options.VulnTags == "" {
		options.VulnTags = config.Nuclei.Tags
	}
	if options.VulnExcludeTags == "dos,fuzz,intrusive" && config.Nuclei.ExcludeTags != "" {
		options.VulnExcludeTags = config.Nuclei.ExcludeTags
	}
	if options.VulnRateLimit == 50 && config.Nuclei.RateLimit > 0 {
		options.VulnRateLimit = config.Nuclei.RateLimit
	}
	if options.VulnConcurrency == 25 && config.Nuclei.Concurrency > 0 {
		options.VulnConcurrency = config.Nuclei.Concurrency
	}
	if options.VulnOutput == "" {
		options.VulnOutput = config.Nuclei.Output
	}
	if config.Nuclei.UpdateTemplates {
		options.VulnUpdateTemplates = true
	}
	if config.Nuclei.Headless {
		options.VulnHeadless = true
	}
	if config.Nuclei.Code {
		options.VulnCode = true
	}
	if config.Nuclei.DAST {
		options.VulnDAST = true
	}
	if config.Nuclei.IncludeAggressive {
		options.VulnIncludeAggressive = true
		options.VulnExcludeTags = ""
	}
	if config.Curl.Enabled {
		options.Curl = true
	}
	if options.CurlBinary == "" || options.CurlBinary == active.DefaultCurlBinary {
		if config.Curl.Binary != "" {
			options.CurlBinary = config.Curl.Binary
		} else if options.CurlBinary == "" {
			options.CurlBinary = active.DefaultCurlBinary
		}
	}
	if options.CurlExport == "" {
		options.CurlExport = config.Curl.Output
	}
	if options.CurlUserAgent == "did_finder/3.0" && config.Curl.UserAgent != "" {
		options.CurlUserAgent = config.Curl.UserAgent
	}
	if options.CurlHeaders == "" && len(config.Curl.Headers) > 0 {
		options.CurlHeaders = strings.Join(config.Curl.Headers, ",")
	}
	if options.CurlTimeout == 15 && config.Curl.Timeout > 0 {
		options.CurlTimeout = config.Curl.Timeout
	}
	if config.Curl.FollowRedirects != nil {
		options.CurlFollow = *config.Curl.FollowRedirects
	}

	r := &Runner{
		options:  options,
		stats:    output.NewStats(),
		progress: output.NewProgress(!options.Silent && !options.JSON),
		config:   config,
	}

	if options.OutputFile != "" {
		f, err := os.Create(options.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("could not create output file: %w", err)
		}
		r.outFile = f
	}

	// Create output directory
	os.MkdirAll(options.OutputDir, 0755)

	return r, nil
}

func (r *Runner) Run() error {
	if r.outFile != nil {
		defer r.outFile.Close()
	}

	sourceCount := 11
	if r.config.VirusTotal != "" {
		sourceCount++
	}
	if r.config.SecurityTrails != "" {
		sourceCount++
	}
	if r.config.Shodan != "" {
		sourceCount++
	}
	if r.config.GitHub != "" {
		sourceCount++
	}

	if !r.options.Silent {
		output.PrintBanner()
		output.PrintInfo("Loaded %d passive sources", sourceCount)
		output.PrintInfo("Targets: %d domain(s)", len(r.options.Domains))
		if len(r.options.Resolvers) > 0 {
			output.PrintInfo("Custom resolvers: %d", len(r.options.Resolvers))
		}
		if len(r.options.ExcludePatterns) > 0 {
			output.PrintInfo("Exclude patterns: %s", strings.Join(r.options.ExcludePatterns, ", "))
		}
		r.printEnabledFeatures()
		fmt.Println()
	}

	if r.options.CSV {
		r.writeOutput("subdomain,source,ip,status,title,techs")
	}

	for _, domain := range r.options.Domains {
		if err := r.runDomain(domain); err != nil {
			if !r.options.Silent {
				output.PrintError("Error for %s: %s", domain, err)
			}
		}
	}

	if !r.options.Silent {
		r.stats.PrintSummary()
	}

	// Clean up state file on successful completion
	ClearState()

	return nil
}

func (r *Runner) printEnabledFeatures() {
	features := []struct {
		enabled bool
		label   string
	}{
		{r.options.Resolve, "DNS Resolution"},
		{r.options.Probe, "HTTP Probing"},
		{r.options.Bruteforce, "DNS Bruteforce"},
		{r.options.Permute, "Permutations"},
		{r.options.Scrape, "Web Scraping"},
		{r.options.Recursive, fmt.Sprintf("Recursive (depth=%d)", r.options.RecurseDepth)},
		{r.options.Takeover, "Takeover Detection"},
		{r.options.WAFDetect, "WAF Detection"},
		{r.options.CertGrab, "SSL/TLS Cert Grabbing"},
		{r.options.DNSEnum, "DNS Enumeration"},
		{r.options.ZoneTransfer, "Zone Transfer"},
		{r.options.CIDR, "CIDR Reverse DNS"},
		{r.options.PortScan, "Port Scanning"},
		{r.options.Screenshot, "Screenshots"},
		{r.options.CORSCheck, "CORS Checker"},
		{r.options.RedirectCheck, "Open Redirect Checker"},
		{r.options.Ollama, fmt.Sprintf("Ollama Analysis (%s)", r.options.OllamaModel)},
		{r.options.VulnScan, "Nuclei Vulnerability Scan"},
		{r.options.Curl, "Advanced Curl Fingerprints"},
	}
	var enabled []string
	for _, f := range features {
		if f.enabled {
			enabled = append(enabled, f.label)
		}
	}
	if len(enabled) > 0 {
		output.PrintInfo("Active modules: %s", strings.Join(enabled, ", "))
	}
	if r.options.Proxy != "" {
		output.PrintInfo("Proxy: %s", r.options.Proxy)
	}
	if r.options.HTMLReport != "" {
		output.PrintInfo("HTML Report: %s", r.options.HTMLReport)
	}
	if r.options.Ollama {
		output.PrintInfo("Ollama: %s @ %s", r.options.OllamaModel, r.options.OllamaHost)
	}
	if r.options.VulnScan {
		mode := r.options.VulnSeverity
		if mode == "" {
			mode = "all default severities"
		}
		output.PrintInfo("Nuclei: %s (severity=%s, rate=%d/s)", r.options.NucleiBinary, mode, r.options.VulnRateLimit)
	}
	if r.options.Curl {
		output.PrintInfo("Curl: %s (timeout=%ds, follow=%v)", r.options.CurlBinary, r.options.CurlTimeout, r.options.CurlFollow)
	}
}

func (r *Runner) runDomain(domain string) error {
	if !r.options.Silent {
		output.PrintInfo("Enumerating subdomains for: %s", domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.options.Timeout)*time.Second)
	defer cancel()

	// ── RESUME ──
	var allSubs map[string]struct{}
	resumePhase := ""
	if r.options.Resume {
		state, err := LoadState()
		if err == nil && state.Domain == domain {
			allSubs = MergeSubdomains(state)
			resumePhase = state.Phase
			if !r.options.Silent {
				output.PrintSuccess("Resumed scan with %d previously found subdomains (phase: %s)", len(allSubs), resumePhase)
			}
		}
	}

	// ── WILDCARD ──
	wildcard := active.NewWildcardDetector()
	if wildcard.Detect(ctx, domain) && !r.options.Silent {
		output.PrintWarning("Wildcard DNS detected for %s — results will be filtered", domain)
	}

	// ── ZONE TRANSFER ──
	if r.options.ZoneTransfer && resumePhase == "" {
		if !r.options.Silent {
			output.PrintInfo("Attempting DNS zone transfer...")
		}
		ztSubs, err := active.ZoneTransfer(domain)
		if err != nil {
			if !r.options.Silent {
				output.PrintWarning("Zone transfer failed: %s", err)
			}
		} else if len(ztSubs) > 0 && !r.options.Silent {
			output.PrintSuccess("Zone transfer returned %d records!", len(ztSubs))
		}
	}

	// ── PASSIVE ENUM ──
	if allSubs == nil || resumePhase == "" || resumePhase == "passive" {
		passiveSubs := r.runPassive(ctx, domain, 0)
		if allSubs == nil {
			allSubs = passiveSubs
		} else {
			for sub := range passiveSubs {
				allSubs[sub] = struct{}{}
			}
		}
		// Checkpoint after passive
		SaveState(&ScanState{Domain: domain, Subdomains: SubdomainsToSlice(allSubs), Phase: "passive", StartedAt: time.Now()})
	}

	// ── BRUTEFORCE ──
	if r.options.Bruteforce && !isPastPhase(resumePhase, "bruteforce") {
		if !r.options.Silent {
			output.PrintInfo("Running DNS bruteforce...")
		}
		var customWords []string
		if r.options.WordlistPath != "" {
			customWords = loadWordlist(r.options.WordlistPath)
		}
		bruteCtx, bruteCancel := context.WithTimeout(context.Background(), time.Duration(r.options.Timeout)*2*time.Second)
		bruteChan := active.Bruteforce(bruteCtx, domain, r.options.Threads, customWords)
		var bruteCount int
		for sub := range bruteChan {
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = struct{}{}
				bruteCount++
				r.stats.AddFound("bruteforce")
			}
		}
		bruteCancel()
		if !r.options.Silent {
			output.PrintInfo("Bruteforce found %d new subdomains", bruteCount)
		}
		SaveState(&ScanState{Domain: domain, Subdomains: SubdomainsToSlice(allSubs), Phase: "bruteforce", StartedAt: time.Now()})
	}

	// ── CIDR REVERSE DNS ──
	if r.options.CIDR && !isPastPhase(resumePhase, "cidr") {
		if !r.options.Silent {
			output.PrintInfo("Running CIDR reverse DNS scan...")
		}
		cidrCtx, cidrCancel := r.phaseContext(2)
		cidrSubs, err := active.ReverseDNSFromCIDR(cidrCtx, domain, r.options.Threads)
		cidrCancel()
		if err != nil {
			if !r.options.Silent {
				output.PrintWarning("CIDR scan error: %s", err)
			}
		} else {
			var cidrCount int
			for _, sub := range cidrSubs {
				if _, exists := allSubs[sub]; !exists {
					allSubs[sub] = struct{}{}
					cidrCount++
					r.stats.AddFound("cidr-rdns")
				}
			}
			if !r.options.Silent {
				output.PrintInfo("CIDR reverse DNS found %d new subdomains", cidrCount)
			}
		}
	}

	// ── RECURSIVE ──
	if r.options.Recursive {
		recursiveCtx, recursiveCancel := r.phaseContext(2)
		allSubs = r.runRecursive(recursiveCtx, domain, allSubs)
		recursiveCancel()
	}

	// ── APPLY EXCLUDE PATTERNS ──
	finalSubdomains := make([]string, 0, len(allSubs))
	for sub := range allSubs {
		if !r.isExcluded(sub) {
			finalSubdomains = append(finalSubdomains, sub)
		}
	}
	if excluded := len(allSubs) - len(finalSubdomains); excluded > 0 && !r.options.Silent {
		output.PrintInfo("Excluded %d subdomains by pattern", excluded)
	}

	// ── SCRAPE ──
	if r.options.Scrape {
		if !r.options.Silent {
			output.PrintInfo("Scraping %d subdomains...", len(finalSubdomains))
		}
		scrapeCtx, scrapeCancel := r.phaseContext(2)
		scrapeChan := active.Scrape(scrapeCtx, domain, finalSubdomains, r.options.Threads)
		var count int
		for sub := range scrapeChan {
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = struct{}{}
				finalSubdomains = append(finalSubdomains, sub)
				count++
			}
		}
		scrapeCancel()
		r.stats.SetScraped(count)
		if !r.options.Silent {
			output.PrintInfo("Scraper found %d new subdomains", count)
		}
	}

	// ── CERT GRAB (also discovers new subs from SANs) ──
	if r.options.CertGrab {
		if !r.options.Silent {
			output.PrintInfo("Grabbing SSL/TLS certificates...")
		}
		r.progress.StartPhase("Cert Grab", len(finalSubdomains))
		certCtx, certCancel := r.phaseContext(2)
		certChan := active.GrabCerts(certCtx, finalSubdomains, r.options.Threads)
		var certResults []active.CertResult
		for cr := range certChan {
			r.progress.Increment()
			certResults = append(certResults, cr)
			r.reportCerts = append(r.reportCerts, output.CertEntry{
				Subdomain: cr.Subdomain, Subject: cr.Subject,
				Issuer: cr.Issuer, SANCount: len(cr.SANs), Expired: cr.Expired,
			})
			if cr.Expired && !r.options.Silent {
				output.PrintWarning("Expired cert: %s (expired %s)", cr.Subdomain, cr.NotAfter)
			}
		}
		certCancel()
		r.progress.Done()
		// Extract SANs for new subdomains
		sanSubs := active.ExtractSANSubdomains(certResults, domain)
		var sanNew int
		for _, sub := range sanSubs {
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = struct{}{}
				finalSubdomains = append(finalSubdomains, sub)
				sanNew++
				r.stats.AddFound("cert-san")
			}
		}
		if !r.options.Silent {
			output.PrintInfo("Certs grabbed: %d, new SANs: %d", len(certResults), sanNew)
		}
	}

	// ── PERMUTATIONS ──
	if r.options.Permute {
		if !r.options.Silent {
			output.PrintInfo("Generating permutations...")
		}
		perms := active.GeneratePermutations(domain, finalSubdomains)
		r.stats.SetPermutations(len(perms))
		for _, p := range perms {
			if _, exists := allSubs[p]; !exists {
				allSubs[p] = struct{}{}
				finalSubdomains = append(finalSubdomains, p)
			}
		}
		if !r.options.Silent {
			output.PrintInfo("Generated %d permutations (total: %d)", len(perms), len(finalSubdomains))
		}
	}

	// ── DNS RESOLUTION ──
	var liveList []string
	if r.options.Resolve {
		if !r.options.Silent {
			output.PrintInfo("Resolving %d subdomains...", len(finalSubdomains))
		}
		r.progress.StartPhase("DNS Resolve", len(finalSubdomains))
		resolveCtx, resolveCancel := context.WithTimeout(context.Background(), time.Duration(r.options.Timeout)*2*time.Second)
		liveChan := active.Resolve(resolveCtx, finalSubdomains, r.options.Threads)
		for sub := range liveChan {
			r.progress.Increment()
			if wildcard.Detected() {
				ips, _ := net.LookupHost(sub)
				if wildcard.IsWildcard(ips) {
					continue
				}
			}
			liveList = append(liveList, sub)
			r.outputResult(sub, "resolved", "", 0, "")
			r.reportSubdomains = append(r.reportSubdomains, output.SubdomainEntry{Name: sub, Source: "resolved"})
		}
		resolveCancel()
		r.progress.Done()
		r.stats.SetAlive(len(liveList))
		if !r.options.Silent {
			output.PrintSuccess("Found %d alive subdomains out of %d", len(liveList), len(finalSubdomains))
		}
	} else {
		liveList = finalSubdomains
		for _, sub := range finalSubdomains {
			r.outputResult(sub, "passive", "", 0, "")
			r.reportSubdomains = append(r.reportSubdomains, output.SubdomainEntry{Name: sub, Source: "passive"})
		}
	}

	// ── HTTP PROBING ──
	var probedURLs []string
	if r.options.Probe && len(liveList) > 0 {
		probeCtx, probeCancel := r.phaseContext(2)
		probedURLs = r.runProbe(probeCtx, liveList)
		probeCancel()
	}

	// ── DNS ENUMERATION ──
	if r.options.DNSEnum && len(liveList) > 0 {
		dnsCtx, dnsCancel := r.phaseContext(2)
		r.runDNSEnum(dnsCtx, liveList)
		dnsCancel()
	}

	// ── TAKEOVER CHECK ──
	if r.options.Takeover && len(liveList) > 0 {
		takeoverCtx, takeoverCancel := r.phaseContext(2)
		r.runTakeover(takeoverCtx, liveList)
		takeoverCancel()
	}

	// ── WAF DETECTION ──
	if r.options.WAFDetect && len(liveList) > 0 {
		wafCtx, wafCancel := r.phaseContext(2)
		r.runWAF(wafCtx, liveList)
		wafCancel()
	}

	// ── PORT SCANNING ──
	if r.options.PortScan && len(liveList) > 0 {
		portCtx, portCancel := r.phaseContext(2)
		r.runPortScan(portCtx, liveList)
		portCancel()
	}

	// ── CORS CHECK ──
	if r.options.CORSCheck && len(liveList) > 0 {
		corsCtx, corsCancel := r.phaseContext(2)
		r.runCORSCheck(corsCtx, liveList)
		corsCancel()
	}

	// ── OPEN REDIRECT CHECK ──
	if r.options.RedirectCheck && len(liveList) > 0 {
		redirectCtx, redirectCancel := r.phaseContext(2)
		r.runRedirectCheck(redirectCtx, liveList)
		redirectCancel()
	}

	curlTargets := nucleiTargets(liveList, probedURLs)
	if r.options.Curl && len(curlTargets) > 0 {
		r.runCurlFingerprints(ctx, curlTargets)
	}

	// ── OPEN-SOURCE VULNERABILITY SCAN ──
	if r.options.VulnScan && len(curlTargets) > 0 {
		r.runVulnScan(ctx, curlTargets)
	}

	// ── SCREENSHOTS ──
	if r.options.Screenshot && len(liveList) > 0 {
		screenshotCtx, screenshotCancel := r.phaseContext(2)
		r.runScreenshots(screenshotCtx, liveList)
		screenshotCancel()
	}

	if r.options.CurlExport != "" && len(curlTargets) > 0 {
		if err := r.writeCurlReplay(domain, curlTargets); err != nil {
			if !r.options.Silent {
				output.PrintWarning("Could not write curl replay script: %s", err)
			}
		}
	}

	// ── LOCAL AI ANALYSIS ──
	if r.options.Ollama {
		analysis, err := r.runOllamaAnalysis(domain, liveList)
		if err != nil {
			if !r.options.Silent {
				output.PrintWarning("Ollama analysis skipped: %s", err)
			}
		} else {
			r.reportAIAnalysis = analysis
		}
	}

	// ── HTML REPORT ──
	if r.options.HTMLReport != "" {
		if !r.options.Silent {
			output.PrintInfo("Generating HTML report: %s", r.options.HTMLReport)
		}
		reportData := output.HTMLReportData{
			Domain:           domain,
			Subdomains:       r.reportSubdomains,
			TakeoverVulns:    r.reportTakeovers,
			WAFDetections:    r.reportWAFs,
			CertInfos:        r.reportCerts,
			PortResults:      r.reportPorts,
			CORSFindings:     r.reportCORS,
			RedirectFindings: r.reportRedirects,
			VulnFindings:     r.reportVulns,
			CurlResults:      r.reportCurl,
			AIAnalysis:       r.reportAIAnalysis,
			AIModel:          r.options.OllamaModel,
			Stats:            r.stats,
			ScanTime:         time.Now(),
		}
		if err := output.GenerateHTMLReport(reportData, r.options.HTMLReport); err != nil {
			output.PrintError("Report generation failed: %s", err)
		} else if !r.options.Silent {
			output.PrintSuccess("HTML report saved to %s", r.options.HTMLReport)
		}
	}

	// ── WEBHOOKS ──
	takeoverVulnCount := 0
	for _, t := range r.reportTakeovers {
		if t.Vuln {
			takeoverVulnCount++
		}
	}
	if r.config.Webhook.Discord != "" {
		_ = utils.SendDiscordWebhook(r.config.Webhook.Discord, domain, len(allSubs), takeoverVulnCount)
	}
	if r.config.Webhook.Slack != "" {
		_ = utils.SendSlackWebhook(r.config.Webhook.Slack, domain, len(allSubs), takeoverVulnCount)
	}

	return nil
}

func (r *Runner) phaseContext(multiplier int) (context.Context, context.CancelFunc) {
	if multiplier <= 0 {
		multiplier = 1
	}
	timeout := time.Duration(r.options.Timeout*multiplier) * time.Second
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

// ──────────── EXCLUDE ────────────

func (r *Runner) isExcluded(subdomain string) bool {
	for _, pattern := range r.options.ExcludePatterns {
		if matchGlob(pattern, subdomain) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, s string) bool {
	// Simple glob matching supporting * wildcard
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}

	// Check prefix
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// Check middle parts
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	// Check suffix
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// ──────────── PASSIVE ────────────

func (r *Runner) runPassive(ctx context.Context, domain string, depth int) map[string]struct{} {
	results := make(chan sources.Result)
	allSubs := make(map[string]struct{})
	var mu sync.Mutex

	passiveSources := []sources.Source{
		&crtsh.Source{},
		&hackertarget.Source{},
		&alienvault.Source{},
		&wayback.Source{},
		&certspotter.Source{},
		&anubis.Source{},
		&threatcrowd.Source{},
		&rapiddns.Source{},
		&urlscan.Source{},
		&bufferover.Source{},
		&commoncrawl.Source{},
		&virustotal.Source{APIKey: r.config.VirusTotal},
		&securitytrails.Source{APIKey: r.config.SecurityTrails},
		&shodan.Source{APIKey: r.config.Shodan},
		&github.Source{APIKey: r.config.GitHub},
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		for result := range results {
			if result.Error != nil {
				if r.options.Verbose && !r.options.Silent {
					output.PrintError("%s: %s", result.Source, result.Error)
				}
				continue
			}
			if result.Value == "" {
				continue
			}
			sub := utils.NormalizeHostname(result.Value)
			if !utils.BelongsToDomain(sub, domain) {
				continue
			}
			mu.Lock()
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = struct{}{}
				r.stats.AddFound(result.Source)
				if !r.options.Resolve && !r.options.Scrape && !r.options.Permute &&
					!r.options.Bruteforce && !r.options.CertGrab && depth == 0 {
					r.outputResult(sub, result.Source, "", 0, "")
					r.reportSubdomains = append(r.reportSubdomains, output.SubdomainEntry{Name: sub, Source: result.Source})
				}
			}
			mu.Unlock()
		}
		close(done)
	}()

	for _, source := range passiveSources {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			s.Run(ctx, domain, results)
		}(source)
	}

	wg.Wait()
	close(results)
	<-done

	if !r.options.Silent && depth == 0 {
		output.PrintInfo("Passive enumeration found %d unique subdomains", len(allSubs))
	}

	return allSubs
}

// ──────────── RECURSIVE ────────────

func (r *Runner) runRecursive(ctx context.Context, baseDomain string, allSubs map[string]struct{}) map[string]struct{} {
	if !r.options.Silent {
		output.PrintInfo("Starting recursive enumeration (depth=%d)...", r.options.RecurseDepth)
	}
	processed := make(map[string]struct{})
	processed[baseDomain] = struct{}{}

	for depth := 1; depth <= r.options.RecurseDepth; depth++ {
		var newTargets []string
		for sub := range allSubs {
			if _, done := processed[sub]; !done && sub != baseDomain {
				newTargets = append(newTargets, sub)
				processed[sub] = struct{}{}
			}
		}
		if len(newTargets) == 0 {
			break
		}
		if !r.options.Silent {
			output.PrintInfo("Recursion depth %d: %d targets", depth, len(newTargets))
		}
		for _, target := range newTargets {
			newSubs := r.runPassive(ctx, target, depth)
			for sub := range newSubs {
				allSubs[sub] = struct{}{}
			}
		}
	}
	return allSubs
}

// ──────────── PROBE ────────────

func (r *Runner) runProbe(ctx context.Context, subdomains []string) []string {
	if !r.options.Silent {
		output.PrintInfo("HTTP Probing %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("HTTP Probe", len(subdomains))
	probeChan := active.Probe(ctx, subdomains, r.options.Threads)
	var probed int
	var urls []string
	for result := range probeChan {
		probed++
		r.progress.Increment()
		techStr := strings.Join(result.Technologies, ",")
		if result.URL != "" {
			urls = append(urls, result.URL)
		}

		// Update report data
		for i := range r.reportSubdomains {
			if r.reportSubdomains[i].Name == result.Subdomain {
				r.reportSubdomains[i].Status = result.StatusCode
				r.reportSubdomains[i].Title = result.Title
				r.reportSubdomains[i].Techs = techStr
				break
			}
		}

		if r.options.JSON {
			data, _ := json.Marshal(result)
			r.writeOutput(string(data))
		} else if r.options.CSV {
			r.writeOutput(fmt.Sprintf("%s,%s,%d,%s,%s", result.Subdomain, result.URL, result.StatusCode, result.Title, techStr))
		} else if !r.options.Silent {
			line := fmt.Sprintf("%s [%d] [%s]",
				output.Colorize(output.Green, result.URL),
				result.StatusCode,
				output.Colorize(output.Cyan, result.Title))
			if result.Server != "" {
				line += fmt.Sprintf(" [%s]", output.Colorize(output.Yellow, result.Server))
			}
			if techStr != "" {
				line += fmt.Sprintf(" [%s]", output.Colorize(output.Magenta, techStr))
			}
			fmt.Println(line)
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		output.PrintSuccess("Probed %d web services", probed)
	}
	return urls
}

// ──────────── DNS ENUM ────────────

func (r *Runner) runDNSEnum(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Running DNS enumeration on %d hosts...", len(subdomains))
	}
	dnsChan := active.EnumerateDNS(ctx, subdomains, r.options.Threads)
	for record := range dnsChan {
		if r.options.JSON {
			data, _ := json.Marshal(record)
			r.writeOutput(string(data))
		} else if !r.options.Silent {
			parts := []string{output.Colorize(output.Green, record.Subdomain)}
			if len(record.A) > 0 {
				parts = append(parts, fmt.Sprintf("A:%s", strings.Join(record.A, ",")))
			}
			if len(record.AAAA) > 0 {
				parts = append(parts, fmt.Sprintf("AAAA:%s", strings.Join(record.AAAA, ",")))
			}
			if record.CNAME != "" {
				parts = append(parts, fmt.Sprintf("CNAME:%s", record.CNAME))
			}
			if len(record.MX) > 0 {
				parts = append(parts, fmt.Sprintf("MX:%s", strings.Join(record.MX, ",")))
			}
			if len(record.TXT) > 0 {
				parts = append(parts, fmt.Sprintf("TXT:%d records", len(record.TXT)))
			}
			fmt.Println(strings.Join(parts, " | "))
		}

		// Update report IPs
		if len(record.A) > 0 {
			for i := range r.reportSubdomains {
				if r.reportSubdomains[i].Name == record.Subdomain {
					r.reportSubdomains[i].IPs = strings.Join(record.A, ",")
					break
				}
			}
		}
	}
}

// ──────────── TAKEOVER ────────────

func (r *Runner) runTakeover(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Checking %d subdomains for takeover...", len(subdomains))
	}
	r.progress.StartPhase("Takeover Check", len(subdomains))
	toChan := active.CheckTakeover(ctx, subdomains, r.options.Threads)
	var vulnCount int
	for result := range toChan {
		r.progress.Increment()
		r.reportTakeovers = append(r.reportTakeovers, output.TakeoverEntry{
			Subdomain: result.Subdomain, CNAME: result.CNAME,
			Service: result.Service, Vuln: result.Vulnerable,
		})
		if result.Vulnerable {
			vulnCount++
			if !r.options.Silent {
				fmt.Printf("%s %s\n",
					output.Colorize(output.Red, "[TAKEOVER]"),
					active.FormatTakeoverResult(result))
			}
		} else if r.options.Verbose && !r.options.Silent {
			fmt.Printf("%s %s → %s (%s)\n",
				output.Colorize(output.Yellow, "[CNAME]"),
				result.Subdomain, result.CNAME, result.Service)
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		if vulnCount > 0 {
			output.PrintSuccess("Found %d potential takeover vulnerabilities!", vulnCount)
		} else {
			output.PrintInfo("No takeover vulnerabilities found")
		}
	}
}

// ──────────── WAF ────────────

func (r *Runner) runWAF(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Detecting WAF on %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("WAF Detect", len(subdomains))
	wafChan := active.DetectWAF(ctx, subdomains, r.options.Threads)
	for result := range wafChan {
		r.progress.Increment()
		r.reportWAFs = append(r.reportWAFs, output.WAFEntry{
			Subdomain: result.Subdomain, WAF: result.WAF, Evidence: result.Evidence,
		})
		if !r.options.Silent {
			fmt.Printf("%s %s → %s\n",
				output.Colorize(output.Magenta, "[WAF]"),
				output.Colorize(output.Green, result.Subdomain),
				output.Colorize(output.Yellow, result.WAF))
		}
	}
	r.progress.Done()
}

// ──────────── PORT SCAN ────────────

func (r *Runner) runPortScan(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Scanning ports on %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("Port Scan", len(subdomains))
	portChan := active.PortScan(ctx, subdomains, r.options.Threads)
	var totalOpen int
	for result := range portChan {
		r.progress.Increment()
		totalOpen += len(result.OpenPorts)
		r.reportPorts = append(r.reportPorts, output.PortEntry{
			Subdomain: result.Subdomain,
			OpenPorts: result.OpenPorts,
		})
		if !r.options.Silent {
			portStrs := make([]string, len(result.OpenPorts))
			for i, p := range result.OpenPorts {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			fmt.Printf("%s %s → %s\n",
				output.Colorize(output.Cyan, "[PORTS]"),
				output.Colorize(output.Green, result.Subdomain),
				output.Colorize(output.Yellow, strings.Join(portStrs, ",")))
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		output.PrintSuccess("Found %d open ports across hosts", totalOpen)
	}
}

// ──────────── CORS ────────────

func (r *Runner) runCORSCheck(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Checking CORS on %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("CORS Check", len(subdomains))
	corsChan := active.CheckCORS(ctx, subdomains, r.options.Threads)
	var vulnCount int
	for result := range corsChan {
		r.progress.Increment()
		if result.Vulnerable {
			vulnCount++
			r.reportCORS = append(r.reportCORS, output.CORSEntry{
				Subdomain: result.Subdomain,
				Origin:    result.Origin,
				Type:      result.Type,
				WithCreds: result.AllowCredentials,
			})
			if !r.options.Silent {
				fmt.Printf("%s %s [%s] Origin: %s\n",
					output.Colorize(output.Red, "[CORS]"),
					output.Colorize(output.Green, result.Subdomain),
					output.Colorize(output.Yellow, result.Type),
					result.Origin)
			}
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		if vulnCount > 0 {
			output.PrintSuccess("Found %d CORS misconfigurations!", vulnCount)
		} else {
			output.PrintInfo("No CORS misconfigurations found")
		}
	}
}

// ──────────── OPEN REDIRECT ────────────

func (r *Runner) runRedirectCheck(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Checking open redirects on %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("Redirect Check", len(subdomains))
	redirChan := active.CheckOpenRedirect(ctx, subdomains, r.options.Threads)
	var vulnCount int
	for result := range redirChan {
		r.progress.Increment()
		vulnCount++
		r.reportRedirects = append(r.reportRedirects, output.RedirectEntry{
			Subdomain: result.Subdomain,
			URL:       result.URL,
			Parameter: result.Parameter,
			Location:  result.Location,
		})
		if !r.options.Silent {
			fmt.Printf("%s %s [param=%s] → %s\n",
				output.Colorize(output.Red, "[REDIRECT]"),
				output.Colorize(output.Green, result.Subdomain),
				output.Colorize(output.Yellow, result.Parameter),
				result.Location)
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		if vulnCount > 0 {
			output.PrintSuccess("Found %d open redirect vulnerabilities!", vulnCount)
		} else {
			output.PrintInfo("No open redirects found")
		}
	}
}

// ──────────── VULNERABILITY SCAN ────────────

func (r *Runner) runVulnScan(ctx context.Context, targets []string) {
	targets = uniqueTargets(targets)
	if len(targets) == 0 {
		return
	}
	if !r.options.Silent {
		output.PrintInfo("Running Nuclei vulnerability scan on %d targets...", len(targets))
	}

	scanTimeout := time.Duration(r.options.Timeout) * time.Second
	if scanTimeout < 5*time.Minute {
		scanTimeout = 5 * time.Minute
	}
	scanCtx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	findings, err := active.RunNuclei(scanCtx, targets, active.NucleiOptions{
		Binary:          r.options.NucleiBinary,
		Templates:       splitCommaList(r.options.VulnTemplates),
		Severity:        r.options.VulnSeverity,
		Tags:            r.options.VulnTags,
		ExcludeTags:     r.options.VulnExcludeTags,
		RateLimit:       r.options.VulnRateLimit,
		Concurrency:     r.options.VulnConcurrency,
		Timeout:         r.options.Timeout,
		Proxy:           r.options.Proxy,
		UpdateTemplates: r.options.VulnUpdateTemplates,
		Headless:        r.options.VulnHeadless,
		Code:            r.options.VulnCode,
		DAST:            r.options.VulnDAST,
	})
	if err != nil {
		if !r.options.Silent {
			output.PrintWarning("Nuclei scan skipped or incomplete: %s", err)
		}
		if len(findings) == 0 {
			return
		}
	}

	for _, finding := range findings {
		entry := output.VulnEntry{
			Target:     findingTarget(finding),
			TemplateID: finding.TemplateID,
			Name:       finding.Info.Name,
			Severity:   finding.Info.Severity,
			Type:       finding.Type,
			MatchedAt:  finding.MatchedAt,
			Tags:       strings.Join(finding.Info.Tags, ","),
			CVEs:       strings.Join(finding.Info.Classification.CVEID, ","),
		}
		r.reportVulns = append(r.reportVulns, entry)

		if r.options.JSON {
			data, _ := json.Marshal(finding)
			r.writeOutput(string(data))
		} else if r.options.CSV {
			r.writeOutput(fmt.Sprintf("vulnerability,%s,%s,%s,%s,%s",
				entry.Target, entry.Severity, entry.TemplateID, entry.Name, entry.MatchedAt))
		} else if !r.options.Silent {
			fmt.Printf("%s [%s] %s %s (%s)\n",
				output.Colorize(output.Red, "[VULN]"),
				output.Colorize(severityColor(entry.Severity), strings.ToUpper(entry.Severity)),
				output.Colorize(output.Green, entry.Target),
				entry.Name,
				entry.TemplateID)
		}
	}

	if r.options.VulnOutput != "" {
		if err := writeNucleiFindings(r.options.VulnOutput, findings); err != nil {
			if !r.options.Silent {
				output.PrintWarning("Could not write Nuclei findings: %s", err)
			}
		} else if !r.options.Silent {
			output.PrintSuccess("Nuclei findings saved to %s", r.options.VulnOutput)
		}
	}

	if !r.options.Silent {
		output.PrintSuccess("Nuclei reported %d findings", len(findings))
	}
}

func nucleiTargets(liveList, probedURLs []string) []string {
	if len(probedURLs) > 0 {
		return uniqueTargets(probedURLs)
	}
	return uniqueTargets(liveList)
}

func findingTarget(f active.NucleiFinding) string {
	for _, value := range []string{f.MatchedAt, f.URL, f.Host} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return f.TemplateID
}

func severityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return output.Red
	case "medium":
		return output.Yellow
	case "low":
		return output.Cyan
	default:
		return output.Dim
	}
}

func writeNucleiFindings(path string, findings []active.NucleiFinding) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, finding := range findings {
		if len(finding.Raw) > 0 {
			if _, err := f.Write(finding.Raw); err != nil {
				return err
			}
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
			continue
		}
		if err := enc.Encode(finding); err != nil {
			return err
		}
	}
	return nil
}

func uniqueTargets(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func splitCommaList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ──────────── CURL ────────────

func (r *Runner) runCurlFingerprints(ctx context.Context, targets []string) {
	targets = uniqueTargets(targets)
	if len(targets) == 0 {
		return
	}
	if !r.options.Silent {
		output.PrintInfo("Running curl fingerprints on %d targets...", len(targets))
	}

	batches := len(targets)/maxInt(r.options.Threads, 1) + 1
	curlCtx, cancel := context.WithTimeout(context.Background(), time.Duration(maxInt(r.options.CurlTimeout, 1)*batches+30)*time.Second)
	defer cancel()

	curlChan := active.CurlProbe(curlCtx, targets, active.CurlOptions{
		Binary:          r.options.CurlBinary,
		Timeout:         r.options.CurlTimeout,
		ConnectTimeout:  r.options.CurlTimeout,
		Threads:         r.options.Threads,
		UserAgent:       r.options.CurlUserAgent,
		Proxy:           r.options.Proxy,
		Headers:         splitCommaList(r.options.CurlHeaders),
		FollowRedirects: r.options.CurlFollow,
	})

	for result := range curlChan {
		entry := output.CurlEntry{
			Target:       result.Target,
			EffectiveURL: result.EffectiveURL,
			Status:       result.HTTPCode,
			ContentType:  result.ContentType,
			RemoteIP:     result.RemoteIP,
			Redirects:    result.NumRedirects,
			TimeTotal:    result.TimeTotal,
			Error:        result.Error,
		}
		r.reportCurl = append(r.reportCurl, entry)

		if r.options.JSON {
			data, _ := json.Marshal(result)
			r.writeOutput(string(data))
		} else if r.options.CSV {
			r.writeOutput(fmt.Sprintf("curl,%s,%s,%d,%s,%s,%.3f,%s",
				entry.Target, entry.EffectiveURL, entry.Status, entry.ContentType, entry.RemoteIP, entry.TimeTotal, entry.Error))
		} else if !r.options.Silent {
			if result.Error != "" {
				fmt.Printf("%s %s %s\n", output.Colorize(output.Yellow, "[CURL]"), result.Target, result.Error)
				continue
			}
			fmt.Printf("%s %s [%d] [%s] [%.3fs] [%s]\n",
				output.Colorize(output.Cyan, "[CURL]"),
				output.Colorize(output.Green, result.EffectiveURL),
				result.HTTPCode,
				result.ContentType,
				result.TimeTotal,
				result.RemoteIP)
		}
	}
}

func (r *Runner) writeCurlReplay(domain string, targets []string) error {
	path := strings.ReplaceAll(r.options.CurlExport, "{domain}", domain)
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		path = filepath.Join(path, domain+"-curl-replay.sh")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "#!/usr/bin/env bash")
	fmt.Fprintln(f, "set -euo pipefail")
	fmt.Fprintf(f, "# Generated by did_finder for %s\n\n", domain)

	for _, target := range uniqueTargets(targets) {
		fmt.Fprintf(f, "%s\n", r.curlCommand(target))
	}
	for _, finding := range r.reportVulns {
		target := finding.MatchedAt
		if target == "" {
			target = finding.Target
		}
		if target != "" {
			fmt.Fprintf(f, "\n# Nuclei: %s %s %s\n", finding.Severity, finding.TemplateID, finding.Name)
			fmt.Fprintf(f, "%s\n", r.curlCommand(target))
		}
	}
	for _, redirect := range r.reportRedirects {
		if redirect.URL != "" {
			fmt.Fprintf(f, "\n# Open redirect check: %s\n", redirect.Parameter)
			fmt.Fprintf(f, "%s\n", r.curlCommand(redirect.URL))
		}
	}

	if !r.options.Silent {
		output.PrintSuccess("Curl replay script saved to %s", path)
	}
	return nil
}

func (r *Runner) curlCommand(target string) string {
	args := []string{
		r.options.CurlBinary,
		"-k",
		"-sS",
		"--compressed",
		"--path-as-is",
		"-i",
		"--max-time", fmt.Sprintf("%d", maxInt(r.options.CurlTimeout, 1)),
		"-A", r.options.CurlUserAgent,
	}
	if r.options.CurlFollow {
		args = append(args, "-L")
	}
	if r.options.Proxy != "" {
		args = append(args, "--proxy", r.options.Proxy)
	}
	for _, header := range splitCommaList(r.options.CurlHeaders) {
		args = append(args, "-H", header)
	}
	args = append(args, target)

	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if !strings.ContainsAny(value, " \t\n'\"\\$`!*?[]{}()<>|&;") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ──────────── SCREENSHOTS ────────────

func (r *Runner) runScreenshots(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("Capturing screenshots of %d hosts...", len(subdomains))
	}
	screenshotDir := filepath.Join(r.options.OutputDir, "screenshots")
	r.progress.StartPhase("Screenshots", len(subdomains))
	shotChan := active.TakeScreenshots(ctx, subdomains, r.options.Threads, r.options.OutputDir)
	var captured int
	for result := range shotChan {
		r.progress.Increment()
		if result.Error != "" {
			if r.options.Verbose && !r.options.Silent {
				output.PrintWarning("Screenshot: %s", result.Error)
			}
			continue
		}
		captured++
		if !r.options.Silent {
			fmt.Printf("%s %s → %s\n",
				output.Colorize(output.Cyan, "[SCREENSHOT]"),
				output.Colorize(output.Green, result.Subdomain),
				output.Colorize(output.Dim, result.FilePath))
		}
	}
	r.progress.Done()
	if !r.options.Silent {
		output.PrintSuccess("Captured %d screenshots → %s", captured, screenshotDir)
	}
}

// ──────────── OLLAMA ────────────

func (r *Runner) runOllamaAnalysis(domain string, liveList []string) (string, error) {
	if !r.options.Silent {
		output.PrintInfo("Generating local Ollama analysis with %s...", r.options.OllamaModel)
	}

	timeout := time.Duration(r.options.Timeout) * time.Second
	if timeout < 2*time.Minute {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := ai.NewOllamaClient(r.options.OllamaHost, r.options.OllamaModel)
	client.HTTPClient.Timeout = timeout
	hasModel, err := client.HasModel(ctx)
	if err != nil {
		return "", err
	}
	if !hasModel {
		return "", fmt.Errorf("model %q is not installed; run: ollama pull %s", r.options.OllamaModel, r.options.OllamaModel)
	}

	analysis, err := client.Generate(ctx, r.buildOllamaPrompt(domain, liveList))
	if err != nil {
		return "", err
	}

	if r.options.OllamaOutput != "" {
		if err := r.writeOllamaAnalysis(domain, analysis); err != nil {
			return "", err
		}
	}

	if !r.options.Silent && !r.options.JSON && !r.options.CSV {
		fmt.Println()
		fmt.Printf("%s Ollama analysis (%s)\n", output.Colorize(output.Magenta, "[AI]"), r.options.OllamaModel)
		fmt.Println(analysis)
		fmt.Println()
	}

	return analysis, nil
}

func (r *Runner) buildOllamaPrompt(domain string, liveList []string) string {
	var b strings.Builder

	subdomains := sampleSubdomains(liveList, r.reportSubdomains, 60)
	vulnTakeovers := countVulnerableTakeovers(r.reportTakeovers)
	expiredCerts := countExpiredCerts(r.reportCerts)
	openPortHosts := countPortHosts(r.reportPorts)
	highRiskVulns := countHighRiskVulns(r.reportVulns)

	fmt.Fprintf(&b, "You are helping review authorized did_finder recon results for %s.\n", domain)
	fmt.Fprintln(&b, "Write concise Markdown for a security operator.")
	fmt.Fprintln(&b, "Prioritize confirmed risks first, then likely next steps. Do not invent findings that are not in the data.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Summary:")
	fmt.Fprintf(&b, "- Subdomains collected: %d\n", len(r.reportSubdomains))
	fmt.Fprintf(&b, "- Live or candidate hosts: %d\n", len(liveList))
	fmt.Fprintf(&b, "- Potential takeover vulnerabilities: %d\n", vulnTakeovers)
	fmt.Fprintf(&b, "- CORS findings: %d\n", len(r.reportCORS))
	fmt.Fprintf(&b, "- Open redirect findings: %d\n", len(r.reportRedirects))
	fmt.Fprintf(&b, "- Nuclei vulnerability findings: %d\n", len(r.reportVulns))
	fmt.Fprintf(&b, "- High/critical vulnerability findings: %d\n", highRiskVulns)
	fmt.Fprintf(&b, "- WAF detections: %d\n", len(r.reportWAFs))
	fmt.Fprintf(&b, "- Hosts with open ports: %d\n", openPortHosts)
	fmt.Fprintf(&b, "- Curl fingerprints collected: %d\n", len(r.reportCurl))
	fmt.Fprintf(&b, "- Certificates checked: %d\n", len(r.reportCerts))
	fmt.Fprintf(&b, "- Expired certificates: %d\n", expiredCerts)
	fmt.Fprintln(&b)

	writeSubdomainSample(&b, "Subdomain sample", subdomains)
	writeTakeoverFindings(&b, r.reportTakeovers)
	writeCORSFindings(&b, r.reportCORS)
	writeRedirectFindings(&b, r.reportRedirects)
	writeVulnFindings(&b, r.reportVulns)
	writePortFindings(&b, r.reportPorts)
	writeCurlFindings(&b, r.reportCurl)
	writeWAFFindings(&b, r.reportWAFs)
	writeCertFindings(&b, r.reportCerts)

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Return these sections only:")
	fmt.Fprintln(&b, "1. Highest priority findings")
	fmt.Fprintln(&b, "2. Interesting exposure patterns")
	fmt.Fprintln(&b, "3. Recommended next commands or validations")

	return b.String()
}

func (r *Runner) writeOllamaAnalysis(domain, analysis string) error {
	path := strings.ReplaceAll(r.options.OllamaOutput, "{domain}", domain)
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		path = filepath.Join(path, domain+"-ollama-analysis.md")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if len(r.options.Domains) > 1 && !strings.Contains(r.options.OllamaOutput, "{domain}") {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}

	f, err := os.OpenFile(path, flags, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "# Ollama analysis for %s\n\n%s\n\n", domain, analysis); err != nil {
		return err
	}
	if !r.options.Silent {
		output.PrintSuccess("Ollama analysis saved to %s", path)
	}
	return nil
}

func sampleSubdomains(liveList []string, entries []output.SubdomainEntry, limit int) []string {
	seen := make(map[string]struct{})
	var values []string
	for _, sub := range liveList {
		if sub == "" {
			continue
		}
		if _, ok := seen[sub]; !ok {
			seen[sub] = struct{}{}
			values = append(values, sub)
		}
	}
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		if _, ok := seen[entry.Name]; !ok {
			seen[entry.Name] = struct{}{}
			values = append(values, entry.Name)
		}
	}
	sort.Strings(values)
	if len(values) > limit {
		return values[:limit]
	}
	return values
}

func writeSubdomainSample(b *strings.Builder, label string, values []string) {
	fmt.Fprintf(b, "%s:\n", label)
	if len(values) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
}

func writeTakeoverFindings(b *strings.Builder, findings []output.TakeoverEntry) {
	fmt.Fprintln(b, "\nTakeover findings:")
	wrote := 0
	for _, finding := range findings {
		if !finding.Vuln {
			continue
		}
		fmt.Fprintf(b, "- %s -> %s (%s)\n", finding.Subdomain, finding.CNAME, finding.Service)
		wrote++
		if wrote >= 25 {
			break
		}
	}
	if wrote == 0 {
		fmt.Fprintln(b, "- none")
	}
}

func writeCORSFindings(b *strings.Builder, findings []output.CORSEntry) {
	fmt.Fprintln(b, "\nCORS findings:")
	if len(findings) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for i, finding := range findings {
		if i >= 25 {
			break
		}
		fmt.Fprintf(b, "- %s: %s origin=%s credentials=%v\n", finding.Subdomain, finding.Type, finding.Origin, finding.WithCreds)
	}
}

func writeRedirectFindings(b *strings.Builder, findings []output.RedirectEntry) {
	fmt.Fprintln(b, "\nOpen redirect findings:")
	if len(findings) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for i, finding := range findings {
		if i >= 25 {
			break
		}
		fmt.Fprintf(b, "- %s: parameter=%s location=%s\n", finding.Subdomain, finding.Parameter, finding.Location)
	}
}

func writeVulnFindings(b *strings.Builder, findings []output.VulnEntry) {
	fmt.Fprintln(b, "\nNuclei vulnerability findings:")
	if len(findings) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for i, finding := range findings {
		if i >= 40 {
			break
		}
		cves := finding.CVEs
		if cves == "" {
			cves = "no CVE listed"
		}
		fmt.Fprintf(b, "- [%s] %s: %s (%s, %s)\n", finding.Severity, finding.Target, finding.Name, finding.TemplateID, cves)
	}
}

func writePortFindings(b *strings.Builder, findings []output.PortEntry) {
	fmt.Fprintln(b, "\nOpen port findings:")
	wrote := 0
	for _, finding := range findings {
		if len(finding.OpenPorts) == 0 {
			continue
		}
		if wrote >= 40 {
			break
		}
		portStrs := make([]string, 0, len(finding.OpenPorts))
		for _, port := range finding.OpenPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", port))
		}
		fmt.Fprintf(b, "- %s: %s\n", finding.Subdomain, strings.Join(portStrs, ","))
		wrote++
	}
	if wrote == 0 {
		fmt.Fprintln(b, "- none")
	}
}

func writeCurlFindings(b *strings.Builder, findings []output.CurlEntry) {
	fmt.Fprintln(b, "\nCurl fingerprint notes:")
	if len(findings) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for i, finding := range findings {
		if i >= 30 {
			break
		}
		if finding.Error != "" {
			fmt.Fprintf(b, "- %s: curl error=%s\n", finding.Target, finding.Error)
			continue
		}
		fmt.Fprintf(b, "- %s -> %s status=%d type=%s ip=%s time=%.3fs redirects=%d\n",
			finding.Target, finding.EffectiveURL, finding.Status, finding.ContentType,
			finding.RemoteIP, finding.TimeTotal, finding.Redirects)
	}
}

func writeWAFFindings(b *strings.Builder, findings []output.WAFEntry) {
	fmt.Fprintln(b, "\nWAF detections:")
	if len(findings) == 0 {
		fmt.Fprintln(b, "- none")
		return
	}
	for i, finding := range findings {
		if i >= 25 {
			break
		}
		fmt.Fprintf(b, "- %s: %s (%s)\n", finding.Subdomain, finding.WAF, finding.Evidence)
	}
}

func writeCertFindings(b *strings.Builder, findings []output.CertEntry) {
	fmt.Fprintln(b, "\nCertificate notes:")
	wrote := 0
	for _, finding := range findings {
		if !finding.Expired {
			continue
		}
		if wrote >= 25 {
			break
		}
		fmt.Fprintf(b, "- expired: %s issuer=%s subject=%s\n", finding.Subdomain, finding.Issuer, finding.Subject)
		wrote++
	}
	if wrote == 0 {
		fmt.Fprintln(b, "- no expired certificates reported")
	}
}

func countVulnerableTakeovers(findings []output.TakeoverEntry) int {
	count := 0
	for _, finding := range findings {
		if finding.Vuln {
			count++
		}
	}
	return count
}

func countExpiredCerts(findings []output.CertEntry) int {
	count := 0
	for _, finding := range findings {
		if finding.Expired {
			count++
		}
	}
	return count
}

func countPortHosts(findings []output.PortEntry) int {
	count := 0
	for _, finding := range findings {
		if len(finding.OpenPorts) > 0 {
			count++
		}
	}
	return count
}

func countHighRiskVulns(findings []output.VulnEntry) int {
	count := 0
	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case "critical", "high":
			count++
		}
	}
	return count
}

// ──────────── OUTPUT ────────────

func (r *Runner) outputResult(subdomain, source, ip string, status int, title string) {
	if r.options.JSON {
		data := map[string]interface{}{"subdomain": subdomain, "source": source}
		if ip != "" {
			data["ip"] = ip
		}
		if status > 0 {
			data["status"] = status
		}
		if title != "" {
			data["title"] = title
		}
		j, _ := json.Marshal(data)
		r.writeOutput(string(j))
	} else if r.options.CSV {
		r.writeOutput(fmt.Sprintf("%s,%s,%s,%d,%s", subdomain, source, ip, status, title))
	} else if r.options.Silent {
		fmt.Println(subdomain)
	} else {
		output.PrintFound(subdomain, source)
	}
}

func (r *Runner) writeOutput(line string) {
	fmt.Println(line)
	if r.outFile != nil {
		fmt.Fprintln(r.outFile, line)
	}
}

func loadWordlist(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if w := strings.TrimSpace(scanner.Text()); w != "" {
			words = append(words, w)
		}
	}
	return words
}

// isPastPhase checks if the resume phase is past the given phase
func isPastPhase(resumePhase, phase string) bool {
	if resumePhase == "" {
		return false
	}
	phases := []string{"passive", "bruteforce", "cidr", "active"}
	resumeIdx := -1
	phaseIdx := -1
	for i, p := range phases {
		if p == resumePhase {
			resumeIdx = i
		}
		if p == phase {
			phaseIdx = i
		}
	}
	return resumeIdx >= 0 && phaseIdx >= 0 && resumeIdx > phaseIdx
}
