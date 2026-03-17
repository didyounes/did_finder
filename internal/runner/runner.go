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
	"strings"
	"sync"
	"time"

	"github.com/yel-joul/did_finder/internal/active"
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

	sourceCount := 13
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
		cidrSubs, err := active.ReverseDNSFromCIDR(ctx, domain, r.options.Threads)
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
		allSubs = r.runRecursive(ctx, domain, allSubs)
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
		scrapeChan := active.Scrape(ctx, domain, finalSubdomains, r.options.Threads)
		var count int
		for sub := range scrapeChan {
			if _, exists := allSubs[sub]; !exists {
				allSubs[sub] = struct{}{}
				finalSubdomains = append(finalSubdomains, sub)
				count++
			}
		}
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
		certChan := active.GrabCerts(ctx, finalSubdomains, r.options.Threads)
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
	if r.options.Probe && len(liveList) > 0 {
		r.runProbe(ctx, liveList)
	}

	// ── DNS ENUMERATION ──
	if r.options.DNSEnum && len(liveList) > 0 {
		r.runDNSEnum(ctx, liveList)
	}

	// ── TAKEOVER CHECK ──
	if r.options.Takeover && len(liveList) > 0 {
		r.runTakeover(ctx, liveList)
	}

	// ── WAF DETECTION ──
	if r.options.WAFDetect && len(liveList) > 0 {
		r.runWAF(ctx, liveList)
	}

	// ── PORT SCANNING ──
	if r.options.PortScan && len(liveList) > 0 {
		r.runPortScan(ctx, liveList)
	}

	// ── CORS CHECK ──
	if r.options.CORSCheck && len(liveList) > 0 {
		r.runCORSCheck(ctx, liveList)
	}

	// ── OPEN REDIRECT CHECK ──
	if r.options.RedirectCheck && len(liveList) > 0 {
		r.runRedirectCheck(ctx, liveList)
	}

	// ── SCREENSHOTS ──
	if r.options.Screenshot && len(liveList) > 0 {
		r.runScreenshots(ctx, liveList)
	}

	// ── HTML REPORT ──
	if r.options.HTMLReport != "" {
		if !r.options.Silent {
			output.PrintInfo("Generating HTML report: %s", r.options.HTMLReport)
		}
		reportData := output.HTMLReportData{
			Domain:        domain,
			Subdomains:    r.reportSubdomains,
			TakeoverVulns: r.reportTakeovers,
			WAFDetections: r.reportWAFs,
			CertInfos:     r.reportCerts,
			PortResults:   r.reportPorts,
			CORSFindings:  r.reportCORS,
			RedirectFindings: r.reportRedirects,
			Stats:         r.stats,
			ScanTime:      time.Now(),
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
			sub := strings.ToLower(strings.TrimSpace(result.Value))
			if !strings.HasSuffix(sub, domain) {
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

func (r *Runner) runProbe(ctx context.Context, subdomains []string) {
	if !r.options.Silent {
		output.PrintInfo("HTTP Probing %d hosts...", len(subdomains))
	}
	r.progress.StartPhase("HTTP Probe", len(subdomains))
	probeChan := active.Probe(ctx, subdomains, r.options.Threads)
	var probed int
	for result := range probeChan {
		probed++
		r.progress.Increment()
		techStr := strings.Join(result.Technologies, ",")

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
				Subdomain:  result.Subdomain,
				Origin:     result.Origin,
				Type:       result.Type,
				WithCreds:  result.AllowCredentials,
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
