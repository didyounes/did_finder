package runner

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/yel-joul/did_finder/internal/active"
	"github.com/yel-joul/did_finder/internal/ai"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Options struct {
	Domain          string
	DomainList      string
	Threads         int
	Timeout         int
	Verbose         bool
	Silent          bool
	OutputFile      string
	JSON            bool
	CSV             bool
	Resolve         bool
	Permute         bool
	Scrape          bool
	Probe           bool
	Recursive       bool
	RecurseDepth    int
	ZoneTransfer    bool
	Proxy           string
	RateLimit       int
	Sources         string
	ExcludeSources  string
	ListSources     bool
	MinSources      int
	InterestingOnly bool
	NoColor         bool
	Takeover        bool
	WAFDetect       bool
	CertGrab        bool
	DNSEnum         bool
	Bruteforce      bool
	WordlistPath    string
	CIDR            bool
	HTMLReport      string
	ConfigPath      string
	All             bool

	// v3.0 new features
	PortScan      bool
	Screenshot    bool
	CORSCheck     bool
	RedirectCheck bool
	Resume        bool
	Resolver      string
	ResolverList  string
	Exclude       string
	OutputDir     string

	// Local Ollama analysis
	Ollama       bool
	OllamaHost   string
	OllamaModel  string
	OllamaOutput string

	// Open-source vulnerability scanning through Nuclei
	VulnScan              bool
	VulnAll               bool
	VulnTemplates         string
	VulnSeverity          string
	VulnTags              string
	VulnExcludeTags       string
	VulnRateLimit         int
	VulnConcurrency       int
	VulnOutput            string
	VulnUpdateTemplates   bool
	VulnHeadless          bool
	VulnCode              bool
	VulnDAST              bool
	VulnIncludeAggressive bool
	NucleiBinary          string

	// Advanced curl fingerprints and replay exports
	Curl          bool
	CurlExport    string
	CurlBinary    string
	CurlUserAgent string
	CurlHeaders   string
	CurlTimeout   int
	CurlFollow    bool

	// Embedded bug bounty toolkit catalog
	Tools          bool
	ToolsCategory  string
	ToolsSearch    string
	ToolsCheck     bool
	ToolsJSON      bool
	ToolsRecommend bool

	// Populated at runtime
	Domains         []string
	TargetSeeds     map[string][]string
	Resolvers       []string
	ExcludePatterns []string
}

func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.Domain, "d", "", "Domain to find subdomains for")
	flag.StringVar(&options.DomainList, "dL", "", "File containing list of domains")
	flag.IntVar(&options.Threads, "t", 30, "Number of concurrent goroutines")
	flag.IntVar(&options.Timeout, "timeout", 30, "Timeout in seconds")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&options.Silent, "silent", false, "Only output subdomains")
	flag.StringVar(&options.OutputFile, "o", "", "Write output to file")
	flag.BoolVar(&options.JSON, "json", false, "JSONL output")
	flag.BoolVar(&options.CSV, "csv", false, "CSV output")
	flag.BoolVar(&options.Resolve, "resolve", false, "Resolve subdomains via DNS")
	flag.BoolVar(&options.Permute, "permute", false, "Generate permutations")
	flag.BoolVar(&options.Scrape, "scrape", false, "Scrape live hosts for subdomains")
	flag.BoolVar(&options.Probe, "probe", false, "HTTP probe (status, title, tech)")
	flag.BoolVar(&options.Recursive, "recursive", false, "Recursive enumeration")
	flag.IntVar(&options.RecurseDepth, "depth", 2, "Recursion depth")
	flag.BoolVar(&options.ZoneTransfer, "zt", false, "Attempt DNS zone transfer")
	flag.StringVar(&options.Proxy, "proxy", "", "HTTP/SOCKS5 proxy URL")
	flag.IntVar(&options.RateLimit, "rate", 5, "Max passive source requests per second")
	flag.StringVar(&options.Sources, "sources", "", "Comma-separated passive sources to include (use -list-sources)")
	flag.StringVar(&options.ExcludeSources, "exclude-sources", "", "Comma-separated passive sources to skip")
	flag.BoolVar(&options.ListSources, "list-sources", false, "List passive source names and exit")
	flag.IntVar(&options.MinSources, "min-sources", 1, "Only keep subdomains seen from at least this many sources")
	flag.BoolVar(&options.InterestingOnly, "interesting", false, "Only keep high-signal subdomains based on labels and source confidence")
	flag.BoolVar(&options.NoColor, "nc", false, "Disable colors")
	flag.BoolVar(&options.Takeover, "takeover", false, "Check for subdomain takeover")
	flag.BoolVar(&options.WAFDetect, "waf", false, "Detect WAF on live hosts")
	flag.BoolVar(&options.CertGrab, "certs", false, "Grab SSL/TLS certs & extract SANs")
	flag.BoolVar(&options.DNSEnum, "dns-enum", false, "Full DNS record enumeration")
	flag.BoolVar(&options.Bruteforce, "brute", false, "DNS bruteforce with built-in wordlist")
	flag.StringVar(&options.WordlistPath, "w", "", "Custom wordlist for bruteforce")
	flag.BoolVar(&options.CIDR, "cidr", false, "CIDR/reverse DNS discovery")
	flag.StringVar(&options.HTMLReport, "report", "", "Generate HTML report to file")
	flag.StringVar(&options.ConfigPath, "config", "", "Path to YAML config file")
	flag.BoolVar(&options.All, "all", false, "Enable ALL features")

	// v3.0 new flags
	flag.BoolVar(&options.PortScan, "ports", false, "Scan top 100 ports on live hosts")
	flag.BoolVar(&options.Screenshot, "screenshot", false, "Capture screenshots of live web services")
	flag.BoolVar(&options.CORSCheck, "cors", false, "Check for CORS misconfigurations")
	flag.BoolVar(&options.RedirectCheck, "redirect", false, "Check for open redirect vulnerabilities")
	flag.BoolVar(&options.Resume, "resume", false, "Resume a previously interrupted scan")
	flag.StringVar(&options.Resolver, "r", "", "Custom DNS resolver (e.g. 8.8.8.8)")
	flag.StringVar(&options.ResolverList, "rL", "", "File containing list of DNS resolvers")
	flag.StringVar(&options.Exclude, "exclude", "", "Comma-separated patterns to exclude (e.g. *.staging.*,*.dev.*)")
	flag.StringVar(&options.OutputDir, "oD", "output", "Output directory for screenshots and reports")
	flag.BoolVar(&options.Ollama, "ollama", false, "Analyze scan findings with local Ollama")
	flag.StringVar(&options.OllamaHost, "ollama-host", "", fmt.Sprintf("Ollama host URL (default: %s)", ai.DefaultOllamaHost))
	flag.StringVar(&options.OllamaModel, "ollama-model", "", fmt.Sprintf("Ollama model name (default: %s)", ai.DefaultOllamaModel))
	flag.StringVar(&options.OllamaOutput, "ollama-out", "", "Write Ollama analysis Markdown to file")
	flag.BoolVar(&options.VulnScan, "vuln", false, "Run open-source Nuclei vulnerability scanning on discovered targets")
	flag.BoolVar(&options.VulnAll, "vuln-all", false, "Run all default Nuclei template severities instead of low,medium,high,critical only")
	flag.StringVar(&options.VulnTemplates, "vuln-templates", "", "Comma-separated Nuclei template files/directories to run")
	flag.StringVar(&options.VulnSeverity, "vuln-severity", "low,medium,high,critical", "Nuclei severity filter")
	flag.StringVar(&options.VulnTags, "vuln-tags", "", "Nuclei tags to include")
	flag.StringVar(&options.VulnExcludeTags, "vuln-exclude-tags", "dos,fuzz,intrusive", "Nuclei tags to exclude")
	flag.IntVar(&options.VulnRateLimit, "vuln-rate", 50, "Nuclei maximum requests per second")
	flag.IntVar(&options.VulnConcurrency, "vuln-concurrency", 25, "Nuclei template concurrency")
	flag.StringVar(&options.VulnOutput, "vuln-output", "", "Write Nuclei JSONL findings to file")
	flag.BoolVar(&options.VulnUpdateTemplates, "vuln-update", false, "Update Nuclei templates before scanning")
	flag.BoolVar(&options.VulnHeadless, "vuln-headless", false, "Enable Nuclei headless templates")
	flag.BoolVar(&options.VulnCode, "vuln-code", false, "Enable Nuclei code protocol templates")
	flag.BoolVar(&options.VulnDAST, "vuln-dast", false, "Enable Nuclei DAST/fuzz templates")
	flag.BoolVar(&options.VulnIncludeAggressive, "vuln-include-aggressive", false, "Do not exclude dos/fuzz/intrusive Nuclei tags")
	flag.StringVar(&options.NucleiBinary, "nuclei-bin", active.DefaultNucleiBinary, "Path/name of nuclei binary")
	flag.BoolVar(&options.Curl, "curl", false, "Run advanced curl HTTP fingerprinting on live targets")
	flag.StringVar(&options.CurlExport, "curl-export", "", "Write replayable curl commands to a shell script")
	flag.StringVar(&options.CurlBinary, "curl-bin", active.DefaultCurlBinary, "Path/name of curl binary")
	flag.StringVar(&options.CurlUserAgent, "curl-user-agent", "did_finder/3.0", "User-Agent for curl requests")
	flag.StringVar(&options.CurlHeaders, "curl-headers", "", "Comma-separated extra curl headers")
	flag.IntVar(&options.CurlTimeout, "curl-timeout", 15, "Curl max time and connect timeout in seconds")
	flag.BoolVar(&options.CurlFollow, "curl-follow", true, "Follow redirects with curl")
	flag.BoolVar(&options.Tools, "tools", false, "Show embedded awesome-bugbounty-tools catalog")
	flag.StringVar(&options.ToolsCategory, "tools-category", "", "Filter tool catalog by category")
	flag.StringVar(&options.ToolsSearch, "tools-search", "", "Search tool catalog")
	flag.BoolVar(&options.ToolsCheck, "tools-check", false, "Check whether catalog tools are installed in PATH")
	flag.BoolVar(&options.ToolsJSON, "tools-json", false, "Print tool catalog as JSON")
	flag.BoolVar(&options.ToolsRecommend, "tools-recommend", false, "Recommend companion tools for enabled did_finder modules")

	flag.Parse()

	options.TargetSeeds = make(map[string][]string)
	seenDomains := make(map[string]struct{})
	seenSeeds := make(map[string]struct{})

	// -all enables everything
	if options.All {
		options.Resolve = true
		options.Probe = true
		options.Takeover = true
		options.WAFDetect = true
		options.CertGrab = true
		options.Bruteforce = true
		options.Permute = true
		options.Scrape = true
		options.Recursive = true
		options.ZoneTransfer = true
		options.CIDR = true
		options.PortScan = true
		options.Screenshot = true
		options.CORSCheck = true
		options.RedirectCheck = true
		options.DNSEnum = true
		options.VulnScan = true
		options.Curl = true
	}
	if options.VulnAll {
		options.VulnScan = true
		options.VulnSeverity = ""
	}
	if options.VulnIncludeAggressive {
		options.VulnExcludeTags = ""
	}

	// Collect domains
	if options.Domain != "" {
		addTargets(options, parseTargetValues(options.Domain), seenDomains, seenSeeds)
	}
	if options.DomainList != "" {
		domains, err := readTargetLines(options.DomainList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading domain list: %s\n", err)
		} else {
			addTargets(options, domains, seenDomains, seenSeeds)
		}
	}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			addTargets(options, parseTargetValues(scanner.Text()), seenDomains, seenSeeds)
		}
	}

	// Parse custom resolvers
	if options.Resolver != "" {
		options.Resolvers = append(options.Resolvers, options.Resolver)
	}
	if options.ResolverList != "" {
		resolvers, err := readLines(options.ResolverList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading resolver list: %s\n", err)
		} else {
			options.Resolvers = append(options.Resolvers, resolvers...)
		}
	}

	// Parse exclude patterns
	if options.Exclude != "" {
		for _, p := range strings.Split(options.Exclude, ",") {
			if p = strings.TrimSpace(p); p != "" {
				options.ExcludePatterns = append(options.ExcludePatterns, p)
			}
		}
	}

	return options
}

func (o *Options) ToolsRequested() bool {
	return o.Tools || o.ToolsCategory != "" || o.ToolsSearch != "" ||
		o.ToolsCheck || o.ToolsJSON || o.ToolsRecommend
}

func (o *Options) EnabledToolModules() []string {
	var modules []string
	if o.All {
		modules = append(modules, "all")
	}
	if o.Resolve {
		modules = append(modules, "resolve")
	}
	if o.Probe {
		modules = append(modules, "probe")
	}
	if o.Bruteforce {
		modules = append(modules, "brute")
	}
	if o.Permute {
		modules = append(modules, "permute")
	}
	if o.Scrape {
		modules = append(modules, "scrape")
	}
	if o.Recursive {
		modules = append(modules, "passive")
	}
	if o.CertGrab {
		modules = append(modules, "certs")
	}
	if o.DNSEnum {
		modules = append(modules, "dns-enum")
	}
	if o.ZoneTransfer {
		modules = append(modules, "zt")
	}
	if o.CIDR {
		modules = append(modules, "cidr")
	}
	if o.Takeover {
		modules = append(modules, "takeover")
	}
	if o.WAFDetect {
		modules = append(modules, "waf")
	}
	if o.PortScan {
		modules = append(modules, "ports")
	}
	if o.CORSCheck {
		modules = append(modules, "cors")
	}
	if o.RedirectCheck {
		modules = append(modules, "redirect")
	}
	if o.Screenshot {
		modules = append(modules, "screenshot")
	}
	if o.Ollama {
		modules = append(modules, "ollama")
	}
	if o.VulnScan {
		modules = append(modules, "vuln")
	}
	if o.Curl {
		modules = append(modules, "curl")
	}
	if o.InterestingOnly {
		modules = append(modules, "interesting")
	}
	if len(modules) == 0 {
		modules = append(modules, "passive")
	}
	return modules
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func readTargetLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		targets = append(targets, parseTargetValues(scanner.Text())...)
	}
	return targets, scanner.Err()
}

func parseTargetValues(value string) []string {
	var targets []string
	for _, field := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if strings.HasPrefix(field, "#") {
			break
		}
		host := utils.NormalizeHostname(field)
		if host != "" {
			targets = append(targets, host)
		}
	}
	return targets
}

func addTargets(options *Options, targets []string, seenDomains, seenSeeds map[string]struct{}) {
	for _, target := range targets {
		host := utils.NormalizeHostname(target)
		if host == "" {
			continue
		}
		root := utils.RegistrableDomain(host)
		if root == "" {
			continue
		}
		if _, exists := seenDomains[root]; !exists {
			seenDomains[root] = struct{}{}
			options.Domains = append(options.Domains, root)
		}
		seedKey := root + "\x00" + host
		if _, exists := seenSeeds[seedKey]; !exists {
			seenSeeds[seedKey] = struct{}{}
			options.TargetSeeds[root] = append(options.TargetSeeds[root], host)
		}
	}
}
