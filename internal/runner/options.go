package runner

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Options struct {
	Domain       string
	DomainList   string
	Threads      int
	Timeout      int
	Verbose      bool
	Silent       bool
	OutputFile   string
	JSON         bool
	CSV          bool
	Resolve      bool
	Permute      bool
	Scrape       bool
	Probe        bool
	Recursive    bool
	RecurseDepth int
	ZoneTransfer bool
	Proxy        string
	RateLimit    int
	NoColor      bool
	Takeover     bool
	WAFDetect    bool
	CertGrab     bool
	DNSEnum      bool
	Bruteforce   bool
	WordlistPath string
	CIDR         bool
	HTMLReport   string
	ConfigPath   string
	All          bool

	// v3.0 new features
	PortScan     bool
	Screenshot   bool
	CORSCheck    bool
	RedirectCheck bool
	Resume       bool
	Resolver     string
	ResolverList string
	Exclude      string
	OutputDir    string

	// Populated at runtime
	Domains      []string
	Resolvers    []string
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
	flag.IntVar(&options.RateLimit, "rate", 50, "Max requests per second")
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

	flag.Parse()

	// -all enables everything
	if options.All {
		options.Resolve = true
		options.Probe = true
		options.Takeover = true
		options.WAFDetect = true
		options.CertGrab = true
		options.Bruteforce = true
		options.Permute = true
		options.PortScan = true
		options.CORSCheck = true
		options.RedirectCheck = true
		options.DNSEnum = true
	}

	// Collect domains
	if options.Domain != "" {
		options.Domains = append(options.Domains, options.Domain)
	}
	if options.DomainList != "" {
		domains, err := readLines(options.DomainList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading domain list: %s\n", err)
		} else {
			options.Domains = append(options.Domains, domains...)
		}
	}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if line := scanner.Text(); line != "" {
				options.Domains = append(options.Domains, line)
			}
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

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
