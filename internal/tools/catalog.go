package tools

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

const (
	SourceName    = "vavkamil/awesome-bugbounty-tools"
	SourceURL     = "https://github.com/vavkamil/awesome-bugbounty-tools"
	SourceCommit  = "943385c58d406756f0c2626c2e18cce03be46c4e"
	SourceLicense = "CC0-1.0"
)

//go:embed catalog.json
var catalogJSON []byte

type Tool struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

type ListOptions struct {
	Category  string
	Search    string
	Check     bool
	JSON      bool
	Recommend bool
	Modules   []string
}

type ToolView struct {
	Tool
	Installed *bool    `json:"installed,omitempty"`
	Commands  []string `json:"commands,omitempty"`
	Path      string   `json:"path,omitempty"`
}

func Catalog() ([]Tool, error) {
	var tools []Tool
	if err := json.Unmarshal(catalogJSON, &tools); err != nil {
		return nil, fmt.Errorf("could not load embedded bug bounty catalog: %w", err)
	}
	return tools, nil
}

func PrintCatalog(w io.Writer, opts ListOptions) error {
	all, err := Catalog()
	if err != nil {
		return err
	}

	filtered := all
	if opts.Recommend {
		filtered = Recommended(all, opts.Modules)
	}
	filtered = filterTools(filtered, opts.Category, opts.Search)

	views := make([]ToolView, 0, len(filtered))
	for _, tool := range filtered {
		view := ToolView{Tool: tool}
		if opts.Check {
			view.Commands = commandCandidates(tool.Name)
			installed, path := installedPath(view.Commands)
			view.Installed = &installed
			view.Path = path
		}
		views = append(views, view)
	}

	if opts.JSON {
		return json.NewEncoder(w).Encode(struct {
			Source struct {
				Name    string `json:"name"`
				URL     string `json:"url"`
				Commit  string `json:"commit"`
				License string `json:"license"`
			} `json:"source"`
			Tools []ToolView `json:"tools"`
		}{
			Source: struct {
				Name    string `json:"name"`
				URL     string `json:"url"`
				Commit  string `json:"commit"`
				License string `json:"license"`
			}{
				Name: SourceName, URL: SourceURL, Commit: SourceCommit, License: SourceLicense,
			},
			Tools: views,
		})
	}

	fmt.Fprintf(w, "Bug bounty tools catalog: %d shown / %d embedded\n", len(views), len(all))
	fmt.Fprintf(w, "Source: %s (%s, %s)\n", SourceURL, SourceLicense, SourceCommit[:12])
	if opts.Recommend {
		fmt.Fprintf(w, "Mode: recommendations for %s\n", strings.Join(displayModules(opts.Modules), ", "))
	}
	if opts.Category != "" || opts.Search != "" {
		fmt.Fprintf(w, "Filters: category=%q search=%q\n", opts.Category, opts.Search)
	}
	fmt.Fprintln(w)

	currentCategory := ""
	for _, view := range views {
		if view.Category != currentCategory {
			currentCategory = view.Category
			fmt.Fprintf(w, "[%s]\n", currentCategory)
		}
		prefix := "  -"
		if opts.Check {
			prefix = "  [?]"
			if view.Installed != nil && *view.Installed {
				prefix = "  [ok]"
			} else if len(view.Commands) > 0 {
				prefix = "  [missing]"
			}
		}
		fmt.Fprintf(w, "%s %s - %s\n", prefix, view.Name, view.Description)
		fmt.Fprintf(w, "      %s\n", view.URL)
		if opts.Check && len(view.Commands) > 0 {
			detail := "checks: " + strings.Join(view.Commands, ", ")
			if view.Path != "" {
				detail = "found: " + view.Path
			}
			fmt.Fprintf(w, "      %s\n", detail)
		}
	}

	if len(views) == 0 {
		fmt.Fprintln(w, "No tools matched.")
	}
	return nil
}

func Categories() ([]string, error) {
	all, err := Catalog()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, tool := range all {
		seen[tool.Category] = struct{}{}
	}
	categories := make([]string, 0, len(seen))
	for category := range seen {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	return categories, nil
}

func Recommended(all []Tool, modules []string) []Tool {
	if len(modules) == 0 {
		modules = []string{"passive", "resolve", "probe", "takeover", "ports", "screenshot"}
	}

	byName := make(map[string]Tool, len(all))
	for _, tool := range all {
		byName[normalizeKey(tool.Name)] = tool
	}

	seen := make(map[string]struct{})
	var out []Tool
	for _, module := range modules {
		for _, name := range recommendedNames[normalizeKey(module)] {
			key := normalizeKey(name)
			if _, ok := seen[key]; ok {
				continue
			}
			tool, ok := byName[key]
			if !ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, tool)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func filterTools(tools []Tool, category, search string) []Tool {
	category = normalizeKey(category)
	search = strings.ToLower(strings.TrimSpace(search))
	if category == "" && search == "" {
		return tools
	}

	var out []Tool
	for _, tool := range tools {
		if category != "" && normalizeKey(tool.Category) != category {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(tool.Category + " " + tool.Name + " " + tool.Description + " " + tool.URL)
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		out = append(out, tool)
	}
	return out
}

func installedPath(commands []string) (bool, string) {
	for _, command := range commands {
		path, err := exec.LookPath(command)
		if err == nil {
			return true, path
		}
	}
	return false, ""
}

func commandCandidates(name string) []string {
	var candidates []string
	if known, ok := knownCommands[name]; ok {
		candidates = append(candidates, known...)
	}
	if known, ok := knownCommands[strings.ToLower(name)]; ok {
		candidates = append(candidates, known...)
	}

	derived := deriveCommandName(name)
	if derived != "" {
		candidates = append(candidates, derived)
	}

	return uniqueStrings(candidates)
}

func deriveCommandName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".py")
	name = strings.TrimSuffix(name, ".rb")
	name = strings.TrimSuffix(name, ".go")
	name = strings.TrimSuffix(name, ".js")
	if strings.ContainsAny(name, " /\\()[]{}:") {
		return ""
	}
	if validCommandName.MatchString(name) {
		return name
	}
	return ""
}

func displayModules(modules []string) []string {
	if len(modules) == 0 {
		return []string{"default recon"}
	}
	out := make([]string, 0, len(modules))
	for _, module := range modules {
		if strings.TrimSpace(module) != "" {
			out = append(out, module)
		}
	}
	if len(out) == 0 {
		return []string{"default recon"}
	}
	return out
}

func uniqueStrings(values []string) []string {
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
	return out
}

func normalizeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.Join(strings.Fields(value), "-")
	return value
}

var validCommandName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var recommendedNames = map[string][]string{
	"passive":     {"subfinder", "Amass", "assetfinder", "github-subdomains", "gitlab-subdomains", "dnsx"},
	"resolve":     {"dnsx", "massdns", "puredns", "shuffledns"},
	"probe":       {"httpx", "webanalyze", "whatweb", "fingerprintx"},
	"brute":       {"puredns", "shuffledns", "massdns", "gobuster"},
	"permute":     {"alterx", "gotator", "dnsgen", "altdns"},
	"scrape":      {"katana", "hakrawler", "gau", "waybackurls", "GoLinkFinder", "jsluice"},
	"certs":       {"tlsx", "cero"},
	"dns-enum":    {"dnsx", "tlsx", "asnmap", "mapcidr"},
	"zt":          {"dnsx", "nmap"},
	"cidr":        {"asnmap", "mapcidr", "hakrevdns"},
	"takeover":    {"subzy", "subjack", "dnsReaper", "can-i-take-over-xyz", "nuclei"},
	"waf":         {"wafw00f", "cdncheck"},
	"ports":       {"naabu", "nmap", "RustScan", "masscan", "nrich"},
	"cors":        {"Corsy", "Corser", "CORStest"},
	"redirect":    {"Oralyzer", "OpenRedireX", "Injectus"},
	"screenshot":  {"gowitness", "aquatone", "EyeWitness", "screenshoteer"},
	"ollama":      {"PentestGPT", "PayloadsAllTheThings", "SecLists"},
	"vuln":        {"nuclei", "nuclei-templates", "jaeles", "nikto", "OWASP ZAP"},
	"curl":        {"httpx", "whatweb", "webanalyze"},
	"all":         {"subfinder", "Amass", "httpx", "nuclei", "katana", "dnsx", "naabu", "gowitness"},
	"recommended": {"subfinder", "Amass", "httpx", "nuclei", "katana", "dnsx", "naabu", "gowitness"},
}

var knownCommands = map[string][]string{
	"Amass":                {"amass"},
	"CORStest":             {"corstest"},
	"CorsMe":               {"corsme"},
	"Corsy":                {"corsy"},
	"EyeWitness":           {"eyewitness"},
	"GoLinkFinder":         {"golinkfinder"},
	"OpenRedireX":          {"openredirex"},
	"OWASP ZAP":            {"zap", "zap.sh"},
	"PayloadsAllTheThings": {"payloadsallthethings"},
	"RustScan":             {"rustscan"},
	"SecLists":             {"seclists"},
	"Sublist3r":            {"sublist3r"},
	"SubOver":              {"subover"},
	"acccheck":             {"acccheck"},
	"can-i-take-over-xyz":  {"can-i-take-over-xyz"},
	"commix":               {"commix"},
	"dirsearch":            {"dirsearch"},
	"dnsReaper":            {"dnsreaper"},
	"ffuf":                 {"ffuf"},
	"gobuster":             {"gobuster"},
	"gowitness":            {"gowitness"},
	"hakrawler":            {"hakrawler"},
	"hakrevdns":            {"hakrevdns"},
	"httpx":                {"httpx"},
	"jaeles":               {"jaeles"},
	"jsluice":              {"jsluice"},
	"katana":               {"katana"},
	"masscan":              {"masscan"},
	"massdns":              {"massdns"},
	"naabu":                {"naabu"},
	"nikto":                {"nikto"},
	"nmap":                 {"nmap"},
	"nuclei":               {"nuclei"},
	"nuclei-templates":     {"nuclei-templates"},
	"puredns":              {"puredns"},
	"retire.js":            {"retire"},
	"screenshoteer":        {"screenshoteer"},
	"shuffledns":           {"shuffledns"},
	"subfinder":            {"subfinder"},
	"subjack":              {"subjack"},
	"subzy":                {"subzy"},
	"tlsx":                 {"tlsx"},
	"wafw00f":              {"wafw00f"},
	"waybackurls":          {"waybackurls"},
	"webanalyze":           {"webanalyze"},
	"whatweb":              {"whatweb"},
	"xnLinkFinder":         {"xnlinkfinder"},
	"XSStrike":             {"xsstrike"},
	"GitHound":             {"githound"},
	"github-subdomains":    {"github-subdomains"},
	"gitlab-subdomains":    {"gitlab-subdomains"},
	"gau":                  {"gau"},
	"dnsx":                 {"dnsx"},
	"cdncheck":             {"cdncheck"},
	"asnmap":               {"asnmap"},
	"mapcidr":              {"mapcidr"},
	"alterx":               {"alterx"},
	"gotator":              {"gotator"},
	"dnsgen":               {"dnsgen"},
	"altdns":               {"altdns"},
	"assetfinder":          {"assetfinder"},
	"fingerprintx":         {"fingerprintx"},
	"cero":                 {"cero"},
	"nrich":                {"nrich"},
	"Oralyzer":             {"oralyzer"},
	"Injectus":             {"injectus"},
	"PentestGPT":           {"pentestgpt"},
}
