package runner

import (
	"fmt"
	"io"
	"sort"
	"strings"

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

type passiveSourceSpec struct {
	Name        string
	Provider    sources.Provider
	RequiresKey bool
	HasKey      bool
}

func passiveSourceSpecs(config *utils.Config) []passiveSourceSpec {
	if config == nil {
		config = &utils.Config{}
	}
	return []passiveSourceSpec{
		{Name: "crt.sh", Provider: &crtsh.Source{}, HasKey: true},
		{Name: "hackertarget", Provider: &hackertarget.Source{}, HasKey: true},
		{Name: "alienvault", Provider: &alienvault.Source{}, HasKey: true},
		{Name: "waybackarchive", Provider: &wayback.Source{}, HasKey: true},
		{Name: "certspotter", Provider: &certspotter.Source{}, HasKey: true},
		{Name: "anubisdb", Provider: &anubis.Source{}, HasKey: true},
		{Name: "threatcrowd", Provider: &threatcrowd.Source{}, HasKey: true},
		{Name: "rapiddns", Provider: &rapiddns.Source{}, HasKey: true},
		{Name: "urlscan", Provider: &urlscan.Source{}, HasKey: true},
		{Name: "bufferover", Provider: &bufferover.Source{}, HasKey: true},
		{Name: "commoncrawl", Provider: &commoncrawl.Source{}, HasKey: true},
		{Name: "virustotal", Provider: &virustotal.Source{APIKey: config.VirusTotal}, RequiresKey: true, HasKey: config.VirusTotal != ""},
		{Name: "securitytrails", Provider: &securitytrails.Source{APIKey: config.SecurityTrails}, RequiresKey: true, HasKey: config.SecurityTrails != ""},
		{Name: "shodan", Provider: &shodan.Source{APIKey: config.Shodan}, RequiresKey: true, HasKey: config.Shodan != ""},
		{Name: "github", Provider: &github.Source{APIKey: config.GitHub}, RequiresKey: true, HasKey: config.GitHub != ""},
	}
}

func PrintSourceList(w io.Writer) {
	fmt.Fprintln(w, "Passive sources:")
	for _, spec := range passiveSourceSpecs(nil) {
		keyNote := ""
		if spec.RequiresKey {
			keyNote = " (requires API key)"
		}
		fmt.Fprintf(w, "  - %s%s\n", spec.Name, keyNote)
	}
}

func validateSourceSelection(options *Options) error {
	for _, list := range []string{options.Sources, options.ExcludeSources} {
		if _, unknown := parseSourceSet(list); len(unknown) > 0 {
			return fmt.Errorf("unknown passive source(s): %s (run -list-sources)", strings.Join(unknown, ", "))
		}
	}
	return nil
}

func (r *Runner) passiveSources() []sources.Provider {
	include, _ := parseSourceSet(r.options.Sources)
	exclude, _ := parseSourceSet(r.options.ExcludeSources)

	var selected []sources.Provider
	for _, spec := range passiveSourceSpecs(r.config) {
		name := sourceCanonical(spec.Name)
		if include != nil {
			if _, ok := include[name]; !ok {
				continue
			}
		}
		if _, skip := exclude[name]; skip {
			continue
		}
		if spec.RequiresKey && !spec.HasKey {
			continue
		}
		selected = append(selected, spec.Provider)
	}
	return selected
}

func parseSourceSet(value string) (map[string]struct{}, []string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	selected := make(map[string]struct{})
	var unknown []string
	for _, part := range splitCommaList(value) {
		if strings.EqualFold(part, "all") {
			return nil, nil
		}
		canonical, ok := canonicalSourceName(part)
		if !ok {
			unknown = append(unknown, part)
			continue
		}
		selected[canonical] = struct{}{}
	}
	if len(selected) == 0 && len(unknown) == 0 {
		return nil, nil
	}
	sort.Strings(unknown)
	return selected, unknown
}

func canonicalSourceName(value string) (string, bool) {
	key := normalizeSourceKey(value)
	aliases := map[string]string{
		"crt":            "crt.sh",
		"crtsh":          "crt.sh",
		"hackertarget":   "hackertarget",
		"alienvault":     "alienvault",
		"otx":            "alienvault",
		"wayback":        "waybackarchive",
		"waybackarchive": "waybackarchive",
		"archive":        "waybackarchive",
		"certspotter":    "certspotter",
		"anubis":         "anubisdb",
		"anubisdb":       "anubisdb",
		"threatcrowd":    "threatcrowd",
		"rapiddns":       "rapiddns",
		"urlscan":        "urlscan",
		"bufferover":     "bufferover",
		"commoncrawl":    "commoncrawl",
		"cc":             "commoncrawl",
		"virustotal":     "virustotal",
		"vt":             "virustotal",
		"securitytrails": "securitytrails",
		"shodan":         "shodan",
		"github":         "github",
	}
	name, ok := aliases[key]
	return name, ok
}

func sourceCanonical(value string) string {
	name, ok := canonicalSourceName(value)
	if !ok {
		return strings.ToLower(strings.TrimSpace(value))
	}
	return name
}

func normalizeSourceKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(".", "", "-", "", "_", "", " ", "").Replace(value)
	return value
}
