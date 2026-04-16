package active

import (
	"slices"
	"testing"
)

func TestBuildNucleiArgsUsesSafeJSONLOutput(t *testing.T) {
	args := buildNucleiArgs("targets.txt", NucleiOptions{
		Templates:   []string{"cves/", "exposures/"},
		Severity:    "low,medium,high,critical",
		Tags:        "cve,rce",
		ExcludeTags: "dos,fuzz,intrusive",
		RateLimit:   25,
		Concurrency: 10,
		Timeout:     15,
		Proxy:       "http://127.0.0.1:8080",
		Headless:    true,
		Code:        true,
		DAST:        true,
	})

	for _, want := range []string{
		"-l", "targets.txt", "-jsonl", "-silent", "-no-stdin", "-nc", "-or", "-ot",
		"-t", "cves/", "-t", "exposures/", "-s", "low,medium,high,critical",
		"-tags", "cve,rce", "-etags", "dos,fuzz,intrusive", "-rl", "25",
		"-c", "10", "-timeout", "15", "-proxy", "http://127.0.0.1:8080",
		"-headless", "-code", "-dast",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("expected args to contain %q: %#v", want, args)
		}
	}
}

func TestParseNucleiFinding(t *testing.T) {
	line := []byte(`{"template-id":"cve-2024-test","info":{"name":"Example CVE","severity":"high","tags":"cve,rce","classification":{"cve-id":["CVE-2024-0001"]}},"host":"https://example.com","matched-at":"https://example.com/login","type":"http"}`)

	finding, err := parseNucleiFinding(line)
	if err != nil {
		t.Fatalf("parseNucleiFinding returned error: %v", err)
	}
	if finding.TemplateID != "cve-2024-test" || finding.Info.Name != "Example CVE" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if len(finding.Info.Tags) != 2 || finding.Info.Tags[0] != "cve" || finding.Info.Tags[1] != "rce" {
		t.Fatalf("unexpected tags: %#v", finding.Info.Tags)
	}
	if len(finding.Info.Classification.CVEID) != 1 || finding.Info.Classification.CVEID[0] != "CVE-2024-0001" {
		t.Fatalf("unexpected CVEs: %#v", finding.Info.Classification.CVEID)
	}
}
