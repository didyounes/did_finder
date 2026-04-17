package runner

import (
	"os"
	"reflect"
	"testing"
)

func TestParseTargetValuesNormalizesURLsAndComments(t *testing.T) {
	got := parseTargetValues("https://API.example.com:8443/path, *.dev.example.com # comment ignored")
	want := []string{"api.example.com", "dev.example.com"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargetValues() = %#v, want %#v", got, want)
	}
}

func TestAddTargetsGroupsSubdomainsByRegistrableRoot(t *testing.T) {
	options := &Options{TargetSeeds: make(map[string][]string)}
	seenDomains := make(map[string]struct{})
	seenSeeds := make(map[string]struct{})

	addTargets(options, []string{
		"https://api.example.co.uk/path",
		"www.example.co.uk",
		"example.co.uk",
		"https://api.example.co.uk/again",
	}, seenDomains, seenSeeds)

	if want := []string{"example.co.uk"}; !reflect.DeepEqual(options.Domains, want) {
		t.Fatalf("Domains = %#v, want %#v", options.Domains, want)
	}
	if want := []string{"api.example.co.uk", "www.example.co.uk", "example.co.uk"}; !reflect.DeepEqual(options.TargetSeeds["example.co.uk"], want) {
		t.Fatalf("TargetSeeds = %#v, want %#v", options.TargetSeeds["example.co.uk"], want)
	}
}

func TestReadTargetLinesSplitsListsAndSkipsComments(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "targets-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("# comment\nhttps://a.example.com/path, b.example.com\nc.example.com # trailing\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := readTargetLines(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readTargetLines() = %#v, want %#v", got, want)
	}
}

func TestParseSourceSetSupportsAliases(t *testing.T) {
	got, unknown := parseSourceSet("crtsh,wayback,vt")
	if len(unknown) > 0 {
		t.Fatalf("unexpected unknown sources: %#v", unknown)
	}
	for _, want := range []string{"crt.sh", "waybackarchive", "virustotal"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("source set missing %q: %#v", want, got)
		}
	}
}

func TestProfileSubdomainScoresHighSignalLabels(t *testing.T) {
	score, tags := profileSubdomain("admin-dev.example.com", 3)
	if score < 40 {
		t.Fatalf("score = %d, want high-signal score", score)
	}
	wantTags := map[string]bool{"admin": true, "non-prod": true, "high-confidence": true}
	for _, tag := range tags {
		delete(wantTags, tag)
	}
	if len(wantTags) > 0 {
		t.Fatalf("missing tags: %#v from %#v", wantTags, tags)
	}
}
