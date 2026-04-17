package utils

import "testing"

func TestBelongsToDomainRequiresLabelBoundary(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"deep.www.example.com.", true},
		{"*.example.com", true},
		{"testexample.com", false},
		{"m.testexample.com", false},
		{"example.com.evil.test", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := BelongsToDomain(tt.host, "example.com"); got != tt.want {
			t.Fatalf("BelongsToDomain(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestNormalizeHostnameCleansTargetForms(t *testing.T) {
	tests := map[string]string{
		"HTTPS://API.Example.COM:8443/path?q=1": "api.example.com",
		"*.Dev.Example.com.":                    "dev.example.com",
		"//cdn.example.com/assets/app.js":       "cdn.example.com",
		"example.com:443":                       "example.com",
		"bad*.example.com":                      "",
	}

	for input, want := range tests {
		if got := NormalizeHostname(input); got != want {
			t.Fatalf("NormalizeHostname(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRegistrableDomainUsesPublicSuffixBoundaries(t *testing.T) {
	tests := map[string]string{
		"api.example.com":                "example.com",
		"https://a.b.example.co.uk/path": "example.co.uk",
		"example.com":                    "example.com",
		"localhost":                      "localhost",
	}

	for input, want := range tests {
		if got := RegistrableDomain(input); got != want {
			t.Fatalf("RegistrableDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestExtractSubdomainsFiltersByDomainBoundary(t *testing.T) {
	got := ExtractSubdomains("www.example.com m.testexample.com api.example.com.", "example.com")
	want := map[string]bool{
		"www.example.com": true,
		"api.example.com": true,
	}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, sub := range got {
		if !want[sub] {
			t.Fatalf("unexpected subdomain: %s", sub)
		}
	}
}
