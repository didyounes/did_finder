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
