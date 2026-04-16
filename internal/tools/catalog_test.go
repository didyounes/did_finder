package tools

import "testing"

func TestCatalogLoadsEmbeddedAwesomeBugBountyTools(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog returned error: %v", err)
	}
	if len(catalog) < 400 {
		t.Fatalf("catalog has %d tools, want at least 400", len(catalog))
	}
}

func TestRecommendedMapsDidFinderModulesToTools(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatalf("Catalog returned error: %v", err)
	}

	recommended := Recommended(catalog, []string{"takeover", "ports"})
	names := make(map[string]bool)
	for _, tool := range recommended {
		names[tool.Name] = true
	}

	for _, want := range []string{"subzy", "nmap", "naabu"} {
		if !names[want] {
			t.Fatalf("expected recommendation %q in %#v", want, names)
		}
	}
}

func TestFilterToolsSearchesNamesDescriptionsAndCategories(t *testing.T) {
	filtered := filterTools([]Tool{
		{Category: "Subdomain Enumeration", Name: "subfinder", Description: "subdomain discovery"},
		{Category: "Port Scanning", Name: "naabu", Description: "fast scanner"},
	}, "", "port")

	if len(filtered) != 1 || filtered[0].Name != "naabu" {
		t.Fatalf("unexpected filtered tools: %#v", filtered)
	}
}
