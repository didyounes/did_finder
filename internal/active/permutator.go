package active

import (
	"fmt"
	"strings"
)

var defaultPermutations = []string{
	"api", "dev", "staging", "test", "prod", "vpn",
	"mail", "admin", "portal", "web", "cdn", "v1", "v2",
}

// GeneratePermutations takes a base domain and a list of found subdomains
// and generates potential new subdomains based on common patterns
func GeneratePermutations(domain string, foundSubdomains []string) []string {
	permutations := make(map[string]struct{})

	// Base permutations (e.g., api.domain.com, api-dev.domain.com)
	for _, perm := range defaultPermutations {
		permutations[fmt.Sprintf("%s.%s", perm, domain)] = struct{}{}
		permutations[fmt.Sprintf("%s-%s.%s", perm, perm, domain)] = struct{}{} // example: api-v1.domain.com
	}

	// Permute found subdomains
	for _, sub := range foundSubdomains {
		if sub == domain {
			continue
		}
		
		// Remove base domain from sub to get the prefix
		prefix := strings.TrimSuffix(sub, "."+domain)
		
		for _, perm := range defaultPermutations {
			// Prepend: dev-api.domain.com
			permutations[fmt.Sprintf("%s-%s.%s", perm, prefix, domain)] = struct{}{}
			permutations[fmt.Sprintf("%s.%s.%s", perm, prefix, domain)] = struct{}{}
			
			// Append: api-dev.domain.com
			permutations[fmt.Sprintf("%s-%s.%s", prefix, perm, domain)] = struct{}{}
			permutations[fmt.Sprintf("%s.%s.%s", prefix, perm, domain)] = struct{}{}
		}
	}

	var results []string
	for p := range permutations {
		results = append(results, p)
	}

	return results
}
