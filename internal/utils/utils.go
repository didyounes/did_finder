package utils

import (
	"regexp"
)

func ExtractSubdomains(body, domain string) []string {
	// Simple regex to find subdomains of the given domain
	re := regexp.MustCompile(`([a-zA-Z0-9.\-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(body, -1)
	
	unique := make(map[string]struct{})
	var result []string
	for _, match := range matches {
		if _, exists := unique[match]; !exists {
			unique[match] = struct{}{}
			result = append(result, match)
		}
	}
	return result
}
