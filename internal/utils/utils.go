package utils

import (
	"regexp"
	"strings"
)

func NormalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	for strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "*") {
		return ""
	}
	return value
}

func BelongsToDomain(host, domain string) bool {
	host = NormalizeHostname(host)
	domain = NormalizeHostname(domain)
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func ExtractSubdomains(body, domain string) []string {
	// Simple regex to find subdomains of the given domain
	re := regexp.MustCompile(`([a-zA-Z0-9.\-]+\.` + regexp.QuoteMeta(domain) + `)`)
	matches := re.FindAllString(body, -1)

	unique := make(map[string]struct{})
	var result []string
	for _, match := range matches {
		match = NormalizeHostname(match)
		if !BelongsToDomain(match, domain) {
			continue
		}
		if _, exists := unique[match]; !exists {
			unique[match] = struct{}{}
			result = append(result, match)
		}
	}
	return result
}
