package utils

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func NormalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, "\"'`<>()[]{}")

	if strings.HasPrefix(value, "//") {
		value = "https:" + value
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	if idx := strings.IndexAny(value, "/?#"); idx >= 0 {
		value = value[:idx]
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if idx := strings.LastIndex(value, ":"); idx > -1 && strings.Count(value, ":") == 1 {
		if _, err := strconv.Atoi(value[idx+1:]); err == nil {
			value = value[:idx]
		}
	}

	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")
	for strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "*") || strings.ContainsAny(value, " \t\r\n@") {
		return ""
	}
	return value
}

func RegistrableDomain(value string) string {
	host := NormalizeHostname(value)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	if domain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return domain
	}

	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return host
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
