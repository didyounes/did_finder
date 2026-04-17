package active

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
)

// WildcardDetector detects and filters wildcard DNS records
type WildcardDetector struct {
	wildcardIPs map[string]struct{}
	mu          sync.RWMutex
	detected    bool
}

func NewWildcardDetector() *WildcardDetector {
	return &WildcardDetector{
		wildcardIPs: make(map[string]struct{}),
	}
}

// Detect queries 3 random subdomains that almost certainly don't exist.
// If they all resolve to the same IP set, it's a wildcard.
func (w *WildcardDetector) Detect(ctx context.Context, domain string) bool {
	return w.DetectWithResolvers(ctx, domain, nil)
}

func (w *WildcardDetector) DetectWithResolvers(ctx context.Context, domain string, resolvers []string) bool {
	var allIPs [][]string
	dnsClient := NewDNSClient(resolvers)

	for i := 0; i < 3; i++ {
		random := fmt.Sprintf("%s.%s", randomString(12), domain)
		ips, err := dnsClient.LookupHost(ctx, random)
		if err != nil || len(ips) == 0 {
			return false // non-existent sub didn't resolve → no wildcard
		}
		allIPs = append(allIPs, ips)
	}

	// Check if all random lookups returned the same set
	if len(allIPs) == 3 && sameIPs(allIPs[0], allIPs[1]) && sameIPs(allIPs[1], allIPs[2]) {
		w.mu.Lock()
		w.detected = true
		for _, ip := range allIPs[0] {
			w.wildcardIPs[ip] = struct{}{}
		}
		w.mu.Unlock()
		return true
	}

	return false
}

// IsWildcard returns true if the given IPs match known wildcard IPs
func (w *WildcardDetector) IsWildcard(ips []string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if !w.detected {
		return false
	}

	for _, ip := range ips {
		if _, exists := w.wildcardIPs[ip]; exists {
			return true
		}
	}
	return false
}

func (w *WildcardDetector) Detected() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.detected
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func sameIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{})
	for _, ip := range a {
		set[ip] = struct{}{}
	}
	for _, ip := range b {
		if _, exists := set[ip]; !exists {
			return false
		}
	}
	return true
}
