package active

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/yel-joul/did_finder/internal/utils"
)

// ReverseDNSFromCIDR performs reverse DNS lookups on IP ranges found for the domain
func ReverseDNSFromCIDR(ctx context.Context, domain string, threads int) ([]string, error) {
	var results []string
	seen := make(map[string]struct{})

	// Step 1: Resolve the base domain to get its IP(s)
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("could not resolve %s: %w", domain, err)
	}

	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			continue // Skip IPv6 for now
		}

		// Step 2: Generate /24 CIDR for the IP
		octets := strings.Split(ip, ".")
		if len(octets) != 4 {
			continue
		}
		cidrBase := fmt.Sprintf("%s.%s.%s", octets[0], octets[1], octets[2])

		// Step 3: Reverse DNS each IP in the /24
		for i := 1; i < 255; i++ {
			targetIP := fmt.Sprintf("%s.%d", cidrBase, i)

			names, err := net.DefaultResolver.LookupAddr(ctx, targetIP)
			if err != nil || len(names) == 0 {
				continue
			}

			for _, name := range names {
				nameLower := utils.NormalizeHostname(name)

				// Only keep names that belong to our target domain
				if utils.BelongsToDomain(nameLower, domain) {
					if _, exists := seen[nameLower]; !exists {
						seen[nameLower] = struct{}{}
						results = append(results, nameLower)
					}
				}
			}
		}
	}

	return results, nil
}
