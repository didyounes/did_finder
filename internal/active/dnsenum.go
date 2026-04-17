package active

import (
	"context"
	"net"
	"strings"
	"sync"
)

// DNSRecord holds a comprehensive DNS record for a subdomain
type DNSRecord struct {
	Subdomain string   `json:"subdomain"`
	A         []string `json:"a,omitempty"`
	AAAA      []string `json:"aaaa,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
	MX        []string `json:"mx,omitempty"`
	NS        []string `json:"ns,omitempty"`
	TXT       []string `json:"txt,omitempty"`
}

// EnumerateDNS performs full DNS enumeration on subdomains
func EnumerateDNS(ctx context.Context, subdomains []string, threads int) <-chan DNSRecord {
	return EnumerateDNSWithResolvers(ctx, subdomains, threads, nil)
}

func EnumerateDNSWithResolvers(ctx context.Context, subdomains []string, threads int, resolvers []string) <-chan DNSRecord {
	results := make(chan DNSRecord)
	jobs := make(chan string, len(subdomains))

	if threads <= 0 {
		threads = 1
	}
	dnsClient := NewDNSClient(resolvers)

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				record := DNSRecord{Subdomain: sub}

				// A records
				ips, err := dnsClient.LookupHost(ctx, sub)
				if err == nil {
					for _, ip := range ips {
						parsed := net.ParseIP(ip)
						if parsed != nil {
							if parsed.To4() != nil {
								record.A = append(record.A, ip)
							} else {
								record.AAAA = append(record.AAAA, ip)
							}
						}
					}
				}

				// CNAME
				cname, err := dnsClient.LookupCNAME(ctx, sub)
				if err == nil && cname != "" && cname != sub+"." {
					record.CNAME = strings.TrimSuffix(cname, ".")
				}

				// MX
				mxRecords, err := dnsClient.LookupMX(ctx, sub)
				if err == nil {
					for _, mx := range mxRecords {
						record.MX = append(record.MX, strings.TrimSuffix(mx.Host, "."))
					}
				}

				// NS
				nsRecords, err := dnsClient.LookupNS(ctx, sub)
				if err == nil {
					for _, ns := range nsRecords {
						record.NS = append(record.NS, strings.TrimSuffix(ns.Host, "."))
					}
				}

				// TXT
				txtRecords, err := dnsClient.LookupTXT(ctx, sub)
				if err == nil {
					record.TXT = txtRecords
				}

				if len(record.A) > 0 || len(record.AAAA) > 0 || record.CNAME != "" {
					results <- record
				}
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- sub:
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
