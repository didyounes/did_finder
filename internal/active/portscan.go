package active

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// PortResult holds the result of a port scan for a subdomain
type PortResult struct {
	Subdomain string `json:"subdomain"`
	OpenPorts []int  `json:"open_ports"`
}

// Top 100 most common ports
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 465, 587, 631, 636, 993, 995, 1025,
	1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2096,
	2181, 3000, 3128, 3306, 3389, 3690, 4000, 4443, 4444, 4848,
	5000, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6443, 6666,
	7001, 7002, 7071, 7080, 7443, 8000, 8008, 8009, 8042, 8060,
	8069, 8080, 8081, 8083, 8088, 8090, 8091, 8123, 8161, 8200,
	8333, 8443, 8500, 8686, 8834, 8880, 8888, 8983, 9000, 9001,
	9042, 9090, 9091, 9200, 9300, 9418, 9443, 9999, 10000, 10250,
	11211, 15672, 16080, 18080, 20000, 27017, 27018, 28017, 50000, 50070,
}

// PortScan scans common ports on discovered subdomains
func PortScan(ctx context.Context, subdomains []string, threads int) <-chan PortResult {
	results := make(chan PortResult)
	jobs := make(chan string, len(subdomains))

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				result := scanHost(ctx, sub)
				if len(result.OpenPorts) > 0 {
					results <- result
				}
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func scanHost(ctx context.Context, subdomain string) PortResult {
	result := PortResult{Subdomain: subdomain}
	
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // Limit concurrent port checks per host

	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return result
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			addr := net.JoinHostPort(subdomain, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				result.OpenPorts = append(result.OpenPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return result
}
