package active

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolve concurrently resolves a list of subdomains
// and returns a channel of live subdomains
func Resolve(ctx context.Context, subdomains []string, threads int) <-chan string {
	live := make(chan string)
	jobs := make(chan string, len(subdomains))

	// Custom resolver with short per-query timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				ips, err := resolver.LookupHost(queryCtx, sub)
				cancel()
				if err == nil && len(ips) > 0 {
					live <- sub
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, sub := range subdomains {
			select {
			case <-ctx.Done():
				break
			case jobs <- sub:
			}
		}
		close(jobs)
	}()

	// Wait and close result channel
	go func() {
		wg.Wait()
		close(live)
	}()

	return live
}
