package active

import (
	"context"
	"sync"
)

// Resolve concurrently resolves a list of subdomains
// and returns a channel of live subdomains
func Resolve(ctx context.Context, subdomains []string, threads int) <-chan string {
	return ResolveWithResolvers(ctx, subdomains, threads, nil)
}

func ResolveWithResolvers(ctx context.Context, subdomains []string, threads int, resolvers []string) <-chan string {
	live := make(chan string)
	jobs := make(chan string, len(subdomains))

	if threads <= 0 {
		threads = 1
	}
	dnsClient := NewDNSClient(resolvers)

	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				ips, err := dnsClient.LookupHost(ctx, sub)
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
				close(jobs)
				return
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
