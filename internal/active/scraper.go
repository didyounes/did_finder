package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/yel-joul/did_finder/internal/utils"
)

// Scrape concurrently visits live subdomains to find more subdomains in JS/HTML
func Scrape(ctx context.Context, domain string, liveSubdomains []string, threads int) <-chan string {
	results := make(chan string)
	jobs := make(chan string, len(liveSubdomains))

	// Insecure transport for scraping to handle bad certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				// Try HTTP and HTTPS
				urls := []string{
					fmt.Sprintf("http://%s", sub),
					fmt.Sprintf("https://%s", sub),
				}

				for _, u := range urls {
					req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
					if err != nil {
						continue
					}

					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						continue
					}

					extracted := utils.ExtractSubdomains(string(body), domain)
					for _, ext := range extracted {
						results <- ext
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, sub := range liveSubdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	// Wait and close result channel
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
