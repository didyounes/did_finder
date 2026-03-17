package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RedirectResult holds the result of an open redirect check
type RedirectResult struct {
	Subdomain string `json:"subdomain"`
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Location  string `json:"location"`
}

// Common redirect parameters to test
var redirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "next", "redir",
	"return", "return_to", "returnTo", "return_url", "go", "goto",
	"dest", "destination", "out", "continue", "target", "link",
	"forward", "view", "image_url", "to", "site", "callback",
	"ref", "data", "RelayState", "SAMLRequest", "auth_url",
}

// Canary domain for detecting open redirects
const canaryDomain = "https://evil.did-finder-test.com"

// CheckOpenRedirect checks subdomains for open redirect vulnerabilities
func CheckOpenRedirect(ctx context.Context, subdomains []string, threads int) <-chan RedirectResult {
	results := make(chan RedirectResult)
	jobs := make(chan string, len(subdomains))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				checkRedirectSingle(ctx, client, sub, results)
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

func checkRedirectSingle(ctx context.Context, client *http.Client, subdomain string, results chan<- RedirectResult) {
	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	for _, baseURL := range baseURLs {
		for _, param := range redirectParams {
			select {
			case <-ctx.Done():
				return
			default:
			}

			testURL := fmt.Sprintf("%s/?%s=%s", baseURL, param, canaryDomain)

			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "did_finder/3.0")

			resp, err := client.Do(req)
			if err != nil {
				break // Host unreachable, skip to next base URL
			}
			resp.Body.Close()

			// Check if response redirects to our canary
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" && isCanaryRedirect(location) {
					results <- RedirectResult{
						Subdomain: subdomain,
						URL:       testURL,
						Parameter: param,
						Location:  location,
					}
					return // One finding per subdomain is enough
				}
			}
		}
		break // Only try first working scheme
	}
}

func isCanaryRedirect(location string) bool {
	location = strings.ToLower(location)
	return strings.Contains(location, "evil.did-finder-test.com")
}
