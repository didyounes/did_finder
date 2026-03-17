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

// CORSResult holds the result of a CORS misconfiguration check
type CORSResult struct {
	Subdomain       string `json:"subdomain"`
	URL             string `json:"url"`
	Origin          string `json:"origin"`
	AllowOrigin     string `json:"allow_origin"`
	AllowCredentials bool  `json:"allow_credentials"`
	Vulnerable      bool   `json:"vulnerable"`
	Type            string `json:"type"` // "reflected", "wildcard", "null", "prefix"
}

// CheckCORS checks subdomains for CORS misconfigurations
func CheckCORS(ctx context.Context, subdomains []string, threads int) <-chan CORSResult {
	results := make(chan CORSResult)
	jobs := make(chan string, len(subdomains))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				checkCORSSingle(ctx, client, sub, results)
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

func checkCORSSingle(ctx context.Context, client *http.Client, subdomain string, results chan<- CORSResult) {
	urls := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	evilOrigins := []struct {
		origin string
		typ    string
	}{
		{"https://evil.com", "reflected"},
		{"null", "null"},
		{fmt.Sprintf("https://%s.evil.com", subdomain), "prefix"},
		{fmt.Sprintf("https://evil-%s", subdomain), "prefix"},
	}

	for _, u := range urls {
		for _, test := range evilOrigins {
			select {
			case <-ctx.Done():
				return
			default:
			}

			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", test.origin)
			req.Header.Set("User-Agent", "did_finder/3.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

			if allowOrigin == "" {
				continue
			}

			vuln := false
			vulnType := ""

			switch {
			case allowOrigin == "*" && strings.EqualFold(allowCreds, "true"):
				vuln = true
				vulnType = "wildcard-with-credentials"
			case allowOrigin == test.origin && test.typ == "reflected":
				vuln = true
				vulnType = "reflected-origin"
			case allowOrigin == "null" && test.origin == "null":
				vuln = true
				vulnType = "null-origin"
			case allowOrigin == test.origin && test.typ == "prefix":
				vuln = true
				vulnType = "prefix-bypass"
			}

			if vuln {
				results <- CORSResult{
					Subdomain:        subdomain,
					URL:              u,
					Origin:           test.origin,
					AllowOrigin:      allowOrigin,
					AllowCredentials: strings.EqualFold(allowCreds, "true"),
					Vulnerable:       true,
					Type:             vulnType,
				}
				return // One finding per subdomain is enough
			}
		}
		break // Only try first working URL scheme
	}
}
