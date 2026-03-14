package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ProbeResult holds the result of probing a subdomain
type ProbeResult struct {
	Subdomain    string   `json:"subdomain"`
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title,omitempty"`
	ContentLength int64   `json:"content_length"`
	Server       string   `json:"server,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Alive        bool     `json:"alive"`
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*([^<]+)\s*</title>`)

// Probe performs HTTP probing on live subdomains across multiple ports
func Probe(ctx context.Context, subdomains []string, threads int) <-chan ProbeResult {
	results := make(chan ProbeResult)
	jobs := make(chan string, len(subdomains))

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:      100,
		IdleConnTimeout:   5 * time.Second,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
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
				// Try common ports
				urls := []string{
					fmt.Sprintf("https://%s", sub),
					fmt.Sprintf("http://%s", sub),
					fmt.Sprintf("https://%s:8443", sub),
					fmt.Sprintf("http://%s:8080", sub),
				}

				for _, u := range urls {
					result := probeSingle(ctx, client, sub, u)
					if result.Alive {
						results <- result
						break // Found a live port, move on
					}
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

func probeSingle(ctx context.Context, client *http.Client, subdomain, url string) ProbeResult {
	result := ProbeResult{
		Subdomain: subdomain,
		URL:       url,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}
	req.Header.Set("User-Agent", "did_finder/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Alive = true
	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength
	result.Server = resp.Header.Get("Server")

	// Read body for title extraction and tech detection
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // 100KB max
	if err == nil {
		bodyStr := string(body)

		// Extract title
		if matches := titleRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
			result.Title = strings.TrimSpace(matches[1])
		}

		// Basic technology fingerprinting
		result.Technologies = detectTechnologies(resp.Header, bodyStr)
	}

	return result
}

func detectTechnologies(headers http.Header, body string) []string {
	var techs []string

	// Header-based detection
	powered := headers.Get("X-Powered-By")
	if powered != "" {
		techs = append(techs, powered)
	}

	server := headers.Get("Server")
	switch {
	case strings.Contains(strings.ToLower(server), "nginx"):
		techs = append(techs, "Nginx")
	case strings.Contains(strings.ToLower(server), "apache"):
		techs = append(techs, "Apache")
	case strings.Contains(strings.ToLower(server), "cloudflare"):
		techs = append(techs, "Cloudflare")
	case strings.Contains(strings.ToLower(server), "iis"):
		techs = append(techs, "IIS")
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)
	techPatterns := map[string]string{
		"wp-content":          "WordPress",
		"react":               "React",
		"angular":             "Angular",
		"vue.js":              "Vue.js",
		"next.js":             "Next.js",
		"jquery":              "jQuery",
		"bootstrap":           "Bootstrap",
		"laravel":             "Laravel",
		"django":              "Django",
		"express":             "Express",
		"rails":               "Rails",
		"__next":              "Next.js",
		"_nuxt":               "Nuxt.js",
		"shopify":             "Shopify",
		"drupal":              "Drupal",
		"joomla":              "Joomla",
		"craft cms":           "Craft CMS",
	}

	for pattern, tech := range techPatterns {
		if strings.Contains(bodyLower, pattern) {
			techs = append(techs, tech)
		}
	}

	return techs
}
