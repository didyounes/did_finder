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
	seen := make(map[string]bool)
	addTech := func(t string) {
		if !seen[t] {
			seen[t] = true
			techs = append(techs, t)
		}
	}

	// Header-based detection
	powered := headers.Get("X-Powered-By")
	if powered != "" {
		addTech(powered)
	}

	serverLower := strings.ToLower(headers.Get("Server"))
	serverPatterns := map[string]string{
		"nginx":         "Nginx",
		"apache":        "Apache",
		"cloudflare":    "Cloudflare",
		"iis":           "IIS",
		"litespeed":     "LiteSpeed",
		"openresty":     "OpenResty",
		"caddy":         "Caddy",
		"envoy":         "Envoy",
		"gunicorn":      "Gunicorn",
		"varnish":       "Varnish",
		"tengine":       "Tengine",
		"cowboy":        "Cowboy",
	}
	for pattern, tech := range serverPatterns {
		if strings.Contains(serverLower, pattern) {
			addTech(tech)
			break
		}
	}

	// Header fingerprints
	headerMapping := map[string]string{
		"X-Drupal-Cache":   "Drupal",
		"X-Generator":      "",
		"X-Shopify-Stage":  "Shopify",
		"X-Amz-Cf-Id":     "CloudFront",
		"X-Vercel-Id":     "Vercel",
		"X-Netlify-Id":    "Netlify",
		"Fly-Request-Id":  "Fly.io",
	}
	for header, tech := range headerMapping {
		val := headers.Get(header)
		if val != "" {
			if tech != "" {
				addTech(tech)
			} else {
				addTech(val)
			}
		}
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)
	techPatterns := map[string]string{
		"wp-content":                  "WordPress",
		"wp-includes":                 "WordPress",
		"react":                       "React",
		"angular":                     "Angular",
		"vue.js":                      "Vue.js",
		"vue.min.js":                  "Vue.js",
		"next.js":                     "Next.js",
		"__next":                      "Next.js",
		"_nuxt":                       "Nuxt.js",
		"jquery":                      "jQuery",
		"bootstrap":                   "Bootstrap",
		"tailwindcss":                 "Tailwind CSS",
		"laravel":                     "Laravel",
		"django":                      "Django",
		"express":                     "Express",
		"rails":                       "Rails",
		"shopify":                     "Shopify",
		"drupal":                      "Drupal",
		"joomla":                      "Joomla",
		"craft cms":                   "Craft CMS",
		"svelte":                      "Svelte",
		"gatsby":                      "Gatsby",
		"hugo":                        "Hugo",
		"ghost":                       "Ghost",
		"magento":                     "Magento",
		"woocommerce":                 "WooCommerce",
		"strapi":                      "Strapi",
		"contentful":                  "Contentful",
		"prismic":                     "Prismic",
		"firebase":                    "Firebase",
		"supabase":                    "Supabase",
		"graphql":                     "GraphQL",
		"swagger-ui":                  "Swagger",
		"openapi":                     "OpenAPI",
		"kubernetes":                  "Kubernetes",
		"docker":                      "Docker",
		"grafana":                     "Grafana",
		"jenkins":                     "Jenkins",
		"gitlab":                      "GitLab",
		"phpmyadmin":                  "phpMyAdmin",
		"webpackchunk":                "Webpack",
		"cloudflare-static":           "Cloudflare",
		"ember":                       "Ember.js",
		"backbone":                    "Backbone.js",
		"amp-":                        "AMP",
		"recaptcha":                   "reCAPTCHA",
		"google-analytics":            "Google Analytics",
		"gtag":                        "Google Tag Manager",
		"hotjar":                      "Hotjar",
		"sentry":                      "Sentry",
	}

	for pattern, tech := range techPatterns {
		if strings.Contains(bodyLower, pattern) {
			addTech(tech)
		}
	}

	return techs
}

