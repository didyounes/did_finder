package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/yel-joul/did_finder/internal/sources"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Source struct {
	APIKey string
}

func (s *Source) Name() string {
	return "github"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	if s.APIKey == "" {
		return // Silently skip if no API key
	}

	seen := make(map[string]struct{})
	subRe := regexp.MustCompile(`([a-zA-Z0-9][-a-zA-Z0-9]*\.)+` + regexp.QuoteMeta(domain))

	// Search multiple pages (max 5 to avoid rate limits)
	for page := 1; page <= 5; page++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=100&page=%d", domain, page), nil)
		if err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		req.Header.Set("Authorization", fmt.Sprintf("token %s", s.APIKey))
		req.Header.Set("Accept", "application/vnd.github.v3.text-match+json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			break // Rate limited
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("github API returned %d", resp.StatusCode)}
			return
		}

		var data struct {
			Items []struct {
				TextMatches []struct {
					Fragment string `json:"fragment"`
				} `json:"text_matches"`
			} `json:"items"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}
		resp.Body.Close()

		for _, item := range data.Items {
			for _, tm := range item.TextMatches {
				matches := subRe.FindAllString(tm.Fragment, -1)
				for _, match := range matches {
					match = utils.NormalizeHostname(match)
					if utils.BelongsToDomain(match, domain) {
						if _, exists := seen[match]; !exists {
							seen[match] = struct{}{}
							results <- sources.Result{Source: s.Name(), Value: match}
						}
					}
				}
			}
		}

		if len(data.Items) < 100 {
			break // No more pages
		}

		// Respect GitHub rate limits
		time.Sleep(2 * time.Second)
	}
}
