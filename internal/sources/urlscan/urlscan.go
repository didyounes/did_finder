package urlscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Source struct{}

func (s *Source) Name() string {
	return "urlscan"
}

func (s *Source) Run(ctx context.Context, domain string) (<-chan sources.Result, error) {
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=1000", domain), nil)
		if err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		resp, err := sources.Do(req)
		if err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("status %d", resp.StatusCode)}
			return
		}

		var data struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		for _, r := range data.Results {
			sub := utils.NormalizeHostname(r.Page.Domain)
			if utils.BelongsToDomain(sub, domain) {
				results <- sources.Result{Source: s.Name(), Value: sub}
			}
		}
	}()

	return results, nil
}
