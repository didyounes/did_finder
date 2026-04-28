package threatcrowd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct{}

func (s *Source) Name() string {
	return "threatcrowd"
}

func (s *Source) Run(ctx context.Context, domain string) (<-chan sources.Result, error) {
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain), nil)
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

		var data struct {
			Subdomains []string `json:"subdomains"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		for _, sub := range data.Subdomains {
			if sub != "" {
				results <- sources.Result{Source: s.Name(), Value: sub}
			}
		}
	}()

	return results, nil
}
