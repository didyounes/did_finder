package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct {
	APIKey string
}

func (s *Source) Name() string {
	return "shodan"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	if s.APIKey == "" {
		return // Silently skip if no API key
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, s.APIKey), nil)
	if err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("shodan API returned %d", resp.StatusCode)}
		return
	}

	var data struct {
		Domain     string `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, sub := range data.Subdomains {
		if sub != "" {
			results <- sources.Result{Source: s.Name(), Value: fmt.Sprintf("%s.%s", sub, domain)}
		}
	}
}
