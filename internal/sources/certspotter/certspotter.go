package certspotter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct{}

func (s *Source) Name() string {
	return "certspotter"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), nil)
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
		results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
		return
	}

	var data []struct {
		DNSNames []string `json:"dns_names"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, entry := range data {
		for _, name := range entry.DNSNames {
			results <- sources.Result{Source: s.Name(), Value: name}
		}
	}
}
