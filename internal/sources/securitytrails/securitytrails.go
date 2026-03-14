package securitytrails

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
	return "securitytrails"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	if s.APIKey == "" {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), nil)
	if err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}
	req.Header.Set("APIKEY", s.APIKey)

	resp, err := http.DefaultClient.Do(req)
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
		Subdomains []string `json:"subdomains"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, sub := range data.Subdomains {
		if sub != "" {
			results <- sources.Result{Source: s.Name(), Value: sub + "." + domain}
		}
	}
}
