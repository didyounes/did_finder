package virustotal

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
	return "virustotal"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	if s.APIKey == "" {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain), nil)
	if err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}
	req.Header.Set("x-apikey", s.APIKey)

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
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, entry := range data.Data {
		if entry.ID != "" {
			results <- sources.Result{Source: s.Name(), Value: entry.ID}
		}
	}
}
