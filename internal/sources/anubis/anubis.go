package anubis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct{}

func (s *Source) Name() string {
	return "anubisdb"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain), nil)
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

	var subs []string
	if err := json.NewDecoder(resp.Body).Decode(&subs); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, sub := range subs {
		if sub != "" {
			results <- sources.Result{Source: s.Name(), Value: sub}
		}
	}
}
