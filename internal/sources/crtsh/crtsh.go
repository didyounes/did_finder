package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct{}

func (s *Source) Name() string {
	return "crt.sh"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain), nil)
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

	if resp.StatusCode != http.StatusOK {
		results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
		return
	}

	var data []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	for _, entry := range data {
		for _, sub := range strings.Split(entry.NameValue, "\n") {
			sub = strings.TrimSpace(sub)
			if strings.HasPrefix(sub, "*.") {
				sub = strings.TrimPrefix(sub, "*.")
			}
			if sub != "" {
				results <- sources.Result{Source: s.Name(), Value: sub}
			}
		}
	}
}
