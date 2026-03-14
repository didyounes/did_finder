package urlscan

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
	return "urlscan"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=1000", domain), nil)
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
		sub := r.Page.Domain
		if sub != "" && strings.HasSuffix(sub, domain) {
			results <- sources.Result{Source: s.Name(), Value: sub}
		}
	}
}
