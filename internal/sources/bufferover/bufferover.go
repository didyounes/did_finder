package bufferover

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
	return "bufferover"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain), nil)
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

	var data struct {
		Results []string `json:"Results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	seen := make(map[string]struct{})
	for _, entry := range data.Results {
		// Format is "ip,hostname" or just comma-separated values
		parts := strings.Split(entry, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasSuffix(part, domain) {
				if _, exists := seen[part]; !exists {
					seen[part] = struct{}{}
					results <- sources.Result{Source: s.Name(), Value: part}
				}
			}
		}
	}
}
