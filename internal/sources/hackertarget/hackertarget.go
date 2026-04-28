package hackertarget

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/yel-joul/did_finder/internal/sources"
)

type Source struct{}

func (s *Source) Name() string {
	return "hackertarget"
}

func (s *Source) Run(ctx context.Context, domain string) (<-chan sources.Result, error) {
	results := make(chan sources.Result)

	go func() {
		defer close(results)

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain), nil)
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

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- sources.Result{Source: s.Name(), Error: err}
			return
		}

		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ",")
			if len(parts) > 0 && parts[0] != "" {
				results <- sources.Result{Source: s.Name(), Value: parts[0]}
			}
		}
	}()

	return results, nil
}
