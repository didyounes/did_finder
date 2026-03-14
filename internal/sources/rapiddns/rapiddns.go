package rapiddns

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/yel-joul/did_finder/internal/sources"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Source struct{}

func (s *Source) Name() string {
	return "rapiddns"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain), nil)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- sources.Result{Source: s.Name(), Error: err}
		return
	}

	subs := utils.ExtractSubdomains(string(body), domain)
	for _, sub := range subs {
		results <- sources.Result{Source: s.Name(), Value: sub}
	}
}
