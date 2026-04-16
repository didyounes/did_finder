package commoncrawl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yel-joul/did_finder/internal/sources"
	"github.com/yel-joul/did_finder/internal/utils"
)

type Source struct{}

func (s *Source) Name() string {
	return "commoncrawl"
}

func (s *Source) Run(ctx context.Context, domain string, results chan sources.Result) {
	// Get the latest index
	indexes, err := getIndexes(ctx)
	if err != nil || len(indexes) == 0 {
		results <- sources.Result{Source: s.Name(), Error: fmt.Errorf("failed to get indexes: %w", err)}
		return
	}

	// Use the latest index only to avoid excessive requests
	latestIndex := indexes[0].API

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s?url=*.%s&output=json&fl=url", latestIndex, domain), nil)
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

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract hostname from URL
		host := utils.NormalizeHostname(extractHost(entry.URL))
		if utils.BelongsToDomain(host, domain) {
			if _, exists := seen[host]; !exists {
				seen[host] = struct{}{}
				results <- sources.Result{Source: s.Name(), Value: host}
			}
		}
	}
}

type indexEntry struct {
	API string `json:"cdx-api"`
}

func getIndexes(ctx context.Context) ([]indexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var indexes []indexEntry
	if err := json.NewDecoder(resp.Body).Decode(&indexes); err != nil {
		return nil, err
	}
	return indexes, nil
}

func extractHost(rawURL string) string {
	// Remove scheme
	u := rawURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Remove path
	if idx := strings.IndexAny(u, "/?#"); idx != -1 {
		u = u[:idx]
	}
	// Remove port
	if idx := strings.LastIndex(u, ":"); idx != -1 {
		u = u[:idx]
	}
	return strings.ToLower(strings.TrimSpace(u))
}
