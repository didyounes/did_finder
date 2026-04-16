package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultOllamaHost  = "http://127.0.0.1:11434"
	DefaultOllamaModel = "llama3.2:1b"
)

type OllamaClient struct {
	Host       string
	Model      string
	HTTPClient *http.Client
}

func NewOllamaClient(host, model string) *OllamaClient {
	if host == "" {
		host = DefaultOllamaHost
	}
	if model == "" {
		model = DefaultOllamaModel
	}

	return &OllamaClient{
		Host:  normalizeHost(host),
		Model: model,
		HTTPClient: &http.Client{
			Timeout: 2 * time.Minute,
		},
	}
}

func (c *OllamaClient) HasModel(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Host+"/api/tags", nil)
	if err != nil {
		return false, err
	}

	resp, err := c.client().Do(req)
	if err != nil {
		return false, fmt.Errorf("could not reach Ollama at %s: %w", c.Host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("ollama model list failed: %s", readLimited(resp.Body))
	}

	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return false, fmt.Errorf("could not parse Ollama model list: %w", err)
	}

	for _, model := range tags.Models {
		if modelMatches(c.Model, model.Name) {
			return true, nil
		}
	}
	return false, nil
}

func (c *OllamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	body := map[string]interface{}{
		"model":  c.Model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.2,
		},
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Host+"/api/generate", bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama generate failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("ollama generate failed: %s", readLimited(resp.Body))
	}

	var result struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("could not parse Ollama response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("ollama generate failed: %s", result.Error)
	}
	if strings.TrimSpace(result.Response) == "" {
		return "", fmt.Errorf("ollama returned an empty response")
	}

	return strings.TrimSpace(result.Response), nil
}

func (c *OllamaClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, "/")
	if host == "" {
		return DefaultOllamaHost
	}
	return host
}

func modelMatches(want, have string) bool {
	if have == want {
		return true
	}
	return strings.TrimSuffix(have, ":latest") == want || have == want+":latest"
}

func readLimited(r io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(r, 4096))
	return strings.TrimSpace(string(data))
}
