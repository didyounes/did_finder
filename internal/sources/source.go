package sources

import (
	"context"
	"net/http"
)

type Result struct {
	Type   string
	Source string
	Value  string
	Error  error
}

type Provider interface {
	Name() string
	Run(ctx context.Context, domain string) (<-chan Result, error)
}

type Source = Provider

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}
