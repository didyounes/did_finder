package sources

import "context"

type Result struct {
	Type   string
	Source string
	Value  string
	Error  error
}

type Source interface {
	Run(ctx context.Context, domain string, results chan Result)
	Name() string
}
