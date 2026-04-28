package active

import (
	"context"
	"time"

	"github.com/yel-joul/did_finder/internal/limits"
)

type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

type WorkOptions struct {
	Concurrency int
	Timeout     time.Duration
	Limiter     limits.Limiter
}

type ResolveOptions struct {
	WorkOptions
	Resolver DNSResolver
}
