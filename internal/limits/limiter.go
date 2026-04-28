package limits

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

type Limiter interface {
	Wait(ctx context.Context) error
}

type AdaptiveLimiter interface {
	Limiter
	Observe(Observation)
}

type Observation struct {
	StatusCode int
	Err        error
	RetryAfter time.Duration
}

type BucketConfig struct {
	Name  string
	Rate  rate.Limit
	Burst int
	Min   rate.Limit
	Max   rate.Limit
}

type tokenBucketLimiter struct {
	limiter *rate.Limiter
}

func NewTokenBucket(rateLimit float64, burst int) Limiter {
	if rateLimit <= 0 {
		rateLimit = 1
	}
	if burst <= 0 {
		burst = 1
	}
	return &tokenBucketLimiter{
		limiter: rate.NewLimiter(rate.Limit(rateLimit), burst),
	}
}

func (t *tokenBucketLimiter) Wait(ctx context.Context) error {
	return t.limiter.Wait(ctx)
}
