package utils

import (
	"sync"
	"time"
)

// RateLimiter implements a token-bucket rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	rate     int
	tokens   int
	lastTime time.Time
}

func NewRateLimiter(ratePerSecond int) *RateLimiter {
	return &RateLimiter{
		rate:     ratePerSecond,
		tokens:   ratePerSecond,
		lastTime: time.Now(),
	}
}

func (rl *RateLimiter) Wait() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime)

	// Add tokens based on elapsed time
	newTokens := int(elapsed.Seconds() * float64(rl.rate))
	rl.tokens += newTokens
	if rl.tokens > rl.rate {
		rl.tokens = rl.rate
	}
	rl.lastTime = now

	if rl.tokens > 0 {
		rl.tokens--
		return
	}

	// Wait for next available token
	waitTime := time.Second / time.Duration(rl.rate)
	rl.mu.Unlock()
	time.Sleep(waitTime)
	rl.mu.Lock()
}
