package sources

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/yel-joul/did_finder/internal/limits"
)

const defaultUserAgent = "did_finder/3.1"

type HTTPClient struct {
	Client  *http.Client
	Limiter limits.Limiter
	Retries int
}

var defaultHTTP = struct {
	sync.RWMutex
	client *HTTPClient
}{
	client: NewHTTPClient(http.DefaultClient, limits.NewTokenBucket(5, 1)),
}

func SetRateLimit(perSecond int) {
	if perSecond <= 0 {
		perSecond = 1
	}
	SetLimiter(limits.NewTokenBucket(float64(perSecond), perSecond))
}

func SetLimiter(limiter limits.Limiter) {
	if limiter == nil {
		limiter = limits.NewTokenBucket(1, 1)
	}
	defaultHTTP.Lock()
	defaultHTTP.client.Limiter = limiter
	defaultHTTP.Unlock()
}

func NewHTTPClient(client *http.Client, limiter limits.Limiter) *HTTPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPClient{
		Client:  client,
		Limiter: limiter,
		Retries: 3,
	}
}

func Do(req *http.Request) (*http.Response, error) {
	defaultHTTP.RLock()
	client := *defaultHTTP.client
	defaultHTTP.RUnlock()
	return (&client).Do(req)
}

func DoWithClient(client *http.Client, req *http.Request) (*http.Response, error) {
	defaultHTTP.RLock()
	limiter := defaultHTTP.client.Limiter
	defaultHTTP.RUnlock()
	return NewHTTPClient(client, limiter).Do(req)
}

func (h *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	if h == nil {
		h = NewHTTPClient(http.DefaultClient, nil)
	}
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}
	retries := h.Retries
	if retries <= 0 {
		retries = 3
	}

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if h.Limiter != nil {
			if err := h.Limiter.Wait(req.Context()); err != nil {
				return nil, err
			}
		}

		resp, err := client.Do(req.Clone(req.Context()))
		if err != nil {
			lastErr = err
			if req.Context().Err() != nil || attempt == retries-1 {
				return nil, err
			}
			if err := sleepContext(req.Context(), backoffDelay(attempt, nil)); err != nil {
				return nil, err
			}
			continue
		}

		if !shouldRetry(resp.StatusCode) || attempt == retries-1 {
			return resp, nil
		}

		delay := backoffDelay(attempt, resp)
		resp.Body.Close()
		if err := sleepContext(req.Context(), delay); err != nil {
			return nil, err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("request failed after retries")
}

func shouldRetry(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusRequestTimeout ||
		status == http.StatusTooEarly || (status >= 500 && status <= 599)
}

func backoffDelay(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if value := resp.Header.Get("Retry-After"); value != "" {
			if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
			if retryAt, err := http.ParseTime(value); err == nil {
				if delay := time.Until(retryAt); delay > 0 {
					return delay
				}
			}
		}
	}

	base := time.Duration(1<<attempt) * time.Second
	jitter := time.Duration(rand.Intn(250)) * time.Millisecond
	return base + jitter
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
