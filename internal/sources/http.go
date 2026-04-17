package sources

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const defaultUserAgent = "did_finder/3.1"

var throttle = struct {
	sync.Mutex
	interval time.Duration
	last     time.Time
}{
	interval: 200 * time.Millisecond,
}

func SetRateLimit(perSecond int) {
	if perSecond <= 0 {
		perSecond = 1
	}
	throttle.Lock()
	throttle.interval = time.Second / time.Duration(perSecond)
	throttle.Unlock()
}

func Do(req *http.Request) (*http.Response, error) {
	return DoWithClient(http.DefaultClient, req)
}

func DoWithClient(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := waitForTurn(req.Context()); err != nil {
			return nil, err
		}

		resp, err := client.Do(req.Clone(req.Context()))
		if err != nil {
			lastErr = err
			if req.Context().Err() != nil || attempt == 2 {
				return nil, err
			}
			if err := sleepContext(req.Context(), backoffDelay(attempt, nil)); err != nil {
				return nil, err
			}
			continue
		}

		if !shouldRetry(resp.StatusCode) || attempt == 2 {
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

func waitForTurn(ctx context.Context) error {
	throttle.Lock()
	defer throttle.Unlock()

	now := time.Now()
	wait := throttle.last.Add(throttle.interval).Sub(now)
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	throttle.last = time.Now()
	return nil
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
