package runner

import (
	"context"
	"sync"

	"github.com/yel-joul/did_finder/internal/logging"
	"github.com/yel-joul/did_finder/internal/sources"
)

func RunPassive(ctx context.Context, domain string, providers []sources.Provider, logger logging.Logger) <-chan sources.Result {
	if logger == nil {
		logger = logging.Nop()
	}

	out := make(chan sources.Result)
	var wg sync.WaitGroup

	for _, provider := range providers {
		wg.Add(1)
		go func(prov sources.Provider) {
			defer wg.Done()

			logger.Debugf("starting passive source: %s", prov.Name())

			results, err := prov.Run(ctx, domain)
			if err != nil {
				logger.Errorf("[%s] initialization failed: %v", prov.Name(), err)
				return
			}
			if results == nil {
				logger.Warnf("[%s] returned a nil results channel", prov.Name())
				return
			}

			for result := range results {
				select {
				case out <- result:
				case <-ctx.Done():
					drainResults(results)
					logger.Debugf("[%s] context cancelled, drained provider output", prov.Name())
					return
				}
			}

			logger.Debugf("[%s] source finished and closed its channel", prov.Name())
		}(provider)
	}

	go func() {
		wg.Wait()
		logger.Debugf("all passive sources completed, closing passive runner output")
		close(out)
	}()

	return out
}

func drainResults(results <-chan sources.Result) {
	for range results {
	}
}
