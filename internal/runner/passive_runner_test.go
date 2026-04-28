package runner

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/yel-joul/did_finder/internal/logging"
	"github.com/yel-joul/did_finder/internal/sources"
)

type testProvider struct {
	name   string
	values []string
	err    error
}

func (p testProvider) Name() string {
	return p.name
}

func (p testProvider) Run(ctx context.Context, domain string) (<-chan sources.Result, error) {
	if p.err != nil {
		return nil, p.err
	}

	out := make(chan sources.Result)
	go func() {
		defer close(out)
		for _, value := range p.values {
			select {
			case <-ctx.Done():
				return
			case out <- sources.Result{Type: "subdomain", Source: p.name, Value: value + "." + domain}:
			}
		}
	}()
	return out, nil
}

func TestRunPassiveFansInProviderResults(t *testing.T) {
	ctx := context.Background()
	results := RunPassive(ctx, "example.com", []sources.Provider{
		testProvider{name: "one", values: []string{"api", "www"}},
		testProvider{name: "two", values: []string{"dev"}},
	}, logging.Nop())

	var got []string
	for result := range results {
		got = append(got, result.Source+":"+result.Value)
	}
	sort.Strings(got)

	want := []string{
		"one:api.example.com",
		"one:www.example.com",
		"two:dev.example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RunPassive() = %#v, want %#v", got, want)
	}
}

func TestRunPassiveClosesWhenProviderInitFails(t *testing.T) {
	ctx := context.Background()
	results := RunPassive(ctx, "example.com", []sources.Provider{
		testProvider{name: "bad", err: errors.New("boom")},
	}, logging.Nop())

	for result := range results {
		t.Fatalf("unexpected result from failed provider: %#v", result)
	}
}
