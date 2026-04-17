package active

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

var defaultResolverAddrs = []string{
	"",
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
}

type DNSClient struct {
	resolvers []string
	timeout   time.Duration
}

func NewDNSClient(resolvers []string) *DNSClient {
	clean := NormalizeResolvers(resolvers)
	if len(clean) == 0 {
		clean = append([]string(nil), defaultResolverAddrs...)
	}
	return &DNSClient{
		resolvers: clean,
		timeout:   3 * time.Second,
	}
}

func NormalizeResolvers(resolvers []string) []string {
	seen := make(map[string]struct{})
	var clean []string
	for _, resolver := range resolvers {
		resolver = strings.TrimSpace(resolver)
		if resolver == "" {
			continue
		}
		resolver = strings.TrimPrefix(resolver, "udp://")
		resolver = strings.TrimPrefix(resolver, "tcp://")
		if _, _, err := net.SplitHostPort(resolver); err != nil {
			resolver = net.JoinHostPort(strings.Trim(resolver, "[]"), "53")
		}
		if _, exists := seen[resolver]; exists {
			continue
		}
		seen[resolver] = struct{}{}
		clean = append(clean, resolver)
	}
	return clean
}

func (c *DNSClient) LookupHost(ctx context.Context, host string) ([]string, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupHost(queryCtx, host)
	})
}

func (c *DNSClient) LookupCNAME(ctx context.Context, host string) (string, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) (string, error) {
		return resolver.LookupCNAME(queryCtx, host)
	})
}

func (c *DNSClient) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) ([]*net.MX, error) {
		return resolver.LookupMX(queryCtx, host)
	})
}

func (c *DNSClient) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) ([]*net.NS, error) {
		return resolver.LookupNS(queryCtx, host)
	})
}

func (c *DNSClient) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupTXT(queryCtx, host)
	})
}

func (c *DNSClient) LookupAddr(ctx context.Context, address string) ([]string, error) {
	return lookupDNS(ctx, c.resolvers, c.timeout, func(queryCtx context.Context, resolver *net.Resolver) ([]string, error) {
		return resolver.LookupAddr(queryCtx, address)
	})
}

func lookupDNS[T any](ctx context.Context, resolvers []string, timeout time.Duration, query func(context.Context, *net.Resolver) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for _, address := range resolvers {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}

		queryCtx, cancel := context.WithTimeout(ctx, timeout)
		value, err := query(queryCtx, resolverFor(address))
		cancel()
		if err == nil {
			return value, nil
		}
		lastErr = err
		if isDNSNotFound(err) {
			return zero, err
		}
	}
	if lastErr != nil {
		return zero, lastErr
	}
	return zero, context.Canceled
}

func resolverFor(address string) *net.Resolver {
	if address == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
