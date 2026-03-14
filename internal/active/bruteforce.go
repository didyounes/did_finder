package active

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Built-in wordlist for DNS bruteforce
var defaultWordlist = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
	"webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
	"test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
	"vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support",
	"mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
	"demo", "cp", "calendar", "wiki", "web", "media", "email", "images",
	"img", "www1", "intranet", "portal", "video", "sip", "dns2", "api",
	"cdn", "stats", "dns1", "ns4", "www3", "dns", "search", "staging",
	"server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
	"proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
	"info", "apps", "download", "remote", "db", "forums", "store", "relay",
	"files", "newsletter", "app", "live", "owa", "en", "start", "sms",
	"office", "exchange", "ipv4", "mail3", "help", "blogs", "helpdesk",
	"web1", "home", "library", "ftp2", "ntp", "monitor", "login", "service",
	"update", "ssl", "gw", "status", "members", "dev2", "panel",
	"stage", "services", "music", "apache", "irc", "ns5", "upload",
	"s1", "smtp2", "feeds", "s2", "cloud", "git", "jobs",
	"web2", "it", "preview", "photo", "data", "lab", "management",
	"uat", "qa", "preprod", "sandbox", "alpha", "internal",
	"stg", "acc", "prod", "production", "api1", "api2",
	"api-dev", "api-staging", "api-prod", "api-test", "api-v1", "api-v2",
	"v1", "v2", "v3", "grafana", "kibana", "jenkins", "gitlab",
	"jira", "confluence", "nexus",
	"prometheus", "elastic", "elasticsearch",
	"redis", "mongo", "postgres",
	"docker", "k8s", "registry", "vault",
	"traefik", "harbor", "rancher",
	"argocd", "drone", "sentry",
}

// Bruteforce performs DNS bruteforce using the built-in wordlist
func Bruteforce(ctx context.Context, domain string, threads int, customWordlist []string) <-chan string {
	results := make(chan string)

	wordlist := defaultWordlist
	if len(customWordlist) > 0 {
		wordlist = customWordlist
	}

	jobs := make(chan string, len(wordlist))

	// Custom resolver with short timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				sub := word + "." + domain
				// Per-query timeout of 3 seconds
				queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				ips, err := resolver.LookupHost(queryCtx, sub)
				cancel()
				if err == nil && len(ips) > 0 {
					results <- sub
				}
			}
		}()
	}

	go func() {
		for _, word := range wordlist {
			select {
			case <-ctx.Done():
				break
			case jobs <- strings.TrimSpace(word):
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}
