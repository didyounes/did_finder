package active

import (
	"slices"
	"testing"
)

func TestBuildCurlArgs(t *testing.T) {
	args := buildCurlArgs("https://example.com", CurlOptions{
		Timeout:         20,
		ConnectTimeout:  5,
		UserAgent:       "custom-agent",
		Proxy:           "http://127.0.0.1:8080",
		Headers:         []string{"X-Test: yes"},
		FollowRedirects: true,
	})

	for _, want := range []string{
		"-k", "-sS", "--compressed", "--path-as-is", "-o", "/dev/null",
		"--max-time", "20", "--connect-timeout", "5", "-A", "custom-agent",
		"-w", "%{json}", "-L", "--proxy", "http://127.0.0.1:8080",
		"-H", "X-Test: yes", "https://example.com",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("expected args to contain %q: %#v", want, args)
		}
	}
}

func TestParseCurlJSON(t *testing.T) {
	result, err := parseCurlJSON([]byte(`{"url_effective":"https://example.com/","http_code":200,"content_type":"text/html","remote_ip":"93.184.216.34","num_redirects":1,"ssl_verify_result":0,"time_connect":0.12,"time_appconnect":0.34,"time_total":0.56,"size_download":1256}`))
	if err != nil {
		t.Fatalf("parseCurlJSON returned error: %v", err)
	}
	if result.HTTPCode != 200 || result.EffectiveURL != "https://example.com/" || result.NumRedirects != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.SizeDownload != 1256 {
		t.Fatalf("unexpected download size: %d", result.SizeDownload)
	}
}

func TestCurlTargetCandidates(t *testing.T) {
	got := curlTargetCandidates("example.com")
	want := []string{"https://example.com", "http://example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
