package active

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const DefaultCurlBinary = "curl"

type CurlOptions struct {
	Binary          string
	Timeout         int
	ConnectTimeout  int
	Threads         int
	UserAgent       string
	Proxy           string
	Headers         []string
	FollowRedirects bool
}

type CurlResult struct {
	Target          string  `json:"target"`
	EffectiveURL    string  `json:"effective_url,omitempty"`
	HTTPCode        int     `json:"http_code,omitempty"`
	ContentType     string  `json:"content_type,omitempty"`
	RemoteIP        string  `json:"remote_ip,omitempty"`
	NumRedirects    int     `json:"num_redirects,omitempty"`
	SSLVerifyResult int     `json:"ssl_verify_result,omitempty"`
	TimeConnect     float64 `json:"time_connect,omitempty"`
	TimeTLS         float64 `json:"time_tls,omitempty"`
	TimeTotal       float64 `json:"time_total,omitempty"`
	SizeDownload    int64   `json:"size_download,omitempty"`
	Error           string  `json:"error,omitempty"`
}

func CurlProbe(ctx context.Context, targets []string, opts CurlOptions) <-chan CurlResult {
	results := make(chan CurlResult)
	targets = uniqueNonEmpty(targets)
	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	go func() {
		defer close(results)
		binary := strings.TrimSpace(opts.Binary)
		if binary == "" {
			binary = DefaultCurlBinary
		}
		path, err := exec.LookPath(binary)
		if err != nil {
			for _, target := range targets {
				results <- CurlResult{Target: target, Error: "curl is not installed or not in PATH"}
			}
			return
		}

		jobs := make(chan string, len(targets))
		var wg sync.WaitGroup
		for i := 0; i < opts.Threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for target := range jobs {
					results <- runCurlTarget(ctx, path, target, opts)
				}
			}()
		}
		for _, target := range targets {
			jobs <- target
		}
		close(jobs)
		wg.Wait()
	}()

	return results
}

func runCurlTarget(ctx context.Context, binary, target string, opts CurlOptions) CurlResult {
	candidates := curlTargetCandidates(target)
	last := CurlResult{Target: target}
	for _, candidate := range candidates {
		result := runCurlURL(ctx, binary, candidate, opts)
		result.Target = target
		if result.Error == "" && result.HTTPCode > 0 {
			return result
		}
		last = result
	}
	return last
}

func runCurlURL(ctx context.Context, binary, target string, opts CurlOptions) CurlResult {
	cmd := exec.CommandContext(ctx, binary, buildCurlArgs(target, opts)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	result, parseErr := parseCurlJSON(out)
	result.Target = target
	if parseErr != nil && err == nil {
		result.Error = parseErr.Error()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		result.Error = msg
	}
	return result
}

func buildCurlArgs(target string, opts CurlOptions) []string {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15
	}
	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = timeout
	}
	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = "did_finder/3.0"
	}

	args := []string{
		"-k",
		"-sS",
		"--compressed",
		"--path-as-is",
		"-o", "/dev/null",
		"--max-time", strconv.Itoa(timeout),
		"--connect-timeout", strconv.Itoa(connectTimeout),
		"-A", userAgent,
		"-w", "%{json}",
	}
	if opts.FollowRedirects {
		args = append(args, "-L")
	}
	if opts.Proxy != "" {
		args = append(args, "--proxy", opts.Proxy)
	}
	for _, header := range opts.Headers {
		header = strings.TrimSpace(header)
		if header != "" {
			args = append(args, "-H", header)
		}
	}
	args = append(args, target)
	return args
}

func parseCurlJSON(data []byte) (CurlResult, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return CurlResult{}, fmt.Errorf("curl returned no JSON metrics")
	}

	var raw struct {
		URL          string  `json:"url_effective"`
		HTTPCode     int     `json:"http_code"`
		ContentType  string  `json:"content_type"`
		RemoteIP     string  `json:"remote_ip"`
		Redirects    int     `json:"num_redirects"`
		SSLVerify    int     `json:"ssl_verify_result"`
		TimeConnect  float64 `json:"time_connect"`
		TimeTLS      float64 `json:"time_appconnect"`
		TimeTotal    float64 `json:"time_total"`
		SizeDownload float64 `json:"size_download"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return CurlResult{}, err
	}

	return CurlResult{
		EffectiveURL:    raw.URL,
		HTTPCode:        raw.HTTPCode,
		ContentType:     raw.ContentType,
		RemoteIP:        raw.RemoteIP,
		NumRedirects:    raw.Redirects,
		SSLVerifyResult: raw.SSLVerify,
		TimeConnect:     raw.TimeConnect,
		TimeTLS:         raw.TimeTLS,
		TimeTotal:       raw.TimeTotal,
		SizeDownload:    int64(raw.SizeDownload),
	}, nil
}

func curlTargetCandidates(target string) []string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}
	return []string{"https://" + target, "http://" + target}
}
