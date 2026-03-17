package active

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ScreenshotResult holds the result of a screenshot capture
type ScreenshotResult struct {
	Subdomain string `json:"subdomain"`
	URL       string `json:"url"`
	FilePath  string `json:"file_path"`
	Error     string `json:"error,omitempty"`
}

// TakeScreenshots captures screenshots of live HTTP services using headless Chrome
func TakeScreenshots(ctx context.Context, subdomains []string, threads int, outputDir string) <-chan ScreenshotResult {
	results := make(chan ScreenshotResult)

	// Check if Chrome/Chromium is available
	chromePath := findChrome()
	if chromePath == "" {
		go func() {
			results <- ScreenshotResult{Error: "Chrome/Chromium not found — skipping screenshots"}
			close(results)
		}()
		return results
	}

	// Create output directory
	screenshotDir := filepath.Join(outputDir, "screenshots")
	os.MkdirAll(screenshotDir, 0755)

	jobs := make(chan string, len(subdomains))
	var wg sync.WaitGroup

	// Limit concurrency for screenshots (resource-heavy)
	conc := threads / 3
	if conc < 1 {
		conc = 1
	}
	if conc > 5 {
		conc = 5
	}

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				result := captureScreenshot(ctx, chromePath, sub, screenshotDir)
				results <- result
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func findChrome() string {
	candidates := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium",
		"chromium-browser",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func captureScreenshot(ctx context.Context, chromePath, subdomain, outputDir string) ScreenshotResult {
	url := fmt.Sprintf("https://%s", subdomain)
	filename := fmt.Sprintf("%s.png", subdomain)
	outPath := filepath.Join(outputDir, filename)

	// Use Chrome DevTools Protocol via command line
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-extensions",
		"--disable-background-networking",
		"--ignore-certificate-errors",
		fmt.Sprintf("--screenshot=%s", outPath),
		"--window-size=1280,720",
		"--hide-scrollbars",
		fmt.Sprintf("--virtual-time-budget=%d", 5000),
		url,
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, chromePath, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	result := ScreenshotResult{
		Subdomain: subdomain,
		URL:       url,
	}

	if err := cmd.Run(); err != nil {
		// Try HTTP fallback
		url = fmt.Sprintf("http://%s", subdomain)
		args[len(args)-1] = url
		cmd2 := exec.CommandContext(cmdCtx, chromePath, args...)
		cmd2.Stdout = nil
		cmd2.Stderr = nil
		if err2 := cmd2.Run(); err2 != nil {
			result.Error = fmt.Sprintf("screenshot failed: %s", err2)
			return result
		}
	}

	if _, err := os.Stat(outPath); err == nil {
		result.FilePath = outPath
		result.URL = url
	} else {
		result.Error = "screenshot file not created"
	}

	return result
}

// FormatScreenshotResult returns a JSON-friendly representation
func FormatScreenshotResult(r ScreenshotResult) string {
	data, _ := json.Marshal(r)
	return string(data)
}
