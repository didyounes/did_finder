package active

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const DefaultNucleiBinary = "nuclei"

type NucleiOptions struct {
	Binary          string
	Templates       []string
	Severity        string
	Tags            string
	ExcludeTags     string
	RateLimit       int
	Concurrency     int
	Timeout         int
	Proxy           string
	UpdateTemplates bool
	Headless        bool
	Code            bool
	DAST            bool
}

type NucleiFinding struct {
	TemplateID   string          `json:"template-id"`
	TemplatePath string          `json:"template-path,omitempty"`
	TemplateURL  string          `json:"template-url,omitempty"`
	Info         NucleiInfo      `json:"info"`
	Type         string          `json:"type,omitempty"`
	Host         string          `json:"host,omitempty"`
	MatchedAt    string          `json:"matched-at,omitempty"`
	URL          string          `json:"url,omitempty"`
	IP           string          `json:"ip,omitempty"`
	Scheme       string          `json:"scheme,omitempty"`
	Port         interface{}     `json:"port,omitempty"`
	MatcherName  string          `json:"matcher-name,omitempty"`
	Extracted    StringList      `json:"extracted-results,omitempty"`
	Timestamp    string          `json:"timestamp,omitempty"`
	Raw          json.RawMessage `json:"-"`
}

type NucleiInfo struct {
	Name           string               `json:"name,omitempty"`
	Severity       string               `json:"severity,omitempty"`
	Description    string               `json:"description,omitempty"`
	Tags           StringList           `json:"tags,omitempty"`
	Classification NucleiClassification `json:"classification,omitempty"`
}

type NucleiClassification struct {
	CVEID StringList `json:"cve-id,omitempty"`
	CWEID StringList `json:"cwe-id,omitempty"`
}

type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*s = values
		return nil
	}

	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		if value == "" {
			*s = nil
			return nil
		}
		parts := strings.Split(value, ",")
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				values = append(values, part)
			}
		}
		*s = values
		return nil
	}

	if bytes.Equal(data, []byte("null")) {
		*s = nil
		return nil
	}
	return fmt.Errorf("expected string or string array, got %s", string(data))
}

func RunNuclei(ctx context.Context, targets []string, opts NucleiOptions) ([]NucleiFinding, error) {
	targets = uniqueNonEmpty(targets)
	if len(targets) == 0 {
		return nil, nil
	}

	binary := strings.TrimSpace(opts.Binary)
	if binary == "" {
		binary = DefaultNucleiBinary
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("nuclei is not installed or not in PATH; install it with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}

	if opts.UpdateTemplates {
		if err := updateNucleiTemplates(ctx, path); err != nil {
			return nil, err
		}
	}

	targetFile, err := writeTargetsFile(targets)
	if err != nil {
		return nil, err
	}
	defer os.Remove(targetFile)

	args := buildNucleiArgs(targetFile, opts)
	cmd := exec.CommandContext(ctx, path, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []NucleiFinding
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		finding, err := parseNucleiFinding(line)
		if err != nil {
			continue
		}
		findings = append(findings, finding)
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return findings, err
	}

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return findings, fmt.Errorf("nuclei scan failed: %s", msg)
	}

	return findings, nil
}

func buildNucleiArgs(targetFile string, opts NucleiOptions) []string {
	args := []string{
		"-l", targetFile,
		"-jsonl",
		"-silent",
		"-no-stdin",
		"-nc",
		"-or",
		"-ot",
	}

	for _, template := range opts.Templates {
		template = strings.TrimSpace(template)
		if template != "" {
			args = append(args, "-t", template)
		}
	}
	if opts.Severity != "" {
		args = append(args, "-s", opts.Severity)
	}
	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}
	if opts.ExcludeTags != "" {
		args = append(args, "-etags", opts.ExcludeTags)
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(opts.RateLimit))
	}
	if opts.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(opts.Concurrency))
	}
	if opts.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(opts.Timeout))
	}
	if opts.Proxy != "" {
		args = append(args, "-proxy", opts.Proxy)
	}
	if opts.Headless {
		args = append(args, "-headless")
	}
	if opts.Code {
		args = append(args, "-code")
	}
	if opts.DAST {
		args = append(args, "-dast")
	}
	return args
}

func updateNucleiTemplates(ctx context.Context, binary string) error {
	cmd := exec.CommandContext(ctx, binary, "-update-templates", "-nc")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nuclei template update failed: %s", msg)
	}
	return nil
}

func parseNucleiFinding(line []byte) (NucleiFinding, error) {
	var finding NucleiFinding
	if err := json.Unmarshal(line, &finding); err != nil {
		return finding, err
	}
	finding.Raw = append(finding.Raw[:0], line...)
	return finding, nil
}

func writeTargetsFile(targets []string) (string, error) {
	f, err := os.CreateTemp("", "did_finder-nuclei-targets-*.txt")
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, target := range targets {
		if _, err := fmt.Fprintln(f, target); err != nil {
			return "", err
		}
	}
	return f.Name(), nil
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
