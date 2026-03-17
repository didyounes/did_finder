package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ScanState holds checkpoint data for resumable scans
type ScanState struct {
	Domain       string              `json:"domain"`
	Subdomains   []string            `json:"subdomains"`
	Phase        string              `json:"phase"`
	StartedAt    time.Time           `json:"started_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
}

const stateFile = ".did_finder_state.json"

// SaveState writes the current scan state to disk
func SaveState(state *ScanState) error {
	state.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return os.WriteFile(stateFile, data, 0644)
}

// LoadState reads a saved scan state from disk
func LoadState() (*ScanState, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &state, nil
}

// ClearState removes the state file after a successful scan
func ClearState() {
	os.Remove(stateFile)
}

// MergeSubdomains loads previously found subdomains into the map
func MergeSubdomains(state *ScanState) map[string]struct{} {
	merged := make(map[string]struct{})
	for _, sub := range state.Subdomains {
		merged[sub] = struct{}{}
	}
	return merged
}

// SubdomainsToSlice converts a subdomain map to a slice for serialization
func SubdomainsToSlice(subs map[string]struct{}) []string {
	result := make([]string, 0, len(subs))
	for sub := range subs {
		result = append(result, sub)
	}
	return result
}
