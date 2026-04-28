package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Progress provides real-time progress tracking for scan phases
type Progress struct {
	mu      sync.Mutex
	total   int
	current int
	phase   string
	enabled bool
}

// NewProgress creates a new progress tracker
func NewProgress(enabled bool) *Progress {
	return &Progress{enabled: enabled}
}

// StartPhase begins tracking a new phase
func (p *Progress) StartPhase(phase string, total int) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = phase
	p.total = total
	p.current = 0
	p.render()
}

// Increment adds to the current progress count
func (p *Progress) Increment() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current++
	p.render()
}

// Done completes the current phase and clears the progress line
func (p *Progress) Done() {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Clear the progress line
	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 80))
}

func (p *Progress) render() {
	if p.total <= 0 {
		return
	}

	pct := float64(p.current) / float64(p.total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * float64(p.current) / float64(p.total))
	if filled > barWidth {
		filled = barWidth
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Fprintf(os.Stderr, "\r%s[%s]%s %s%s %d/%d (%.0f%%)%s  ",
		Cyan, bar, Reset,
		Dim, p.phase, p.current, p.total, pct, Reset)
}
