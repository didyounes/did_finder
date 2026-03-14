package output

import (
	"fmt"
	"sync"
	"time"
)

type Stats struct {
	mu            sync.Mutex
	StartTime     time.Time
	TotalFound    int
	TotalAlive    int
	SourceCounts  map[string]int
	Permutations  int
	Scraped       int
}

func NewStats() *Stats {
	return &Stats{
		StartTime:    time.Now(),
		SourceCounts: make(map[string]int),
	}
}

func (s *Stats) AddFound(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalFound++
	s.SourceCounts[source]++
}

func (s *Stats) SetAlive(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalAlive = count
}

func (s *Stats) SetPermutations(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Permutations = count
}

func (s *Stats) SetScraped(count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Scraped = count
}

func (s *Stats) PrintSummary() {
	s.mu.Lock()
	defer s.mu.Unlock()

	elapsed := time.Since(s.StartTime).Round(time.Millisecond)

	fmt.Println()
	fmt.Println(Bold + Cyan + "┌─────────────────────────────────────────┐" + Reset)
	fmt.Println(Bold + Cyan + "│" + Reset + Bold + "         did_finder — Summary             " + Cyan + "│" + Reset)
	fmt.Println(Bold + Cyan + "├─────────────────────────────────────────┤" + Reset)
	fmt.Printf(Cyan+"│"+Reset+" %-20s %18d "+Cyan+"│"+Reset+"\n", "Unique Subdomains:", s.TotalFound)
	if s.TotalAlive > 0 {
		fmt.Printf(Cyan+"│"+Reset+" %-20s %18d "+Cyan+"│"+Reset+"\n", "Alive Hosts:", s.TotalAlive)
	}
	if s.Permutations > 0 {
		fmt.Printf(Cyan+"│"+Reset+" %-20s %18d "+Cyan+"│"+Reset+"\n", "Permutations:", s.Permutations)
	}
	if s.Scraped > 0 {
		fmt.Printf(Cyan+"│"+Reset+" %-20s %18d "+Cyan+"│"+Reset+"\n", "Scraped New:", s.Scraped)
	}
	fmt.Println(Bold + Cyan + "├─────────────────────────────────────────┤" + Reset)
	fmt.Printf(Cyan+"│"+Reset+" %-20s %18s "+Cyan+"│"+Reset+"\n", "Sources:", "")
	for source, count := range s.SourceCounts {
		fmt.Printf(Cyan+"│"+Reset+"   %-18s %16d "+Cyan+"│"+Reset+"\n", source, count)
	}
	fmt.Println(Bold + Cyan + "├─────────────────────────────────────────┤" + Reset)
	fmt.Printf(Cyan+"│"+Reset+" %-20s %18s "+Cyan+"│"+Reset+"\n", "Time Elapsed:", elapsed.String())
	fmt.Println(Bold + Cyan + "└─────────────────────────────────────────┘" + Reset)
	fmt.Println()
}
