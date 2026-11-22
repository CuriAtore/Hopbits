package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// trafficSaveEvery is how far the daily count may grow before the guard
// writes it to its traffic file again: a crash forgets at most this much.
const trafficSaveEvery = 1 << 20

// trafficRecord is the traffic file: a UTC day and the bytes counted on it.
type trafficRecord struct {
	Day       string `json:"day"`
	UsedBytes int64  `json:"used_bytes"`
}

// trafficStore keeps the daily traffic count in a file across restarts.
type trafficStore struct {
	path string

	mu       sync.Mutex
	lastDay  string
	lastUsed int64
}

// utcDay names now's UTC day, such as "2026-11-13".
func utcDay(now time.Time) string {
	return now.UTC().Format("2006-01-02")
}

// load reads the file. A missing or unreadable file counts nothing.
func (s *trafficStore) load() (trafficRecord, bool) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return trafficRecord{}, false
	}
	var r trafficRecord
	if json.Unmarshal(b, &r) != nil || r.Day == "" || r.UsedBytes < 0 {
		return trafficRecord{}, false
	}
	s.mu.Lock()
	s.lastDay, s.lastUsed = r.Day, r.UsedBytes
	s.mu.Unlock()
	return r, true
}

// save writes r unless a count at least as high for the same day is
// already written. It writes a temporary file and renames it over the
// file, so a crash leaves the old count or the new one.
func (s *trafficStore) save(r trafficRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("safety: encode traffic count: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Day == s.lastDay && r.UsedBytes <= s.lastUsed {
		return nil
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("safety: write traffic count: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("safety: replace traffic count: %w", err)
	}
	s.lastDay, s.lastUsed = r.Day, r.UsedBytes
	return nil
}

// rollTrafficDay starts a fresh count when the UTC day changes. g.mu must be
// held.
func (g *Guard) rollTrafficDay(now time.Time) {
	if day := utcDay(now); g.trafficDay != day {
		g.trafficDay = day
		g.trafficUsed = 0
		g.trafficSaved = 0
	}
}

// addTraffic charges bytes to the current UTC day's traffic counter and,
// every trafficSaveEvery bytes, writes the count to the traffic file. The
// write is best effort: a failed write only means a restart may count less.
func (g *Guard) addTraffic(n int64) {
	if n <= 0 {
		return
	}
	g.mu.Lock()
	g.rollTrafficDay(g.now())
	g.trafficUsed += n
	save := g.traffic != nil && g.trafficUsed-g.trafficSaved >= trafficSaveEvery
	rec := trafficRecord{Day: g.trafficDay, UsedBytes: g.trafficUsed}
	if save {
		g.trafficSaved = g.trafficUsed
	}
	g.mu.Unlock()
	if save {
		_ = g.traffic.save(rec)
	}
}
