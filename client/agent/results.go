package agent

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

const (
	pendingDirName = "pending"
	// maxPendingResults and maxPendingAge bound the native node's buffer of
	// results waiting for ResultAck.
	maxPendingResults = 500
	maxPendingAge     = 24 * time.Hour
)

// jobKey names one attempt of one job.
type jobKey struct {
	id      string
	attempt uint32
}

// pendingResult is a signed result waiting for ResultAck.
type pendingResult struct {
	key    jobKey
	stored time.Time
	signed *nodev1.SignedResult
}

// pendingFile is the on-disk form of a pendingResult.
type pendingFile struct {
	JobID        string `json:"job_id"`
	Attempt      uint32 `json:"attempt"`
	StoredUnixMs int64  `json:"stored_unix_ms"`
	// Result is the serialised SignedResult, exactly as sent.
	Result []byte `json:"result"`
}

// resultStore is the durable buffer of unacknowledged signed results, one
// file per job attempt under dataDir/pending.
type resultStore struct {
	dir string
	now func() time.Time
	log *slog.Logger

	mu    sync.Mutex
	byKey map[jobKey]*pendingResult
}

func openResultStore(dataDir string, now func() time.Time, log *slog.Logger) (*resultStore, error) {
	s := &resultStore{
		dir:   filepath.Join(dataDir, pendingDirName),
		now:   now,
		log:   log,
		byKey: make(map[jobKey]*pendingResult),
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: create result buffer: %w", err)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("agent: read result buffer: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(s.dir, name)
		switch {
		case e.IsDir():
			continue
		case isTempFile(name):
			_ = os.Remove(path)
			continue
		case !strings.HasSuffix(name, ".json"):
			continue
		}
		p, err := readPending(path)
		if err != nil || pendingFileName(p.key) != name {
			log.Warn("dropping an unreadable buffered result", "file", name, "err", err)
			_ = os.Remove(path)
			continue
		}
		s.byKey[p.key] = p
	}
	s.mu.Lock()
	s.pruneLocked()
	s.mu.Unlock()
	return s, nil
}

func readPending(path string) (*pendingResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f pendingFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	sr := &nodev1.SignedResult{}
	if err := proto.Unmarshal(f.Result, sr); err != nil {
		return nil, err
	}
	if len(sr.GetBody()) == 0 || len(sr.GetSig()) == 0 {
		return nil, errors.New("empty signed result")
	}
	return &pendingResult{
		key:    jobKey{id: f.JobID, attempt: f.Attempt},
		stored: time.UnixMilli(f.StoredUnixMs),
		signed: sr,
	}, nil
}

// pendingFileName derives a safe file name from a job attempt; job ids come
// from the server and are never used as paths.
func pendingFileName(k jobKey) string {
	sum := sha256.Sum256([]byte(k.id))
	return hex.EncodeToString(sum[:16]) + "-" + strconv.FormatUint(uint64(k.attempt), 10) + ".json"
}

// put stores a signed result durably before it is sent.
func (s *resultStore) put(k jobKey, sr *nodev1.SignedResult) error {
	raw, err := proto.Marshal(sr)
	if err != nil {
		return fmt.Errorf("agent: encode result: %w", err)
	}
	now := s.now()
	b, err := json.Marshal(pendingFile{JobID: k.id, Attempt: k.attempt, StoredUnixMs: now.UnixMilli(), Result: raw})
	if err != nil {
		return fmt.Errorf("agent: encode buffered result: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFileAtomic(filepath.Join(s.dir, pendingFileName(k)), b); err != nil {
		return fmt.Errorf("agent: buffer result: %w", err)
	}
	s.byKey[k] = &pendingResult{key: k, stored: now, signed: sr}
	s.pruneLocked()
	return nil
}

// remove deletes an acknowledged result. It reports whether one was held.
func (s *resultStore) remove(k jobKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byKey[k]; !ok {
		return false
	}
	s.deleteLocked(k)
	return true
}

// list returns the results still waiting, oldest first, after dropping any
// that are too old.
func (s *resultStore) list() []*pendingResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	out := make([]*pendingResult, 0, len(s.byKey))
	for _, p := range s.byKey {
		out = append(out, &pendingResult{key: p.key, stored: p.stored, signed: proto.CloneOf(p.signed)})
	}
	sortPending(out)
	return out
}

// len returns how many results wait for acknowledgement.
func (s *resultStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byKey)
}

// prune drops results older than maxPendingAge and the oldest beyond
// maxPendingResults.
func (s *resultStore) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
}

func (s *resultStore) pruneLocked() {
	cutoff := s.now().Add(-maxPendingAge)
	for k, p := range s.byKey {
		if p.stored.Before(cutoff) {
			s.log.Warn("dropping a result never acknowledged within 24 hours", "job_id", k.id, "attempt", k.attempt)
			s.deleteLocked(k)
		}
	}
	if len(s.byKey) <= maxPendingResults {
		return
	}
	all := make([]*pendingResult, 0, len(s.byKey))
	for _, p := range s.byKey {
		all = append(all, p)
	}
	sortPending(all)
	for _, p := range all[:len(all)-maxPendingResults] {
		s.log.Warn("result buffer full; dropping the oldest result", "job_id", p.key.id, "attempt", p.key.attempt)
		s.deleteLocked(p.key)
	}
}

func (s *resultStore) deleteLocked(k jobKey) {
	delete(s.byKey, k)
	if err := os.Remove(filepath.Join(s.dir, pendingFileName(k))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("cannot delete a buffered result", "job_id", k.id, "err", err)
	}
}

func sortPending(ps []*pendingResult) {
	slices.SortFunc(ps, func(a, b *pendingResult) int {
		if c := a.stored.Compare(b.stored); c != 0 {
			return c
		}
		if c := strings.Compare(a.key.id, b.key.id); c != 0 {
			return c
		}
		return cmp.Compare(a.key.attempt, b.key.attempt)
	})
}
