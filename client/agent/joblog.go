package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

const (
	jobLogFileName = "jobs.log"
	// jobLogKeep is how many jobs the operator's local job log keeps.
	jobLogKeep = 100
	// outcomeNotRun marks a job the node refused before running it.
	outcomeNotRun = "NOT_RUN"
)

// jobRecord is one line of dataDir/jobs.log. Target hostnames and addresses
// are omitted so local node logs never accumulate customer target lists.
type jobRecord struct {
	Time    time.Time `json:"time"`
	JobID   string    `json:"job_id"`
	Attempt uint32    `json:"attempt"`
	Kind    string    `json:"kind"`
	Outcome string    `json:"outcome"`
	Error   string    `json:"error,omitempty"`
}

// jobLog keeps the last jobLogKeep jobs as JSON lines.
type jobLog struct {
	path string

	mu   sync.Mutex
	recs []jobRecord
}

func openJobLog(dataDir string) (*jobLog, error) {
	l := &jobLog{path: filepath.Join(dataDir, jobLogFileName)}
	b, err := os.ReadFile(l.path)
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read job log: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		var r jobRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			l.recs = append(l.recs, r)
		}
	}
	if n := len(l.recs); n > jobLogKeep {
		l.recs = append([]jobRecord(nil), l.recs[n-jobLogKeep:]...)
	}
	if bytes.Contains(b, []byte(`"target_host"`)) {
		if err := l.rewriteLocked(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// add appends a record and rewrites the file with the last jobLogKeep.
func (l *jobLog) add(r jobRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r)
	if n := len(l.recs); n > jobLogKeep {
		l.recs = append([]jobRecord(nil), l.recs[n-jobLogKeep:]...)
	}
	return l.rewriteLocked()
}

func (l *jobLog) rewriteLocked() error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range l.recs {
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("agent: encode job log: %w", err)
		}
	}
	if err := writeFileAtomic(l.path, buf.Bytes()); err != nil {
		return fmt.Errorf("agent: write job log: %w", err)
	}
	return nil
}

// records returns a copy of the kept records, oldest first.
func (l *jobLog) records() []jobRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]jobRecord(nil), l.recs...)
}

// outcomeName renders an outcome without its enum prefix, such as "OK".
func outcomeName(o nodev1.Outcome) string {
	return strings.TrimPrefix(o.String(), "OUTCOME_")
}

// codeName renders an error code without its enum prefix, "" for none.
func codeName(c nodev1.ErrorCode) string {
	if c == nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(c.String(), "ERROR_CODE_")
}
