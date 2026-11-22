package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

const (
	stateFileName = "state.json"
	// maxStoredRevocations bounds the revocations kept across restarts.
	maxStoredRevocations = 256
)

// persistedState is dataDir/state.json: what the agent must remember across
// restarts.
type persistedState struct {
	// ReconnectAfterUnixMs ends the reconnect window of the last Bye.
	ReconnectAfterUnixMs int64 `json:"reconnect_after_unix_ms,omitempty"`
	// ByeReason is the reason the last Bye gave, for the operator.
	ByeReason string `json:"bye_reason,omitempty"`
	// ByeClientVersion is the ClientVersion that received ByeReason, so an
	// UPGRADE_REQUIRED hold is cleared automatically once the binary upgrades.
	ByeClientVersion string `json:"bye_client_version,omitempty"`
	// Revocations are root-signed revocations already verified, so a
	// revoked dispatcher key stays revoked after a restart.
	Revocations []storedRevocation `json:"revocations,omitempty"`
	// ConsentGrantedUnix records when each locally consented job class,
	// keyed by its number, was first seen in the local setting.
	ConsentGrantedUnix map[string]int64 `json:"consent_granted_unix,omitempty"`
}

type storedRevocation struct {
	Body      []byte `json:"body"`
	Sig       []byte `json:"sig"`
	RootIndex uint32 `json:"root_index"`
}

// stateStore guards state.json.
type stateStore struct {
	path string

	mu sync.Mutex
	st persistedState
}

// openState loads dataDir/state.json. A corrupt file is moved aside and
// replaced, since every field is either re-learned from the gateway or only
// delays a reconnect.
func openState(dataDir string, log *slog.Logger) (*stateStore, error) {
	s := &stateStore{path: filepath.Join(dataDir, stateFileName)}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read state: %w", err)
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		aside := s.path + ".corrupt"
		log.Warn("state file is corrupt; starting a fresh one", "err", err, "moved_to", aside)
		if rerr := os.Rename(s.path, aside); rerr != nil {
			return nil, fmt.Errorf("agent: move corrupt state aside: %w", rerr)
		}
		s.st = persistedState{}
	}
	return s, nil
}

func (s *stateStore) saveLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode state: %w", err)
	}
	if err := writeFileAtomic(s.path, append(b, '\n')); err != nil {
		return fmt.Errorf("agent: save state: %w", err)
	}
	return nil
}

// reconnectAfter returns the end of the last Bye window, zero if none.
func (s *stateStore) reconnectAfter() time.Time {
	return s.reconnectAfterVersion("")
}

// reconnectAfterVersion returns the end of the last Bye window, ignoring a
// stored BYE_REASON_UPGRADE_REQUIRED hold once clientVersion changes.
func (s *stateStore) reconnectAfterVersion(clientVersion string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ReconnectAfterUnixMs == 0 {
		return time.Time{}
	}
	if s.st.ByeReason == nodev1.ByeReason_BYE_REASON_UPGRADE_REQUIRED.String() && s.st.ByeClientVersion != clientVersion {
		return time.Time{}
	}
	return time.UnixMilli(s.st.ReconnectAfterUnixMs)
}

// setReconnectAfter records a Bye window and persists it.
func (s *stateStore) setReconnectAfter(t time.Time, reason string) error {
	return s.setReconnectAfterVersion(t, reason, "")
}

// setReconnectAfterVersion records a Bye window along with clientVersion and
// persists it.
func (s *stateStore) setReconnectAfterVersion(t time.Time, reason, clientVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.ReconnectAfterUnixMs = t.UnixMilli()
	s.st.ByeReason = reason
	s.st.ByeClientVersion = clientVersion
	return s.saveLocked()
}

// revocations returns the stored revocations, oldest first.
func (s *stateStore) revocations() []*nodev1.SignedRevocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*nodev1.SignedRevocation, 0, len(s.st.Revocations))
	for _, r := range s.st.Revocations {
		out = append(out, &nodev1.SignedRevocation{Body: r.Body, Sig: r.Sig, RootIndex: r.RootIndex})
	}
	return out
}

// addRevocation stores a verified revocation unless it is already known.
func (s *stateStore) addRevocation(sr *nodev1.SignedRevocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.st.Revocations {
		if bytes.Equal(r.Body, sr.GetBody()) {
			return nil
		}
	}
	s.st.Revocations = append(s.st.Revocations, storedRevocation{
		Body:      bytes.Clone(sr.GetBody()),
		Sig:       bytes.Clone(sr.GetSig()),
		RootIndex: sr.GetRootIndex(),
	})
	if n := len(s.st.Revocations); n > maxStoredRevocations {
		s.st.Revocations = append([]storedRevocation(nil), s.st.Revocations[n-maxStoredRevocations:]...)
	}
	return s.saveLocked()
}

// consentGrants returns when each class in classes was first consented,
// recording classes seen for the first time at now and forgetting classes
// the operator withdrew.
func (s *stateStore) consentGrants(classes []nodev1.JobClass, now time.Time) (map[nodev1.JobClass]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.st.ConsentGrantedUnix
	next := make(map[string]int64, len(classes))
	out := make(map[nodev1.JobClass]int64, len(classes))
	changed := false
	for _, c := range classes {
		k := strconv.Itoa(int(c))
		t, ok := old[k]
		if !ok {
			t = now.Unix()
			changed = true
		}
		next[k] = t
		out[c] = t
	}
	if !changed && len(old) == len(next) {
		return out, nil
	}
	s.st.ConsentGrantedUnix = next
	return out, s.saveLocked()
}
