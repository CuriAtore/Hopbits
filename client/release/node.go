package release

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/hopbits/client/agent"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/all"
	"github.com/hopbits/client/protocol"
	"github.com/hopbits/client/safety"
)

// Node is a node as the hopbits-agent command builds it, with the same
// modules and the same safety guard, in a folder of its own. It never
// connects anywhere. It exists so that a file can be put through the very
// check a node in the field gives it before the file is published: what
// this Node refuses, the nodes refuse.
type Node struct {
	agent *agent.Agent
}

// NewNode builds a Node in dir, an empty folder it may write to, trusting
// roots as its compiled root keys. A nil now is the wall clock.
func NewNode(dir string, roots protocol.Roots, now func() time.Time) (*Node, error) {
	if now == nil {
		now = time.Now
	}
	reg, err := module.NewRegistry(all.Default()...)
	if err != nil {
		return nil, fmt.Errorf("release: build the node's modules: %w", err)
	}
	a, err := agent.New(agent.Config{
		DataDir:  dir,
		Roots:    roots,
		Registry: reg,
		Gate:     safety.NewGuard(safety.Config{Caps: safety.AgentCaps(), Now: now}),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      now,
		// This node asks nobody for anything.
		PausePollInterval:  -1,
		UpdatePollInterval: -1,
	})
	if err != nil {
		return nil, fmt.Errorf("release: build the node: %w", err)
	}
	return &Node{agent: a}, nil
}

// Manifest checks a release manifest file as a node does when it fetches
// one: the release key's certificate against the roots, the signature, the
// dates. It returns what the manifest says and the id of the key that
// signed it.
func (n *Node) Manifest(raw []byte) (*agent.ReleaseManifest, string, error) {
	return n.agent.VerifyReleaseManifest(raw)
}

// Binary checks a downloaded binary against its entry in a manifest this
// Node accepted: size, SHA-256 and the release key's signature.
func (n *Node) Binary(keyID string, artifact agent.ReleaseArtifact, data []byte) error {
	return n.agent.VerifyArtifactBinary(keyID, artifact, data)
}

// Pause checks a pause file as a node does when it fetches one, and reports
// whether it pauses the node.
func (n *Node) Pause(raw []byte) (paused bool, err error) {
	return n.agent.ApplyPauseFile(raw)
}
