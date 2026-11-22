package module

import (
	"context"
	"testing"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

type fakeModule struct {
	kind    string
	version uint32
}

func (f fakeModule) Kind() string           { return f.kind }
func (f fakeModule) Version() uint32        { return f.version }
func (f fakeModule) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }
func (f fakeModule) Needs() Needs           { return Needs{Transport: TransportTCP, Ports: []uint16{443}} }
func (f fakeModule) SelfTest(context.Context, Env) []protocol.Capability {
	return nil
}
func (f fakeModule) Check(*Job) error { return nil }
func (f fakeModule) Run(context.Context, *Job, TargetNet) Result {
	return Result{Outcome: nodev1.Outcome_OUTCOME_OK}
}

func TestRegistry(t *testing.T) {
	r, err := NewRegistry(fakeModule{"http", 1}, fakeModule{"icmp_ping", 1}, fakeModule{"http", 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup("http", 2); !ok {
		t.Fatal("http v2 missing")
	}
	if _, ok := r.Lookup("http", 3); ok {
		t.Fatal("unregistered version found")
	}
	if !r.HasKind("icmp_ping") || r.HasKind("traceroute") {
		t.Fatal("HasKind wrong")
	}
	off := r.Without("icmp_ping")
	if off.HasKind("icmp_ping") || len(off.Modules()) != 2 {
		t.Fatal("Without did not remove the kind")
	}
	if _, err := NewRegistry(fakeModule{"http", 1}, fakeModule{"http", 1}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := NewRegistry(fakeModule{"", 1}); err == nil {
		t.Fatal("empty kind accepted")
	}
}

func TestCodeOf(t *testing.T) {
	if CodeOf(Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING, "port %d", 22)) != nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING {
		t.Fatal("code lost")
	}
	if CodeOf(context.Canceled) != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatal("plain error should map to REFUSED_LOCALLY")
	}
}
