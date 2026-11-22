package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

func TestSendObservationsAnchorOnlyAndReconnectFlush(t *testing.T) {
	// Regular agent nodes must reject SendObservations.
	hNode := newHarness(t, false)
	aNode, err := New(hNode.config())
	if err != nil {
		t.Fatal(err)
	}
	if err := aNode.SendObservations(context.Background(), []*nodev1.Observation{{Nonce: []byte("n1")}}); err == nil {
		t.Fatal("non-anchor agent accepted SendObservations")
	}

	// Anchor mode signs and sends ObservationBatch frames and buffers across disconnects.
	h := newHarness(t, false)
	cfg := h.config()
	cfg.ClientKind = nodev1.ClientKind_CLIENT_KIND_ANCHOR
	r := h.start(cfg, nil)

	gc := h.gw.accept(t)
	hello := h.gw.establish(t, gc)
	if hello.GetClientKind() != nodev1.ClientKind_CLIENT_KIND_ANCHOR {
		t.Fatalf("Hello client kind = %v, want ANCHOR", hello.GetClientKind())
	}

	obs1 := &nodev1.Observation{
		Nonce:                 []byte("nonce-http-1"),
		SourceAddress:         "198.51.100.42",
		HandshakeRttUs:        1234,
		TlsRttUs:              2345,
		ServedAndAcknowledged: true,
		ObservedUnixMs:        t0.UnixMilli(),
	}
	if err := r.a.SendObservations(context.Background(), []*nodev1.Observation{obs1}); err != nil {
		t.Fatalf("SendObservations: %v", err)
	}

	env := gc.waitFor(t, "observation batch", func(e *nodev1.Envelope) bool {
		return e.GetObservations() != nil
	})
	sob := env.GetObservations()
	if !protocol.Verify(ed25519.PublicKey(hello.GetPublicKey()), protocol.PurposeObservations, sob.GetBody(), sob.GetSig()) {
		t.Fatal("observation batch signature failed")
	}
	var batch nodev1.ObservationBatch
	if err := proto.Unmarshal(sob.GetBody(), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.GetObservations()) != 1 || string(batch.GetObservations()[0].GetNonce()) != "nonce-http-1" ||
		batch.GetObservations()[0].GetHandshakeRttUs() != 1234 {
		t.Fatalf("unexpected observation batch: %+v", &batch)
	}

	// Drop connection, queue observations while disconnected, and verify flush on reconnect.
	_ = gc.c.CloseNow()
	waitUntil(t, "session cleared", func() bool { return r.a.currentSession() == nil })

	// Send > maxObservationsPerBatch to test multi-batch chunking.
	var queued []*nodev1.Observation
	for i := range maxObservationsPerBatch + 5 {
		queued = append(queued, &nodev1.Observation{
			Nonce:          []byte(fmt.Sprintf("queued-%d", i)),
			ObservedUnixMs: t0.Add(time.Duration(i) * time.Millisecond).UnixMilli(),
		})
	}
	if err := r.a.SendObservations(context.Background(), queued); err != nil {
		t.Fatalf("queued SendObservations: %v", err)
	}

	gc2 := h.gw.accept(t)
	h.gw.establish(t, gc2)

	var total int
	for total < len(queued) {
		e := gc2.waitFor(t, "flushed observation batch", func(e *nodev1.Envelope) bool {
			return e.GetObservations() != nil
		})
		var b nodev1.ObservationBatch
		if err := proto.Unmarshal(e.GetObservations().GetBody(), &b); err != nil {
			t.Fatal(err)
		}
		if len(b.GetObservations()) > maxObservationsPerBatch {
			t.Fatalf("batch size %d exceeded max %d", len(b.GetObservations()), maxObservationsPerBatch)
		}
		total += len(b.GetObservations())
	}
	if total != len(queued) {
		t.Fatalf("flushed %d observations, want %d", total, len(queued))
	}
}
