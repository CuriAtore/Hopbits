package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

// SendObservations queues anchor-mode observations and flushes them to the
// gateway as signed ObservationBatch envelopes. When the session is offline,
// up to maxBufferedObservations recent observations are retained and sent on
// reconnect.
func (a *Agent) SendObservations(ctx context.Context, obs []*nodev1.Observation) error {
	if a.cfg.ClientKind != nodev1.ClientKind_CLIENT_KIND_ANCHOR {
		return errors.New("agent: observations are allowed only in anchor mode")
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	var clean []*nodev1.Observation
	for _, o := range obs {
		if o != nil {
			clean = append(clean, proto.Clone(o).(*nodev1.Observation))
		}
	}
	if len(clean) == 0 {
		return nil
	}

	a.obsMu.Lock()
	a.obsBuf = appendBoundedObservations(a.obsBuf, clean)
	a.obsMu.Unlock()

	if s := a.currentSession(); s != nil {
		return a.flushObservations(s)
	}
	return nil
}

func (a *Agent) flushObservations(s *session) error {
	if a.cfg.ClientKind != nodev1.ClientKind_CLIENT_KIND_ANCHOR || s == nil {
		return nil
	}
	a.obsFlushMu.Lock()
	defer a.obsFlushMu.Unlock()

	for {
		batch := a.popObservationBatch()
		if len(batch) == 0 {
			return nil
		}
		env, err := a.buildObservationEnvelope(batch)
		if err != nil {
			a.requeueObservations(batch)
			return err
		}
		if err := s.send(env); err != nil {
			a.requeueObservations(batch)
			return err
		}
	}
}

func (a *Agent) popObservationBatch() []*nodev1.Observation {
	a.obsMu.Lock()
	defer a.obsMu.Unlock()
	if len(a.obsBuf) == 0 {
		return nil
	}
	n := min(len(a.obsBuf), maxObservationsPerBatch)
	batch := slices.Clone(a.obsBuf[:n])
	copy(a.obsBuf, a.obsBuf[n:])
	a.obsBuf = a.obsBuf[:len(a.obsBuf)-n]
	return batch
}

func (a *Agent) requeueObservations(batch []*nodev1.Observation) {
	if len(batch) == 0 {
		return
	}
	a.obsMu.Lock()
	defer a.obsMu.Unlock()
	a.obsBuf = appendBoundedObservations(batch, a.obsBuf)
}

func appendBoundedObservations(head, tail []*nodev1.Observation) []*nodev1.Observation {
	combined := make([]*nodev1.Observation, 0, len(head)+len(tail))
	combined = append(combined, head...)
	combined = append(combined, tail...)
	if len(combined) > maxBufferedObservations {
		combined = combined[len(combined)-maxBufferedObservations:]
	}
	return combined
}

func (a *Agent) buildObservationEnvelope(batch []*nodev1.Observation) (*nodev1.Envelope, error) {
	body, err := proto.Marshal(&nodev1.ObservationBatch{
		Observations: batch,
		SentUnixMs:   a.now().UnixMilli(),
	})
	if err != nil {
		return nil, fmt.Errorf("agent: encode observation batch: %w", err)
	}
	return &nodev1.Envelope{
		Body: &nodev1.Envelope_Observations{
			Observations: &nodev1.SignedObservationBatch{
				Body: body,
				Sig:  protocol.Sign(a.key, protocol.PurposeObservations, body),
			},
		},
	}, nil
}
