package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

type jobState int

const (
	jobUnknown jobState = iota
	jobAdmitting
	jobRunning
	jobFinished
)

// jobEntry is what the agent remembers of one job attempt: enough to cancel
// it and to never run it twice.
type jobEntry struct {
	state  jobState
	cancel context.CancelFunc
	// sess is the session that delivered the job last; its answer goes there.
	sess     *session
	forgetAt time.Time
	anchor   bool
}

// handleJob verifies a signed job, then refuses it, acknowledges it again
// as a duplicate, or starts it. It runs on the read loop; the safety gate,
// which may resolve names, runs in the job's own goroutine.
func (s *session) handleJob(sj *nodev1.SignedJob) {
	a := s.a
	now := a.now()
	// The body is parsed only after its signature verifies.
	err := a.ring.Verify(sj.GetKeyId(), nodev1.KeyRole_KEY_ROLE_DISPATCHER, protocol.PurposeJob, sj.GetBody(), sj.GetSig(), now)
	if err != nil {
		code := nodev1.ErrorCode_ERROR_CODE_SIGNATURE_INVALID
		if errors.Is(err, protocol.ErrKeyRevoked) {
			code = nodev1.ErrorCode_ERROR_CODE_KEY_REVOKED
		}
		a.log.Warn("refused a job whose signature does not verify", "key_id", sj.GetKeyId(), "err", err)
		s.sendError(code, "job signature does not verify")
		return
	}
	job := &nodev1.Job{}
	if err := proto.Unmarshal(sj.GetBody(), job); err != nil {
		a.log.Warn("refused a signed job that does not decode", "err", err)
		s.sendError(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "job body does not decode")
		return
	}
	if job.GetJobId() == "" {
		s.sendError(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "job has no id")
		return
	}
	if !bytes.Equal(job.GetNodeId(), a.nodeID) {
		s.refuse(job, nodev1.ErrorCode_ERROR_CODE_SIGNATURE_INVALID)
		return
	}
	key := jobKey{id: job.GetJobId(), attempt: job.GetAttempt()}
	switch a.redeliver(key, s) {
	case jobAdmitting:
		// The gate is deciding; its acknowledgement follows on this session.
		return
	case jobRunning, jobFinished:
		a.log.Info("acknowledged a duplicate job without running it again", "job_id", key.id, "attempt", key.attempt)
		if err := s.ack(key, true, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED); err != nil {
			a.log.Debug("cannot acknowledge a duplicate job", "job_id", key.id, "err", err)
		}
		return
	}
	mod, code := a.checkJob(job, now)
	if code != nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		s.refuse(job, code)
		return
	}
	mj := moduleJob(job)
	if err := a.checkParams(mod, mj); err != nil {
		s.refuse(job, module.CodeOf(err))
		return
	}
	ctx, cancel, ok := a.startAdmission(key, s, time.UnixMilli(job.GetDeadlineUnixMs()).Sub(now), IsAnchorDomainHost(job.GetTarget().GetHost()))
	if !ok {
		s.refuse(job, nodev1.ErrorCode_ERROR_CODE_CAPACITY)
		return
	}
	go a.runJob(ctx, cancel, job, mj, mod)
}

// checkJob applies the checks that need no I/O, in protocol order, and
// returns the module for the job's kind version.
func (a *Agent) checkJob(job *nodev1.Job, now time.Time) (module.Module, nodev1.ErrorCode) {
	deadline := time.UnixMilli(job.GetDeadlineUnixMs())
	issued := time.UnixMilli(job.GetIssuedUnixMs())
	switch {
	case !now.Before(deadline), issued.After(now.Add(maxIssueAhead)):
		return nil, nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED
	case a.isPaused(now) && !IsAnchorDomainHost(job.GetTarget().GetHost()):
		return nil, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY
	case job.GetJobClass() != nodev1.JobClass_JOB_CLASS_MEASURE:
		return nil, nodev1.ErrorCode_ERROR_CODE_CLASS_NOT_ENABLED
	case !a.consent[job.GetJobClass()]:
		return nil, nodev1.ErrorCode_ERROR_CODE_CONSENT_MISSING
	case !a.cfg.Registry.HasKind(job.GetKind()):
		return nil, nodev1.ErrorCode_ERROR_CODE_KIND_UNSUPPORTED
	}
	mod, ok := a.cfg.Registry.Lookup(job.GetKind(), job.GetKindVersion())
	switch {
	case !ok:
		return nil, nodev1.ErrorCode_ERROR_CODE_KIND_VERSION_UNSUPPORTED
	case mod.Class() != job.GetJobClass():
		return nil, nodev1.ErrorCode_ERROR_CODE_CLASS_NOT_ENABLED
	}
	return mod, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
}

// moduleJob converts a verified job to the module's view of it.
func moduleJob(j *nodev1.Job) *module.Job {
	return &module.Job{
		ID:            j.GetJobId(),
		Attempt:       j.GetAttempt(),
		Class:         j.GetJobClass(),
		Kind:          j.GetKind(),
		KindVersion:   j.GetKindVersion(),
		MeasurementID: j.GetMeasurementId(),
		Target:        j.GetTarget(),
		Params:        j.GetParams(),
		Deadline:      time.UnixMilli(j.GetDeadlineUnixMs()),
		Issued:        time.UnixMilli(j.GetIssuedUnixMs()),
	}
}

// checkParams runs a module's compiled parameter check. A panic refuses.
func (a *Agent) checkParams(m module.Module, j *module.Job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("module check panicked", "kind", m.Kind(), "panic", fmt.Sprint(r))
			err = module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "module check failed")
		}
	}()
	return m.Check(j)
}

// startAdmission registers a job delivered on s as waiting for the gate and
// returns its context, which ends at the job's deadline, at maxJobRun, on
// JobCancel or when Run ends; jobs outlive their session but not Run.
func (a *Agent) startAdmission(key jobKey, s *session, remaining time.Duration, anchor bool) (context.Context, context.CancelFunc, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.draining || a.admitting >= maxAdmitting {
		return nil, nil, false
	}
	a.pruneJobsLocked(a.now())
	ctx, cancel := context.WithTimeout(s.runCtx, min(remaining, maxJobRun))
	a.jobs[key] = &jobEntry{state: jobAdmitting, cancel: cancel, sess: s, anchor: anchor}
	a.admitting++
	a.jobWG.Add(1)
	return ctx, cancel, true
}

func (a *Agent) cancelNonAnchorJobs() {
	var cancels []context.CancelFunc
	a.mu.Lock()
	for _, e := range a.jobs {
		if e.state != jobFinished && !e.anchor && e.cancel != nil {
			cancels = append(cancels, e.cancel)
		}
	}
	a.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// runJob admits a job through the safety gate, acknowledges it, runs its
// module and returns the signed result.
func (a *Agent) runJob(ctx context.Context, cancel context.CancelFunc, job *nodev1.Job, mj *module.Job, mod module.Module) {
	defer a.jobWG.Done()
	defer cancel()
	key := jobKey{id: job.GetJobId(), attempt: job.GetAttempt()}

	lease, err := a.cfg.Gate.Admit(ctx, mj, mod.Needs())
	if err == nil && lease == nil {
		err = module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "the gate returned no lease")
	}
	if err != nil {
		code := module.CodeOf(err)
		if s := a.dropJob(key, jobAdmitting); s != nil {
			s.refuse(job, code)
		} else {
			a.recordJob(job, outcomeNotRun, codeName(code))
		}
		return
	}
	s := a.beginRun(key)
	if s == nil {
		_ = lease.Close()
		a.log.Info("dropped an admitted job: its session ended before it was acknowledged", "job_id", key.id, "attempt", key.attempt)
		return
	}
	if err := s.ack(key, true, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED); err != nil {
		_ = lease.Close()
		a.dropJob(key, jobRunning)
		a.log.Info("dropped a job whose acknowledgement could not be sent", "job_id", key.id, "attempt", key.attempt, "err", err)
		return
	}

	measured := a.now()
	res := a.runModule(ctx, mod, mj, lease)
	addr, resolution := lease.Addr(), lease.Resolution()
	if err := lease.Close(); err != nil {
		a.log.Debug("closing a job's lease failed", "job_id", key.id, "err", err)
	}
	a.complete(key, job, res, addr, resolution, measured)
}

// targetNet hides the lease's Close from modules.
type targetNet struct{ module.TargetNet }

// runModule runs an admitted job. A panicking module fails the job rather
// than stopping the agent.
func (a *Agent) runModule(ctx context.Context, m module.Module, j *module.Job, lease module.Lease) (res module.Result) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("module panicked", "kind", m.Kind(), "job_id", j.ID, "panic", fmt.Sprint(r))
			res = module.Result{Outcome: nodev1.Outcome_OUTCOME_FAIL, Error: nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY}
		}
	}()
	return m.Run(ctx, j, targetNet{lease})
}

// complete builds and signs a job's result, stores it durably, sends it on
// the current session and records the job.
func (a *Agent) complete(key jobKey, job *nodev1.Job, res module.Result, addr netip.Addr, resolution nodev1.ResolutionSource, measured time.Time) {
	r := &nodev1.Result{
		JobId:          key.id,
		Attempt:        key.attempt,
		NodeId:         a.nodeID,
		Kind:           job.GetKind(),
		KindVersion:    job.GetKindVersion(),
		Outcome:        res.Outcome,
		Error:          res.Error,
		TsSource:       res.TSSource,
		TxTsSource:     res.TxTSSource,
		Resolution:     resolution,
		Data:           res.Data,
		Load:           &nodev1.NodeLoad{RunningJobs: uint32(a.runningJobs())},
		NetworkMode:    a.cfg.NetworkMode,
		ValidityFlags:  res.ValidityFlags,
		ClientVersion:  a.cfg.ClientVersion,
		MeasuredUnixMs: measured.UnixMilli(),
	}
	if addr.IsValid() {
		r.ConnectedAddress = addr.String()
	}
	if len(r.Data) > maxResultData {
		a.log.Error("a module returned an oversized result; dropping its data", "kind", job.GetKind(), "bytes", len(r.Data))
		r.Data = nil
		r.Outcome = nodev1.Outcome_OUTCOME_FAIL
		r.Error = nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY
	}
	defer a.finishJob(key, job)
	body, err := proto.Marshal(r)
	if err != nil {
		a.log.Error("cannot encode a result", "job_id", key.id, "err", err)
		return
	}
	sr := &nodev1.SignedResult{Body: body, Sig: protocol.Sign(a.key, protocol.PurposeResult, body)}
	// Store first: a result is sent only once it would survive a crash.
	if err := a.results.put(key, sr); err != nil {
		a.log.Error("cannot buffer a result; sending it unbuffered", "job_id", key.id, "err", err)
	}
	if s := a.currentSession(); s != nil {
		if err := s.send(resultEnvelope(sr)); err != nil {
			a.log.Debug("the result will be resent on the next session", "job_id", key.id, "err", err)
		}
	}
	a.recordJob(job, outcomeName(r.Outcome), codeName(r.Error))
}

// redeliver returns what the agent knows of a job and, for a job still
// waiting for the gate, records s as the session to answer on.
func (a *Agent) redeliver(key jobKey, s *session) jobState {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.jobs[key]
	if !ok {
		return jobUnknown
	}
	if e.state == jobAdmitting {
		e.sess = s
	}
	return e.state
}

// beginRun moves an admitted job to running and returns the session to
// acknowledge it on. It returns nil, forgetting the job, when the session
// that last delivered it has ended or stopped intake: the gateway has then
// given up on it.
func (a *Agent) beginRun(key jobKey) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.admitting--
	e := a.jobs[key]
	if a.draining || e == nil || e.sess == nil || a.sess != e.sess || e.sess.ctx.Err() != nil || e.sess.readCtx.Err() != nil {
		delete(a.jobs, key)
		return nil
	}
	e.state = jobRunning
	a.running++
	return e.sess
}

// dropJob forgets a job that will not run and returns the session that
// last delivered it, if any.
func (a *Agent) dropJob(key jobKey, from jobState) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch from {
	case jobAdmitting:
		a.admitting--
	case jobRunning:
		a.running--
	}
	var s *session
	if e := a.jobs[key]; e != nil {
		s = e.sess
	}
	delete(a.jobs, key)
	return s
}

// finishJob marks a job finished and remembers it past its deadline, so a
// replay is acknowledged instead of run.
func (a *Agent) finishJob(key jobKey, job *nodev1.Job) {
	forget := time.UnixMilli(job.GetDeadlineUnixMs())
	if now := a.now(); forget.Before(now) {
		forget = now
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running--
	if e := a.jobs[key]; e != nil {
		e.state = jobFinished
		e.cancel = nil
		e.sess = nil
		e.forgetAt = forget.Add(jobMemory)
	}
}

func (a *Agent) pruneJobs() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneJobsLocked(a.now())
}

// pruneJobsLocked forgets finished jobs past their memory and, beyond
// maxRememberedJobs, the finished jobs that would be forgotten first.
func (a *Agent) pruneJobsLocked(now time.Time) {
	for k, e := range a.jobs {
		if e.state == jobFinished && now.After(e.forgetAt) {
			delete(a.jobs, k)
		}
	}
	if len(a.jobs) < maxRememberedJobs {
		return
	}
	var finished []jobKey
	for k, e := range a.jobs {
		if e.state == jobFinished {
			finished = append(finished, k)
		}
	}
	slices.SortFunc(finished, func(x, y jobKey) int { return a.jobs[x].forgetAt.Compare(a.jobs[y].forgetAt) })
	for _, k := range finished[:min(len(finished), len(a.jobs)-maxRememberedJobs+1)] {
		delete(a.jobs, k)
	}
}

func (a *Agent) runningJobs() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// cancelJob cancels a job the gateway withdrew.
func (a *Agent) cancelJob(c *nodev1.JobCancel) {
	key := jobKey{id: c.GetJobId(), attempt: c.GetAttempt()}
	a.mu.Lock()
	var cancel context.CancelFunc
	if e := a.jobs[key]; e != nil && e.state != jobFinished {
		cancel = e.cancel
	}
	a.mu.Unlock()
	if cancel == nil {
		a.log.Debug("cancel for a job that is not running", "job_id", key.id, "attempt", key.attempt)
		return
	}
	a.log.Info("the gateway cancelled a job", "job_id", key.id, "attempt", key.attempt)
	cancel()
}

// ackResult drops a result the server has stored.
func (a *Agent) ackResult(ra *nodev1.ResultAck) {
	key := jobKey{id: ra.GetJobId(), attempt: ra.GetAttempt()}
	if a.results.remove(key) {
		a.log.Debug("result acknowledged", "job_id", key.id, "attempt", key.attempt)
	}
}

func (s *session) ack(key jobKey, accepted bool, code nodev1.ErrorCode) error {
	return s.send(&nodev1.Envelope{Body: &nodev1.Envelope_JobAck{JobAck: &nodev1.JobAck{
		JobId:    key.id,
		Attempt:  key.attempt,
		Accepted: accepted,
		Error:    code,
	}}})
}

// refuse answers a job with JobAck{accepted: false} and records it. Only
// the code is logged: a refusal's reason can name an address the node
// resolved, which the operator's logs never show.
func (s *session) refuse(job *nodev1.Job, code nodev1.ErrorCode) {
	key := jobKey{id: job.GetJobId(), attempt: job.GetAttempt()}
	if err := s.ack(key, false, code); err != nil {
		s.a.log.Debug("cannot send a refusal", "job_id", key.id, "err", err)
	}
	s.a.recordJob(job, outcomeNotRun, codeName(code))
}

// recordJob writes a job to the operator's job log and the agent's log,
// naming the target only as the job carried it.
func (a *Agent) recordJob(job *nodev1.Job, outcome, code string) {
	rec := jobRecord{
		Time:       a.now().UTC(),
		JobID:      job.GetJobId(),
		Attempt:    job.GetAttempt(),
		Kind:       job.GetKind(),
		TargetHost: job.GetTarget().GetHost(),
		Outcome:    outcome,
		Error:      code,
	}
	if err := a.jobLog.add(rec); err != nil {
		a.log.Warn("cannot write the job log", "err", err)
	}
	msg := "job finished"
	if outcome == outcomeNotRun {
		msg = "job refused"
	}
	a.log.Info(msg, "job_id", rec.JobID, "attempt", rec.Attempt, "kind", rec.Kind,
		"target_host", rec.TargetHost, "outcome", rec.Outcome, "error", rec.Error)
}
