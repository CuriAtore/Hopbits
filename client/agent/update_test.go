package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

func signReleaseManifest(
	t *testing.T,
	rootPriv ed25519.PrivateKey,
	releasePriv ed25519.PrivateKey,
	m ReleaseManifest,
	embedCert bool,
	revs ...*nodev1.SignedRevocation,
) []byte {
	t.Helper()
	relPub := releasePriv.Public().(ed25519.PublicKey)
	keyID := protocol.KeyID(relPub)

	var sCert *SignedKeyCertEntry
	if embedCert {
		cert := protocol.NewKeyCertificate(relPub, nodev1.KeyRole_KEY_ROLE_RELEASE, t0.Add(-time.Hour), t0.Add(365*24*time.Hour))
		sc, err := protocol.CertifyKey(rootPriv, 0, cert)
		if err != nil {
			t.Fatal(err)
		}
		sCert = &SignedKeyCertEntry{Body: sc.Body, Sig: sc.Sig, RootIndex: sc.RootIndex}
	}

	var sRevs []SignedRevocationEntry
	for _, r := range revs {
		sRevs = append(sRevs, SignedRevocationEntry{Body: r.Body, Sig: r.Sig, RootIndex: r.RootIndex})
	}

	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(SignedReleaseManifest{
		Revocations: sRevs,
		Cert:        sCert,
		KeyID:       keyID,
		Body:        body,
		Sig:         protocol.Sign(releasePriv, protocol.PurposeReleaseManifest, body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func makeArtifact(t *testing.T, releasePriv ed25519.PrivateKey, goos, goarch, url string, binaryData []byte) ReleaseArtifact {
	t.Helper()
	sum := sha256.Sum256(binaryData)
	return ReleaseArtifact{
		OS:     goos,
		Arch:   goarch,
		URL:    url,
		SHA256: hex.EncodeToString(sum[:]),
		Size:   int64(len(binaryData)),
		Sig:    protocol.Sign(releasePriv, protocol.PurposeReleaseBinary, sum[:]),
	}
}

func TestReleaseManifestVerification(t *testing.T) {
	h := newHarness(t, false)
	a, err := New(h.config())
	if err != nil {
		t.Fatal(err)
	}

	_, relPriv := mustKey(t)
	valid := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:        "1.3.0",
		MinVersion:     "1.1.0",
		IssuedUnix:     t0.Unix(),
		ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
		RolloutPercent: 100,
	}, true)
	got, _, err := a.VerifyReleaseManifest(valid)
	if err != nil || got.Version != "1.3.0" {
		t.Fatalf("valid manifest rejected: got=%v err=%v", got, err)
	}

	// Dispatcher-role key signing a release manifest must be rejected with role error.
	dispManifest, _ := json.Marshal(SignedReleaseManifest{
		KeyID: h.keys.dispKeyID,
		Body:  []byte(`{"version":"1.4.0","issued_unix":1,"expires_unix":2}`),
		Sig:   protocol.Sign(h.keys.dispPriv, protocol.PurposeReleaseManifest, []byte(`{"version":"1.4.0","issued_unix":1,"expires_unix":2}`)),
	})
	if _, _, err := a.VerifyReleaseManifest(dispManifest); err == nil {
		t.Fatal("dispatcher-signed manifest was accepted")
	}

	// Rollback (older IssuedUnix) must fail.
	older := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:     "1.2.9",
		IssuedUnix:  t0.Add(-time.Minute).Unix(),
		ExpiresUnix: t0.Add(24 * time.Hour).Unix(),
	}, false)
	if _, _, err := a.VerifyReleaseManifest(older); err == nil {
		t.Fatal("older rollback manifest was accepted")
	}

	// Expired manifest must fail.
	expired := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:     "1.4.0",
		IssuedUnix:  t0.Add(-2 * time.Hour).Unix(),
		ExpiresUnix: t0.Add(-time.Hour).Unix(),
	}, false)
	if _, _, err := a.VerifyReleaseManifest(expired); err == nil {
		t.Fatal("expired manifest was accepted")
	}

	// Revoked release key must fail even with an embedded cert.
	relKeyID := protocol.KeyID(relPriv.Public().(ed25519.PublicKey))
	rev := h.keys.revocation(t, relKeyID)
	revokedManifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:     "1.4.0",
		IssuedUnix:  t0.Add(time.Minute).Unix(),
		ExpiresUnix: t0.Add(24 * time.Hour).Unix(),
	}, true, rev)
	if _, _, err := a.VerifyReleaseManifest(revokedManifest); err == nil {
		t.Fatal("manifest signed by revoked release key was accepted")
	}
}

func TestRolloutStagedByNodeIDAndSemver(t *testing.T) {
	if compareSemver("1.2.3", "1.2.3-test") <= 0 {
		t.Fatal("release version should outrank pre-release")
	}
	if compareSemver("v1.10.0", "1.2.9") <= 0 {
		t.Fatal("semver minor 10 must be greater than 2")
	}
	if compareSemver("1.2.3", "v1.2.3") != 0 {
		t.Fatal("matching versions should compare equal")
	}

	var count int
	for i := range 200 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("node-%d", i)))
		if RolloutEligible(sum[:16], 25) {
			count++
		}
		if !RolloutEligible(sum[:16], 100) {
			t.Fatal("100% rollout must include every node")
		}
		if RolloutEligible(sum[:16], 0) {
			t.Fatal("0% rollout must exclude every node")
		}
	}
	if count == 0 || count > 90 {
		t.Fatalf("25%% rollout selected %d/200 nodes", count)
	}
}

func TestSelfUpdateFlowAndInstallerOverTLS(t *testing.T) {
	h := newHarness(t, true)
	_, relPriv := mustKey(t)
	newBin := []byte("#!/bin/sh\necho updated-hopbits-agent\n")

	var (
		mu          sync.Mutex
		manifestRaw []byte
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manifest.json":
			mu.Lock()
			b := manifestRaw
			mu.Unlock()
			_, _ = w.Write(b)
		case "/bin/hopbits-agent-1.3.0":
			_, _ = w.Write(newBin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := newControlHTTPClient(&tls.Config{RootCAs: pool})

	art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, srv.URL+"/bin/hopbits-agent-1.3.0", newBin)
	mu.Lock()
	manifestRaw = signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:        "1.3.0",
		MinVersion:     "1.0.0",
		IssuedUnix:     t0.Unix(),
		ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
		RolloutPercent: 0, // Staged rollout at 0% should defer normal update.
		Artifacts:      []ReleaseArtifact{art},
	}, true)
	mu.Unlock()

	var reexecPath string
	cfg := h.config()
	cfg.ClientVersion = "1.2.3-test"
	cfg.UpdateFetcher = NewHTTPUpdateFetcher(srv.URL+"/manifest.json", client)
	cfg.BinaryInstaller = &VolumeBinaryInstaller{
		DataDir: h.dir,
		Reexec: func(binaryPath string) error {
			reexecPath = binaryPath
			return nil
		},
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 0% rollout defers update.
	out, err := a.CheckAndApplyUpdate(context.Background(), false)
	if err != nil || out != UpdateDeferredRollout || reexecPath != "" {
		t.Fatalf("0%% rollout: out=%v reexec=%q err=%v", out, reexecPath, err)
	}

	// Opt-out via DisableAutoUpdate skips download/install.
	cfgOptOut := cfg
	cfgOptOut.DataDir = t.TempDir()
	cfgOptOut.DisableAutoUpdate = true
	aOptOut, err := New(cfgOptOut)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := aOptOut.CheckAndApplyUpdate(context.Background(), true); err != nil || out != UpdateOptedOut {
		t.Fatalf("opt-out: out=%v err=%v", out, err)
	}

	// Raise rollout to 100%, verify binary staged and re-exec called.
	mu.Lock()
	manifestRaw = signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:        "1.3.0",
		MinVersion:     "1.0.0",
		IssuedUnix:     t0.Add(time.Minute).Unix(),
		ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
		RolloutPercent: 100,
		Artifacts:      []ReleaseArtifact{art},
	}, true)
	mu.Unlock()

	out, err = a.CheckAndApplyUpdate(context.Background(), false)
	if err != nil || out != UpdateApplied {
		t.Fatalf("100%% rollout failed: out=%v err=%v", out, err)
	}
	wantPath := filepath.Join(h.dir, stagedBinDir, stagedBinName)
	if reexecPath != wantPath {
		t.Fatalf("reexec path = %q, want %q", reexecPath, wantPath)
	}
	stagedBytes, err := os.ReadFile(wantPath)
	if err != nil || string(stagedBytes) != string(newBin) {
		t.Fatalf("staged binary mismatch: err=%v len=%d", err, len(stagedBytes))
	}

	// Same or older version never downgrades/reinstalls.
	cfgSame := cfg
	cfgSame.ClientVersion = "1.3.0"
	cfgSame.DataDir = t.TempDir()
	reexecPath = ""
	aSame, err := New(cfgSame)
	if err != nil {
		t.Fatal(err)
	}
	out, err = aSame.CheckAndApplyUpdate(context.Background(), true)
	if err != nil || out != UpdateNone || reexecPath != "" {
		t.Fatalf("same version updated: out=%v reexec=%q err=%v", out, reexecPath, err)
	}

	// Tampered binary fails SHA-256 / signature verification and does not stage.
	badArt := art
	badArt.SHA256 = strings.Repeat("0", 64)
	if err := a.VerifyArtifactBinary(protocol.KeyID(relPriv.Public().(ed25519.PublicKey)), badArt, newBin); err == nil {
		t.Fatal("tampered sha256 artifact accepted")
	}
	badSigArt := art
	badSigArt.Sig[0] ^= 1
	if err := a.VerifyArtifactBinary(protocol.KeyID(relPriv.Public().(ed25519.PublicKey)), badSigArt, newBin); err == nil {
		t.Fatal("bad binary signature accepted")
	}
}

func TestUpgradeRequiredVerifiedAgainstManifest(t *testing.T) {
	_, relPriv := mustKey(t)

	// 1. Spoofed UPGRADE_REQUIRED (manifest min_version is below client version):
	// agent refuses the 1-hour hold and reconnects using normal backoff.
	t.Run("unconfirmed UPGRADE_REQUIRED ignored", func(t *testing.T) {
		h := newHarness(t, false)
		manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
			Version:     "1.2.3",
			MinVersion:  "1.0.0",
			IssuedUnix:  t0.Unix(),
			ExpiresUnix: t0.Add(24 * time.Hour).Unix(),
		}, true)
		cfg := h.config()
		cfg.ClientVersion = "1.2.3"
		cfg.UpdateFetcher = &fakeUpdateFetcher{manifest: manifest}

		waits := make(chan time.Duration, 4)
		r := h.start(cfg, func(a *Agent) {
			a.sleep = func(ctx context.Context, d time.Duration) error {
				waits <- d
				return nil
			}
		})
		_ = r
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
			Reason:        nodev1.ByeReason_BYE_REASON_UPGRADE_REQUIRED,
			ReconnectMinS: 3600,
			ReconnectMaxS: 3600,
		}}})

		select {
		case d := <-waits:
			if d >= time.Second {
				t.Fatalf("honoured unconfirmed UPGRADE_REQUIRED delay %v", d)
			}
		case <-time.After(waitTimeout):
			t.Fatal("timed out waiting for reconnect after Bye")
		}
		// Must accept reconnect quickly.
		_ = h.gw.accept(t)
	})

	// 2. Confirmed UPGRADE_REQUIRED (client version < manifest min_version):
	// agent updates immediately (bypassing 0% rollout) and honours Bye hold if needed.
	t.Run("confirmed UPGRADE_REQUIRED triggers update", func(t *testing.T) {
		h := newHarness(t, false)
		newBin := []byte("verified-binary")
		art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, "https://pause.anchor.hopbits.io/bin", newBin)
		manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
			Version:        "2.0.0",
			MinVersion:     "2.0.0",
			IssuedUnix:     t0.Unix(),
			ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
			RolloutPercent: 0,
			Artifacts:      []ReleaseArtifact{art},
		}, true)

		installed := make(chan string, 1)
		fetcher := &fakeUpdateFetcher{manifest: manifest, bin: newBin}
		cfg := h.config()
		cfg.ClientVersion = "1.2.3"
		cfg.UpdateFetcher = fetcher
		cfg.BinaryInstaller = &VolumeBinaryInstaller{
			DataDir: h.dir,
			Reexec: func(binaryPath string) error {
				installed <- binaryPath
				return nil
			},
		}
		h.start(cfg, nil)
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
			Reason:        nodev1.ByeReason_BYE_REASON_UPGRADE_REQUIRED,
			ReconnectMinS: 3600,
			ReconnectMaxS: 3600,
		}}})

		select {
		case p := <-installed:
			if p == "" {
				t.Fatal("expected staged binary path")
			}
		case <-time.After(waitTimeout):
			t.Fatal("confirmed UPGRADE_REQUIRED did not install update")
		}
		if got := fetcher.manifestFetches.Load(); got != 1 {
			t.Fatalf("manifest fetches = %d, want 1", got)
		}
		if st := readState(t, h.dir); st.ReconnectAfterUnixMs != 0 {
			t.Fatalf("staged update persisted Bye hold in state.json: %+v", st)
		}
	})

	// 3. Opted-out node persists the confirmed UPGRADE_REQUIRED hold for its
	// current ClientVersion, but ignores that hold once upgraded to a newer version.
	t.Run("opted-out UPGRADE_REQUIRED hold clears on version upgrade", func(t *testing.T) {
		h := newHarness(t, false)
		manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
			Version:     "2.0.0",
			MinVersion:  "2.0.0",
			IssuedUnix:  t0.Unix(),
			ExpiresUnix: t0.Add(24 * time.Hour).Unix(),
		}, true)
		cfg := h.config()
		cfg.ClientVersion = "1.2.3"
		cfg.DisableAutoUpdate = true
		cfg.UpdateFetcher = &fakeUpdateFetcher{manifest: manifest}

		waits := make(chan time.Duration, 2)
		r := h.start(cfg, func(a *Agent) {
			a.sleep = func(ctx context.Context, d time.Duration) error {
				waits <- d
				<-ctx.Done()
				return ctx.Err()
			}
		})
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
			Reason:        nodev1.ByeReason_BYE_REASON_UPGRADE_REQUIRED,
			ReconnectMinS: 3600,
			ReconnectMaxS: 3600,
		}}})

		select {
		case d := <-waits:
			if d != time.Hour {
				t.Fatalf("opted-out UPGRADE_REQUIRED wait = %v, want 1h", d)
			}
		case <-time.After(waitTimeout):
			t.Fatal("timed out waiting for opted-out UPGRADE_REQUIRED hold")
		}
		_ = r.stop(t)

		st := readState(t, h.dir)
		if st.ByeClientVersion != "1.2.3" || st.ReconnectAfterUnixMs == 0 {
			t.Fatalf("expected ByeClientVersion=1.2.3 in state.json, got %+v", st)
		}

		// Restarting on the same outdated version still honours the 1h hold.
		aSame, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := aSame.byeWait(); got != time.Hour {
			t.Fatalf("byeWait on unchanged version = %v, want 1h", got)
		}

		// Upgrading container image to 2.0.0 clears the stale UPGRADE_REQUIRED hold.
		cfgUpgraded := cfg
		cfgUpgraded.ClientVersion = "2.0.0"
		aUpgraded, err := New(cfgUpgraded)
		if err != nil {
			t.Fatal(err)
		}
		if got := aUpgraded.byeWait(); got != 0 {
			t.Fatalf("byeWait after upgrading ClientVersion = %v, want 0", got)
		}
	})
}

func TestGracePeriodUpgradeNoticeAndSingleManifestFetch(t *testing.T) {
	_, relPriv := mustKey(t)

	// During the 14-day grace period, Notice.min_client_version names the new
	// release (1.3.0) while manifest.version is 1.3.0 and manifest.min_version
	// is still 1.0.0. The agent must verify once, accept the notice, and update.
	t.Run("grace period notice updates with single manifest fetch", func(t *testing.T) {
		h := newHarness(t, false)
		newBin := []byte("grace-period-binary")
		art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, "https://pause.anchor.hopbits.io/bin", newBin)
		manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
			Version:        "1.3.0",
			MinVersion:     "1.0.0",
			IssuedUnix:     t0.Unix(),
			ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
			RolloutPercent: 100,
			Artifacts:      []ReleaseArtifact{art},
		}, true)

		fetcher := &fakeUpdateFetcher{manifest: manifest, bin: newBin}
		installed := make(chan string, 1)
		cfg := h.config()
		cfg.ClientVersion = "1.0.0"
		cfg.UpdateFetcher = fetcher
		cfg.BinaryInstaller = &VolumeBinaryInstaller{
			DataDir: h.dir,
			Reexec: func(binaryPath string) error {
				installed <- binaryPath
				return nil
			},
		}
		h.start(cfg, nil)
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Notice{Notice: &nodev1.Notice{
			Kind:             nodev1.NoticeKind_NOTICE_KIND_UPGRADE,
			MinClientVersion: "1.3.0",
		}}})

		select {
		case p := <-installed:
			if p == "" {
				t.Fatal("expected staged binary path")
			}
		case <-time.After(waitTimeout):
			t.Fatal("grace-period upgrade notice did not trigger update")
		}
		if got := fetcher.manifestFetches.Load(); got != 1 {
			t.Fatalf("manifest fetches = %d, want 1", got)
		}
	})

	// A spoofed Notice claiming a version higher than manifest.version must be ignored.
	t.Run("spoofed notice version above manifest version ignored", func(t *testing.T) {
		h := newHarness(t, false)
		newBin := []byte("unused-binary")
		art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, "https://pause.anchor.hopbits.io/bin", newBin)
		manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
			Version:        "1.3.0",
			MinVersion:     "1.0.0",
			IssuedUnix:     t0.Unix(),
			ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
			RolloutPercent: 100,
			Artifacts:      []ReleaseArtifact{art},
		}, true)

		fetcher := &fakeUpdateFetcher{manifest: manifest, bin: newBin}
		var execCalled atomic.Bool
		cfg := h.config()
		cfg.ClientVersion = "1.0.0"
		cfg.UpdateFetcher = fetcher
		cfg.BinaryInstaller = &VolumeBinaryInstaller{
			DataDir: h.dir,
			Reexec: func(string) error {
				execCalled.Store(true)
				return nil
			},
		}
		h.start(cfg, nil)
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Notice{Notice: &nodev1.Notice{
			Kind:             nodev1.NoticeKind_NOTICE_KIND_UPGRADE,
			MinClientVersion: "9.9.9",
		}}})

		waitUntil(t, "manifest fetched for notice", func() bool { return fetcher.manifestFetches.Load() == 1 })
		time.Sleep(30 * time.Millisecond)
		if execCalled.Load() || fetcher.binFetches.Load() != 0 {
			t.Fatalf("spoofed notice downloaded/executed update: exec=%v binFetches=%d", execCalled.Load(), fetcher.binFetches.Load())
		}
	})
}

func TestSelfUpdateDrainsInFlightJobAndObservationsBeforeExec(t *testing.T) {
	h := newHarness(t, true)
	jobRelease := make(chan struct{})
	h.mod.block = jobRelease

	_, relPriv := mustKey(t)
	newBin := []byte("drained-update-binary")
	art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, "https://pause.anchor.hopbits.io/bin", newBin)
	manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:        "1.4.0",
		MinVersion:     "1.0.0",
		IssuedUnix:     t0.Unix(),
		ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
		RolloutPercent: 100,
		Artifacts:      []ReleaseArtifact{art},
	}, true)

	stagedCh := make(chan string, 1)
	execCh := make(chan struct{}, 1)
	var (
		pendingCountAtExec int
		drainHookCalled    atomic.Bool
	)
	baseInstaller := NewVolumeBinaryInstaller(h.dir)
	installer := &trackingInstaller{
		stage: func(ctx context.Context, mRaw, bData []byte) (string, error) {
			p, err := baseInstaller.Stage(ctx, mRaw, bData)
			if err == nil {
				stagedCh <- p
			}
			return p, err
		},
		exec: func(string) error {
			pendingCountAtExec = len(pendingFiles(t, h.dir))
			execCh <- struct{}{}
			return nil
		},
	}

	cfg := h.config()
	cfg.ClientKind = nodev1.ClientKind_CLIENT_KIND_ANCHOR
	cfg.ClientVersion = "1.0.0"
	cfg.UpdateFetcher = &fakeUpdateFetcher{manifest: manifest, bin: newBin}
	cfg.BinaryInstaller = installer

	r := h.start(cfg, func(a *Agent) {
		a.SetUpdateDrainHook(func() {
			drainHookCalled.Store(true)
			_ = a.SendObservations(context.Background(), []*nodev1.Observation{{
				Nonce:                 []byte("drain-nonce"),
				SourceAddress:         "198.51.100.42",
				ServedAndAcknowledged: true,
				ObservedUnixMs:        t0.UnixMilli(),
			}})
		})
	})
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	id := h.nodeID(r)

	// Start an accepted measurement job that blocks on jobRelease.
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: h.job(id, "j-drain", nil)}})
	waitStarted(t, h.mod, "j-drain")

	// Trigger signed self-update while j-drain is running.
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Notice{Notice: &nodev1.Notice{
		Kind:             nodev1.NoticeKind_NOTICE_KIND_UPGRADE,
		MinClientVersion: "1.4.0",
	}}})

	select {
	case <-stagedCh:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for update to stage")
	}

	// Exec MUST NOT fire while j-drain is still in flight.
	select {
	case <-execCh:
		t.Fatal("Exec was called while accepted job j-drain was still running")
	case <-time.After(40 * time.Millisecond):
	}

	// Let j-drain finish; both its signed result and the anchor drain observation
	// must be flushed/persisted BEFORE Exec runs.
	close(jobRelease)

	resEnv := gc.waitFor(t, "drained job result", func(e *nodev1.Envelope) bool {
		return e.GetResult() != nil
	})
	var res nodev1.Result
	if err := proto.Unmarshal(resEnv.GetResult().GetBody(), &res); err != nil {
		t.Fatal(err)
	}
	if res.GetJobId() != "j-drain" || res.GetOutcome() != nodev1.Outcome_OUTCOME_OK {
		t.Fatalf("unexpected drained job result: %v", &res)
	}

	obsEnv := gc.waitFor(t, "drained anchor observation batch", func(e *nodev1.Envelope) bool {
		return e.GetObservations() != nil
	})
	if obsEnv == nil {
		t.Fatal("expected anchor observation batch before session closed")
	}

	select {
	case <-execCh:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for Exec after drain")
	}
	if !drainHookCalled.Load() {
		t.Fatal("expected UpdateDrainHook to run before Exec")
	}
	if pendingCountAtExec == 0 {
		t.Fatal("expected job result to be persisted in pending/ before Exec")
	}
}

func TestExecStagedOnStartup(t *testing.T) {
	h := newHarness(t, false)
	_, relPriv := mustKey(t)
	newBin := []byte("staged-across-restart-binary")
	art := makeArtifact(t, relPriv, runtime.GOOS, runtime.GOARCH, "https://pause.anchor.hopbits.io/bin", newBin)
	// Note: ExpiresUnix is 24h from t0; we advance the clock past ExpiresUnix on
	// restart to verify a container reboot days later still boots the verified
	// staged binary without re-downloading over the network.
	manifest := signReleaseManifest(t, h.keys.rootPriv, relPriv, ReleaseManifest{
		Version:        "1.3.0",
		MinVersion:     "1.0.0",
		IssuedUnix:     t0.Unix(),
		ExpiresUnix:    t0.Add(24 * time.Hour).Unix(),
		RolloutPercent: 100,
		Artifacts:      []ReleaseArtifact{art},
	}, true)

	vbi := NewVolumeBinaryInstaller(h.dir)
	stagedPath, err := vbi.Stage(context.Background(), manifest, newBin)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate container restart 5 days later with base image version 1.0.0 and
	// offline network: ExecStagedOnStartup must verify and exec without fetching.
	h.clock.Set(t0.Add(5 * 24 * time.Hour))
	var execGot string
	cfg := h.config()
	cfg.ClientVersion = "1.0.0"
	cfg.UpdateFetcher = &fakeUpdateFetcher{err: fmt.Errorf("unexpected network fetch")}
	cfg.BinaryInstaller = &VolumeBinaryInstaller{
		DataDir: h.dir,
		Reexec: func(p string) error {
			execGot = p
			return nil
		},
	}
	aRestart, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	didExec, err := aRestart.ExecStagedOnStartup()
	if err != nil || !didExec || execGot != stagedPath {
		t.Fatalf("ExecStagedOnStartup: didExec=%v path=%q err=%v", didExec, execGot, err)
	}

	// Already running staged version (1.3.0): must be a no-op.
	execGot = ""
	cfgCurrent := cfg
	cfgCurrent.ClientVersion = "1.3.0"
	aCurrent, err := New(cfgCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if didExec, err := aCurrent.ExecStagedOnStartup(); err != nil || didExec || execGot != "" {
		t.Fatalf("same version re-execed: didExec=%v path=%q err=%v", didExec, execGot, err)
	}

	// Opt-out via DisableAutoUpdate: must not exec staged binary.
	cfgOptOut := cfg
	cfgOptOut.DisableAutoUpdate = true
	aOptOut, err := New(cfgOptOut)
	if err != nil {
		t.Fatal(err)
	}
	if didExec, err := aOptOut.ExecStagedOnStartup(); err != nil || didExec || execGot != "" {
		t.Fatalf("opt-out re-execed: didExec=%v path=%q err=%v", didExec, execGot, err)
	}

	// Persisted revocation of the release key in state.json must reject staged binary.
	relKeyID := protocol.KeyID(relPriv.Public().(ed25519.PublicKey))
	aRestart.applyRevocation(h.keys.revocation(t, relKeyID))
	aRevoked, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if didExec, err := aRevoked.ExecStagedOnStartup(); err == nil || didExec || execGot != "" {
		t.Fatalf("revoked release key staged binary accepted: didExec=%v err=%v", didExec, err)
	}

	// Tampered staged binary on disk must fail verification and not exec.
	dirTampered := t.TempDir()
	vbiTampered := NewVolumeBinaryInstaller(dirTampered)
	tamperedPath, err := vbiTampered.Stage(context.Background(), manifest, newBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedPath, []byte("corrupted-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgTampered := cfg
	cfgTampered.DataDir = dirTampered
	aTampered, err := New(cfgTampered)
	if err != nil {
		t.Fatal(err)
	}
	if didExec, err := aTampered.ExecStagedOnStartup(); err == nil || didExec || execGot != "" {
		t.Fatalf("tampered staged binary accepted: didExec=%v err=%v", didExec, err)
	}
}

type trackingInstaller struct {
	stage func(ctx context.Context, manifestRaw, binaryData []byte) (string, error)
	exec  func(binaryPath string) error
}

func (t *trackingInstaller) Stage(ctx context.Context, manifestRaw, binaryData []byte) (string, error) {
	return t.stage(ctx, manifestRaw, binaryData)
}

func (t *trackingInstaller) Exec(binaryPath string) error {
	return t.exec(binaryPath)
}

type fakeUpdateFetcher struct {
	manifest        []byte
	bin             []byte
	err             error
	manifestFetches atomic.Int64
	binFetches      atomic.Int64
}

func (f *fakeUpdateFetcher) FetchManifest(context.Context) ([]byte, error) {
	f.manifestFetches.Add(1)
	return f.manifest, f.err
}

func (f *fakeUpdateFetcher) FetchBinary(context.Context, string) ([]byte, error) {
	f.binFetches.Add(1)
	return f.bin, f.err
}
