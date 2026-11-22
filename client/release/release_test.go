package release_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hopbits/client/agent"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/all"
	"github.com/hopbits/client/protocol"
	"github.com/hopbits/client/release"
	"github.com/hopbits/client/safety"
)

// t0 is the moment every test signs at.
var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

func at(t time.Time) func() time.Time { return func() time.Time { return t } }

// keys are an owner's keys: the root the nodes are built with, and a
// release key certified by it for 400 days.
type keys struct {
	root  ed25519.PrivateKey
	roots protocol.Roots
	rel   ed25519.PrivateKey
	cert  agent.SignedKeyCertEntry
}

func newKeys(t *testing.T) keys {
	t.Helper()
	rootPub, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := release.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := release.Certify(root, 0, rel.Public().(ed25519.PublicKey), t0.Add(-release.Backdate), t0.Add(400*day))
	if err != nil {
		t.Fatal(err)
	}
	return keys{root: root, roots: protocol.Roots{rootPub}, rel: rel, cert: cert}
}

// fetcher stands in for the network: it hands out one manifest and the
// binaries by address, and remembers what was asked for.
type fetcher struct {
	manifest []byte
	bins     map[string][]byte
	asked    []string
}

func (f *fetcher) FetchManifest(context.Context) ([]byte, error) { return f.manifest, nil }

func (f *fetcher) FetchBinary(_ context.Context, u string) ([]byte, error) {
	f.asked = append(f.asked, u)
	b, ok := f.bins[u]
	if !ok {
		return nil, errors.New("no such file")
	}
	return b, nil
}

// installer stands in for the disk and the restart: it remembers what a
// node staged and what it started.
type installer struct {
	manifest, binary []byte
	started          string
}

func (i *installer) Stage(_ context.Context, manifest, binary []byte) (string, error) {
	i.manifest, i.binary = manifest, binary
	return "the-staged-binary", nil
}

func (i *installer) Exec(path string) error {
	i.started = path
	return nil
}

// newAgent builds a node the way the hopbits-agent command does, with the
// real modules and the real safety guard, at the given version and clock.
func newAgent(t *testing.T, roots protocol.Roots, version string, now func() time.Time, f agent.UpdateFetcher, inst agent.BinaryInstaller) *agent.Agent {
	t.Helper()
	reg, err := module.NewRegistry(all.Default()...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{
		DataDir:           t.TempDir(),
		ClientVersion:     version,
		Roots:             roots,
		Registry:          reg,
		Gate:              safety.NewGuard(safety.Config{Caps: safety.AgentCaps(), Now: now}),
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:               now,
		PausePollInterval: -1,
		UpdateFetcher:     f,
		BinaryInstaller:   inst,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newNode(t *testing.T, roots protocol.Roots, now func() time.Time) *release.Node {
	t.Helper()
	n, err := release.NewNode(t.TempDir(), roots, now)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const urlBase = "https://hopbits.io/releases/"

// binaries are a release's files: the two the installer serves, and one for
// the machine the test runs on, so that a node here can take the update.
func binaries(version string) []release.Binary {
	out := []release.Binary{
		{OS: "linux", Arch: "amd64", URL: urlBase + "hopbits-agent-" + version + "-linux-amd64", Data: []byte("amd64 build of " + version)},
		{OS: "linux", Arch: "arm64", URL: urlBase + "hopbits-agent-" + version + "-linux-arm64", Data: []byte("arm64 build of " + version)},
	}
	for _, b := range out {
		if b.OS == runtime.GOOS && b.Arch == runtime.GOARCH {
			return out
		}
	}
	return append(out, release.Binary{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		URL:  urlBase + "hopbits-agent-" + version + "-" + runtime.GOOS + "-" + runtime.GOARCH,
		Data: []byte("build of " + version + " for this machine"),
	})
}

func hostBinary(t *testing.T, bins []release.Binary) release.Binary {
	t.Helper()
	for _, b := range bins {
		if b.OS == runtime.GOOS && b.Arch == runtime.GOARCH {
			return b
		}
	}
	t.Fatal("no binary for this machine")
	return release.Binary{}
}

func mustSign(t *testing.T, k keys, r release.Release) []byte {
	t.Helper()
	raw, err := release.Sign(k.rel, k.cert, r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func network(raw []byte, bins []release.Binary) *fetcher {
	f := &fetcher{manifest: raw, bins: make(map[string][]byte)}
	for _, b := range bins {
		f.bins[b.URL] = b.Data
	}
	return f
}

// A node built like the ones in the field accepts a signed release, checks
// every listed binary, and installs the one for its machine.
func TestNodeTakesTheRelease(t *testing.T) {
	k := newKeys(t)
	bins := binaries("0.2.0")
	raw := mustSign(t, k, release.Release{
		Version: "0.2.0", RolloutPercent: 100,
		Issued: t0, Expires: t0.Add(300 * day), Binaries: bins,
	})

	node := newNode(t, k.roots, at(t0))
	m, keyID, err := node.Manifest(raw)
	if err != nil {
		t.Fatalf("the node refused the manifest: %v", err)
	}
	if m.Version != "0.2.0" || m.RolloutPercent != 100 || len(m.Artifacts) != len(bins) {
		t.Fatalf("the node read %+v", m)
	}
	if want := protocol.KeyID(k.rel.Public().(ed25519.PublicKey)); keyID != want {
		t.Fatalf("signed by %q, want %q", keyID, want)
	}
	for i, b := range bins {
		art := m.Artifacts[i]
		if art.OS != b.OS || art.Arch != b.Arch || art.URL != b.URL || art.Size != int64(len(b.Data)) {
			t.Fatalf("artifact %d is %+v, want %s/%s at %s", i, art, b.OS, b.Arch, b.URL)
		}
		if err := node.Binary(keyID, art, b.Data); err != nil {
			t.Fatalf("the node refused the %s/%s binary: %v", b.OS, b.Arch, err)
		}
		if err := node.Binary(keyID, art, append([]byte("x"), b.Data...)); err == nil {
			t.Fatalf("the node took a changed %s/%s binary", b.OS, b.Arch)
		}
	}

	// The whole path of an update on a node one version behind.
	host := hostBinary(t, bins)
	net, inst := network(raw, bins), &installer{}
	old := newAgent(t, k.roots, "0.1.0", at(t0), net, inst)
	got, err := old.CheckAndApplyUpdate(context.Background(), false)
	if err != nil || got != agent.UpdateApplied {
		t.Fatalf("update on 0.1.0: outcome %v, err %v", got, err)
	}
	if len(net.asked) != 1 || net.asked[0] != host.URL {
		t.Fatalf("the node downloaded %v, want only %s", net.asked, host.URL)
	}
	if !bytes.Equal(inst.manifest, raw) || !bytes.Equal(inst.binary, host.Data) || inst.started != "the-staged-binary" {
		t.Fatalf("the node staged %d manifest bytes and %q, and started %q", len(inst.manifest), inst.binary, inst.started)
	}

	// A node already on the version, or ahead of it, leaves it alone.
	for _, version := range []string{"0.2.0", "0.3.0"} {
		net, inst := network(raw, bins), &installer{}
		same := newAgent(t, k.roots, version, at(t0), net, inst)
		got, err := same.CheckAndApplyUpdate(context.Background(), false)
		if err != nil || got != agent.UpdateNone || len(net.asked) != 0 || inst.started != "" {
			t.Fatalf("update on %s: outcome %v, err %v, downloads %v", version, got, err, net.asked)
		}
	}
}

// After an update the container still holds the old binary. On every start
// that binary checks the staged release again and hands over to it: for as
// long as the release key's certificate lasts, and not a day longer. This is
// also why a release that fails to start cannot be taken back: nothing but
// the certificate's last day stops the old binary from starting it again.
func TestRestartIntoTheStagedRelease(t *testing.T) {
	k := newKeys(t)
	bins := binaries("0.2.0")
	host := hostBinary(t, bins)
	raw := mustSign(t, k, release.Release{
		Version: "0.2.0", RolloutPercent: 100,
		Issued: t0, Expires: t0.Add(30 * day), Binaries: bins,
	})

	restart := func(dir, version string, now time.Time) (started string, err error) {
		t.Helper()
		reg, rerr := module.NewRegistry(all.Default()...)
		if rerr != nil {
			t.Fatal(rerr)
		}
		a, aerr := agent.New(agent.Config{
			DataDir:           dir,
			ClientVersion:     version,
			Roots:             k.roots,
			Registry:          reg,
			Gate:              safety.NewGuard(safety.Config{Caps: safety.AgentCaps(), Now: at(now)}),
			Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			Now:               at(now),
			PausePollInterval: -1,
			BinaryInstaller: &agent.VolumeBinaryInstaller{DataDir: dir, Reexec: func(path string) error {
				started = path
				return nil
			}},
		})
		if aerr != nil {
			t.Fatal(aerr)
		}
		_, err = a.ExecStagedOnStartup()
		return started, err
	}

	dir := t.TempDir()
	staged, err := agent.NewVolumeBinaryInstaller(dir).Stage(context.Background(), raw, host.Data)
	if err != nil {
		t.Fatal(err)
	}

	// The old binary starts the staged one: the next day, and long after
	// the manifest itself has expired.
	for _, after := range []time.Duration{day, 200 * day, 399 * day} {
		if got, err := restart(dir, "0.1.0", t0.Add(after)); err != nil || got != staged {
			t.Fatalf("a restart %v on: started %q, err %v, want %q", after, got, err, staged)
		}
	}
	// A container rebuilt with the release itself, or a later one, does not.
	for _, version := range []string{"0.2.0", "0.2.1"} {
		if got, err := restart(dir, version, t0.Add(day)); err != nil || got != "" {
			t.Fatalf("a restart on %s: started %q, err %v", version, got, err)
		}
	}
	// When the release key's certificate has ended, the old binary refuses
	// the staged release and runs itself.
	if got, err := restart(dir, "0.1.0", t0.Add(400*day)); err == nil || got != "" {
		t.Fatalf("a restart after the certificate's last day: started %q, err %v", got, err)
	}
}

// The rollout number holds nodes back, and the minimum version overrides it
// for nodes below it.
func TestRolloutAndMinimumVersion(t *testing.T) {
	k := newKeys(t)
	bins := binaries("0.2.0")
	cases := []struct {
		name        string
		rollout     int
		minVersion  string
		nodeVersion string
		want        agent.CheckUpdateOutcome
	}{
		{"nobody yet", 0, "", "0.1.0", agent.UpdateDeferredRollout},
		{"everybody", 100, "", "0.1.0", agent.UpdateApplied},
		{"below the minimum", 0, "0.1.5", "0.1.0", agent.UpdateApplied},
		{"at the minimum", 0, "0.1.5", "0.1.5", agent.UpdateDeferredRollout},
		{"above the minimum", 0, "0.1.5", "0.1.7", agent.UpdateDeferredRollout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := mustSign(t, k, release.Release{
				Version: "0.2.0", MinVersion: c.minVersion, RolloutPercent: c.rollout,
				Issued: t0, Expires: t0.Add(300 * day), Binaries: bins,
			})
			inst := &installer{}
			a := newAgent(t, k.roots, c.nodeVersion, at(t0), network(raw, bins), inst)
			got, err := a.CheckAndApplyUpdate(context.Background(), false)
			if err != nil || got != c.want {
				t.Fatalf("outcome %v, err %v, want %v", got, err, c.want)
			}
			if (inst.started != "") != (c.want == agent.UpdateApplied) {
				t.Fatalf("started %q with outcome %v", inst.started, got)
			}
		})
	}
}

// What a node must refuse, it refuses: another root, a changed manifest, a
// manifest past its date, a key outside its certificate's dates.
func TestNodeRefuses(t *testing.T) {
	k := newKeys(t)
	bins := binaries("0.2.0")
	r := release.Release{Version: "0.2.0", RolloutPercent: 100, Issued: t0, Expires: t0.Add(300 * day), Binaries: bins}
	raw := mustSign(t, k, r)

	stranger := newKeys(t)
	if _, _, err := newNode(t, stranger.roots, at(t0)).Manifest(raw); err == nil {
		t.Fatal("a node built with another root took the manifest")
	}
	// A release key certified by a root the nodes do not have.
	if _, _, err := newNode(t, k.roots, at(t0)).Manifest(mustSign(t, stranger, r)); err == nil {
		t.Fatal("the node took a manifest from a stranger's release key")
	}

	var wrapped agent.SignedReleaseManifest
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		t.Fatal(err)
	}
	wrapped.Body = bytes.Replace(wrapped.Body, []byte(`"0.2.0"`), []byte(`"9.9.9"`), 1)
	changed, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newNode(t, k.roots, at(t0)).Manifest(changed); err == nil {
		t.Fatal("the node took a manifest whose text was changed after signing")
	}

	times := []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"on the day", t0, true},
		{"a clock 23 hours slow", t0.Add(-23 * time.Hour), true},
		{"a clock two days slow", t0.Add(-2 * day), false},
		{"the day before it expires", t0.Add(299 * day), true},
		{"the day it expires", t0.Add(300 * day), false},
	}
	for _, c := range times {
		_, _, err := newNode(t, k.roots, at(c.now)).Manifest(raw)
		if (err == nil) != c.ok {
			t.Fatalf("%s: err %v, want accepted %v", c.name, err, c.ok)
		}
	}

	// An older manifest put back after a newer one was accepted.
	node := newNode(t, k.roots, at(t0.Add(2*day)))
	later := r
	later.Issued = t0.Add(day)
	if _, _, err := node.Manifest(mustSign(t, k, later)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.Manifest(raw); err == nil {
		t.Fatal("the node took an older manifest after a newer one")
	}
}

// Sign refuses what would leave nodes with a release they cannot use.
func TestSignRefuses(t *testing.T) {
	k := newKeys(t)
	good := func() release.Release {
		return release.Release{Version: "0.2.0", RolloutPercent: 100, Issued: t0, Expires: t0.Add(300 * day), Binaries: binaries("0.2.0")}
	}
	if _, err := release.Sign(k.rel, k.cert, good()); err != nil {
		t.Fatalf("the good release: %v", err)
	}

	cases := []struct {
		name   string
		change func(*release.Release)
	}{
		{"no version", func(r *release.Release) { r.Version = "" }},
		{"a word for a version", func(r *release.Release) { r.Version = "latest" }},
		{"two numbers", func(r *release.Release) { r.Version = "0.2" }},
		{"a minimum above the version", func(r *release.Release) { r.MinVersion = "0.2.1" }},
		{"a minimum that is no version", func(r *release.Release) { r.MinVersion = "new" }},
		{"rollout below 0", func(r *release.Release) { r.RolloutPercent = -1 }},
		{"rollout above 100", func(r *release.Release) { r.RolloutPercent = 101 }},
		{"expires before issued", func(r *release.Release) { r.Expires = r.Issued }},
		{"issued before the certificate", func(r *release.Release) { r.Issued = t0.Add(-2 * day) }},
		{"expires after the certificate", func(r *release.Release) { r.Expires = t0.Add(401 * day) }},
		{"no binary", func(r *release.Release) { r.Binaries = nil }},
		{"two binaries for one platform", func(r *release.Release) { r.Binaries = append(r.Binaries, r.Binaries[0]) }},
		{"an empty binary", func(r *release.Release) { r.Binaries[0].Data = nil }},
		{"no platform", func(r *release.Release) { r.Binaries[0].Arch = "" }},
		{"plain http", func(r *release.Release) { r.Binaries[0].URL = "http://hopbits.io/releases/a" }},
		{"another port", func(r *release.Release) { r.Binaries[0].URL = "https://hopbits.io:8443/releases/a" }},
		{"credentials", func(r *release.Release) { r.Binaries[0].URL = "https://u:p@hopbits.io/releases/a" }},
		{"a fragment", func(r *release.Release) { r.Binaries[0].URL = "https://hopbits.io/releases/a#b" }},
		{"no file", func(r *release.Release) { r.Binaries[0].URL = "https://hopbits.io/" }},
	}
	for _, c := range cases {
		r := good()
		c.change(&r)
		if _, err := release.Sign(k.rel, k.cert, r); err == nil {
			t.Errorf("%s: signed", c.name)
		}
	}

	// The minimum may equal the version.
	r := good()
	r.MinVersion = "0.2.0"
	if _, err := release.Sign(k.rel, k.cert, r); err != nil {
		t.Errorf("a minimum equal to the version: %v", err)
	}

	// The certificate must be for the key that signs, and for releases.
	other, err := release.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Sign(other, k.cert, good()); err == nil {
		t.Error("signed with a key the certificate is not for")
	}
	pub := k.rel.Public().(ed25519.PublicKey)
	dispatcher, err := protocol.CertifyKey(k.root, 0,
		protocol.NewKeyCertificate(pub, nodev1.KeyRole_KEY_ROLE_DISPATCHER, t0.Add(-day), t0.Add(400*day)))
	if err != nil {
		t.Fatal(err)
	}
	wrongRole := agent.SignedKeyCertEntry{Body: dispatcher.GetBody(), Sig: dispatcher.GetSig(), RootIndex: dispatcher.GetRootIndex()}
	if _, err := release.Sign(k.rel, wrongRole, good()); err == nil {
		t.Error("signed with a certificate for another role")
	}
}

// The address rules Sign applies are the node's own: what Sign lets
// through, the node's downloader asks for, and what Sign refuses, the
// downloader refuses before it connects.
func TestDownloadAddress(t *testing.T) {
	k := newKeys(t)
	var asked []string
	client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		asked = append(asked, req.URL.String())
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("the file")), Request: req}, nil
	})}
	f := agent.NewHTTPUpdateFetcher("https://pause.anchor.hopbits.io/manifest.json", client)

	cases := []struct {
		url string
		ok  bool
	}{
		{"https://hopbits.io/releases/hopbits-agent-0.2.0-linux-amd64", true},
		{"https://hopbits.io:443/releases/hopbits-agent-0.2.0-linux-amd64", true},
		{"http://hopbits.io/releases/hopbits-agent-0.2.0-linux-amd64", false},
		{"https://hopbits.io:8443/releases/hopbits-agent-0.2.0-linux-amd64", false},
		{"https://u:p@hopbits.io/releases/hopbits-agent-0.2.0-linux-amd64", false},
		{"https://hopbits.io/releases/hopbits-agent-0.2.0-linux-amd64#x", false},
	}
	for _, c := range cases {
		asked = nil
		data, err := f.FetchBinary(context.Background(), c.url)
		nodeOK := err == nil && string(data) == "the file" && len(asked) == 1
		if nodeOK != c.ok || (!c.ok && len(asked) != 0) {
			t.Errorf("the node's downloader on %s: err %v, asked %v, want accepted %v", c.url, err, asked, c.ok)
		}
		r := release.Release{Version: "0.2.0", RolloutPercent: 100, Issued: t0, Expires: t0.Add(day),
			Binaries: []release.Binary{{OS: "linux", Arch: "amd64", URL: c.url, Data: []byte("x")}}}
		if _, err := release.Sign(k.rel, k.cert, r); (err == nil) != c.ok {
			t.Errorf("Sign on %s: err %v, want accepted %v", c.url, err, c.ok)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// The stop switch: a node stops on a signed pause, starts again on a later
// file that clears it, and refuses a file from anyone but the working root.
func TestPause(t *testing.T) {
	k := newKeys(t)
	a := newAgent(t, k.roots, "0.1.0", at(t0.Add(time.Hour)), nil, nil)

	sign := func(root ed25519.PrivateKey, p release.Pause) []byte {
		t.Helper()
		raw, err := release.SignPause(root, p)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	calm := sign(k.root, release.Pause{Issued: t0, Expires: t0.Add(3650 * day)})
	if paused, err := a.ApplyPauseFile(calm); err != nil || paused || a.IsPaused() {
		t.Fatalf("the everyday file: paused %v, err %v", paused, err)
	}

	stop := sign(k.root, release.Pause{Paused: true, Reason: "a test", Issued: t0.Add(10 * time.Minute), Expires: t0.Add(day)})
	if paused, err := a.ApplyPauseFile(stop); err != nil || !paused || !a.IsPaused() {
		t.Fatalf("the pause: paused %v, err %v", paused, err)
	}
	// The everyday file put back is older than the pause: refused, and the
	// node stays stopped.
	if _, err := a.ApplyPauseFile(calm); err == nil || !a.IsPaused() {
		t.Fatalf("the old file put back: err %v, paused %v", err, a.IsPaused())
	}
	clear := sign(k.root, release.Pause{Issued: t0.Add(20 * time.Minute), Expires: t0.Add(3650 * day)})
	if paused, err := a.ApplyPauseFile(clear); err != nil || paused || a.IsPaused() {
		t.Fatalf("the file that ends the pause: paused %v, err %v", paused, err)
	}

	// Only the working root stops the nodes: not a stranger, and not a
	// release key.
	stranger := newKeys(t)
	for name, key := range map[string]ed25519.PrivateKey{"a stranger's root": stranger.root, "the release key": k.rel} {
		forged := sign(key, release.Pause{Paused: true, Issued: t0.Add(30 * time.Minute), Expires: t0.Add(day)})
		if _, err := a.ApplyPauseFile(forged); err == nil || a.IsPaused() {
			t.Fatalf("a pause signed by %s: err %v, paused %v", name, err, a.IsPaused())
		}
	}

	// A file past its date is refused, and a pause ends by itself on it.
	node := newNode(t, k.roots, at(t0.Add(2*day)))
	if _, err := node.Pause(stop); err == nil {
		t.Fatal("the node took a pause file past its date")
	}
	if paused, err := node.Pause(clear); err != nil || paused {
		t.Fatalf("the file that ends the pause, two days on: paused %v, err %v", paused, err)
	}

	if _, err := release.SignPause(k.root, release.Pause{Issued: t0, Expires: t0}); err == nil {
		t.Error("signed a pause file that expires when it is issued")
	}
}

func TestKeyFiles(t *testing.T) {
	key, err := release.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	text := release.FormatKey(key)
	if !bytes.HasSuffix(text, []byte("\n")) || len(bytes.TrimSpace(text)) != 44 {
		t.Fatalf("the key file has %d bytes, want a 32-byte seed in base64 and a line end", len(text))
	}
	back, err := release.ParseKey(text)
	if err != nil || !back.Equal(key) {
		t.Fatalf("the key did not survive its file: %v", err)
	}
	whole, err := release.ParseKey([]byte(base64.StdEncoding.EncodeToString(key)))
	if err != nil || !whole.Equal(key) {
		t.Fatalf("the 64-byte form: %v", err)
	}

	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 31))
	for _, bad := range []string{"", "not base64 !", secret, base64.StdEncoding.EncodeToString(append(key.Seed(), make([]byte, 32)...))} {
		_, err := release.ParseKey([]byte(bad))
		if err == nil {
			t.Fatalf("read a key from %d bytes of bad text", len(bad))
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatalf("the error repeats the key file: %v", err)
		}
	}

	pub := key.Public().(ed25519.PublicKey)
	roots, err := release.ParseRoots(" " + release.FormatPublicKey(pub) + " , " + release.FormatPublicKey(pub) + ",")
	if err != nil || len(roots) != 2 || !roots[0].Equal(pub) {
		t.Fatalf("roots: %v, err %v", roots, err)
	}
	for _, bad := range []string{"", " , ", "abc", release.FormatPublicKey(pub)[:40]} {
		if _, err := release.ParseRoots(bad); err == nil {
			t.Fatalf("read roots from %q", bad)
		}
	}
}

func TestCertificate(t *testing.T) {
	k := newKeys(t)
	c, err := release.Certificate(k.cert)
	if err != nil {
		t.Fatal(err)
	}
	if c.GetRole() != nodev1.KeyRole_KEY_ROLE_RELEASE ||
		c.GetNotBeforeUnix() != t0.Add(-release.Backdate).Unix() || c.GetNotAfterUnix() != t0.Add(400*day).Unix() {
		t.Fatalf("the certificate says %v", c)
	}
	pub := k.rel.Public().(ed25519.PublicKey)
	if _, err := release.Certify(k.root, 0, pub, t0, t0); err == nil {
		t.Error("certified a key for no time at all")
	}
	if _, err := release.Certify(k.root, 0, pub[:5], t0, t0.Add(day)); err == nil {
		t.Error("certified a key that is no key")
	}
	if _, err := release.Certificate(agent.SignedKeyCertEntry{}); err == nil {
		t.Error("read an empty certificate")
	}

	// A certificate from a recovery root: the node looks the root up by the
	// number the certificate carries.
	recoveryPub, recovery, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := release.Certify(recovery, 1, pub, t0.Add(-day), t0.Add(400*day))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := release.Sign(k.rel, second, release.Release{
		Version: "0.2.0", RolloutPercent: 100, Issued: t0, Expires: t0.Add(day), Binaries: binaries("0.2.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newNode(t, protocol.Roots{k.roots[0], recoveryPub}, at(t0)).Manifest(raw); err != nil {
		t.Fatalf("a certificate from root 1: %v", err)
	}
	if _, _, err := newNode(t, k.roots, at(t0)).Manifest(raw); err == nil {
		t.Fatal("a node without root 1 took its certificate")
	}
}

func TestHasVersion(t *testing.T) {
	binary := []byte("\x00\x01hopbits-agent\x000.2.0\x00more")
	for version, want := range map[string]bool{
		"0.2.0": true, "v0.2.0": true, " 0.2.0 ": true,
		"0.2.1": false, "0.3.0": false, "": false, "v": false,
	} {
		if got := release.HasVersion(binary, version); got != want {
			t.Errorf("HasVersion(%q) = %v, want %v", version, got, want)
		}
	}
}
