package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

func TestConfigValidation(t *testing.T) {
	pub, _ := mustKey(t)
	reg, err := module.NewRegistry(newFakeModule())
	if err != nil {
		t.Fatal(err)
	}
	url := func(u string) func(*Config) { return func(c *Config) { c.GatewayURL = u } }
	cases := []struct {
		name   string
		mutate func(*Config)
		ok     bool
	}{
		{"wss", nil, true},
		{"default URL", url(""), true},
		{"wss with a port", url("wss://gw.example.org:8443/v1/node"), true},
		{"ws to 127.0.0.1", url("ws://127.0.0.1:8080/v1/node"), true},
		{"ws to ::1", url("ws://[::1]:8080/v1/node"), true},
		{"ws to localhost", url("ws://localhost:8080/v1/node"), true},
		{"ws to a public host", url("ws://gw.example.org/v1/node"), false},
		{"ws to a public address", url("ws://198.51.100.1:8080/v1/node"), false},
		{"ws to a private address", url("ws://192.168.1.10/v1/node"), false},
		{"ws to another loopback address", url("ws://127.0.0.2/v1/node"), false},
		{"ws to a mapped loopback address", url("ws://[::ffff:127.0.0.1]/v1/node"), false},
		{"ws to a lookalike host", url("ws://localhost.example.org/v1/node"), false},
		{"http", url("http://127.0.0.1/v1/node"), false},
		{"https", url("https://gw.example.org/v1/node"), false},
		{"wrong path", url("wss://gw.example.org/v2/node"), false},
		{"trailing slash", url("wss://gw.example.org/v1/node/"), false},
		{"no path", url("wss://gw.example.org"), false},
		{"query", url("wss://gw.example.org/v1/node?token=secret"), false},
		{"credentials", url("wss://user:pass@gw.example.org/v1/node"), false},
		{"fragment", url("wss://gw.example.org/v1/node#x"), false},
		{"no host", url("wss:///v1/node"), false},
		{"no roots", func(c *Config) { c.Roots = nil }, false},
		{"short root", func(c *Config) { c.Roots = protocol.Roots{pub[:31]} }, false},
		{"no registry", func(c *Config) { c.Registry = nil }, false},
		{"no gate", func(c *Config) { c.Gate = nil }, false},
		{"no data dir", func(c *Config) { c.DataDir = "" }, false},
		{"backoff min above max", func(c *Config) { c.BackoffMin, c.BackoffMax = 10*time.Second, time.Second }, false},
		{"negative backoff", func(c *Config) { c.BackoffMin = -time.Second }, false},
		{"unknown consent class", func(c *Config) { c.ConsentClasses = []nodev1.JobClass{nodev1.JobClass(42)} }, false},
		{"unspecified consent class", func(c *Config) {
			c.ConsentClasses = []nodev1.JobClass{nodev1.JobClass_JOB_CLASS_UNSPECIFIED}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				GatewayURL: "wss://gw.example.org/v1/node",
				DataDir:    t.TempDir(),
				Roots:      protocol.Roots{pub},
				Registry:   reg,
				Gate:       &fakeGate{},
				Logger:     slogTo(io.Discard),
			}
			if c.mutate != nil {
				c.mutate(&cfg)
			}
			_, err := New(cfg)
			if c.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	pub, _ := mustKey(t)
	reg, err := module.NewRegistry(newFakeModule())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{DataDir: t.TempDir(), Roots: protocol.Roots{pub}, Registry: reg, Gate: &fakeGate{}, Logger: slogTo(io.Discard)})
	if err != nil {
		t.Fatal(err)
	}
	c := a.cfg
	if c.GatewayURL != protocol.DefaultGatewayURL || c.ClientKind != nodev1.ClientKind_CLIENT_KIND_AGENT ||
		c.BackoffMin != time.Second || c.BackoffMax != 120*time.Second || c.Now == nil || c.InterfacePrefixes == nil {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if len(c.ConsentClasses) != 1 || c.ConsentClasses[0] != nodev1.JobClass_JOB_CLASS_MEASURE {
		t.Fatalf("default consent %v", c.ConsentClasses)
	}
	ps, err := systemInterfacePrefixes()
	if err != nil {
		t.Fatalf("system interface prefixes: %v", err)
	}
	for _, p := range ps {
		if !p.IsValid() || p.Addr().Is4In6() {
			t.Fatalf("bad interface prefix %v", p)
		}
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	k1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, keyFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize || !ed25519.NewKeyFromSeed(seed).Equal(k1) {
		t.Fatalf("key file is not the base64 seed of the key (err %v)", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file mode %o, want 600", perm)
		}
	}
	k2, err := LoadOrCreateKey(dir)
	if err != nil || !k2.Equal(k1) {
		t.Fatalf("reload gave another key (err %v)", err)
	}

	// An empty file never held a key and is replaced.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k3, err := LoadOrCreateKey(dir)
	if err != nil || k3.Equal(k1) {
		t.Fatalf("empty key file not replaced with a new key (err %v)", err)
	}

	// A damaged file is an error that quotes nothing from the file.
	if err := os.WriteFile(path, []byte("secret-material-not-base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrCreateKey(dir)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("damaged key file: %v", err)
	}
	if _, err := LoadOrCreateKey(""); err == nil {
		t.Fatal("empty data directory accepted")
	}
}

func TestReconnectPolicy(t *testing.T) {
	h := newHarness(t, false)
	cfg := h.config()
	cfg.BackoffMin = 100 * time.Millisecond
	cfg.BackoffMax = 1600 * time.Millisecond
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The jitter returns its bound, so each delay shows the envelope.
	a.jitter = func(n time.Duration) time.Duration { return n }
	b := &backoff{min: cfg.BackoffMin, max: cfg.BackoffMax, jitter: a.jitter}
	failed := sessionEnd{}
	stableBye := func(lo, hi uint32) sessionEnd {
		return sessionEnd{established: true, lasted: time.Hour, bye: &nodev1.Bye{
			Reason: nodev1.ByeReason_BYE_REASON_DEPLOY, ReconnectMinS: lo, ReconnectMaxS: hi,
		}}
	}
	steps := []struct {
		name string
		end  sessionEnd
		want time.Duration
	}{
		{"first failure", failed, 100 * time.Millisecond},
		{"second failure", failed, 200 * time.Millisecond},
		{"third failure", failed, 400 * time.Millisecond},
		{"Bye after a stable session waits its window", stableBye(5, 5), 5 * time.Second},
		{"the Bye did not reset the backoff", failed, 800 * time.Millisecond},
		{"an immediate Bye still takes the backoff", sessionEnd{bye: &nodev1.Bye{}}, 1600 * time.Millisecond},
		{"the envelope stops at BackoffMax", failed, 1600 * time.Millisecond},
		{"a stable session without Bye resets", sessionEnd{established: true, lasted: 2 * time.Second}, 100 * time.Millisecond},
		{"a short session raises", sessionEnd{established: true, lasted: time.Millisecond}, 200 * time.Millisecond},
		{"a Bye window is capped at a day", stableBye(100*3600, 200*3600), 24 * time.Hour},
		{"a Bye window with max below min uses min", stableBye(30, 10), 30 * time.Second},
	}
	for _, s := range steps {
		if got := a.nextWait(context.Background(), s.end, b); got != s.want {
			t.Fatalf("%s: wait %v, want %v", s.name, got, s.want)
		}
	}
	st := readState(t, h.dir)
	if st.ReconnectAfterUnixMs != t0.Add(30*time.Second).UnixMilli() || st.ByeReason != "BYE_REASON_DEPLOY" {
		t.Fatalf("state after the last Bye: %+v", st)
	}
}

func TestBackoffJitterStaysInEnvelope(t *testing.T) {
	b := &backoff{min: time.Second, max: 120 * time.Second, jitter: uniformJitter}
	for i := 0; i < 50; i++ {
		env := b.envelope()
		if d := b.next(); d < 0 || d > env {
			t.Fatalf("delay %v outside [0, %v]", d, env)
		}
	}
	if b.envelope() != 120*time.Second {
		t.Fatalf("envelope after many failures %v", b.envelope())
	}
}

func TestResultStoreBounds(t *testing.T) {
	clock := &fakeClock{t: t0}
	dir := t.TempDir()
	s, err := openResultStore(dir, clock.Now, slogTo(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	signed := func(i int) *nodev1.SignedResult {
		return &nodev1.SignedResult{Body: []byte(fmt.Sprintf("body-%d", i)), Sig: []byte("sig")}
	}
	const n = maxPendingResults + 5
	for i := range n {
		clock.Set(t0.Add(time.Duration(i) * time.Second))
		// Job ids are server strings; a slash must never become a path.
		if err := s.put(jobKey{id: fmt.Sprintf("../job/%d", i), attempt: 1}, signed(i)); err != nil {
			t.Fatal(err)
		}
	}
	list := s.list()
	if len(list) != maxPendingResults || list[0].key.id != "../job/5" {
		t.Fatalf("buffer holds %d results starting at %q", len(list), list[0].key.id)
	}
	if files := pendingFiles(t, dir); len(files) != maxPendingResults {
		t.Fatalf("%d files in the buffer", len(files))
	}
	if _, err := os.Stat(filepath.Join(dir, "job")); err == nil {
		t.Fatal("a job id escaped the buffer directory")
	}

	// The buffer survives a restart.
	s2, err := openResultStore(dir, clock.Now, slogTo(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if s2.len() != maxPendingResults {
		t.Fatalf("reloaded %d results", s2.len())
	}
	if p := s2.list()[0]; !bytes.Equal(p.signed.GetBody(), []byte("body-5")) || !p.stored.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("reloaded result %v stored %v", p.signed, p.stored)
	}
	if !s2.remove(jobKey{id: "../job/5", attempt: 1}) || s2.remove(jobKey{id: "../job/5", attempt: 1}) {
		t.Fatal("remove did not report the result once")
	}
	if files := pendingFiles(t, dir); len(files) != maxPendingResults-1 {
		t.Fatalf("%d files after a remove", len(files))
	}

	// Nothing older than 24 hours is kept.
	clock.Set(t0.Add(time.Duration(n-1)*time.Second + maxPendingAge + time.Second))
	if left := s2.list(); len(left) != 0 {
		t.Fatalf("%d results kept past 24 hours", len(left))
	}
	if files := pendingFiles(t, dir); len(files) != 0 {
		t.Fatalf("%d files kept past 24 hours", len(files))
	}

	// Unreadable files and leftovers of interrupted writes are dropped.
	for _, name := range []string{"garbage.json", ".abc.json.123.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, pendingDirName, name), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s3, err := openResultStore(dir, clock.Now, slogTo(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if s3.len() != 0 || len(pendingFiles(t, dir)) != 0 {
		t.Fatalf("damaged files kept: %v", pendingFiles(t, dir))
	}
}

func TestJobLogKeepsTheLast100(t *testing.T) {
	dir := t.TempDir()
	l, err := openJobLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 150 {
		rec := jobRecord{Time: t0, JobID: fmt.Sprint(i), Kind: "fake", TargetHost: "host.example", Outcome: "OK"}
		if err := l.add(rec); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(filepath.Join(dir, jobLogFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r jobRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("job log line %q: %v", sc.Text(), err)
		}
		ids = append(ids, r.JobID)
	}
	if len(ids) != jobLogKeep || ids[0] != "50" || ids[len(ids)-1] != "149" {
		t.Fatalf("job log holds %d lines from %v to %v", len(ids), ids[0], ids[len(ids)-1])
	}
	l2, err := openJobLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if recs := l2.records(); len(recs) != jobLogKeep || recs[0].JobID != "50" {
		t.Fatalf("reloaded %d records", len(recs))
	}
}

func TestSeqTracker(t *testing.T) {
	var tr seqTracker
	steps := []struct{ seq, ack uint64 }{
		{1, 1}, {3, 1}, {2, 3}, {0, 3}, {2, 3}, {5, 3}, {4, 5}, {6, 6},
	}
	for _, s := range steps {
		tr.received(s.seq)
		if got := tr.ack(); got != s.ack {
			t.Fatalf("after seq %d: ack %d, want %d", s.seq, got, s.ack)
		}
	}
}

func TestParseHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8":           "10.0.0.0/8",
		"10.1.2.3/8":           "10.0.0.0/8",
		"::ffff:10.0.0.0/104":  "10.0.0.0/8",
		"192.0.2.1":            "192.0.2.1/32",
		"::ffff:192.0.2.1":     "192.0.2.1/32",
		"2001:db8::1":          "2001:db8::1/128",
		"2001:db8:aa::/48":     "2001:db8:aa::/48",
		"not a prefix":         "",
		"::ffff:0.0.0.0/80":    "",
		"198.51.100.0/24 junk": "",
	} {
		p, err := parseDenyPrefix(in)
		switch {
		case want == "" && err == nil:
			t.Errorf("%q accepted as %v", in, p)
		case want != "" && (err != nil || p.String() != want):
			t.Errorf("%q: got %v (%v), want %s", in, p, err, want)
		}
	}
	got := parseAddrs([]string{"198.51.100.20", "[2001:db8::7]:443", "198.51.100.21:9", "::ffff:203.0.113.1", "bogus"})
	want := []netip.Addr{
		netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("2001:db8::7"),
		netip.MustParseAddr("198.51.100.21"), netip.MustParseAddr("203.0.113.1"),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("observed addresses %v, want %v", got, want)
	}
	pub := publicPrefixes([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.1.0/24"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("fe80::/64"),
		netip.MustParsePrefix("fd00:1::/64"),
		netip.MustParsePrefix("203.0.113.9/24"),
		netip.MustParsePrefix("2a01:4f8:1:2::5/64"),
	})
	if strings.Join(pub, ",") != "203.0.113.0/24,2a01:4f8:1:2::/64" {
		t.Fatalf("public prefixes %v", pub)
	}
	if !samePrefixes(
		[]netip.Prefix{netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("2001:db8::/64")},
		[]netip.Prefix{netip.MustParsePrefix("2001:db8::9/64"), netip.MustParsePrefix("192.168.1.0/24")},
	) {
		t.Fatal("the same networks compare as different")
	}
}

func TestVerifyGrant(t *testing.T) {
	h := newHarness(t, false)
	a, err := New(h.config())
	if err != nil {
		t.Fatal(err)
	}
	grantPub, grantPriv := mustKey(t)
	cert := protocol.NewKeyCertificate(grantPub, nodev1.KeyRole_KEY_ROLE_TARGET_GRANT, t0.Add(-time.Hour), t0.Add(365*24*time.Hour))
	sc, err := protocol.CertifyKey(h.keys.rootPriv, 0, cert)
	if err != nil {
		t.Fatal(err)
	}
	a.addCertificate(sc, nodev1.KeyRole_KEY_ROLE_TARGET_GRANT)
	a.addCertificate(h.keys.dispCert, nodev1.KeyRole_KEY_ROLE_DISPATCHER)

	grant := func(priv ed25519.PrivateKey, keyID string) *nodev1.SignedTargetGrant {
		body, err := proto.Marshal(&nodev1.TargetGrant{
			Hostname:        "proven.example",
			ProvenAddresses: []string{"198.51.100.5"},
			Ports:           []uint32{8443},
			ExpiresUnix:     t0.Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return &nodev1.SignedTargetGrant{Body: body, Sig: protocol.Sign(priv, protocol.PurposeTargetGrant, body), KeyId: keyID}
	}
	good := grant(grantPriv, cert.GetKeyId())
	tg, err := a.VerifyGrant(good, t0)
	if err != nil || tg.GetHostname() != "proven.example" {
		t.Fatalf("valid grant: %v, %v", tg, err)
	}
	if _, err := a.VerifyGrant(good, t0.Add(2*time.Hour)); err == nil {
		t.Fatal("expired grant accepted")
	}
	if _, err := a.VerifyGrant(grant(h.keys.dispPriv, h.keys.dispKeyID), t0); err == nil {
		t.Fatal("grant signed by a dispatcher key accepted")
	}
	bad := grant(grantPriv, cert.GetKeyId())
	bad.Sig[0] ^= 1
	if _, err := a.VerifyGrant(bad, t0); err == nil {
		t.Fatal("grant with a bad signature accepted")
	}
	if _, err := a.VerifyGrant(nil, t0); err == nil {
		t.Fatal("missing grant accepted")
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openState(dir, slogTo(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if !s.reconnectAfter().IsZero() {
		t.Fatal("a corrupt state file produced a window")
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt state not kept aside: %v", err)
	}

	measure := []nodev1.JobClass{nodev1.JobClass_JOB_CLASS_MEASURE}
	g1, err := s.consentGrants(measure, t0)
	if err != nil || g1[nodev1.JobClass_JOB_CLASS_MEASURE] != t0.Unix() {
		t.Fatalf("first consent record %v (%v)", g1, err)
	}
	g2, err := s.consentGrants(measure, t0.Add(time.Hour))
	if err != nil || g2[nodev1.JobClass_JOB_CLASS_MEASURE] != t0.Unix() {
		t.Fatalf("consent time moved: %v (%v)", g2, err)
	}
	if err := s.setReconnectAfter(t0.Add(time.Minute), "BYE_REASON_SHUTDOWN"); err != nil {
		t.Fatal(err)
	}
	keys := newTestKeys(t)
	rev := keys.revocation(t, "k-one")
	for range 2 {
		if err := s.addRevocation(rev); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := openState(dir, slogTo(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if !s2.reconnectAfter().Equal(t0.Add(time.Minute)) || len(s2.revocations()) != 1 {
		t.Fatalf("reloaded window %v and %d revocations", s2.reconnectAfter(), len(s2.revocations()))
	}
	g3, err := s2.consentGrants(measure, t0.Add(2*time.Hour))
	if err != nil || g3[nodev1.JobClass_JOB_CLASS_MEASURE] != t0.Unix() {
		t.Fatalf("consent record lost across a restart: %v (%v)", g3, err)
	}
}
