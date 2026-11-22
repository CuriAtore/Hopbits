package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerifyIsPurposeBound(t *testing.T) {
	pub, priv := mustKey(t)
	body := []byte("a serialised result")
	sig := Sign(priv, PurposeResult, body)
	if !Verify(pub, PurposeResult, body, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pub, PurposeHello, body, sig) {
		t.Fatal("signature verified under another purpose")
	}
	tampered := append([]byte(nil), body...)
	tampered[0] ^= 1
	if Verify(pub, PurposeResult, tampered, sig) {
		t.Fatal("tampered body verified")
	}
	if Verify(pub, PurposeResult, body, sig[:10]) {
		t.Fatal("short signature verified")
	}
}

func TestNodeID(t *testing.T) {
	pub, _ := mustKey(t)
	id := NodeID(pub)
	if len(id) != NodeIDLength {
		t.Fatalf("node id length %d", len(id))
	}
	back, err := ParseNodeID(NodeIDString(id))
	if err != nil || string(back) != string(id) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := ParseNodeID("zz"); err == nil {
		t.Fatal("invalid node id accepted")
	}
}

func TestCapabilityRoundTrip(t *testing.T) {
	for _, s := range []string{"measure.http.v1", "measure.icmp_ping.v1:ipv4:ts.user", "measure.http.v2:phases"} {
		c, err := ParseCapability(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if c.String() != s {
			t.Fatalf("round trip: got %q want %q", c.String(), s)
		}
	}
	c, _ := ParseCapability("measure.icmp_ping.v1:ipv4:ts.user")
	if c.Base() != "measure.icmp_ping.v1" || !c.Has("ipv4") || c.Has("ipv6") {
		t.Fatalf("unexpected parse %+v", c)
	}
	for _, bad := range []string{"", "measure", "measure.http", "measure.http.1", "measure.http.v0", "measure.http.v1::x"} {
		if _, err := ParseCapability(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestKeyRing(t *testing.T) {
	rootPub, rootPriv := mustKey(t)
	otherRootPub, otherRootPriv := mustKey(t)
	dispPub, dispPriv := mustKey(t)
	now := time.Unix(1_800_000_000, 0)

	ring := NewKeyRing(Roots{rootPub, otherRootPub})
	cert := NewKeyCertificate(dispPub, nodev1.KeyRole_KEY_ROLE_DISPATCHER, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	sc, err := CertifyKey(rootPriv, 0, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.AddCertificate(sc, nodev1.KeyRole_KEY_ROLE_TARGET_GRANT); err != ErrWrongRole {
		t.Fatalf("wrong role accepted: %v", err)
	}
	if _, err := ring.AddCertificate(sc, nodev1.KeyRole_KEY_ROLE_DISPATCHER); err != nil {
		t.Fatal(err)
	}

	body := []byte("job body")
	sig := Sign(dispPriv, PurposeJob, body)
	if err := ring.Verify(cert.GetKeyId(), nodev1.KeyRole_KEY_ROLE_DISPATCHER, PurposeJob, body, sig, now); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	if err := ring.Verify(cert.GetKeyId(), nodev1.KeyRole_KEY_ROLE_DISPATCHER, PurposeJob, body, sig, now.Add(91*24*time.Hour)); err != ErrKeyOutsideValid {
		t.Fatalf("expired key accepted: %v", err)
	}
	if err := ring.Verify("k-unknown", nodev1.KeyRole_KEY_ROLE_DISPATCHER, PurposeJob, body, sig, now); err != ErrUnknownKey {
		t.Fatalf("unknown key accepted: %v", err)
	}

	// A certificate signed by the second root under the first root's index fails.
	bad, _ := CertifyKey(otherRootPriv, 0, cert)
	if _, err := ring.AddCertificate(bad, nodev1.KeyRole_KEY_ROLE_DISPATCHER); err != ErrBadSignature {
		t.Fatalf("mis-indexed certificate accepted: %v", err)
	}
	if _, err := ring.AddCertificate(&nodev1.SignedKeyCertificate{Body: sc.Body, Sig: sc.Sig, RootIndex: 7}, nodev1.KeyRole_KEY_ROLE_DISPATCHER); err != ErrUnknownRoot {
		t.Fatalf("unknown root accepted: %v", err)
	}

	rev, err := SignRevocation(otherRootPriv, 1, &nodev1.Revocation{KeyIds: []string{cert.GetKeyId()}, IssuedUnix: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.ApplyRevocation(rev); err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(cert.GetKeyId(), nodev1.KeyRole_KEY_ROLE_DISPATCHER, PurposeJob, body, sig, now); err != ErrKeyRevoked {
		t.Fatalf("revoked key accepted: %v", err)
	}
	if _, err := ring.AddCertificate(sc, nodev1.KeyRole_KEY_ROLE_DISPATCHER); err != ErrKeyRevoked {
		t.Fatalf("revoked key re-added: %v", err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	env := &nodev1.Envelope{Seq: 3, Ack: 2, Body: &nodev1.Envelope_Ping{Ping: &nodev1.Ping{Nonce: []byte("0123456789abcdef")}}}
	b, err := EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSeq() != 3 || string(got.GetPing().GetNonce()) != "0123456789abcdef" {
		t.Fatalf("round trip mismatch: %v", got)
	}
	if _, err := DecodeEnvelope(make([]byte, MaxFrameBytes+1)); err != ErrFrameTooLarge {
		t.Fatalf("oversized frame accepted: %v", err)
	}
}

func TestKeyRingVerifyWorkingRoot(t *testing.T) {
	workPub, workPriv := mustKey(t)
	recPub, recPriv := mustKey(t)
	ring := NewKeyRing(Roots{workPub, recPub})

	body := []byte(`{"paused":true}`)
	sig := Sign(workPriv, PurposePauseFile, body)
	if err := ring.VerifyWorkingRoot(PurposePauseFile, body, sig); err != nil {
		t.Fatalf("working root signature rejected: %v", err)
	}
	if err := ring.VerifyWorkingRoot(PurposeReleaseManifest, body, sig); err != ErrBadSignature {
		t.Fatalf("wrong purpose accepted: %v", err)
	}
	recSig := Sign(recPriv, PurposePauseFile, body)
	if err := ring.VerifyWorkingRoot(PurposePauseFile, body, recSig); err != ErrBadSignature {
		t.Fatalf("recovery root signature accepted as working root: %v", err)
	}
	emptyRing := NewKeyRing(nil)
	if err := emptyRing.VerifyWorkingRoot(PurposePauseFile, body, sig); err != ErrUnknownRoot {
		t.Fatalf("empty root ring returned %v, want ErrUnknownRoot", err)
	}
}

func TestSanitizeNodeLabelAndHelloSignature(t *testing.T) {
	cases := []struct {
		in        string
		want      string
		truncated bool
	}{
		{"", "", false},
		{"   \t\r\n  ", "", false},
		{"\x00\x07\x1b\x7f", "", false},
		{"  edge-fra-01  ", "edge-fra-01", false},
		{"us east 1", "us east 1", false},
		{"\x00 host\x07-a\x1b\x7f\n ", "host-a", false},
		{strings.Repeat("x", 80), strings.Repeat("x", 80), false},
		{strings.Repeat("x", 95), strings.Repeat("x", 80), true},
		{strings.Repeat("東", 80), strings.Repeat("東", 80), false},
		{strings.Repeat("東", 85), strings.Repeat("東", 80), true},
		{strings.Repeat("🚀", 80), strings.Repeat("🚀", 64), true},
		{"bad-\xff\xfeutf8", "bad-utf8", false},
	}
	for _, tc := range cases {
		got, trunc := SanitizeNodeLabel(tc.in)
		if got != tc.want || trunc != tc.truncated {
			t.Fatalf("SanitizeNodeLabel(%q) = (%q, %v), want (%q, %v)", tc.in, got, trunc, tc.want, tc.truncated)
		}
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > MaxNodeLabelRunes || len(got) > MaxNodeLabelBytes {
			t.Fatalf("SanitizeNodeLabel(%q) violated bounds: runes=%d bytes=%d", tc.in, utf8.RuneCountInString(got), len(got))
		}
	}

	pub, priv := mustKey(t)
	h := &nodev1.Hello{
		ProtocolVersion: Version,
		ClientKind:      nodev1.ClientKind_CLIENT_KIND_AGENT,
		ClientVersion:   "0.2.3",
		PublicKey:       pub,
		NodeId:          NodeID(pub),
		Os:              "linux/amd64",
		TimestampUnixMs: 1_800_000_000_000,
		Nonce:           []byte("0123456789abcdef"),
		Label:           "fra-edge-01",
	}
	body, err := proto.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(priv, PurposeHello, body)
	if !Verify(pub, PurposeHello, body, sig) {
		t.Fatal("SignedHello with Label failed verification")
	}
	var decoded nodev1.Hello
	if err := proto.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetLabel() != "fra-edge-01" {
		t.Fatalf("decoded Hello.Label = %q, want fra-edge-01", decoded.GetLabel())
	}

	// Tampering with Hello.Label invalidates SignedHello signature.
	h2 := proto.Clone(h).(*nodev1.Hello)
	h2.Label = "tampered-label"
	tamperedBody, err := proto.Marshal(h2)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(pub, PurposeHello, tamperedBody, sig) {
		t.Fatal("signature verified after tampering Hello.Label")
	}
}
