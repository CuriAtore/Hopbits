package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
	"github.com/hopbits/client/safety"
)

const (
	// DefaultManifestURL is the signed release manifest served beside the
	// off-core pause file under the compiled anchor domain.
	DefaultManifestURL = "https://" + safety.PauseHost + "/manifest.json"

	defaultUpdatePollInterval = 1 * time.Hour
	// binaryFetchTimeout bounds the download of a new agent (about 10 MB):
	// a whole dial and a transfer over a slow link.
	binaryFetchTimeout   = 10 * time.Minute
	maxManifestBytes     = 1 << 20   // 1 MiB
	maxUpdateBinaryBytes = 128 << 20 // 128 MiB
	stagedBinDir         = "bin"
	stagedBinName        = "hopbits-agent"
	stagedManifestName   = "manifest.json"
)

// UpdateFetcher downloads the signed release manifest and release binary.
type UpdateFetcher interface {
	FetchManifest(ctx context.Context) ([]byte, error)
	FetchBinary(ctx context.Context, artifactURL string) ([]byte, error)
}

// BinaryInstaller stages a verified release binary to persistent storage and
// re-executes the process once active work has drained.
type BinaryInstaller interface {
	Stage(ctx context.Context, manifestRaw, binaryData []byte) (string, error)
	Exec(binaryPath string) error
}

// SignedKeyCertEntry is the JSON form of a root-signed KeyCertificate bundled
// with a release manifest.
type SignedKeyCertEntry struct {
	Body      []byte `json:"body"`
	Sig       []byte `json:"sig"`
	RootIndex uint32 `json:"root_index"`
}

func (e SignedKeyCertEntry) toProto() *nodev1.SignedKeyCertificate {
	return &nodev1.SignedKeyCertificate{
		Body:      e.Body,
		Sig:       e.Sig,
		RootIndex: e.RootIndex,
	}
}

// SignedReleaseManifest wraps the serialized ReleaseManifest, optional
// root-signed revocations/certificate for KEY_ROLE_RELEASE, and the release
// key's Ed25519 signature over Body for protocol.PurposeReleaseManifest.
type SignedReleaseManifest struct {
	Revocations []SignedRevocationEntry `json:"revocations,omitempty"`
	Cert        *SignedKeyCertEntry     `json:"cert,omitempty"`
	KeyID       string                  `json:"key_id"`
	Body        []byte                  `json:"body"`
	Sig         []byte                  `json:"sig"`
}

// ReleaseManifest lists the latest verified release, minimum allowed version,
// staged rollout percentage and per-platform binary artifacts.
type ReleaseManifest struct {
	Version        string            `json:"version"`
	MinVersion     string            `json:"min_version,omitempty"`
	IssuedUnix     int64             `json:"issued_unix"`
	ExpiresUnix    int64             `json:"expires_unix"`
	RolloutPercent int               `json:"rollout_percent"`
	Artifacts      []ReleaseArtifact `json:"artifacts"`
}

// ReleaseArtifact describes one signed release binary.
type ReleaseArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size,omitempty"`
	// Sig is the Ed25519 signature with KEY_ROLE_RELEASE under
	// protocol.PurposeReleaseBinary over the raw 32-byte SHA-256 digest of the binary.
	Sig []byte `json:"sig"`
}

// HTTPUpdateFetcher implements UpdateFetcher over HTTPS (or loopback HTTP for tests).
type HTTPUpdateFetcher struct {
	ManifestURL string
	Client      *http.Client
}

// NewHTTPUpdateFetcher builds an HTTPUpdateFetcher targeting manifestURL
// (defaulting to DefaultManifestURL) using client (or a control HTTP client
// enforcing safety.Denied on resolved addresses).
func NewHTTPUpdateFetcher(manifestURL string, client *http.Client) *HTTPUpdateFetcher {
	if manifestURL == "" {
		manifestURL = DefaultManifestURL
	}
	if client == nil {
		client = newControlHTTPClient(nil)
	}
	return &HTTPUpdateFetcher{ManifestURL: manifestURL, Client: client}
}

// FetchManifest downloads the signed release manifest.
func (f *HTTPUpdateFetcher) FetchManifest(ctx context.Context) ([]byte, error) {
	return fetchSignedJSON(ctx, f.Client, f.ManifestURL, maxManifestBytes)
}

// FetchBinary downloads a release binary from artifactURL with bounded size and timeout.
func (f *HTTPUpdateFetcher) FetchBinary(ctx context.Context, artifactURL string) ([]byte, error) {
	if err := validateControlURL(artifactURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, binaryFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: download %s returned HTTP %d", artifactURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxUpdateBinaryBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxUpdateBinaryBytes {
		return nil, fmt.Errorf("agent: release binary %s exceeds %d bytes", artifactURL, maxUpdateBinaryBytes)
	}
	return b, nil
}

// VolumeBinaryInstaller stages verified binaries under DataDir/bin and
// re-executes the process with the new image.
type VolumeBinaryInstaller struct {
	DataDir string
	Reexec  func(binaryPath string) error
}

// NewVolumeBinaryInstaller returns a BinaryInstaller storing binaries under
// filepath.Join(dataDir, "bin").
func NewVolumeBinaryInstaller(dataDir string) *VolumeBinaryInstaller {
	return &VolumeBinaryInstaller{
		DataDir: dataDir,
		Reexec:  execBinary,
	}
}

// Stage atomically writes the verified manifest and binary into the persistent
// volume and returns the staged binary path.
func (v *VolumeBinaryInstaller) Stage(_ context.Context, manifestRaw, binaryData []byte) (string, error) {
	binDir := filepath.Join(v.DataDir, stagedBinDir)
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return "", fmt.Errorf("agent: create update directory: %w", err)
	}
	manifestPath := filepath.Join(binDir, stagedManifestName)
	if err := writeFileModeAtomic(manifestPath, manifestRaw, 0o600); err != nil {
		return "", fmt.Errorf("agent: stage manifest: %w", err)
	}
	target := filepath.Join(binDir, stagedBinName)
	if err := writeFileModeAtomic(target, binaryData, 0o755); err != nil {
		return "", fmt.Errorf("agent: stage binary: %w", err)
	}
	return target, nil
}

// Exec replaces the current process with binaryPath (or invokes v.Reexec when set).
func (v *VolumeBinaryInstaller) Exec(binaryPath string) error {
	if v.Reexec != nil {
		return v.Reexec(binaryPath)
	}
	return execBinary(binaryPath)
}

// InstallAndReexec stages the manifest and binary and immediately invokes Exec.
func (v *VolumeBinaryInstaller) InstallAndReexec(ctx context.Context, manifestRaw, binaryData []byte) error {
	target, err := v.Stage(ctx, manifestRaw, binaryData)
	if err != nil {
		return err
	}
	return v.Exec(target)
}

func (a *Agent) decodeAndVerifyManifest(raw []byte, enforceExpiry bool) (*ReleaseManifest, string, error) {
	var srm SignedReleaseManifest
	if err := json.Unmarshal(raw, &srm); err != nil {
		return nil, "", fmt.Errorf("agent: decode signed release manifest: %w", err)
	}
	for _, rev := range srm.Revocations {
		a.applyRevocation(rev.toProto())
	}
	if srm.Cert != nil {
		if _, err := a.ring.AddCertificate(srm.Cert.toProto(), nodev1.KeyRole_KEY_ROLE_RELEASE); err != nil {
			return nil, "", fmt.Errorf("agent: release key certificate: %w", err)
		}
	}
	now := a.now()
	if err := a.ring.Verify(srm.KeyID, nodev1.KeyRole_KEY_ROLE_RELEASE, protocol.PurposeReleaseManifest, srm.Body, srm.Sig, now); err != nil {
		return nil, "", fmt.Errorf("agent: release manifest signature: %w", err)
	}
	var m ReleaseManifest
	if err := json.Unmarshal(srm.Body, &m); err != nil {
		return nil, "", fmt.Errorf("agent: decode release manifest: %w", err)
	}
	if m.Version == "" {
		return nil, "", errors.New("agent: release manifest has no version")
	}
	if m.IssuedUnix <= 0 || m.ExpiresUnix <= m.IssuedUnix {
		return nil, "", errors.New("agent: release manifest has invalid validity timestamps")
	}
	if enforceExpiry && now.Unix() >= m.ExpiresUnix {
		return nil, "", errors.New("agent: release manifest is expired")
	}
	return &m, srm.KeyID, nil
}

// VerifyReleaseManifest checks the release key certificate (if embedded),
// verifies the root-certified release signature on raw, checks timestamps and
// rollback protection, and returns the decoded ReleaseManifest and signing key ID.
func (a *Agent) VerifyReleaseManifest(raw []byte) (*ReleaseManifest, string, error) {
	m, keyID, err := a.decodeAndVerifyManifest(raw, true)
	if err != nil {
		return nil, "", err
	}

	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if m.IssuedUnix < a.updateLastIssuedUnix {
		return nil, "", errors.New("agent: release manifest is older than an already accepted manifest")
	}
	a.updateLastIssuedUnix = m.IssuedUnix
	a.latestManifest = m
	return m, keyID, nil
}

// ExecStagedOnStartup checks DataDir/bin for an already-staged release manifest
// and binary on startup (e.g. when a container restarts from its base image
// /hopbits-agent). If auto-update is enabled, the staged version is newer than
// ClientVersion, and both the stored manifest and binary pass cryptographic
// verification against compiled roots and stored revocations, it execs into the
// staged binary without re-downloading over the network.
func (a *Agent) ExecStagedOnStartup() (bool, error) {
	if !a.cfg.AutoUpdateEnabled() || a.cfg.BinaryInstaller == nil {
		return false, nil
	}
	binDir := filepath.Join(a.cfg.DataDir, stagedBinDir)
	manifestPath := filepath.Join(binDir, stagedManifestName)
	binPath := filepath.Join(binDir, stagedBinName)
	if _, err := os.Stat(manifestPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("agent: stat staged manifest: %w", err)
	}
	if _, err := os.Stat(binPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("agent: stat staged binary: %w", err)
	}
	if sameExecutable(binPath) {
		return false, nil
	}
	manifestRaw, err := readBoundedFile(manifestPath, maxManifestBytes)
	if err != nil {
		return false, fmt.Errorf("agent: read staged manifest: %w", err)
	}
	m, keyID, err := a.decodeAndVerifyManifest(manifestRaw, false)
	if err != nil {
		return false, fmt.Errorf("agent: staged manifest verification: %w", err)
	}
	if compareSemver(m.Version, a.cfg.ClientVersion) <= 0 {
		return false, nil
	}
	art, ok := selectArtifact(m.Artifacts, a.cfg.targetOS, a.cfg.targetArch)
	if !ok {
		return false, fmt.Errorf("agent: staged manifest has no artifact for %s/%s", a.cfg.targetOS, a.cfg.targetArch)
	}
	binData, err := readBoundedFile(binPath, maxUpdateBinaryBytes)
	if err != nil {
		return false, fmt.Errorf("agent: read staged binary: %w", err)
	}
	if err := a.VerifyArtifactBinary(keyID, art, binData); err != nil {
		return false, fmt.Errorf("agent: staged binary verification: %w", err)
	}
	a.log.Info("re-executing verified staged release binary on startup",
		"from_version", a.cfg.ClientVersion, "to_version", m.Version, "path", binPath)
	if err := a.cfg.BinaryInstaller.Exec(binPath); err != nil {
		return false, err
	}
	return true, nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxBytes)
	}
	return b, nil
}

func sameExecutable(targetPath string) bool {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return false
	}
	if fi1, err1 := os.Stat(exe); err1 == nil {
		if fi2, err2 := os.Stat(targetPath); err2 == nil && os.SameFile(fi1, fi2) {
			return true
		}
	}
	r1, err1 := filepath.EvalSymlinks(exe)
	r2, err2 := filepath.EvalSymlinks(targetPath)
	if err1 == nil && err2 == nil {
		return filepath.Clean(r1) == filepath.Clean(r2)
	}
	return filepath.Clean(exe) == filepath.Clean(targetPath)
}

// VerifyArtifactBinary verifies binaryData against art's SHA-256 checksum,
// expected length (if positive), and release-key signature under
// protocol.PurposeReleaseBinary.
func (a *Agent) VerifyArtifactBinary(keyID string, art ReleaseArtifact, binaryData []byte) error {
	if art.Size > 0 && int64(len(binaryData)) != art.Size {
		return fmt.Errorf("agent: artifact size %d, want %d", len(binaryData), art.Size)
	}
	wantSum, err := hex.DecodeString(strings.TrimSpace(art.SHA256))
	if err != nil || len(wantSum) != sha256.Size {
		return errors.New("agent: release artifact has invalid sha256")
	}
	sum := sha256.Sum256(binaryData)
	if !equalBytesConstant(sum[:], wantSum) {
		return errors.New("agent: release binary sha256 mismatch")
	}
	if err := a.ring.Verify(keyID, nodev1.KeyRole_KEY_ROLE_RELEASE, protocol.PurposeReleaseBinary, sum[:], art.Sig, a.now()); err != nil {
		return fmt.Errorf("agent: release binary signature: %w", err)
	}
	return nil
}

func equalBytesConstant(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// RolloutEligible reports whether nodeID falls within percent [0..100] of the
// deterministic hash(node_id) rollout bucket.
func RolloutEligible(nodeID []byte, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 || len(nodeID) == 0 {
		return false
	}
	h := sha256.Sum256(nodeID)
	bucket := int(binary.BigEndian.Uint32(h[:4]) % 100)
	return bucket < percent
}

// CheckUpdateOutcome describes the result of CheckAndApplyUpdate.
type CheckUpdateOutcome int

const (
	UpdateNone CheckUpdateOutcome = iota
	UpdateDeferredRollout
	UpdateApplied
	UpdateOptedOut
)

// CheckAndApplyUpdate fetches and verifies the signed release manifest, and if
// an eligible newer release exists (or forceImmediate is true because
// MinVersion requires an upgrade), downloads, verifies, and stages (or
// executes, when Run is not active) the binary.
func (a *Agent) CheckAndApplyUpdate(ctx context.Context, forceImmediate bool) (CheckUpdateOutcome, error) {
	if a.cfg.UpdateFetcher == nil {
		return UpdateNone, nil
	}
	if a.hasStagedUpdate() {
		return UpdateApplied, nil
	}
	rawManifest, err := a.cfg.UpdateFetcher.FetchManifest(ctx)
	if err != nil {
		return UpdateNone, err
	}
	m, keyID, err := a.VerifyReleaseManifest(rawManifest)
	if err != nil {
		return UpdateNone, err
	}
	return a.applyVerifiedManifest(ctx, rawManifest, m, keyID, forceImmediate)
}

func (a *Agent) applyVerifiedManifest(
	ctx context.Context,
	rawManifest []byte,
	m *ReleaseManifest,
	keyID string,
	forceImmediate bool,
) (CheckUpdateOutcome, error) {
	if !a.cfg.AutoUpdateEnabled() {
		return UpdateOptedOut, nil
	}
	if compareSemver(m.Version, a.cfg.ClientVersion) <= 0 {
		return UpdateNone, nil
	}
	if a.hasStagedUpdate() {
		return UpdateApplied, nil
	}
	mandatory := m.MinVersion != "" && compareSemver(a.cfg.ClientVersion, m.MinVersion) < 0
	if !forceImmediate && !mandatory && !RolloutEligible(a.nodeID, m.RolloutPercent) {
		return UpdateDeferredRollout, nil
	}
	art, ok := selectArtifact(m.Artifacts, a.cfg.targetOS, a.cfg.targetArch)
	if !ok {
		return UpdateNone, fmt.Errorf("agent: no release artifact for %s/%s in version %s",
			a.cfg.targetOS, a.cfg.targetArch, m.Version)
	}
	binData, err := a.cfg.UpdateFetcher.FetchBinary(ctx, art.URL)
	if err != nil {
		return UpdateNone, err
	}
	if err := a.VerifyArtifactBinary(keyID, art, binData); err != nil {
		return UpdateNone, err
	}
	if a.cfg.BinaryInstaller == nil {
		return UpdateNone, errors.New("agent: no binary installer configured")
	}
	stagedPath, err := a.cfg.BinaryInstaller.Stage(ctx, rawManifest, binData)
	if err != nil {
		return UpdateNone, err
	}
	if a.stageUpdateForDrain(stagedPath) {
		a.log.Info("staged signed release update; draining active work before re-exec",
			"from_version", a.cfg.ClientVersion, "to_version", m.Version, "path", stagedPath)
		return UpdateApplied, nil
	}
	if err := a.cfg.BinaryInstaller.Exec(stagedPath); err != nil {
		return UpdateNone, err
	}
	a.log.Info("installed signed release update", "from_version", a.cfg.ClientVersion, "to_version", m.Version)
	return UpdateApplied, nil
}

// confirmUpgradeRequired verifies UPGRADE_REQUIRED against the root-certified
// release manifest before honouring a server-mandated upgrade hold or updating.
func (a *Agent) confirmUpgradeRequired(ctx context.Context) bool {
	if a.cfg.UpdateFetcher == nil {
		// No manifest verifier configured in this test/runtime instance.
		return true
	}
	raw, err := a.cfg.UpdateFetcher.FetchManifest(ctx)
	if err != nil {
		a.log.Warn("cannot fetch release manifest to confirm UPGRADE_REQUIRED", "err", err)
		return false
	}
	m, keyID, err := a.VerifyReleaseManifest(raw)
	if err != nil {
		a.log.Warn("release manifest failed verification while checking UPGRADE_REQUIRED", "err", err)
		return false
	}
	if m.MinVersion == "" || compareSemver(a.cfg.ClientVersion, m.MinVersion) >= 0 {
		a.log.Warn("ignoring UPGRADE_REQUIRED: root-certified manifest does not require an upgrade",
			"client_version", a.cfg.ClientVersion, "manifest_min_version", m.MinVersion, "manifest_version", m.Version)
		return false
	}
	if a.cfg.AutoUpdateEnabled() {
		if _, err := a.applyVerifiedManifest(ctx, raw, m, keyID, true); err != nil {
			a.log.Warn("self-update after confirmed UPGRADE_REQUIRED failed", "err", err)
		}
	}
	return true
}

// checkUpgradeNotice verifies a NOTICE_KIND_UPGRADE against the root-certified
// release manifest before triggering a self-update.
func (a *Agent) checkUpgradeNotice(ctx context.Context, n *nodev1.Notice) {
	if n.GetKind() != nodev1.NoticeKind_NOTICE_KIND_UPGRADE || a.cfg.UpdateFetcher == nil {
		return
	}
	raw, err := a.cfg.UpdateFetcher.FetchManifest(ctx)
	if err != nil {
		a.log.Debug("manifest check after upgrade notice failed", "err", err)
		return
	}
	m, keyID, err := a.VerifyReleaseManifest(raw)
	if err != nil {
		a.log.Warn("release manifest rejected after upgrade notice", "err", err)
		return
	}
	if want := n.GetMinClientVersion(); want != "" && compareSemver(want, m.Version) > 0 {
		a.log.Warn("upgrade notice version exceeds root-certified manifest version",
			"notice_min_version", want, "manifest_version", m.Version)
		return
	}
	if a.cfg.AutoUpdateEnabled() && compareSemver(m.Version, a.cfg.ClientVersion) > 0 {
		if _, err := a.applyVerifiedManifest(ctx, raw, m, keyID, false); err != nil {
			a.log.Warn("self-update after upgrade notice failed", "err", err)
		}
	}
}

func (a *Agent) runUpdateLoop(ctx context.Context) {
	if a.cfg.UpdateFetcher == nil || a.cfg.UpdatePollInterval <= 0 || !a.cfg.AutoUpdateEnabled() {
		return
	}
	if _, err := a.CheckAndApplyUpdate(ctx, false); err != nil && ctx.Err() == nil && !isNotExistOrConnRefused(err) {
		a.log.Debug("release manifest poll failed", "err", err)
	}
	ticker := time.NewTicker(a.cfg.UpdatePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.CheckAndApplyUpdate(ctx, false); err != nil && ctx.Err() == nil && !isNotExistOrConnRefused(err) {
				a.log.Warn("release manifest check failed", "err", err)
			}
		}
	}
}

func selectArtifact(artifacts []ReleaseArtifact, goos, goarch string) (ReleaseArtifact, bool) {
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	for _, a := range artifacts {
		if a.OS == goos && a.Arch == goarch {
			return a, true
		}
	}
	return ReleaseArtifact{}, false
}

// compareSemver compares two semantic versions (e.g. "v1.2.3", "1.2.3-dev").
// Pre-release tags compare strictly below the matching release version.
func compareSemver(a, b string) int {
	pa, preA := parseSemver(a)
	pb, preB := parseSemver(b)
	for i := range 3 {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	switch {
	case preA == preB:
		return 0
	case preA == "":
		return 1
	case preB == "":
		return -1
	case preA < preB:
		return -1
	default:
		return 1
	}
}

func parseSemver(v string) (nums [3]int, pre string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err == nil && n >= 0 {
			nums[i] = n
		}
	}
	return nums, pre
}
