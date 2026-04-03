package codesign

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"resigner/pkg/fs"
	"resigner/pkg/keychain"
	"go.uber.org/zap"
)

type stubCodeSigner struct {
	signAppCount    int
	signPathCount   int
	signBinaryCount int
	lastAppPath     string
	appErr          error
}

type stubKeychain struct {
	identity keychain.Identity
	ok       bool
	err      error
}

func (s stubKeychain) Identities(ctx context.Context) ([]string, error) {
	return nil, nil
}

func (s stubKeychain) Identity(ctx context.Context, fingerprint string) (keychain.Identity, bool, error) {
	if s.err != nil {
		return keychain.Identity{}, false, s.err
	}

	return s.identity, s.ok, nil
}

func (s *stubCodeSigner) SignApp(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	s.signAppCount++
	s.lastAppPath = path
	return s.appErr
}

func (s *stubCodeSigner) SignPath(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	s.signPathCount++
	return nil
}

func (s *stubCodeSigner) SignBinary(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	s.signBinaryCount++
	return nil
}

func writeMemFile(t *testing.T, root fs.ReadWriteFS, path string, data []byte) {
	t.Helper()

	f, err := root.CreateRW(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
}

func TestSign_DispatchesByPathType(t *testing.T) {
	root := fs.NewMemFS()
	if err := root.Mkdir("Foo.app"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir("Folder"); err != nil {
		t.Fatal(err)
	}
	writeMemFile(t, root, "binary", []byte("binary"))

	signer := &stubCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	if err := Sign(ctx, logger, signer, root, "Foo.app", SigningConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, logger, signer, root, "Folder", SigningConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := Sign(ctx, logger, signer, root, "binary", SigningConfig{}); err != nil {
		t.Fatal(err)
	}

	if signer.signAppCount != 1 {
		t.Fatalf("expected SignApp once, got %d", signer.signAppCount)
	}
	if signer.signPathCount != 1 {
		t.Fatalf("expected SignPath once, got %d", signer.signPathCount)
	}
	if signer.signBinaryCount != 1 {
		t.Fatalf("expected SignBinary once, got %d", signer.signBinaryCount)
	}
}

func TestSign_DispatchesXCTestAndStatError(t *testing.T) {
	root := fs.NewMemFS()
	if err := root.Mkdir("Suite.xctest"); err != nil {
		t.Fatal(err)
	}

	signer := &stubCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	if err := Sign(ctx, logger, signer, root, "Suite.xctest", SigningConfig{}); err != nil {
		t.Fatal(err)
	}

	if signer.signAppCount != 1 {
		t.Fatalf("expected xctest path to dispatch SignApp once, got %d", signer.signAppCount)
	}

	err := Sign(ctx, logger, signer, root, "does-not-exist", SigningConfig{})
	if err == nil || !strings.Contains(err.Error(), "could not stat file") {
		t.Fatalf("expected stat error wrapper, got %v", err)
	}
}

func TestSign_DispatchesIPA(t *testing.T) {
	archiveData, err := os.ReadFile("testdata/wda.ipa")
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	archivePath := tmp + "/test.ipa"
	if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
		t.Fatal(err)
	}

	root := fs.DirFS(tmp)
	signer := &stubCodeSigner{}

	if err := Sign(context.Background(), zap.NewNop(), signer, root, "test.ipa", SigningConfig{}); err != nil {
		t.Fatal(err)
	}

	if signer.signAppCount != 1 {
		t.Fatalf("expected SignIPA flow to invoke SignApp once, got %d", signer.signAppCount)
	}
	if signer.lastAppPath == "" {
		t.Fatal("expected SignApp to receive extracted bundle path")
	}
}

func TestSignIPA_WrapsSignerErrors(t *testing.T) {
	archiveData, err := os.ReadFile("testdata/wda.ipa")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		onlyVerify bool
		expected   string
	}{
		{onlyVerify: true, expected: "failed to verify app signature"},
		{onlyVerify: false, expected: "failed to sign app"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			tmp := t.TempDir()
			archivePath := tmp + "/test.ipa"
			if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
				t.Fatal(err)
			}

			root := fs.DirFS(tmp)
			signerErr := errors.New("signer failed")
			signer := &stubCodeSigner{appErr: signerErr}

			err := SignIPA(context.Background(), zap.NewNop(), signer, root, "test.ipa", SigningConfig{OnlyVerify: tc.onlyVerify})
			if err == nil {
				t.Fatal("expected SignIPA to fail")
			}

			if !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected error to contain %q, got %q", tc.expected, err.Error())
			}

			if !errors.Is(err, signerErr) {
				t.Fatal("expected wrapped signer error")
			}
		})
	}
}

func TestSignIPA_OnlyVerifyAndUnzipFailure(t *testing.T) {
	t.Run("only verify succeeds without rewriting archive", func(t *testing.T) {
		archiveData, err := os.ReadFile("testdata/wda.ipa")
		if err != nil {
			t.Fatal(err)
		}

		tmp := t.TempDir()
		archivePath := tmp + "/test.ipa"
		if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
			t.Fatal(err)
		}

		before, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}

		signer := &stubCodeSigner{}
		err = SignIPA(context.Background(), zap.NewNop(), signer, fs.DirFS(tmp), "test.ipa", SigningConfig{OnlyVerify: true})
		if err != nil {
			t.Fatal(err)
		}

		after, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}

		if signer.signAppCount != 1 {
			t.Fatalf("expected SignApp to run once, got %d", signer.signAppCount)
		}

		if len(before) != len(after) {
			t.Fatalf("expected verify-only flow to keep archive size unchanged: before=%d after=%d", len(before), len(after))
		}
	})

	t.Run("unzip failure is wrapped", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(tmp+"/bad.ipa", []byte("not-a-zip"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := SignIPA(context.Background(), zap.NewNop(), &stubCodeSigner{}, fs.DirFS(tmp), "bad.ipa", SigningConfig{})
		if err == nil || !strings.Contains(err.Error(), "could not unzip IPA") {
			t.Fatalf("expected unzip wrapper error, got %v", err)
		}
	})
}

func selfSignedIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Unit Test Cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return key, cert
}

func TestSigningConfigNormalize_EarlyAndDefaults(t *testing.T) {
	cfg := SigningConfig{OnlyVerify: true}
	if err := cfg.Normalize(context.Background(), zap.NewNop(), "bundle", "team", "iphoneos"); err != nil {
		t.Fatal(err)
	}

	key, cert := selfSignedIdentity(t)

	cfg = SigningConfig{
		TeamID: "TEAMID",
		Key:    key,
		Cert:   cert,
		Chain:  []*x509.Certificate{cert},
		CertOpts: x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
		},
	}

	if err := cfg.Normalize(context.Background(), zap.NewNop(), "com.example.app", "TEAMID", "iphoneos"); err != nil {
		t.Fatal(err)
	}

	if cfg.BundleID != "com.example.app" {
		t.Fatal("expected bundle id fallback")
	}
	if cfg.Platform != "iphoneos" {
		t.Fatal("expected platform fallback")
	}
	if cfg.Requirements == nil {
		t.Fatal("expected default requirements to be populated")
	}
	if cfg.TeamIDPrefix != "TEAMID" {
		t.Fatal("expected team id prefix to default to team id")
	}

	before := cfg.BundleID
	if err := cfg.Normalize(context.Background(), zap.NewNop(), "changed.bundle", "TEAMID", "changed"); err != nil {
		t.Fatal(err)
	}
	if cfg.BundleID != before {
		t.Fatal("expected already-normalized config not to be recomputed")
	}
}

func TestSigningConfigNormalize_FailurePaths(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	cfg := SigningConfig{}
	err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "insufficient information to choose signing key") {
		t.Fatalf("expected missing key error, got %v", err)
	}

	key, _ := selfSignedIdentity(t)
	cfg = SigningConfig{Key: key}
	err = cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "insufficient information to choose signing cert") {
		t.Fatalf("expected missing cert error, got %v", err)
	}

	cfg = SigningConfig{
		BundleID:        "com.example.app",
		Platform:        "iphoneos",
		ProfileProvider: stubProfileProvider{profilesResult: nil},
	}
	err = cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "unable to find usable provisioning profile") {
		t.Fatalf("expected profile selection error, got %v", err)
	}
}

// TestSigningConfigNormalize_WithProfile verifies that the c.Profile != nil branch
// sets TeamID from the profile and that the dev-cert key-matching loop is executed.
func TestSigningConfigNormalize_WithProfile(t *testing.T) {
	ctx := context.Background()

	// key1/cert1 go into the profile's DeveloperCertificates.
	// key2 is the signing key — it doesn't match cert1, so the loop never
	// assigns c.Cert and we get "insufficient information to choose signing cert".
	_, cert1 := selfSignedIdentity(t)
	key2, _ := selfSignedIdentity(t)

	profile := testProfile()
	profile.DeveloperCertificates = Certificates{cert1}

	cfg := SigningConfig{
		Key:     key2,
		Profile: profile,
	}
	err := cfg.Normalize(ctx, zap.NewNop(), "com.example.app", "OTHER", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "insufficient information to choose signing cert") {
		t.Fatalf("expected missing cert error, got %v", err)
	}
	// TeamID should have been overridden from the profile.
	if cfg.TeamID != profile.GetTeamID() {
		t.Fatalf("TeamID should come from profile, got %q want %q", cfg.TeamID, profile.GetTeamID())
	}
}

// TestSigningConfigNormalize_WithFingerprintProvider exercises the
// c.ProfileFingerprint + c.ProfileProvider certificate-lookup branch.
func TestSigningConfigNormalize_WithFingerprintProvider(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	fp := ProfileFingerprint{Sha1: "abc", Sha256: "def", TeamID: "TEAM1"}

	// Case 1: certificate lookup returns !ok → specific error.
	cfg := SigningConfig{
		ProfileFingerprint: &fp,
		ProfileProvider:    stubProfileProvider{certificateOK: false},
	}
	err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "no certificates found for provisioning profile") {
		t.Fatalf("expected no-cert error, got %v", err)
	}

	// Case 2: certificate lookup returns error → error is wrapped.
	certErr := errors.New("cert lookup failed")
	cfg = SigningConfig{
		ProfileFingerprint: &fp,
		ProfileProvider:    stubProfileProvider{certificateErr: certErr},
	}
	err = cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if !errors.Is(err, certErr) {
		t.Fatalf("expected wrapped cert error, got %v", err)
	}

	// Case 3: certificate found, no key → missing key error.
	_, cert := selfSignedIdentity(t)
	cfg = SigningConfig{
		ProfileFingerprint: &fp,
		ProfileProvider:    stubProfileProvider{certificateResult: cert, certificateOK: true},
	}
	err = cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err == nil || !strings.Contains(err.Error(), "insufficient information to choose signing key") {
		t.Fatalf("expected missing key error, got %v", err)
	}
}

func TestSigningConfigNormalize_WithProfileProvider_FindsIdentity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	key, cert := selfSignedIdentity(t)
	fp := ProfileFingerprint{Sha1: "aa", Sha256: "bb", TeamID: "TEAMFP"}

	profile := testProfile()
	profile.ProfileInfo.Entitlements.Identifier = "PREFIX.com.example.app"

	cfg := SigningConfig{
		ProfileProvider: stubProfileProvider{
			profilesResult:   []ProfileFingerprint{fp},
			certificateResult: cert,
			certificateOK:     true,
			profileResult:     profile,
			profileOK:         true,
		},
		Key:  key,
		TeamID: "OTHER",
		CertOpts: x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
		},
		Chain: []*x509.Certificate{cert},
	}

	err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ProfileFingerprint == nil || cfg.ProfileFingerprint.Sha256 != fp.Sha256 {
		t.Fatalf("expected selected profile fingerprint %q, got %#v", fp.Sha256, cfg.ProfileFingerprint)
	}

	if cfg.TeamID != fp.TeamID {
		t.Fatalf("expected TeamID %q from fingerprint, got %q", fp.TeamID, cfg.TeamID)
	}

	if cfg.Profile == nil {
		t.Fatal("expected profile to be loaded from provider")
	}

	if cfg.TeamIDPrefix != "PREFIX" {
		t.Fatalf("expected TeamIDPrefix from profile, got %q", cfg.TeamIDPrefix)
	}
}

func TestSigningConfigNormalize_ProfileProviderErrors(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("profiles query fails", func(t *testing.T) {
		profilesErr := errors.New("profiles failed")
		cfg := SigningConfig{
			ProfileProvider: stubProfileProvider{profilesErr: profilesErr},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if !errors.Is(err, profilesErr) {
			t.Fatalf("expected wrapped profiles error, got %v", err)
		}
	})

	t.Run("profile lookup fails after selecting fingerprint", func(t *testing.T) {
		key, cert := selfSignedIdentity(t)
		fp := ProfileFingerprint{Sha1: "11", Sha256: "22", TeamID: "TEAMID"}
		profileErr := errors.New("profile lookup failed")

		cfg := SigningConfig{
			ProfileFingerprint: &fp,
			ProfileProvider: stubProfileProvider{
				certificateResult: cert,
				certificateOK:     true,
				profileErr:        profileErr,
			},
			Key: key,
			CertOpts: x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
			Chain: []*x509.Certificate{cert},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if !errors.Is(err, profileErr) {
			t.Fatalf("expected wrapped profile error, got %v", err)
		}
	})

	t.Run("profile lookup not found", func(t *testing.T) {
		key, cert := selfSignedIdentity(t)
		fp := ProfileFingerprint{Sha1: "33", Sha256: "44", TeamID: "TEAMID"}

		cfg := SigningConfig{
			ProfileFingerprint: &fp,
			ProfileProvider: stubProfileProvider{
				certificateResult: cert,
				certificateOK:     true,
				profileOK:         false,
			},
			Key: key,
			CertOpts: x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
			Chain: []*x509.Certificate{cert},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if err == nil || !strings.Contains(err.Error(), "could not find profile for given fingerprint") {
			t.Fatalf("expected missing profile error, got %v", err)
		}
	})
}

func TestSigningConfigNormalize_KeychainLookupBranches(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("key found in keychain", func(t *testing.T) {
		key, cert := selfSignedIdentity(t)

		cfg := SigningConfig{
			TeamID: "TEAMID",
			Cert:   cert,
			Keychain: stubKeychain{
				identity: keychain.Identity{PrivateKey: key, Certificate: cert},
				ok:       true,
			},
			CertOpts: x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
			Chain: []*x509.Certificate{cert},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if err != nil {
			t.Fatal(err)
		}

		if cfg.Key == nil {
			t.Fatal("expected key to be loaded from keychain")
		}
	})

	t.Run("key lookup fails", func(t *testing.T) {
		_, cert := selfSignedIdentity(t)
		lookupErr := errors.New("keychain failure")

		cfg := SigningConfig{
			TeamID:   "TEAMID",
			Cert:     cert,
			Keychain: stubKeychain{err: lookupErr},
			CertOpts: x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
			Chain: []*x509.Certificate{cert},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if !errors.Is(err, lookupErr) {
			t.Fatalf("expected wrapped keychain error, got %v", err)
		}
	})

	t.Run("no key found", func(t *testing.T) {
		_, cert := selfSignedIdentity(t)

		cfg := SigningConfig{
			TeamID:   "TEAMID",
			Cert:     cert,
			Keychain: stubKeychain{ok: false},
			CertOpts: x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			},
			Chain: []*x509.Certificate{cert},
		}

		err := cfg.Normalize(ctx, logger, "com.example.app", "TEAMID", "iphoneos")
		if err == nil || !strings.Contains(err.Error(), "could not find key in keychain") {
			t.Fatalf("expected missing keychain key error, got %v", err)
		}
	})
}
