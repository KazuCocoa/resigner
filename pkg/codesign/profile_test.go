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
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/github/smimesign/ietf-cms/protocol"
	"go.uber.org/zap"
	"howett.net/plist"
	"resigner/pkg/fs"
)

func TestReadProfile(t *testing.T) {
	data, err := os.ReadFile("testdata/embedded.mobileprovision")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseEmptyProfileProviderSpec(t *testing.T) {
	provider, err := ParseEmptyProfileProviderSpec(context.Background(), zap.NewNop(), "", "")
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(context.Background(), "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) != 0 {
		t.Fatal("expected empty provider to return no fingerprints")
	}
}

func TestParseFileProfileProviderSpec_Directory(t *testing.T) {
	dir := t.TempDir()

	provider, err := ParseFileProfileProviderSpec(context.Background(), zap.NewNop(), "file:", dir)
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(context.Background(), "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) != 0 {
		t.Fatal("expected empty directory provider to return no fingerprints")
	}
}

func TestParseFileProfileProviderSpec_File(t *testing.T) {
	provider, err := ParseFileProfileProviderSpec(
		context.Background(),
		zap.NewNop(),
		"file:",
		"testdata/embedded.mobileprovision",
	)
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(context.Background(), "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) == 0 {
		t.Fatal("expected single profile provider to return fingerprints")
	}
}

func TestParseFileProfileProviderSpec_NotFound(t *testing.T) {
	_, err := ParseFileProfileProviderSpec(context.Background(), zap.NewNop(), "file:", "missing.mobileprovision")
	if err == nil {
		t.Fatal("expected missing path to fail")
	}
}

func TestParseFileProfileProviderSpec_HomeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	data, err := os.ReadFile("testdata/embedded.mobileprovision")
	if err != nil {
		t.Fatal(err)
	}

	homeProfile := filepath.Join(home, "home.mobileprovision")
	if err := os.WriteFile(homeProfile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	provider, err := ParseFileProfileProviderSpec(context.Background(), zap.NewNop(), "file:", "~/home.mobileprovision")
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(context.Background(), "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) == 0 {
		t.Fatal("expected home-expanded file profile to return fingerprints")
	}
}

func TestNewSingleProfileProvider_InvalidData(t *testing.T) {
	_, err := NewSingleProfileProvider([]byte("not-a-profile"))
	if err == nil {
		t.Fatal("expected invalid profile data to fail")
	}
}

func TestProfileProviderSpecParserParse(t *testing.T) {
	var parser ProfileProviderSpecParser
	parser.Register("none", ParseEmptyProfileProviderSpec)
	parser.Register("file:", ParseFileProfileProviderSpec)

	provider, err := parser.Parse(
		context.Background(),
		zap.NewNop(),
		"none",
		"file:testdata/embedded.mobileprovision",
	)
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(context.Background(), "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) == 0 {
		t.Fatal("expected parsed providers to include file provider fingerprints")
	}

	_, err = parser.Parse(context.Background(), zap.NewNop(), "bad-spec")
	if err == nil {
		t.Fatal("expected invalid spec to fail")
	}

	if !strings.Contains(err.Error(), "could not parse profile provider spec") {
		t.Fatal("expected parse error to include spec context")
	}

	var parseErr *SpecParseError
	if !errors.As(err, &parseErr) {
		t.Fatal("expected wrapped spec parse error")
	}
}

func TestDirProfileProviderBehavior(t *testing.T) {
	profileData, err := os.ReadFile("testdata/embedded.mobileprovision")
	if err != nil {
		t.Fatal(err)
	}

	fixtureProfile, err := ParseProfile(profileData)
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	profilePath := filepath.Join(tmp, "embedded.mobileprovision")
	if err := os.WriteFile(profilePath, profileData, 0o644); err != nil {
		t.Fatal(err)
	}

	provider, err := NewDirProfileProvider(fs.DirFS(tmp), ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fingerprints, err := provider.Profiles(ctx, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if time.Now().After(fixtureProfile.ExpirationDate) {
		if len(fingerprints) != 0 {
			t.Fatal("expected expired fixture profile to be ignored")
		}
	} else {
		if len(fingerprints) == 0 {
			t.Fatal("expected non-expired fixture profile to be returned")
		}
	}

	injectedProfile := testProfile()
	injectedFingerprints := injectedProfile.Fingerprints()
	if len(injectedFingerprints) == 0 {
		t.Fatal("expected injected profile to have fingerprints")
	}

	provider.lock.Lock()
	for fp := range injectedFingerprints {
		provider.profiles[fp] = injectedProfile
	}
	provider.lock.Unlock()

	var fingerprint ProfileFingerprint
	for fp := range injectedFingerprints {
		fingerprint = fp
		break
	}

	profile, ok, err := provider.Profile(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	if !ok || profile == nil {
		t.Fatal("expected profile lookup to succeed")
	}

	cert, ok, err := provider.Certificate(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	if !ok || cert == nil {
		t.Fatal("expected certificate lookup to succeed")
	}

	if _, ok, err := provider.Profile(ctx, ProfileFingerprint{}); err != nil || ok {
		t.Fatal("expected unknown profile lookup to fail")
	}

	if _, ok, err := provider.Certificate(ctx, ProfileFingerprint{}); err != nil || ok {
		t.Fatal("expected unknown certificate lookup to fail")
	}

	fingerprintsAgain, err := provider.Profiles(ctx, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprintsAgain) == 0 {
		t.Fatal("expected injected profiles to be returned")
	}

	filteredProvider, err := NewDirProfileProvider(fs.DirFS(tmp), ".", func(*Profile) bool { return false })
	if err != nil {
		t.Fatal(err)
	}

	none, err := filteredProvider.Profiles(ctx, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(none) != 0 {
		t.Fatal("expected predicate to filter out all profiles")
	}
}

func makeTestMobileProvisionData(t *testing.T, expiration time.Time, teamID, bundleID string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Unit Test Provisioning Cert",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]interface{}{
		"Entitlements": map[string]interface{}{
			"application-identifier":              teamID + "." + bundleID,
			"com.apple.developer.team-identifier": teamID,
			"get-task-allow":                      false,
			"keychain-access-groups":              []string{teamID + ".*"},
		},
		"TeamIdentifier":              []string{teamID},
		"ApplicationIdentifierPrefix": []string{teamID},
		"DeveloperCertificates":       [][]byte{certDER},
		"Platform":                    []string{"iOS"},
		"ExpirationDate":              expiration,
		"CreationDate":                time.Now().Add(-48 * time.Hour),
		"Name":                        "Unit Test Generated Provisioning Profile",
		"UUID":                        "11111111-2222-3333-4444-555555555555",
		"Version":                     1,
	}

	content, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	eci, err := protocol.NewDataEncapsulatedContentInfo(content)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := protocol.NewSignedData(eci)
	if err != nil {
		t.Fatal(err)
	}

	der, err := sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func TestDirProfileProviderProfiles_ExplicitExpiredProvisioningProfile(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	teamID := "TEAMEXPIRED"
	bundleID := "com.example.expired"

	expired := makeTestMobileProvisionData(t, time.Now().Add(-1*time.Hour), teamID, bundleID)
	if err := os.WriteFile(filepath.Join(tmp, "expired.mobileprovision"), expired, 0o644); err != nil {
		t.Fatal(err)
	}

	provider, err := NewDirProfileProvider(fs.DirFS(tmp), ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	fingerprints, err := provider.Profiles(ctx, bundleID, teamID, "", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) != 0 {
		t.Fatalf("expected expired provisioning profile to be ignored, got %d fingerprints", len(fingerprints))
	}

	valid := makeTestMobileProvisionData(t, time.Now().Add(24*time.Hour), teamID, bundleID)
	if err := os.WriteFile(filepath.Join(tmp, "valid.mobileprovision"), valid, 0o644); err != nil {
		t.Fatal(err)
	}

	fingerprints, err = provider.Profiles(ctx, bundleID, teamID, "", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) == 0 {
		t.Fatal("expected non-expired provisioning profile to be returned")
	}
}

func TestDirProfileProviderProfiles_FiltersInjectedProfiles(t *testing.T) {
	provider, err := NewDirProfileProvider(fs.DirFS(t.TempDir()), ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	profileA := testProfile()
	profileB := testProfile()
	profileB.ProfileInfo.Entitlements.Identifier = "OTHER.com.other.app"
	profileB.ProfileInfo.Entitlements.Team = "OTHER"
	profileB.ProfileInfo.Platform = []string{"tvOS"}
	profileB.Sha256 = "sha256-other"

	provider.lock.Lock()
	for fp := range profileA.Fingerprints() {
		provider.profiles[fp] = profileA
	}
	for fp := range profileB.Fingerprints() {
		provider.profiles[fp] = profileB
	}
	provider.lock.Unlock()

	ctx := context.Background()

	matching, err := provider.Profiles(ctx, "com.example.app", "TEAMID", "", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(matching) == 0 {
		t.Fatal("expected matching team/bundle/platform profile")
	}

	noneByBundle, err := provider.Profiles(ctx, "com.unknown.app", "TEAMID", "", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(noneByBundle) != 0 {
		t.Fatal("expected bundle filter to exclude all profiles")
	}

	noneByPlatform, err := provider.Profiles(ctx, "com.example.app", "TEAMID", "", "appletvos")
	if err != nil {
		t.Fatal(err)
	}

	if len(noneByPlatform) != 0 {
		t.Fatal("expected platform filter to exclude mismatched profile")
	}
}

func TestDirProfileProviderProfiles_BundleIDWithoutTeamID(t *testing.T) {
	provider, err := NewDirProfileProvider(fs.DirFS(t.TempDir()), ".", nil)
	if err != nil {
		t.Fatal(err)
	}

	matching := testProfile()
	nonMatching := testProfile()
	nonMatching.ProfileInfo.Entitlements.Identifier = "OTHER.com.other.app"
	nonMatching.ProfileInfo.Entitlements.Team = "OTHER"
	nonMatching.Sha256 = "sha256-non-matching"

	provider.lock.Lock()
	for fp := range matching.Fingerprints() {
		provider.profiles[fp] = matching
	}
	for fp := range nonMatching.Fingerprints() {
		provider.profiles[fp] = nonMatching
	}
	provider.lock.Unlock()

	fingerprints, err := provider.Profiles(context.Background(), "com.example.app", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) == 0 {
		t.Fatal("expected profile to match bundle id using profile team id when team id is empty")
	}
}

func testProfileInfo() ProfileInfo {
	return ProfileInfo{
		Entitlements: ProfileEntitlements{
			Identifier: "TEAMID.com.example.app",
			Team:       "TEAMID",
		},
		Platform:           []string{"iOS", "tvOS", "custom"},
		ProvisionedDevices: []string{"udid-1", "udid-2"},
		ExpirationDate:     time.Now().Add(24 * time.Hour),
	}
}

func testProfile() *Profile {
	cert := &x509.Certificate{Raw: []byte{1, 2, 3, 4}}

	return &Profile{
		ProfileInfo: ProfileInfo{
			Entitlements: ProfileEntitlements{
				Identifier: "TEAMID.com.example.app",
				Team:       "TEAMID",
			},
			Platform:           []string{"iOS"},
			ProvisionedDevices: []string{"udid-1"},
			DeveloperCertificates: Certificates{
				cert,
			},
			ExpirationDate: time.Now().Add(24 * time.Hour),
		},
		Sha1:   "sha1",
		Sha256: "sha256",
	}
}

func TestProfileInfoBehavior(t *testing.T) {
	info := testProfileInfo()

	if info.GetTeamIDPrefix() != "TEAMID" {
		t.Fatal("unexpected app id prefix")
	}

	if info.GetTeamID() != "TEAMID" {
		t.Fatal("unexpected team id")
	}

	if info.GetBundleID() != "com.example.app" {
		t.Fatal("unexpected bundle id")
	}

	if !info.CanSignUDID("udid-1") {
		t.Fatal("expected known udid to be allowed")
	}

	if info.CanSignUDID("unknown") {
		t.Fatal("expected unknown udid to be denied")
	}

	info.ProvisionsAllDevices = true
	if !info.CanSignUDID("unknown") {
		t.Fatal("expected all devices profile to allow unknown udid")
	}

	if !info.CanSignBundleID("com.example.app", "TEAMID") {
		t.Fatal("expected exact bundle id match")
	}

	if info.CanSignBundleID("com.other.app", "TEAMID") {
		t.Fatal("expected non-matching bundle id to fail")
	}

	info.Entitlements.Identifier = "TEAMID.["
	if info.CanSignBundleID("com.example.app", "TEAMID") {
		t.Fatal("expected invalid match pattern to fail")
	}

	info = testProfileInfo()
	if !info.CanSignPlatform("iphoneos") {
		t.Fatal("expected iOS to map to iphoneos")
	}

	if !info.CanSignPlatform("appletvos") {
		t.Fatal("expected tvOS to map to appletvos")
	}

	if !info.CanSignPlatform("custom") {
		t.Fatal("expected custom platform to be matched directly")
	}

	if info.CanSignPlatform("macos") {
		t.Fatal("expected unknown platform to fail")
	}
}

func TestProfileInfoWildcardAndExpiry(t *testing.T) {
	info := ProfileInfo{
		Entitlements: ProfileEntitlements{
			Identifier: "TEAMID.*",
			Team:       "TEAMID",
		},
		ExpirationDate: time.Now().Add(-1 * time.Hour),
	}

	if !info.IsWildcard() {
		t.Fatal("expected wildcard bundle id")
	}

	if !info.IsExpired() {
		t.Fatal("expected expired profile")
	}
}

func TestCertificatesContains(t *testing.T) {
	certA := &x509.Certificate{Raw: []byte{1, 2, 3}}
	certB := &x509.Certificate{Raw: []byte{9, 9, 9}}

	certs := Certificates{certA}

	if !certs.Contains(certA) {
		t.Fatal("expected certificate collection to contain certA")
	}

	if certs.Contains(certB) {
		t.Fatal("expected certificate collection not to contain certB")
	}
}

func TestProfileFingerprintString(t *testing.T) {
	fingerprint := NewProfileFingerprint("TEAM", "sha1", "sha256", "cert")
	str := fingerprint.String()

	if !strings.Contains(str, "TEAM") {
		t.Fatal("expected team id in fingerprint string")
	}

	if !strings.Contains(str, "sha1") || !strings.Contains(str, "sha256") || !strings.Contains(str, "cert") {
		t.Fatal("expected all fingerprint components in string output")
	}
}

func TestSingleProfileProviderBehavior(t *testing.T) {
	provider := &SingleProfileProvider{profile: testProfile()}

	ctx := context.Background()
	fingerprints, err := provider.Profiles(ctx, "com.example.app", "", "udid-1", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(fingerprints) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(fingerprints))
	}

	fingerprint := fingerprints[0]

	profile, ok, err := provider.Profile(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	if !ok || profile == nil {
		t.Fatal("expected profile lookup to succeed")
	}

	cert, ok, err := provider.Certificate(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}

	if !ok || cert == nil {
		t.Fatal("expected certificate lookup to succeed")
	}

	if _, ok, err := provider.Profile(ctx, ProfileFingerprint{}); err != nil || ok {
		t.Fatal("expected unknown fingerprint lookup to fail")
	}

	if _, ok, err := provider.Certificate(ctx, ProfileFingerprint{}); err != nil || ok {
		t.Fatal("expected unknown certificate lookup to fail")
	}

	none, err := provider.Profiles(ctx, "com.example.app", "", "unknown-udid", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(none) != 0 {
		t.Fatal("expected udid mismatch to filter out profile")
	}

	none, err = provider.Profiles(ctx, "com.other.app", "", "udid-1", "iphoneos")
	if err != nil {
		t.Fatal(err)
	}

	if len(none) != 0 {
		t.Fatal("expected bundle id mismatch to filter out profile")
	}
}

type stubProfileProvider struct {
	profilesResult []ProfileFingerprint
	profilesErr    error

	profileResult *Profile
	profileOK     bool
	profileErr    error

	certificateResult *x509.Certificate
	certificateOK     bool
	certificateErr    error
}

func (s stubProfileProvider) Profiles(ctx context.Context, bundleID, teamID, udid, platform string) ([]ProfileFingerprint, error) {
	if s.profilesErr != nil {
		return nil, s.profilesErr
	}

	return append([]ProfileFingerprint(nil), s.profilesResult...), nil
}

func (s stubProfileProvider) Profile(ctx context.Context, fingerprint ProfileFingerprint) (*Profile, bool, error) {
	if s.profileErr != nil {
		return nil, false, s.profileErr
	}

	return s.profileResult, s.profileOK, nil
}

func (s stubProfileProvider) Certificate(ctx context.Context, fingerprint ProfileFingerprint) (*x509.Certificate, bool, error) {
	if s.certificateErr != nil {
		return nil, false, s.certificateErr
	}

	return s.certificateResult, s.certificateOK, nil
}

func TestMultiProfileProviderBehavior(t *testing.T) {
	ctx := context.Background()

	fpA := ProfileFingerprint{Sha1: "a"}
	fpB := ProfileFingerprint{Sha1: "b"}

	aggregated := MultiProfileProvider(
		stubProfileProvider{profilesResult: []ProfileFingerprint{fpA}},
		stubProfileProvider{profilesResult: []ProfileFingerprint{fpB}},
	)

	fingerprints, err := aggregated.Profiles(ctx, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(fingerprints, []ProfileFingerprint{fpA, fpB}) {
		t.Fatal("expected fingerprints to be concatenated")
	}

	expectedProfile := testProfile()
	profileProvider := MultiProfileProvider(
		stubProfileProvider{profileOK: false},
		stubProfileProvider{profileResult: expectedProfile, profileOK: true},
	)

	profile, ok, err := profileProvider.Profile(ctx, ProfileFingerprint{})
	if err != nil {
		t.Fatal(err)
	}

	if !ok || profile != expectedProfile {
		t.Fatal("expected first successful profile result")
	}

	expectedCert := &x509.Certificate{Raw: []byte{9, 9, 9}}
	certProvider := MultiProfileProvider(
		stubProfileProvider{certificateOK: false},
		stubProfileProvider{certificateResult: expectedCert, certificateOK: true},
	)

	cert, ok, err := certProvider.Certificate(ctx, ProfileFingerprint{})
	if err != nil {
		t.Fatal(err)
	}

	if !ok || cert != expectedCert {
		t.Fatal("expected first successful certificate result")
	}

	profilesErr := errors.New("profiles error")
	_, err = MultiProfileProvider(
		stubProfileProvider{profilesErr: profilesErr},
	).Profiles(ctx, "", "", "", "")
	if !errors.Is(err, profilesErr) {
		t.Fatal("expected profiles error to propagate")
	}

	profileErr := errors.New("profile error")
	_, _, err = MultiProfileProvider(
		stubProfileProvider{profileErr: profileErr},
	).Profile(ctx, ProfileFingerprint{})
	if !errors.Is(err, profileErr) {
		t.Fatal("expected profile error to propagate")
	}

	certificateErr := errors.New("certificate error")
	_, _, err = MultiProfileProvider(
		stubProfileProvider{certificateErr: certificateErr},
	).Certificate(ctx, ProfileFingerprint{})
	if !errors.Is(err, certificateErr) {
		t.Fatal("expected certificate error to propagate")
	}
}
