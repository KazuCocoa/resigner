package codesign

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"strings"

	"go.uber.org/zap"
	"resigner/pkg/fs"
	"resigner/pkg/keychain"

	sha256Simd "github.com/minio/sha256-simd"

	"github.com/github/smimesign/ietf-cms/protocol"
	"howett.net/plist"
)

// SpecParseError is returned when a spec string cannot be parsed.
type SpecParseError struct {
	Spec string
	Err  error
}

func (e *SpecParseError) Error() string {
	return fmt.Sprintf("error while parsing %q: %v", e.Spec, e.Err)
}

func (e *SpecParseError) Unwrap() error { return e.Err }

// ProfileParserFunc is the function signature for profile provider spec handlers.
type ProfileParserFunc func(ctx context.Context, logger *zap.Logger, prefix, rest string) (ProfileProvider, error)

type ProfileProviderSpecParser struct {
	prefixes []string
	fns      []ProfileParserFunc
}

func (p *ProfileProviderSpecParser) Register(prefix string, fn ProfileParserFunc) {
	p.prefixes = append(p.prefixes, prefix)
	p.fns = append(p.fns, fn)
}

func (p *ProfileProviderSpecParser) Parse(ctx context.Context, logger *zap.Logger, specs ...string) (ProfileProvider, error) {
	providers := make([]ProfileProvider, 0, len(specs))
	for _, spec := range specs {
		provider, err := p.parse(ctx, logger, spec)
		if err != nil {
			return nil, fmt.Errorf("could not parse profile provider spec %q: %w", spec, err)
		}
		providers = append(providers, provider)
	}
	return MultiProfileProvider(providers...), nil
}

func (p *ProfileProviderSpecParser) parse(ctx context.Context, logger *zap.Logger, spec string) (ProfileProvider, error) {
	best, bestLen := -1, -1
	for i, prefix := range p.prefixes {
		if strings.HasPrefix(spec, prefix) && len(prefix) > bestLen {
			best, bestLen = i, len(prefix)
		}
	}
	if best < 0 {
		return nil, &SpecParseError{Spec: spec, Err: fmt.Errorf("invalid syntax")}
	}
	ret, err := p.fns[best](ctx, logger, spec[:bestLen], spec[bestLen:])
	if err != nil {
		return nil, &SpecParseError{Spec: spec, Err: err}
	}
	return ret, nil
}

func ParseEmptyProfileProviderSpec(ctx context.Context, logger *zap.Logger, prefix, args string) (ProfileProvider, error) {
	return MultiProfileProvider(), nil
}

func ParseFileProfileProviderSpec(ctx context.Context, logger *zap.Logger, prefix, args string) (ProfileProvider, error) {
	path, err := expandHomePath(args)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if stat.IsDir() {
		return NewDirProfileProvider(fs.DirFS(path), ".", nil)
	}

	profileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read provisioning profile: %w", err)
	}

	return NewSingleProfileProvider(profileData)
}

func expandHomePath(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dirname, path[2:]), nil
}

const BundleIDWildcard = "*"

type Profile struct {
	ProfileInfo
	Raw          []byte
	Sha256       string
	Sha1         string
	lazyOnce     sync.Once
	fingerprints map[ProfileFingerprint]bool
	certificates map[string]*x509.Certificate
}

func ParseProfile(data []byte) (*Profile, error) {
	profile := Profile{
		Raw: append(make([]byte, 0, len(data)), data...),
	}

	ci, err := protocol.ParseContentInfo(data)
	if err != nil {
		return nil, err
	}
	signedData, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}

	content, err := signedData.EncapContentInfo.EContentValue()
	if err != nil {
		return nil, err
	}

	_, err = plist.Unmarshal(content, &profile.ProfileInfo)
	if err != nil {
		return nil, err
	}

	hsh1 := sha1.New()

	hsh1.Write(profile.Raw)
	profile.Sha1 = hex.EncodeToString(hsh1.Sum(nil))

	hsh256 := sha256Simd.New()
	hsh256.Write(profile.Raw)
	profile.Sha256 = hex.EncodeToString(hsh256.Sum(nil))

	return &profile, nil
}

func (p *Profile) setup() {
	p.certificates = make(map[string]*x509.Certificate)
	p.fingerprints = make(map[ProfileFingerprint]bool)

	teamID := p.GetTeamID()

	for _, cert := range p.DeveloperCertificates {
		certFingerprint := keychain.CertificateFingerprint(cert)
		p.certificates[certFingerprint] = cert
		p.fingerprints[NewProfileFingerprint(
			teamID,
			p.Sha1,
			p.Sha256,
			certFingerprint,
		)] = true
	}
}

func (p *Profile) Certificate(fingerprint string) (*x509.Certificate, bool) {
	p.lazyOnce.Do(p.setup)

	cert, ok := p.certificates[fingerprint]
	return cert, ok
}

func (p *Profile) Fingerprints() map[ProfileFingerprint]bool {
	p.lazyOnce.Do(p.setup)

	return p.fingerprints
}

type ProfileInfo struct {
	AppIDName                   string              `plist:"AppIDName,omitempty"`
	ApplicationIdentifierPrefix []string            `plist:"ApplicationIdentifierPrefix,omitempty"`
	CreationDate                time.Time           `plist:"CreationDate,omitempty"`
	Platform                    []string            `plist:"Platform,omitempty"`
	IsXcodeManaged              bool                `plist:"IsXcodeManaged,omitempty"`
	DeveloperCertificates       Certificates        `plist:"DeveloperCertificates,omitempty"`
	Entitlements                ProfileEntitlements `plist:"Entitlements,omitempty"`
	ExpirationDate              time.Time           `plist:"ExpirationDate,omitempty"`
	Name                        string              `plist:"Name,omitempty"`
	ProvisionedDevices          []string            `plist:"ProvisionedDevices,omitempty"`
	ProvisionsAllDevices        bool                `plist:"ProvisionsAllDevices,omitempty"`
	TeamIdentifier              []string            `plist:"TeamIdentifier,omitempty"`
	TeamName                    string              `plist:"TeamName,omitempty"`
	TimeToLive                  int                 `plist:"TimeToLive,omitempty"`
	UUID                        string              `plist:"UUID,omitempty"`
	Version                     int                 `plist:"Version,omitempty"`

	udidLookup     map[string]bool
	platformLookup map[string]bool
}

func (p *ProfileInfo) IsWildcard() bool {
	return p.GetBundleID() == BundleIDWildcard
}

func (p *ProfileInfo) IsExpired() bool {
	return time.Now().After(p.ExpirationDate)
}

func (p *ProfileInfo) CanSignUDID(udid string) bool {
	if p.udidLookup == nil {
		p.udidLookup = make(map[string]bool)
		for _, udid := range p.ProvisionedDevices {
			p.udidLookup[udid] = true
		}
	}

	return p.ProvisionsAllDevices || p.udidLookup[udid]
}

func (p *ProfileInfo) GetTeamIDPrefix() string {
	return strings.SplitN(p.Entitlements.Identifier, ".", 2)[0]
}

func (p *ProfileInfo) GetTeamID() string {
	return p.Entitlements.Team
}

func (p *ProfileInfo) GetBundleID() string {
	return strings.TrimPrefix(p.Entitlements.Identifier, p.GetTeamIDPrefix()+".")
}

func (p *ProfileInfo) CanSignBundleID(bundleID, teamID string) bool {
	ok, err := filepath.Match(p.Entitlements.Identifier, fmt.Sprintf("%s.%s", teamID, bundleID))
	if err != nil {
		return false
	}

	return ok
}

func (p *ProfileInfo) CanSignPlatform(dtPlatform string) bool {
	if p.platformLookup == nil {
		p.platformLookup = make(map[string]bool)

		for _, platform := range p.Platform {
			switch platform {
			case "iOS":
				p.platformLookup["iphoneos"] = true
			case "tvOS":
				p.platformLookup["appletvos"] = true
			default:
				p.platformLookup[platform] = true
			}
		}
	}

	return p.platformLookup[dtPlatform]
}

type Certificates []*x509.Certificate

func (c *Certificates) Contains(target *x509.Certificate) bool {
	for _, cert := range *c {
		if cert.Equal(target) {
			return true
		}
	}

	return false
}

func (c *Certificates) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var rawCerts [][]byte
	err := unmarshal(&rawCerts)
	if err != nil {
		return err
	}

	*c = make([]*x509.Certificate, 0, len(rawCerts))

	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}

		*c = append(*c, cert)
	}

	return nil
}

type ProfileEntitlements struct {
	Groups       []string `plist:"keychain-access-groups,omitempty"`
	Team         string   `plist:"com.apple.developer.team-identifier,omitempty"`
	Identifier   string   `plist:"application-identifier,omitempty"`
	GetTaskAllow bool     `plist:"get-task-allow,omitempty"`
}

type ProfileFingerprint struct {
	TeamID                 string `json:"team_id"`
	Sha1                   string `json:"sha_1"`
	Sha256                 string `json:"sha_256"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

func (f ProfileFingerprint) String() string {
	return fmt.Sprintf("%40s:%64s:%64s:%s", f.Sha1, f.Sha256, f.CertificateFingerprint, f.TeamID)
}

func NewProfileFingerprint(teamID, sha1, sha256, certFingerprint string) ProfileFingerprint {
	return ProfileFingerprint{
		TeamID:                 teamID,
		Sha1:                   sha1,
		Sha256:                 sha256,
		CertificateFingerprint: certFingerprint,
	}
}

type ProfileProvider interface {
	Profiles(ctx context.Context, teamID, bundleID, udid, platform string) ([]ProfileFingerprint, error)
	Profile(ctx context.Context, fingerprint ProfileFingerprint) (*Profile, bool, error)

	Certificate(ctx context.Context, fingerprint ProfileFingerprint) (*x509.Certificate, bool, error)
}

type DirProfileProvider struct {
	fs        fs.FS
	dir       string
	predicate func(*Profile) bool

	lock         sync.RWMutex
	profiles     map[ProfileFingerprint]*Profile
	seenProfiles map[string]time.Time
}

func NewDirProfileProvider(f fs.FS, dir string, predicate func(*Profile) bool) (*DirProfileProvider, error) {
	return &DirProfileProvider{
		fs:           f,
		dir:          dir,
		predicate:    predicate,
		profiles:     make(map[ProfileFingerprint]*Profile),
		seenProfiles: make(map[string]time.Time),
	}, nil
}

func (p *DirProfileProvider) Profiles(ctx context.Context, bundleID, teamID, udid, platform string) ([]ProfileFingerprint, error) {
	err := fs.WalkDir(p.fs, p.dir, func(path string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !isProfileFile(dirEntry, path) {
			return nil
		}

		fileInfo, err := dirEntry.Info()
		if err != nil {
			return err
		}

		if !p.shouldRefreshProfile(path, fileInfo.ModTime()) {
			return nil
		}

		profile, err := p.loadProfile(path)
		if err != nil {
			return err
		}

		if p.shouldSkipLoadedProfile(profile, udid) {
			return nil
		}

		p.storeProfile(profile)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return p.filteredFingerprints(bundleID, teamID, platform), nil
}

func isProfileFile(dirEntry fs.DirEntry, path string) bool {
	if dirEntry.IsDir() {
		return false
	}

	return strings.HasSuffix(path, "provision")
}

func (p *DirProfileProvider) shouldRefreshProfile(path string, modTime time.Time) bool {
	p.lock.Lock()
	defer p.lock.Unlock()

	if !modTime.After(p.seenProfiles[path]) {
		return false
	}

	p.seenProfiles[path] = modTime
	return true
}

func (p *DirProfileProvider) loadProfile(path string) (*Profile, error) {
	profileData, err := fs.ReadFile(p.fs, path)
	if err != nil {
		return nil, err
	}

	return ParseProfile(profileData)
}

func (p *DirProfileProvider) shouldSkipLoadedProfile(profile *Profile, udid string) bool {
	if profile.IsExpired() {
		return true
	}

	if p.predicate != nil && !p.predicate(profile) {
		return true
	}

	if udid != "" && !profile.CanSignUDID(udid) {
		return true
	}

	return false
}

func (p *DirProfileProvider) storeProfile(profile *Profile) {
	p.lock.Lock()
	defer p.lock.Unlock()

	for fingerprint := range profile.Fingerprints() {
		p.profiles[fingerprint] = profile
	}
}

func (p *DirProfileProvider) filteredFingerprints(bundleID, teamID, platform string) []ProfileFingerprint {
	checkedProfiles := make(map[string]bool)
	fingerprints := make([]ProfileFingerprint, 0, len(p.profiles))

	for _, profile := range p.profiles {
		if checkedProfiles[profile.Sha256] {
			continue
		}

		checkedProfiles[profile.Sha256] = true

		if !matchesBundleAndTeam(profile, bundleID, teamID) {
			continue
		}

		if platform != "" && !profile.CanSignPlatform(platform) {
			continue
		}

		for fingerprint := range profile.Fingerprints() {
			fingerprints = append(fingerprints, fingerprint)
		}
	}

	return fingerprints
}

func matchesBundleAndTeam(profile *Profile, bundleID, teamID string) bool {
	if bundleID == "" {
		return true
	}

	teams := teamID
	if teams == "" {
		teams = profile.GetTeamID()
	}

	return profile.CanSignBundleID(bundleID, teams)
}

func (p *DirProfileProvider) Profile(ctx context.Context, fingerprint ProfileFingerprint) (*Profile, bool, error) {
	p.lock.RLock()
	profile, ok := p.profiles[fingerprint]
	defer p.lock.RUnlock()

	if !ok {
		return nil, false, nil
	}

	return profile, true, nil
}

func (p *DirProfileProvider) Certificate(ctx context.Context, fingerprint ProfileFingerprint) (*x509.Certificate, bool, error) {
	p.lock.RLock()
	profile, ok := p.profiles[fingerprint]
	defer p.lock.RUnlock()

	if !ok {
		return nil, false, nil
	}

	cert, ok := profile.Certificate(fingerprint.CertificateFingerprint)
	if !ok {
		return nil, false, nil
	}

	return cert, true, nil
}

type SingleProfileProvider struct {
	profile *Profile
}

var _ ProfileProvider

func NewSingleProfileProvider(data []byte) (*SingleProfileProvider, error) {
	profile, err := ParseProfile(data)
	if err != nil {
		return nil, err
	}

	return &SingleProfileProvider{profile: profile}, nil
}

func (p *SingleProfileProvider) Profiles(ctx context.Context, bundleID, teamID, udid, platform string) ([]ProfileFingerprint, error) {
	if udid != "" && !p.profile.CanSignUDID(udid) {
		return nil, nil
	}

	if bundleID != "" {
		if teamID == "" {
			if !p.profile.CanSignBundleID(bundleID, p.profile.GetTeamID()) {
				return nil, nil
			}
		} else {
			if !p.profile.CanSignBundleID(bundleID, teamID) {
				return nil, nil
			}
		}

		if platform != "" {
			if !p.profile.CanSignPlatform(platform) {
				return nil, nil
			}
		}
	}

	fingerprints := make([]ProfileFingerprint, 0, len(p.profile.Fingerprints()))

	for fingerprint := range p.profile.Fingerprints() {
		fingerprints = append(fingerprints, fingerprint)
	}

	return fingerprints, nil
}

func (p *SingleProfileProvider) Profile(ctx context.Context, fingerprint ProfileFingerprint) (*Profile, bool, error) {
	if !p.profile.Fingerprints()[fingerprint] {
		return nil, false, nil
	}

	return p.profile, true, nil
}

func (p *SingleProfileProvider) Certificate(ctx context.Context, fingerprint ProfileFingerprint) (*x509.Certificate, bool, error) {
	if !p.profile.Fingerprints()[fingerprint] {
		return nil, false, nil
	}

	cert, ok := p.profile.certificates[fingerprint.CertificateFingerprint]
	if !ok {
		return nil, false, nil
	}

	return cert, true, nil
}

func MultiProfileProvider(providers ...ProfileProvider) ProfileProvider {
	return multiProfileProvider(providers)
}

type multiProfileProvider []ProfileProvider

func (p multiProfileProvider) Profiles(ctx context.Context, bundleID, teamID, udid, platform string) ([]ProfileFingerprint, error) {
	var fingerprints []ProfileFingerprint

	for _, provider := range p {
		providerFingerprints, err := provider.Profiles(ctx, bundleID, teamID, udid, platform)
		if err != nil {
			return nil, err
		}

		fingerprints = append(fingerprints, providerFingerprints...)
	}

	return fingerprints, nil
}

func (p multiProfileProvider) Profile(ctx context.Context, fingerprint ProfileFingerprint) (*Profile, bool, error) {
	for _, provider := range p {
		profile, ok, err := provider.Profile(ctx, fingerprint)
		if err != nil {
			return nil, false, err
		}

		if !ok {
			continue
		}

		return profile, true, nil
	}

	return nil, false, nil
}

func (p multiProfileProvider) Certificate(ctx context.Context, fingerprint ProfileFingerprint) (*x509.Certificate, bool, error) {
	for _, provider := range p {
		cert, ok, err := provider.Certificate(ctx, fingerprint)
		if err != nil {
			return nil, false, err
		}

		if !ok {
			continue
		}

		return cert, true, nil
	}

	return nil, false, nil
}
