package codesign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"resigner/pkg/codesign/certs"
	"resigner/pkg/fs"
	"resigner/pkg/keychain"
	"resigner/pkg/macho"
	"resigner/pkg/requirements"
)

var ErrCertificateMismatch = fmt.Errorf("certificate mismatch")

type CodeSigner interface {
	SignApp(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error
	SignPath(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error
	SignBinary(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error
}

func Sign(ctx context.Context, logger *zap.Logger, signer CodeSigner, root fs.ReadWriteFS, path string, config SigningConfig) error {
	logger = logger.With(zap.String("path", path))
	logger.Info("Signing")
	var err error
	defer func() { logger.Info("Finished signing", zap.Error(err)) }()

	cleanPath := filepath.Clean(path)
	fileinfo, statErr := root.Stat(cleanPath)
	if statErr != nil {
		return fmt.Errorf("could not stat file: %w", statErr)
	}

	switch {
	case fileinfo.IsDir():
		err = routeDirectorySign(ctx, logger, signer, root, path, fileinfo, config)
	case isIPA(fileinfo.Name()):
		err = SignIPA(ctx, logger, signer, root, path, config)
	default:
		err = signer.SignBinary(ctx, logger, root, path, config)
	}

	return err
}

func isIPA(name string) bool {
	return strings.HasSuffix(name, ".ipa")
}

func isAppBundle(name string) bool {
	return strings.HasSuffix(name, ".app") || strings.HasSuffix(name, ".xctest")
}

func routeDirectorySign(ctx context.Context, logger *zap.Logger, signer CodeSigner, root fs.ReadWriteFS, path string, info os.FileInfo, config SigningConfig) error {
	if isAppBundle(info.Name()) {
		return signer.SignApp(ctx, logger, root, path, config)
	}
	return signer.SignPath(ctx, logger, root, path, config)
}

func SignIPA(ctx context.Context, logger *zap.Logger, signer CodeSigner, root fs.ReadWriteFS, path string, config SigningConfig) error {
	logger = logger.With(zap.String("ipa", path))
	logger.Info("Signing as ipa")
	var err error
	defer func() { logger.Info("Finished signing as ipa", zap.Error(err)) }()

	zipFile, err := root.OpenRW(path)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipFileInfo, err := zipFile.Stat()
	if err != nil {
		return err
	}

	memFS := fs.NewMemFS()
	appBundle, err := UnzipIPA(zipFile, zipFileInfo.Size(), memFS, ".")
	if err != nil {
		return fmt.Errorf("could not unzip IPA: %w", err)
	}

	err = signer.SignApp(ctx, logger, memFS, appBundle, config)
	if err != nil {
		return wrapSigningError(err, config.OnlyVerify)
	}

	if config.OnlyVerify {
		return nil
	}

	return rewriteIPAFile(zipFile, memFS)
}

func wrapSigningError(err error, onlyVerify bool) error {
	if onlyVerify {
		return fmt.Errorf("failed to verify app signature: %w", err)
	}
	return fmt.Errorf("failed to sign app: %w", err)
}

func rewriteIPAFile(target fs.ReadWriteFile, source fs.FS) error {
	if _, err := target.Seek(0, 0); err != nil {
		return fmt.Errorf("could not seek to beginning of zip file: %w", err)
	}
	if err := target.Truncate(0); err != nil {
		return fmt.Errorf("could not truncate zip file: %w", err)
	}
	if err := ZipIPA(source, ".", target); err != nil {
		return fmt.Errorf("could not zip IPA: %w", err)
	}
	return nil
}

type SigningConfig struct {
	normalized bool

	Force      bool
	OnlyVerify bool

	UDID string

	BundleVersion string

	BundleID    string
	BundleIDMap map[string]string

	TeamID       string
	TeamIDPrefix string
	Platform     string

	PreserveRequirements bool
	Requirements         requirements.Requirements

	PreserveEntitlements bool
	Entitlements         macho.Entitlements

	ProfileProvider    ProfileProvider
	ProfileFingerprint *ProfileFingerprint
	Profile            *Profile

	CodeResources *CodeResources

	Keychain keychain.Keychain

	Key      crypto.Signer
	Cert     *x509.Certificate
	CertOpts x509.VerifyOptions

	Chain []*x509.Certificate
}

func (c *SigningConfig) Normalize(ctx context.Context, logger *zap.Logger, bundleID, teamID, platform string) error {
	if c.normalized || c.OnlyVerify {
		return nil
	}

	logger.Debug("Normalizing signing config", zap.String("udid", c.UDID))
	defer func() { logger.Debug("Finished normalizing signing config") }()

	c.applyBundleIDAndPlatform(logger, bundleID, platform)

	if err := c.resolveProfileIdentity(ctx, logger); err != nil {
		return err
	}

	if err := c.resolveCertificate(ctx, logger); err != nil {
		return err
	}

	if err := c.resolveKey(ctx, logger); err != nil {
		return err
	}

	if c.Key == nil {
		logger.Debug("Could not choose key")
		return fmt.Errorf("insufficient information to choose signing key")
	}

	if c.Cert == nil {
		logger.Debug("Could not choose certificate")
		return fmt.Errorf("insufficient information to choose signing cert")
	}

	c.Cert.UnhandledCriticalExtensions = nil                                       // go doesn't understand some apple-specific cert extensions
	c.CertOpts.KeyUsages = append(c.Cert.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) // need to enable codesigning usage

	if err := c.ensureTrustStores(); err != nil {
		return err
	}

	if err := c.ensureChain(logger); err != nil {
		return err
	}

	if c.Requirements == nil {
		c.Requirements = DefaultRequirements(c.BundleID, c.Cert.Subject.CommonName)
	}

	if err := c.attachProfileFromFingerprint(ctx, logger); err != nil {
		return err
	}

	if c.TeamIDPrefix == "" {
		logger.Debug("Assuming TeamID == TeamIDPrefix")
		c.TeamIDPrefix = c.TeamID
	}

	c.normalized = true

	c.logChosenIdentity(logger)

	return nil
}

func (c *SigningConfig) applyBundleIDAndPlatform(logger *zap.Logger, bundleID, platform string) {
	if c.BundleID == "" {
		logger.Debug("Reusing bundle ID", zap.String("bundleID", bundleID))
		c.BundleID = bundleID
	} else {
		logger.Debug("Using bundle ID", zap.String("bundleID", c.BundleID))
	}

	if c.Platform == "" {
		logger.Debug("Reusing platform", zap.String("platform", platform))
		c.Platform = platform
	} else {
		logger.Debug("Using platform", zap.String("platform", c.Platform))
	}
}

func (c *SigningConfig) resolveProfileIdentity(ctx context.Context, logger *zap.Logger) error {
	if c.Profile != nil {
		logger.Debug("Using profile", zap.String("profile", c.Profile.Name))
		c.TeamID = c.Profile.GetTeamID()
		return nil
	}

	if c.ProfileProvider == nil || c.ProfileFingerprint != nil || c.Profile != nil {
		return nil
	}

	logger.Debug("Using profile provider",
		zap.String("bundleID", c.BundleID),
		zap.String("teamID", c.TeamID),
		zap.String("udid", c.UDID),
		zap.String("platform", c.Platform),
	)

	fingerprints, err := c.ProfileProvider.Profiles(ctx, c.BundleID, c.TeamID, c.UDID, c.Platform)
	if err != nil {
		return err
	}

	for _, fingerprint := range fingerprints {
		matched, err := c.tryUseFingerprint(ctx, logger, fingerprint)
		if err != nil {
			return err
		}
		if matched {
			return nil
		}
	}

	logger.Debug("Could not find signing identity")
	return fmt.Errorf("unable to find usable provisioning profile for %s.%s", c.TeamID, c.BundleID)
}

func (c *SigningConfig) tryUseFingerprint(ctx context.Context, logger *zap.Logger, fingerprint ProfileFingerprint) (bool, error) {
	logger.Debug("Trying profile", zap.Stringer("fingerprint", fingerprint))

	cert, ok, err := c.ProfileProvider.Certificate(ctx, fingerprint)
	if err != nil {
		logger.Debug("Could not get certificate for profile", zap.Stringer("fingerprint", fingerprint), zap.Error(err))
		return false, fmt.Errorf("could not get certificate: %w", err)
	}
	if !ok {
		logger.Debug("Could not find certificate for profile", zap.Stringer("fingerprint", fingerprint))
		return false, nil
	}

	logger.Debug("Found certificate", zap.String("certificate", cert.Subject.CommonName))

	ok, err = c.acceptCertificateForKey(ctx, logger, cert)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	c.ProfileFingerprint = &fingerprint
	c.TeamID = fingerprint.TeamID
	c.Cert = cert

	logger.Debug("Found signing identity",
		zap.Stringer("fingerprint", fingerprint),
		zap.String("certificate", cert.Subject.CommonName),
		zap.String("teamID", fingerprint.TeamID),
	)

	return true, nil
}

func (c *SigningConfig) acceptCertificateForKey(ctx context.Context, logger *zap.Logger, cert *x509.Certificate) (bool, error) {
	if c.Key == nil && c.Keychain != nil {
		logger.Debug("Trying to find key for certificate", zap.String("certificate", cert.Subject.CommonName))
		key, ok, err := keychain.KeyForCert(ctx, c.Keychain, cert)
		if err != nil {
			logger.Debug("Could not get key for certificate", zap.String("certificate", cert.Subject.CommonName), zap.Error(err))
			return false, fmt.Errorf("could not get key: %w", err)
		}
		if !ok {
			logger.Debug("Could not find key for certificate", zap.String("certificate", cert.Subject.CommonName))
			return false, nil
		}
		c.Key = key
		logger.Debug("Found key for certificate", zap.String("certificate", cert.Subject.CommonName))
		return true, nil
	}

	if c.Key == nil {
		return true, nil
	}

	if !publicKeysMatch(cert.PublicKey, c.Key.Public()) {
		logger.Debug("Skipping invalid key for certificate", zap.String("certificate", cert.Subject.CommonName))
		return false, nil
	}

	logger.Debug("Found key for certificate", zap.String("certificate", cert.Subject.CommonName))
	return true, nil
}

func publicKeysMatch(certKey interface{}, signerKey interface{}) bool {
	switch pkey := certKey.(type) {
	case *rsa.PublicKey:
		candidate, ok := signerKey.(*rsa.PublicKey)
		return ok && pkey.Equal(candidate)
	case *ecdsa.PublicKey:
		candidate, ok := signerKey.(*ecdsa.PublicKey)
		return ok && pkey.Equal(candidate)
	default:
		return false
	}
}

func (c *SigningConfig) resolveCertificate(ctx context.Context, logger *zap.Logger) error {
	if c.Cert != nil {
		return nil
	}

	if c.Profile != nil && c.Key != nil {
		for _, cert := range c.Profile.DeveloperCertificates {
			if !publicKeysMatch(cert.PublicKey, c.Key.Public()) {
				logger.Debug("Skipping invalid key for certificate", zap.String("certificate", cert.Subject.CommonName))
				continue
			}

			logger.Debug("Found key for certificate", zap.String("certificate", cert.Subject.CommonName))
			c.Cert = cert
			return nil
		}
	}

	if c.ProfileFingerprint != nil && c.ProfileProvider != nil {
		cert, ok, err := c.ProfileProvider.Certificate(ctx, *c.ProfileFingerprint)
		if err != nil {
			logger.Debug("Could not get certificate for profile", zap.Stringer("fingerprint", *c.ProfileFingerprint), zap.Error(err))
			return fmt.Errorf("could not get certificate: %w", err)
		}
		if !ok {
			logger.Debug("Could not find certificate for profile", zap.Stringer("fingerprint", *c.ProfileFingerprint))
			return fmt.Errorf("no certificates found for provisioning profile %s", c.ProfileFingerprint.Sha256)
		}

		logger.Debug("Found certificate", zap.String("certificate", cert.Subject.CommonName))
		c.Cert = cert
	}

	return nil
}

func (c *SigningConfig) resolveKey(ctx context.Context, logger *zap.Logger) error {
	if c.Key != nil || c.Cert == nil || c.Keychain == nil {
		return nil
	}

	key, ok, err := keychain.KeyForCert(ctx, c.Keychain, c.Cert)
	if err != nil {
		logger.Debug("Could not get key for certificate", zap.String("certificate", c.Cert.Subject.CommonName), zap.Error(err))
		return fmt.Errorf("could not get key: %w", err)
	}
	if !ok {
		logger.Debug("Could not find key for certificate", zap.String("certificate", c.Cert.Subject.CommonName))
		return fmt.Errorf("could not find key in keychain")
	}

	logger.Debug("Found key for certificate", zap.String("certificate", c.Cert.Subject.CommonName))
	c.Key = key
	return nil
}

func (c *SigningConfig) ensureTrustStores() error {
	if c.CertOpts.Roots == nil {
		rootPool, err := certs.RootPool()
		if err != nil {
			return err
		}
		c.CertOpts.Roots = rootPool
	}

	if c.CertOpts.Intermediates == nil {
		intermediatePool, err := certs.IntermediatePool()
		if err != nil {
			return err
		}
		c.CertOpts.Intermediates = intermediatePool
	}

	return nil
}

func (c *SigningConfig) ensureChain(logger *zap.Logger) error {
	if c.Chain != nil {
		return nil
	}

	chains, err := c.Cert.Verify(c.CertOpts)
	if err != nil {
		logger.Debug("Could not create trust chain for cert", zap.String("certificate", c.Cert.Subject.CommonName))
		return fmt.Errorf("could not create trust chain for certificate: %w", err)
	}

	c.Chain = chains[0]
	return nil
}

func (c *SigningConfig) attachProfileFromFingerprint(ctx context.Context, logger *zap.Logger) error {
	if c.Profile != nil || c.ProfileFingerprint == nil || c.ProfileProvider == nil {
		return nil
	}

	profile, ok, err := c.ProfileProvider.Profile(ctx, *c.ProfileFingerprint)
	if err != nil {
		logger.Debug("Could not get profile", zap.Stringer("fingerprint", *c.ProfileFingerprint), zap.Error(err))
		return fmt.Errorf("could not get profile: %w", err)
	}
	if !ok {
		logger.Debug("Could not find profile", zap.Stringer("fingerprint", *c.ProfileFingerprint))
		return fmt.Errorf("could not find profile for given fingerprint %x", c.ProfileFingerprint.Sha256)
	}

	c.Profile = profile
	c.TeamIDPrefix = profile.GetTeamIDPrefix()
	return nil
}

func (c *SigningConfig) logChosenIdentity(logger *zap.Logger) {
	if c.Profile != nil {
		logger.Debug("Chose signing identity",
			zap.String("profile", c.Profile.Name),
			zap.String("certificate", c.Cert.Subject.CommonName),
			zap.String("teamID", c.TeamID),
			zap.String("bundleID", c.BundleID),
		)
		return
	}

	if c.ProfileFingerprint != nil {
		logger.Debug("Chose signing identity",
			zap.Stringer("fingerprint", *c.ProfileFingerprint),
			zap.String("certificate", c.Cert.Subject.CommonName),
			zap.String("teamID", c.TeamID),
			zap.String("bundleID", c.BundleID),
		)
		return
	}

	logger.Debug("Chose signing identity",
		zap.String("certificate", c.Cert.Subject.CommonName),
		zap.String("teamID", c.TeamID),
		zap.String("bundleID", c.BundleID),
	)
}
