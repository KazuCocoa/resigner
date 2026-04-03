package codesign

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	stdfs "io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"resigner/pkg/fs"
	"resigner/pkg/macho"
	"go.uber.org/zap"
	"howett.net/plist"
)

const (
	EmbeddedProfileName = "embedded.mobileprovision"
)

var ErrInvalidSignature = errors.New("invalid signature")

type NativeCodeSigner struct{}

func NewNativeCodeSigner() (*NativeCodeSigner, error) {
	return &NativeCodeSigner{}, nil
}

// SignBinary signs a mach-o binary file
func (s *NativeCodeSigner) SignBinary(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	logger = logger.With(zap.String("binary", path))
	logger.Info("Signing as binary")
	var err error
	defer func() { logger.Info("Finished signing as binary", zap.Error(err)) }()

	err = func() error {
		binFile, err := root.OpenRW(path)
		if err != nil {
			return err
		}
		defer binFile.Close()

		bin, err := macho.Parse(binFile, 0)
		if err != nil {
			return err
		}

		sigInfo := extractSignatureInfoFromBinary(bin, &config)

		if !sigInfo.NeedsResign && sigInfo.WasSignedWithProfile {
			logger.Info("Binary does not need resigning")
			return nil
		}

		if config.OnlyVerify {
			return ErrInvalidSignature
		}

		err = config.Normalize(ctx, logger, sigInfo.BundleID, sigInfo.TeamID, config.Platform)
		if err != nil {
			return fmt.Errorf("could not normalize signing config: %w", err)
		}

		infoData := sigInfo.InfoPlist

		err = bin.Sign(config.Key, config.Chain, config.Entitlements, config.Requirements, func(val macho.Struct, visit func() error) error {
			switch val := val.(type) {
			case *macho.CodeSignatureCodeDirectoryBlob:
				updateCodeDirectoryIdentifiers(val, &config, sigInfo.BundleID)
				if infoData != nil {
					hsh := val.HashType.New()
					_, err := hsh.Write(infoData)
					if err != nil {
						return err
					}
					val.Hashes[-int(macho.CodeSignatureSlotKindInfo)] = hsh.Sum(nil)
				}
			}
			return visit()
		})
		if err != nil {
			return fmt.Errorf("could not sign binary: %w", err)
		}

		return encodeAndWriteExecutable(binFile, bin)
	}()

	return err
}

func extractSignatureInfoFromBinary(bin macho.Binary, config *SigningConfig) signatureInfoResult {
	result := signatureInfoResult{NeedsResign: true}

	bin.Visit(func(val macho.Struct, visit func() error) error {
		switch val := val.(type) {
		case *macho.Section64:
			if isBinaryInfoPlistSection(string(val.SegName[:]), string(val.SectName[:])) {
				result.InfoPlist = val.Data
			}
		case *macho.Section32:
			if isBinaryInfoPlistSection(string(val.SegName[:]), string(val.SectName[:])) {
				result.InfoPlist = val.Data
			}
		case *macho.CodeSignatureCodeDirectoryBlob:
			result.BundleID = val.Identifier
			result.TeamID = val.TeamID
		case *macho.CodeSignatureEntitlementsBlob:
			if config.PreserveEntitlements {
				config.Entitlements = val.Entitlements
			}
		case *macho.CodeSignatureRequirementsBlob:
			if config.PreserveRequirements {
				config.Requirements = val.Requirements
			}
		case *macho.CodeSignatureCMSSignatureBlob:
			if checkSignatureMatchesProfile(val, config) {
				result.WasSignedWithProfile = true
				result.NeedsResign = false
			}
		}
		return visit()
	})

	return result
}

type signatureInfoResult struct {
	BundleID              string
	TeamID                string
	InfoPlist             macho.Data
	NeedsResign           bool
	WasSignedWithProfile  bool
}

func isBinaryInfoPlistSection(segmentName, sectionName string) bool {
	return strings.Trim(segmentName, "\x00") == "__TEXT" &&
		strings.Trim(sectionName, "\x00") == "__info_plist"
}

func checkSignatureMatchesProfile(sig *macho.CodeSignatureCMSSignatureBlob, config *SigningConfig) bool {
	if config.Profile == nil || sig.SignedData == nil {
		return false
	}
	certs, err := sig.SignedData.X509Certificates()
	if err != nil {
		return false
	}
	return len(certs) > 0 && config.Profile.DeveloperCertificates.Contains(certs[len(certs)-1])
}

func updateCodeDirectoryIdentifiers(blob *macho.CodeSignatureCodeDirectoryBlob, config *SigningConfig, originalBundleID string) {
	if config.BundleID != "" {
		blob.Identifier = config.BundleID
	} else if config.BundleIDMap[originalBundleID] != "" {
		blob.Identifier = config.BundleIDMap[originalBundleID]
	}

	if config.TeamID != "" {
		blob.TeamID = config.TeamID
	}
}

func encodeAndWriteExecutable(file fs.ReadWriteFile, executable macho.Binary) error {
	_, err := file.Seek(0, 0)
	if err != nil {
		return err
	}

	err = file.Truncate(0)
	if err != nil {
		return err
	}

	err = executable.Encode(file, 0, func(_ macho.Struct, encode func() error) error {
		return encode()
	})
	return err
}


func readInfo(root fs.ReadWriteFS, path string, config SigningConfig) ([]byte, InfoPlist, map[string]interface{}, error) {
	infoFile, err := root.Open(filepath.Join(path, "Info.plist"))
	if err != nil {
		return nil, InfoPlist{}, nil, err
	}
	defer infoFile.Close()

	infoData, err := io.ReadAll(infoFile)
	if err != nil {
		return nil, InfoPlist{}, nil, err
	}

	var info InfoPlist
	_, err = plist.Unmarshal(infoData, &info)
	if err != nil {
		return nil, InfoPlist{}, nil, err
	}

	var rawInfo map[string]interface{}
	_, err = plist.Unmarshal(infoData, &rawInfo)
	if err != nil {
		return nil, InfoPlist{}, nil, err
	}

	return infoData, info, rawInfo, nil
}

func writeInfo(root fs.ReadWriteFS, path string, info InfoPlist, rawInfo map[string]interface{}) ([]byte, error) {
	rawInfo["CFBundleVersion"] = info.BundleVersion
	rawInfo["CFBundleIdentifier"] = info.BundleIdentifier
	rawInfo["CFBundleExecutable"] = info.BundleExecutable
	rawInfo["DTPlatformName"] = info.PlatformName

	infoFile, err := root.OpenRW(filepath.Join(path, "Info.plist"))
	if err != nil {
		return nil, err
	}
	defer infoFile.Close()

	infoData, err := plist.Marshal(rawInfo, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}

	_, err = infoFile.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	err = infoFile.Truncate(0)
	if err != nil {
		return nil, err
	}

	_, err = infoFile.Write(infoData)
	if err != nil {
		return nil, err
	}

	return infoData, nil
}

func writeResources(root fs.ReadWriteFS, path string, config SigningConfig) ([]byte, error) {
	err := root.Mkdir(filepath.Join(path, "_CodeSignature"))
	if err != nil && !errors.Is(err, stdfs.ErrExist) {
		return nil, err
	}

	resourcesData, err := plist.MarshalIndent(config.CodeResources, plist.XMLFormat, "  ")
	if err != nil {
		return nil, err
	}

	resoursesFile, err := root.CreateRW(filepath.Join(path, "_CodeSignature", "CodeResources"))
	if err != nil {
		return nil, err
	}
	defer resoursesFile.Close()

	_, err = resoursesFile.Write(resourcesData)
	if err != nil {
		return nil, err
	}

	return resourcesData, err
}

func (c *NativeCodeSigner) SignPath(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	logger = logger.With(zap.String("path", path))
	logger.Info("Signing as path")
	var err error
	defer func() { logger.Info("Finished signing as path", zap.Error(err)) }()

	err = func() error {
		infoData, info, rawInfo, err := readInfo(root, path, config)
		if err != nil {
			return err
		}

		executableFile, err := root.OpenRW(filepath.Join(path, info.BundleExecutable))
		if err != nil {
			return err
		}
		defer executableFile.Close()

		executable, err := macho.Parse(executableFile, 0)
		if err != nil {
			return err
		}

		var needsResign bool = true
		var bundleID, teamID string

		// Extract signature information from executable
		executable.Visit(func(val macho.Struct, visit func() error) error {
			switch val := val.(type) {
			case *macho.CodeSignatureCodeDirectoryBlob:
				bundleID = val.Identifier
				teamID = val.TeamID
			case *macho.CodeSignatureEntitlementsBlob:
				if config.PreserveEntitlements {
					config.Entitlements = val.Entitlements
				}
			case *macho.CodeSignatureRequirementsBlob:
				if config.PreserveRequirements {
					config.Requirements = val.Requirements
				}
			case *macho.CodeSignatureCMSSignatureBlob:
				if checkSignatureMatchesProfile(val, &config) {
					needsResign = false
				}
			}
			return visit()
		})

		if !needsResign {
			logger.Info("Path does not need resigning")
			return nil
		}

		if config.OnlyVerify {
			return ErrInvalidSignature
		}

		if bundleID == "" {
			bundleID = info.BundleIdentifier
		}

		if config.BundleID != "" {
			bundleID = config.BundleID
			info.BundleIdentifier = config.BundleID
		} else if config.BundleIDMap[info.BundleIdentifier] != "" {
			config.BundleID = config.BundleIDMap[info.BundleIdentifier]
			bundleID = config.BundleIDMap[info.BundleIdentifier]
			info.BundleIdentifier = config.BundleIDMap[info.BundleIdentifier]
		}

		infoData, err = writeInfo(root, path, info, rawInfo)
		if err != nil {
			return err
		}

		err = config.Normalize(ctx, logger, bundleID, teamID, info.PlatformName)
		if err != nil {
			return fmt.Errorf("could not normalize signing config: %w", err)
		}

		if config.CodeResources == nil {
			resources, err := GenerateCodeResources(root, path)
			if err != nil {
				return err
			}
			config.CodeResources = resources
		}

		resourceData, err := writeResources(root, path, config)
		if err != nil {
			return err
		}

		err = executable.Sign(config.Key, config.Chain, config.Entitlements, config.Requirements, func(val macho.Struct, visit func() error) error {
			switch val := val.(type) {
			case *macho.CodeSignatureCodeDirectoryBlob:
				updateCodeDirectoryIdentifiers(val, &config, bundleID)
				updateCodeDirectoryHashesForPath(val, infoData, resourceData)
			}
			return visit()
		})
		if err != nil {
			return err
		}

		return encodeAndWriteExecutable(executableFile, executable)
	}()

	return err
}

func updateCodeDirectoryHashesForPath(blob *macho.CodeSignatureCodeDirectoryBlob, infoData, resourceData []byte) {
	if infoData != nil {
		infoHash := blob.HashType.New()
		infoHash.Write(infoData)
		blob.Hashes[-int(macho.CodeSignatureSlotKindInfo)] = infoHash.Sum(nil)
	}

	if resourceData != nil {
		resourceHash := blob.HashType.New()
		resourceHash.Write(resourceData)
		blob.Hashes[-int(macho.CodeSignatureSlotKindResourceDir)] = resourceHash.Sum(nil)
	}
}


type VerificationFailureHint uint

const VerificationFailureHintNone VerificationFailureHint = 0

const (
	VerificationFailureHintProfileExpired VerificationFailureHint = 1 << iota
	VerificationFailureHintProfileMissingUDID
	VerificationFailureHintProfileTeamMismatch
	VerificationFailureHintProfileBundleIDMismatch
	VerificationFailureHintProfileIdentifierMismatch
	VerificationFailureHintProfileMissingCertificate
	VerificationFailureHintRecursiveVerificationFailed
)

func (h VerificationFailureHint) Contains(h2 VerificationFailureHint) bool {
	return h&h2 == h2
}

func (h VerificationFailureHint) String() string {
	if h == VerificationFailureHintNone {
		return "none"
	}

	var sb strings.Builder

	if h.Contains(VerificationFailureHintProfileExpired) {
		sb.WriteString(" | profile expired")
		h &= ^VerificationFailureHintProfileExpired
	}

	if h.Contains(VerificationFailureHintProfileMissingUDID) {
		sb.WriteString(" | profile missing UDID")
		h &= ^VerificationFailureHintProfileMissingUDID
	}

	if h.Contains(VerificationFailureHintProfileTeamMismatch) {
		sb.WriteString(" | profile team mismatch")
		h &= ^VerificationFailureHintProfileTeamMismatch
	}

	if h.Contains(VerificationFailureHintProfileBundleIDMismatch) {
		sb.WriteString(" | profile bundle ID mismatch")
		h &= ^VerificationFailureHintProfileBundleIDMismatch
	}

	if h.Contains(VerificationFailureHintProfileIdentifierMismatch) {
		sb.WriteString(" | profile identifier mismatch")
		h &= ^VerificationFailureHintProfileIdentifierMismatch
	}

	if h.Contains(VerificationFailureHintProfileMissingCertificate) {
		sb.WriteString(" | profile missing certificate")
		h &= ^VerificationFailureHintProfileMissingCertificate
	}

	if h.Contains(VerificationFailureHintRecursiveVerificationFailed) {
		sb.WriteString(" | recursive verification failed")
		h &= ^VerificationFailureHintRecursiveVerificationFailed
	}

	if h != 0 {
		fmt.Fprintf(&sb, " | unknown (%d)", h)
	}

	return sb.String()[3:]
}

type VerificationFailureError struct {
	Path  string
	Hint  VerificationFailureHint
	Cause error
}

func (e *VerificationFailureError) Error() string {
	return fmt.Sprintf("verification failed for path %q (hint: %v): %v", e.Path, e.Hint, e.Cause)
}

func (e *VerificationFailureError) Unwrap() error {
	return e.Cause
}

var ErrResignNeeded = errors.New("resign needed")

func (c *NativeCodeSigner) SignApp(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	logger = logger.With(zap.String("app", path))
	logger.Info("Signing as app")
	var err error
	defer func() { logger.Info("Finished signing as app", zap.Error(err)) }()

	err = func() error {
		infoData, info, rawInfo, err := readInfo(root, path, config)
		if err != nil {
			return fmt.Errorf("could not handle Info.plist: %w", err)
		}

		executableFile, err := root.OpenRW(filepath.Join(path, info.BundleExecutable))
		if err != nil {
			return fmt.Errorf("could not open %q: %w", path, err)
		}
		defer executableFile.Close()

		executable, err := macho.Parse(executableFile, 0)
		if err != nil {
			return fmt.Errorf("could not parse %q: %w", path, err)
		}

		appInfo := collectAppSignatureInfo(executable, &config)
		bundleID := appInfo.BundleID
		if bundleID == "" {
			bundleID = info.BundleIdentifier
		}

		verifyResult, err := c.verifyExistingSignatureProfile(ctx, logger, root, path, bundleID, appInfo.TeamID, appInfo.Certificates, config)
		if err != nil {
			return err
		}

		if verifyResult.IsValid && !config.Force {
			logger.Info("App does not need resigning")
			return nil
		}

		if config.OnlyVerify && verifyResult.HasFailure {
			errorCause := verifyResult.Error
			if errorCause == nil {
				errorCause = ErrResignNeeded
			}
			return &VerificationFailureError{
				Path:  path,
				Hint:  verifyResult.FailureHint,
				Cause: errorCause,
			}
		}

		err = c.applyAppSigningConfig(ctx, logger, root, path, bundleID, appInfo.TeamID, &config, &info, rawInfo)
		if err != nil {
			return err
		}

		err = config.Normalize(ctx, logger, info.BundleIdentifier, appInfo.TeamID, info.PlatformName)
		if err != nil {
			return fmt.Errorf("could not normalize signing config: %w", err)
		}

		err = c.signChildren(ctx, logger, root, path, config)
		if err != nil {
			return err
		}

		if config.CodeResources == nil {
			resources, err := GenerateCodeResources(root, path)
			if err != nil {
				return err
			}
			config.CodeResources = resources
		}

		getTaskAllow := false
		if config.Profile != nil {
			for fingerprint := range config.Profile.Fingerprints() {
				profileSha1, err := hex.DecodeString(fingerprint.Sha1)
				if err != nil {
					return err
				}
				profileSha256, err := hex.DecodeString(fingerprint.Sha256)
				if err != nil {
					return err
				}
				config.CodeResources.SetResource(EmbeddedProfileName, profileSha1, profileSha256, false)
				break
			}
			getTaskAllow = config.Profile.Entitlements.GetTaskAllow
		} else if config.ProfileFingerprint != nil {
			profileSha1, err := hex.DecodeString(config.ProfileFingerprint.Sha1)
			if err != nil {
				return err
			}
			profileSha256, err := hex.DecodeString(config.ProfileFingerprint.Sha256)
			if err != nil {
				return err
			}
			getTaskAllow = true
			config.CodeResources.SetResource(EmbeddedProfileName, profileSha1, profileSha256, false)
		}

		if config.Entitlements == nil {
			config.Entitlements = DefaultEntitlements(config.TeamIDPrefix, config.TeamID, config.BundleID, getTaskAllow)
		}

		resourceData, err := writeResources(root, path, config)
		if err != nil {
			return err
		}

		infoData, err = writeAppInfo(root, path, info, rawInfo)
		if err != nil {
			return err
		}

		err = executable.Sign(config.Key, config.Chain, config.Entitlements, config.Requirements, func(val macho.Struct, visit func() error) error {
			switch val := val.(type) {
			case *macho.CodeSignatureCodeDirectoryBlob:
				updateCodeDirectoryIdentifiers(val, &config, appInfo.BundleID)
				updateCodeDirectoryHashesForPath(val, infoData, resourceData)
			}
			return visit()
		})
		if err != nil {
			return err
		}

		err = encodeAndWriteExecutable(executableFile, executable)
		if err != nil {
			return err
		}

		if config.Profile != nil {
			profileFile, err := root.CreateRW(filepath.Join(path, EmbeddedProfileName))
			if err != nil {
				return err
			}
			defer profileFile.Close()
			_, err = profileFile.Write(config.Profile.Raw)
			if err != nil {
				return err
			}
		}

		return nil
	}()

	return err
}

type appVerificationResult struct {
	IsValid      bool
	HasFailure   bool
	FailureHint  VerificationFailureHint
	Error        error
}

func collectAppSignatureInfo(executable macho.Binary, config *SigningConfig) appSignatureData {
	result := appSignatureData{}

	executable.Visit(func(val macho.Struct, visit func() error) error {
		switch val := val.(type) {
		case *macho.CodeSignatureCodeDirectoryBlob:
			result.TeamID = val.TeamID
			result.BundleID = val.Identifier
		case *macho.CodeSignatureEntitlementsBlob:
			if config.PreserveEntitlements {
				config.Entitlements = val.Entitlements
			}
		case *macho.CodeSignatureRequirementsBlob:
			if config.PreserveRequirements {
				config.Requirements = val.Requirements
			}
		case *macho.CodeSignatureCMSSignatureBlob:
			if certs, err := val.SignedData.X509Certificates(); err == nil && len(certs) > 0 {
				result.Certificates = append(result.Certificates, certs[len(certs)-1])
			}
		}
		return visit()
	})

	return result
}

type appSignatureData struct {
	TeamID       string
	BundleID     string
	Certificates []*x509.Certificate
}

func (c *NativeCodeSigner) verifyExistingSignatureProfile(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path, bundleID, teamID string, leaves []*x509.Certificate, config SigningConfig) (appVerificationResult, error) {
	result := appVerificationResult{IsValid: true}

	if len(leaves) == 0 || config.Force {
		return result, nil
	}

	profileData, err := fs.ReadFile(root, filepath.Join(path, EmbeddedProfileName))
	if errors.Is(err, fs.ErrNotExist) {
		return result, nil
	} else if err != nil {
		return result, err
	}

	profile, err := ParseProfile(profileData)
	if err != nil {
		return result, err
	}

	checks := []profileCheck{
		{
			test:   time.Now().After(profile.ExpirationDate),
			hint:   VerificationFailureHintProfileExpired,
			reason: "profile expired",
		},
		{
			test:   config.UDID != "" && !profile.CanSignUDID(config.UDID),
			hint:   VerificationFailureHintProfileMissingUDID,
			reason: "profile missing UDID",
		},
		{
			test:   config.TeamID != "" && config.TeamID != teamID,
			hint:   VerificationFailureHintProfileTeamMismatch,
			reason: "profile team mismatch",
		},
		{
			test:   config.BundleID != "" && config.BundleID != bundleID,
			hint:   VerificationFailureHintProfileBundleIDMismatch,
			reason: "profile bundle ID mismatch",
		},
		{
			test:   !profile.CanSignBundleID(bundleID, teamID),
			hint:   VerificationFailureHintProfileIdentifierMismatch,
			reason: "profile identifier mismatch",
		},
	}

	for _, check := range checks {
		if check.test {
			result.IsValid = false
			result.HasFailure = true
			result.FailureHint |= check.hint
		}
	}

	for _, leaf := range leaves {
		if !profile.DeveloperCertificates.Contains(leaf) {
			result.IsValid = false
			result.HasFailure = true
			result.FailureHint |= VerificationFailureHintProfileMissingCertificate
			break
		}
	}

	// Skip recursive verification if we're not verifying or if validation already passed
	if !config.OnlyVerify && result.IsValid {
		return result, nil
	}

	// Verify children recursively (during OnlyVerify or when validation failed)
	verifyConfig := config
	verifyConfig.OnlyVerify = true
	verifyConfig.Profile = profile

	verifyErr := c.signChildren(ctx, logger, root, path, verifyConfig)
	if verifyErr != nil {
		result.IsValid = false
		result.HasFailure = true
		result.FailureHint |= VerificationFailureHintRecursiveVerificationFailed
		result.Error = verifyErr
	}

	return result, nil
}

type profileCheck struct {
	test   bool
	hint   VerificationFailureHint
	reason string
}

func (c *NativeCodeSigner) applyAppSigningConfig(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path, bundleID, teamID string, config *SigningConfig, info *InfoPlist, rawInfo map[string]interface{}) error {
	if config.BundleID != "" {
		bundleID = config.BundleID
		info.BundleIdentifier = config.BundleID
	} else if mapping := config.BundleIDMap[info.BundleIdentifier]; mapping != "" {
		config.BundleID = mapping
		bundleID = mapping
		info.BundleIdentifier = mapping
	}

	if config.BundleVersion != "" {
		info.BundleVersion = config.BundleVersion
	}

	config.BundleID = bundleID

	_, err := writeInfo(root, path, *info, rawInfo)
	return err
}

func writeAppInfo(root fs.ReadWriteFS, path string, info InfoPlist, rawInfo map[string]interface{}) ([]byte, error) {
	infoData, err := writeInfo(root, path, info, rawInfo)
	return infoData, err
}


func (c *NativeCodeSigner) signChildren(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	setErr := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	walkErr := stdfs.WalkDir(root, path, func(subPath string, d stdfs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		relPath, err := filepath.Rel(path, subPath)
		if err != nil {
			return fmt.Errorf("could not compute relative path %q %q:%w", path, subPath, err)
		}

		if strings.HasSuffix(relPath, ".dSym") {
			return stdfs.SkipDir
		}

		strategy := determineChildSigningStrategy(relPath, d.IsDir(), config)
		if strategy == nil {
			return nil
		}

		wg.Add(1)
		go func(relPath, subPath string, strategy childSigningStrategy) {
			defer wg.Done()

			action := "resign"
			if config.OnlyVerify {
				action = "verify"
			}

			err := strategy.sign(ctx, logger, root, subPath, config)
			if err != nil {
				setErr(fmt.Errorf("failed to %s %q: %w", action, relPath, err))
			}
		}(relPath, subPath, strategy)

		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		setErr(fmt.Errorf("failed to walk app children: %w", walkErr))
	}

	wg.Wait()
	return firstErr
}

type childSigningStrategy interface {
	sign(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error
}

func determineChildSigningStrategy(relPath string, isDir bool, config SigningConfig) childSigningStrategy {
	switch {
	case strings.HasPrefix(relPath, "Frameworks") && strings.HasSuffix(relPath, ".framework") && isDir:
		return frameworkStrategy{}
	case strings.HasPrefix(relPath, "Frameworks") && strings.HasSuffix(relPath, ".dylib") && !isDir:
		return dylibStrategy{}
	case strings.HasPrefix(relPath, "PlugIns") && strings.HasSuffix(relPath, ".xctest") && isDir:
		return xctestStrategy{}
	case strings.HasPrefix(relPath, "PlugIns") && strings.HasSuffix(relPath, ".appex") && isDir:
		return appexStrategy{}
	}
	return nil
}

type frameworkStrategy struct{}

func (s frameworkStrategy) sign(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	cfg := SigningConfig{
		BundleIDMap: config.BundleIDMap,
		Force:       config.Force,
		OnlyVerify:  config.OnlyVerify,
		UDID:        config.UDID,
		TeamID:      config.TeamID,
		Profile:     config.Profile,
		Key:         config.Key,
		Cert:        config.Cert,
		CertOpts:    config.CertOpts,
		Chain:       config.Chain,
	}
	var c NativeCodeSigner
	return c.SignPath(ctx, logger, root, path, cfg)
}

type dylibStrategy struct{}

func (s dylibStrategy) sign(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	cfg := SigningConfig{
		BundleIDMap: config.BundleIDMap,
		Force:       config.Force,
		OnlyVerify:  config.OnlyVerify,
		UDID:        config.UDID,
		TeamID:      config.TeamID,
		Profile:     config.Profile,
		Key:         config.Key,
		Cert:        config.Cert,
		CertOpts:    config.CertOpts,
		Chain:       config.Chain,
	}
	var c NativeCodeSigner
	return c.SignBinary(ctx, logger, root, path, cfg)
}

type xctestStrategy struct{}

func (s xctestStrategy) sign(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	cfg := SigningConfig{
		BundleIDMap:     config.BundleIDMap,
		Force:           config.Force,
		OnlyVerify:      config.OnlyVerify,
		UDID:            config.UDID,
		TeamID:          config.TeamID,
		Keychain:        config.Keychain,
		ProfileProvider: config.ProfileProvider,
	}
	var c NativeCodeSigner
	return c.SignApp(ctx, logger, root, path, cfg)
}

type appexStrategy struct{}

func (s appexStrategy) sign(ctx context.Context, logger *zap.Logger, root fs.ReadWriteFS, path string, config SigningConfig) error {
	cfg := SigningConfig{
		BundleIDMap:     config.BundleIDMap,
		Force:           config.Force,
		OnlyVerify:      config.OnlyVerify,
		UDID:            config.UDID,
		TeamID:          config.TeamID,
		Keychain:        config.Keychain,
		ProfileProvider: config.ProfileProvider,
	}
	var c NativeCodeSigner
	return c.SignApp(ctx, logger, root, path, cfg)
}

