package codesign

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"resigner/pkg/fs"
	"go.uber.org/zap"
)

func unzipIPAForTest(t *testing.T) (string, string, fs.ReadWriteFS) {
	t.Helper()

	tmp := t.TempDir()
	archiveBytes, err := os.ReadFile("testdata/wda.ipa")
	if err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(tmp, "wda.ipa")
	if err := os.WriteFile(archivePath, archiveBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	archive, err := os.OpenFile(archivePath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	archiveInfo, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}

	root := fs.DirFS(tmp)
	bundle, err := UnzipIPA(archive, archiveInfo.Size(), root, ".")
	if err != nil {
		t.Fatal(err)
	}

	return tmp, bundle, root
}

func TestSignBinary_ErrorPaths(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("missing binary", func(t *testing.T) {
		err := signer.SignBinary(ctx, logger, fs.NewMemFS(), "missing", SigningConfig{})
		if err == nil {
			t.Fatal("expected missing binary error")
		}
	})

	t.Run("invalid macho", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmp, "bin"), []byte("not-macho"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := signer.SignBinary(ctx, logger, fs.DirFS(tmp), "bin", SigningConfig{})
		if err == nil {
			t.Fatal("expected invalid macho parse error")
		}
	})

	t.Run("real macho only verify invalid signature", func(t *testing.T) {
		_, bundle, root := unzipIPAForTest(t)
		binaryPath := filepath.Join(bundle, "WebDriverAgentRunner-Runner")

		err := signer.SignBinary(ctx, logger, root, binaryPath, SigningConfig{OnlyVerify: true})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for verify-only on unsigned/mismatched binary, got %v", err)
		}
	})
}

func TestSignPathAndSignApp_InfoErrors(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	tmp := t.TempDir()
	appPath := filepath.Join(tmp, "My.app")
	if err := os.MkdirAll(appPath, 0o755); err != nil {
		t.Fatal(err)
	}

	err := signer.SignPath(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
	if err == nil {
		t.Fatal("expected SignPath info read error")
	}

	err = signer.SignApp(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
	if err == nil {
		t.Fatal("expected SignApp info read error")
	}
	if !strings.Contains(err.Error(), "could not handle Info.plist") {
		t.Fatalf("expected info error wrapper, got %q", err.Error())
	}
}

func TestSignPathAndSignApp_ExecutableErrors(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("missing executable", func(t *testing.T) {
		tmp := t.TempDir()
		appPath := filepath.Join(tmp, "My.app")
		if err := os.MkdirAll(appPath, 0o755); err != nil {
			t.Fatal(err)
		}

		writeInfoFixture(t, appPath, map[string]interface{}{
			"CFBundleIdentifier": "com.example.app",
			"CFBundleExecutable": "MissingExec",
			"CFBundleVersion":    "1",
			"DTPlatformName":     "iphoneos",
		})

		err := signer.SignPath(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
		if err == nil {
			t.Fatal("expected SignPath missing executable error")
		}

		err = signer.SignApp(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
		if err == nil {
			t.Fatal("expected SignApp missing executable error")
		}
		if !strings.Contains(err.Error(), "could not open") {
			t.Fatalf("expected open wrapper error, got %q", err.Error())
		}
	})

	t.Run("invalid executable parse", func(t *testing.T) {
		tmp := t.TempDir()
		appPath := filepath.Join(tmp, "My.app")
		if err := os.MkdirAll(appPath, 0o755); err != nil {
			t.Fatal(err)
		}

		writeInfoFixture(t, appPath, map[string]interface{}{
			"CFBundleIdentifier": "com.example.app",
			"CFBundleExecutable": "Exec",
			"CFBundleVersion":    "1",
			"DTPlatformName":     "iphoneos",
		})

		if err := os.WriteFile(filepath.Join(appPath, "Exec"), []byte("not-macho"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := signer.SignPath(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
		if err == nil {
			t.Fatal("expected SignPath macho parse error")
		}

		err = signer.SignApp(ctx, logger, fs.DirFS(tmp), "My.app", SigningConfig{})
		if err == nil {
			t.Fatal("expected SignApp macho parse error")
		}
		if !strings.Contains(err.Error(), "could not parse") {
			t.Fatalf("expected parse wrapper error, got %q", err.Error())
		}
	})
}

func TestSignPath_RealAppBranches(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("only verify returns invalid signature", func(t *testing.T) {
		_, bundle, root := unzipIPAForTest(t)

		err := signer.SignPath(ctx, logger, root, bundle, SigningConfig{OnlyVerify: true})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("bundle id map updates info before normalize failure", func(t *testing.T) {
		_, bundle, root := unzipIPAForTest(t)

		_, original, _, err := readInfo(root, bundle, SigningConfig{})
		if err != nil {
			t.Fatal(err)
		}

		mappedID := "mapped." + original.BundleIdentifier
		err = signer.SignPath(ctx, logger, root, bundle, SigningConfig{
			BundleIDMap: map[string]string{original.BundleIdentifier: mappedID},
		})
		if err == nil || !strings.Contains(err.Error(), "could not normalize signing config") {
			t.Fatalf("expected normalize wrapper error, got %v", err)
		}

		_, updated, _, err := readInfo(root, bundle, SigningConfig{})
		if err != nil {
			t.Fatal(err)
		}

		if updated.BundleIdentifier != mappedID {
			t.Fatalf("expected bundle id to be updated to %q, got %q", mappedID, updated.BundleIdentifier)
		}
	})
}

func TestSignApp_OnlyVerifyFailures(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("only-verify with team-id mismatch returns verification failure", func(t *testing.T) {
		_, bundle, root := unzipIPAForTest(t)

		err := signer.SignApp(ctx, logger, root, bundle, SigningConfig{OnlyVerify: true, TeamID: "TEAM-MISMATCH"})
		if err == nil {
			t.Fatal("expected verification failure")
		}

		var verifyErr *VerificationFailureError
		if !errors.As(err, &verifyErr) {
			t.Fatalf("expected VerificationFailureError, got %T (%v)", err, err)
		}

		if !errors.Is(err, ErrResignNeeded) {
			t.Fatalf("expected ErrResignNeeded cause, got %v", err)
		}

		if verifyErr.Hint == VerificationFailureHintNone {
			t.Fatal("expected non-empty verification hint")
		}
	})

	t.Run("recursive verify failure includes recursive hint", func(t *testing.T) {
		tmp, bundle, root := unzipIPAForTest(t)

		childBinary := filepath.Join(bundle,
			"PlugIns",
			"WebDriverAgentRunner.xctest",
			"Frameworks",
			"WebDriverAgentLib.framework",
			"WebDriverAgentLib",
		)

		if err := os.Remove(filepath.Join(tmp, filepath.Clean(childBinary))); err != nil {
			t.Fatal(err)
		}

		err := signer.SignApp(ctx, logger, root, bundle, SigningConfig{OnlyVerify: true, TeamID: "TEAM-MISMATCH"})
		if err == nil {
			t.Fatal("expected recursive verification failure")
		}

		var verifyErr *VerificationFailureError
		if !errors.As(err, &verifyErr) {
			t.Fatalf("expected VerificationFailureError, got %T (%v)", err, err)
		}

		if !verifyErr.Hint.Contains(VerificationFailureHintRecursiveVerificationFailed) {
			t.Fatalf("expected recursive verification hint, got %s", verifyErr.Hint.String())
		}
	})
}

func TestSignApp_BundleIDMapPersistsAfterFullFlow(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	tmp, bundle, root := unzipIPAForTest(t)

	_, appBefore, _, err := readInfo(root, bundle, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}

	// Keep this focused on SignApp's own info rewrite path by removing nested plugins.
	if err := os.RemoveAll(filepath.Join(tmp, bundle, "PlugIns")); err != nil {
		t.Fatal(err)
	}

	appMappedID := "mapped." + appBefore.BundleIdentifier

	key, cert := selfSignedIdentity(t)

	err = signer.SignApp(ctx, logger, root, bundle, SigningConfig{
		Force: true,
		BundleIDMap: map[string]string{
			appBefore.BundleIdentifier: appMappedID,
		},
		Key:          key,
		Cert:         cert,
		Chain:        []*x509.Certificate{cert},
		TeamID:       "TEAMID12345",
		TeamIDPrefix: "TEAMID12345",
	})
	if err != nil {
		t.Fatalf("expected SignApp to succeed with remap config, got %v", err)
	}

	_, appAfter, _, err := readInfo(root, bundle, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if appAfter.BundleIdentifier != appMappedID {
		t.Fatalf("expected app bundle id %q, got %q", appMappedID, appAfter.BundleIdentifier)
	}
}

func TestSignApp_XCTestBundleIDMapPersistsAfterFullFlow(t *testing.T) {
	signer := &NativeCodeSigner{}
	ctx := context.Background()
	logger := zap.NewNop()

	_, bundle, root := unzipIPAForTest(t)
	xctestPath := filepath.Join(bundle, "PlugIns", "WebDriverAgentRunner.xctest")

	_, xctestBefore, _, err := readInfo(root, xctestPath, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}

	mappedID := "mapped." + xctestBefore.BundleIdentifier

	key, cert := selfSignedIdentity(t)
	err = signer.SignApp(ctx, logger, root, xctestPath, SigningConfig{
		Force: true,
		BundleIDMap: map[string]string{
			xctestBefore.BundleIdentifier: mappedID,
		},
		Key:          key,
		Cert:         cert,
		Chain:        []*x509.Certificate{cert},
		TeamID:       "TEAMID12345",
		TeamIDPrefix: "TEAMID12345",
	})
	if err != nil {
		t.Fatalf("expected xctest SignApp to succeed with remap config, got %v", err)
	}

	_, xctestAfter, _, err := readInfo(root, xctestPath, SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if xctestAfter.BundleIdentifier != mappedID {
		t.Fatalf("expected xctest bundle id %q, got %q", mappedID, xctestAfter.BundleIdentifier)
	}
}

func TestSignChildren_BranchErrors(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(root string) error
		onlyVerify bool
		expected   string
	}{
		{
			name: "framework branch",
			setup: func(root string) error {
				return os.MkdirAll(filepath.Join(root, "My.app", "Frameworks", "A.framework"), 0o755)
			},
			onlyVerify: false,
			expected:   "failed to resign \"Frameworks/A.framework\"",
		},
		{
			name: "dylib verify branch",
			setup: func(root string) error {
				if err := os.MkdirAll(filepath.Join(root, "My.app", "Frameworks"), 0o755); err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(root, "My.app", "Frameworks", "A.dylib"), []byte("not-macho"), 0o644)
			},
			onlyVerify: true,
			expected:   "failed to verify \"Frameworks/A.dylib\"",
		},
		{
			name: "xctest branch",
			setup: func(root string) error {
				return os.MkdirAll(filepath.Join(root, "My.app", "PlugIns", "B.xctest"), 0o755)
			},
			onlyVerify: false,
			expected:   "failed to resign \"PlugIns/B.xctest\"",
		},
		{
			name: "appex branch",
			setup: func(root string) error {
				return os.MkdirAll(filepath.Join(root, "My.app", "PlugIns", "C.appex"), 0o755)
			},
			onlyVerify: false,
			expected:   "failed to resign \"PlugIns/C.appex\"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			if err := tc.setup(tmp); err != nil {
				t.Fatal(err)
			}

			signer := &NativeCodeSigner{}
			err := signer.signChildren(context.Background(), zap.NewNop(), fs.DirFS(tmp), "My.app", SigningConfig{OnlyVerify: tc.onlyVerify})
			if err == nil {
				t.Fatal("expected signChildren branch error")
			}
			if !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("expected error to contain %q, got %q", tc.expected, err.Error())
			}
		})
	}
}
