package codesign

import (
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
	"resigner/pkg/fs"
)

func writeInfoFixture(t *testing.T, dir string, info map[string]interface{}) {
	t.Helper()

	data, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "Info.plist"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNewNativeCodeSigner(t *testing.T) {
	signer, err := NewNativeCodeSigner()
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		t.Fatal("expected signer instance")
	}
}

func TestReadInfo(t *testing.T) {
	tmp := t.TempDir()
	appDir := filepath.Join(tmp, "My.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fixture := map[string]interface{}{
		"CFBundleIdentifier": "com.example.app",
		"CFBundleExecutable": "MyExec",
		"CFBundleVersion":    "1",
		"DTPlatformName":     "iphoneos",
		"Extra":              "value",
	}
	writeInfoFixture(t, appDir, fixture)

	data, info, raw, err := readInfo(fs.DirFS(tmp), "My.app", SigningConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Fatal("expected Info.plist bytes")
	}
	if info.BundleIdentifier != "com.example.app" {
		t.Fatal("unexpected bundle identifier")
	}
	if info.BundleExecutable != "MyExec" {
		t.Fatal("unexpected bundle executable")
	}
	if raw["Extra"] != "value" {
		t.Fatal("expected raw plist fields to be preserved")
	}
}

func TestWriteInfo(t *testing.T) {
	tmp := t.TempDir()
	appDir := filepath.Join(tmp, "My.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fixture := map[string]interface{}{
		"CFBundleIdentifier": "com.old.app",
		"CFBundleExecutable": "OldExec",
		"CFBundleVersion":    "1",
		"DTPlatformName":     "iphoneos",
		"Custom":             "keep",
	}
	writeInfoFixture(t, appDir, fixture)

	info := InfoPlist{
		BundleIdentifier: "com.new.app",
		BundleExecutable: "NewExec",
		BundleVersion:    "2",
		PlatformName:     "appletvos",
	}

	data, err := writeInfo(fs.DirFS(tmp), "My.app", info, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected encoded Info.plist data")
	}

	readData, err := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]interface{}
	if _, err := plist.Unmarshal(readData, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded["CFBundleIdentifier"] != "com.new.app" {
		t.Fatal("expected updated bundle identifier")
	}
	if decoded["CFBundleExecutable"] != "NewExec" {
		t.Fatal("expected updated bundle executable")
	}
	if decoded["CFBundleVersion"] != "2" {
		t.Fatal("expected updated bundle version")
	}
	if decoded["DTPlatformName"] != "appletvos" {
		t.Fatal("expected updated platform")
	}
	if decoded["Custom"] != "keep" {
		t.Fatal("expected custom field to be preserved")
	}
}

func TestWriteResources(t *testing.T) {
	tmp := t.TempDir()
	appDir := filepath.Join(tmp, "My.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := SigningConfig{
		CodeResources: &CodeResources{FilesV1: map[string]FileResourceV1{"foo": {Hash: []byte{1}}}},
	}

	data, err := writeResources(fs.DirFS(tmp), "My.app", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected serialized code resources")
	}

	if _, err := os.Stat(filepath.Join(appDir, "_CodeSignature", "CodeResources")); err != nil {
		t.Fatal(err)
	}

	if _, err := writeResources(fs.DirFS(tmp), "My.app", cfg); err != nil {
		t.Fatal(err)
	}
}
