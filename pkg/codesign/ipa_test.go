package codesign

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zip"
	"resigner/pkg/fs"
)

func TestUnzipIPAZip(t *testing.T) {
	unzipDir := filepath.Join(t.TempDir(), "wda.resign")

	err := os.Mkdir(unzipDir, 0o755)
	if err != nil {
		t.Fatal(err)
	}

	archiveBytes, err := os.ReadFile("testdata/wda.ipa")
	if err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "wda.ipa")
	err = os.WriteFile(archivePath, archiveBytes, 0o644)
	if err != nil {
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

	_, err = UnzipIPA(archive, archiveInfo.Size(), fs.DirFS(unzipDir), ".")
	if err != nil {
		t.Fatal(err)
	}

	err = ZipIPA(fs.DirFS(unzipDir), ".", archive)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnzipIPA_NoAppBundle(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	w, err := zw.Create("README.txt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write([]byte("not an ipa payload")); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = UnzipIPA(bytes.NewReader(buf.Bytes()), int64(buf.Len()), fs.NewMemFS(), ".")
	if err == nil || !strings.Contains(err.Error(), "expected exactly one app bundle") {
		t.Fatalf("expected missing app bundle error, got %v", err)
	}
}

func TestExtractArchiveEntry_PathTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// Craft an entry whose name escapes the destination via ../
	w, err := zw.Create("../../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dst := fs.NewMemFS()
	_, err = UnzipIPA(bytes.NewReader(buf.Bytes()), int64(buf.Len()), dst, ".")
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("expected path traversal error, got %v", err)
	}
}
