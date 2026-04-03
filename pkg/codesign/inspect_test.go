package codesign

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"resigner/pkg/fs"
	"howett.net/plist"
)

func TestCollectBundlePrintEntries_SimpleBundle(t *testing.T) {
	root := fs.NewMemFS()
	mkdirAllInspect(t, root, "Sample.app")
	writeInfoPlistInspect(t, root, "Sample.app", "com.example.sample", "Sample")
	writeMemFileInspect(t, root, "Sample.app/Sample", []byte("not-a-macho"))

	entries, err := CollectBundlePrintEntries(root, "Sample.app")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Path != "Sample.app" {
		t.Fatalf("unexpected path: %s", entries[0].Path)
	}

	if entries[0].BundleID != "com.example.sample" {
		t.Fatalf("unexpected bundle id: %s", entries[0].BundleID)
	}
}

func TestCollectBundlePrintEntries_NestedBundles(t *testing.T) {
	root := fs.NewMemFS()
	mkdirAllInspect(t, root, "Sample.app")
	writeInfoPlistInspect(t, root, "Sample.app", "com.example.sample", "Sample")
	writeMemFileInspect(t, root, "Sample.app/Sample", []byte("not-a-macho"))

	mkdirAllInspect(t, root, "Sample.app/PlugIns/Test.xctest")
	writeInfoPlistInspect(t, root, "Sample.app/PlugIns/Test.xctest", "com.example.test", "Test")
	writeMemFileInspect(t, root, "Sample.app/PlugIns/Test.xctest/Test", []byte("not-a-macho"))

	entries, err := CollectBundlePrintEntries(root, "Sample.app")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	paths := []string{entries[0].Path, entries[1].Path}
	sort.Strings(paths)

	expected := []string{"Sample.app", "Sample.app/PlugIns/Test.xctest"}
	for i := range expected {
		if paths[i] != expected[i] {
			t.Fatalf("unexpected path[%d]: %s", i, paths[i])
		}
	}
}

func mkdirAllInspect(t *testing.T, root fs.ReadWriteFS, path string) {
	t.Helper()

	parts := strings.Split(path, "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		cur = filepath.Join(cur, p)
		err := root.Mkdir(cur)
		if err != nil && err != fs.ErrExist {
			t.Fatal(err)
		}
	}
}

func writeInfoPlistInspect(t *testing.T, root fs.ReadWriteFS, dir, bundleID, exec string) {
	t.Helper()

	info := map[string]string{
		"CFBundleIdentifier": bundleID,
		"CFBundleExecutable": exec,
		"CFBundleVersion":    "1",
		"DTPlatformName":     "iphoneos",
	}

	data, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	writeMemFileInspect(t, root, filepath.Join(dir, "Info.plist"), data)
}

func writeMemFileInspect(t *testing.T, root fs.ReadWriteFS, path string, data []byte) {
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
