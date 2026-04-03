package fs

import (
	"errors"
	"io"
	"syscall"
	"testing"
)

func TestMemFS_FileOperations(t *testing.T) {
	root := NewMemFS()

	if err := root.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}

	file, err := root.CreateRW("dir/file.txt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 5)
	if _, err := file.Read(buf); err != nil {
		t.Fatal(err)
	}

	if string(buf) != "hello" {
		t.Fatalf("unexpected file data: %q", string(buf))
	}

	readAt := make([]byte, 2)
	if _, err := file.ReadAt(readAt, 1); err != nil {
		t.Fatal(err)
	}
	if string(readAt) != "el" {
		t.Fatalf("unexpected ReadAt data: %q", string(readAt))
	}

	if _, err := file.WriteAt([]byte("!"), 5); err != nil {
		t.Fatal(err)
	}

	if err := file.Truncate(3); err != nil {
		t.Fatal(err)
	}

	// Seeking beyond EOF is valid; subsequent Write will extend the file.
	if pos, err := file.Seek(4, io.SeekStart); err != nil || pos != 4 {
		t.Fatalf("expected seek beyond EOF to succeed at position 4, got pos=%d err=%v", pos, err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := root.Stat("dir/file.txt")
	if err != nil {
		t.Fatal(err)
	}

	if info.Size() != 3 {
		t.Fatalf("expected size 3, got %d", info.Size())
	}

	dirHandle, err := root.Open("dir")
	if err != nil {
		t.Fatal(err)
	}
	defer dirHandle.Close()

	rdf, ok := dirHandle.(ReadDirFile)
	if !ok {
		t.Fatal("expected dir handle to implement ReadDirFile")
	}

	entries, err := rdf.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) == 0 {
		t.Fatal("expected at least one dir entry")
	}
}

func TestMemFS_DirectoryAndRemoveBehavior(t *testing.T) {
	root := NewMemFS()
	subRWRoot, ok := root.(SubReadWriteFS)
	if !ok {
		t.Fatal("expected mem fs to implement SubReadWriteFS")
	}
	if err := root.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}

	if _, err := subRWRoot.SubRW("dir"); err != nil {
		t.Fatal(err)
	}

	if _, err := root.Create("dir/file"); err != nil {
		t.Fatal(err)
	}

	if err := root.Remove("dir"); !errors.Is(err, ErrIsDir) {
		t.Fatalf("expected ErrIsDir, got %v", err)
	}

	if err := root.Remove("dir/file"); err != nil {
		t.Fatal(err)
	}

	if err := root.RemoveAll("dir"); err != nil {
		t.Fatal(err)
	}

	if _, err := root.Stat("dir"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("expected ErrNotExist after RemoveAll, got %v", err)
	}

	if _, err := root.OpenRW("."); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("expected EISDIR for OpenRW on dir, got %v", err)
	}
}

func TestDirFS_Operations(t *testing.T) {
	tmp := t.TempDir()
	root := DirFS(tmp)
	subRWRoot, ok := root.(SubReadWriteFS)
	if !ok {
		t.Fatal("expected dir fs to implement SubReadWriteFS")
	}
	truncateRoot, ok := root.(TruncateFS)
	if !ok {
		t.Fatal("expected dir fs to implement TruncateFS")
	}

	if err := root.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}

	if _, err := subRWRoot.SubRW("dir"); err != nil {
		t.Fatal(err)
	}

	f, err := root.Create("dir/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.(io.Writer).Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := truncateRoot.Truncate("dir/file.txt", 2); err != nil {
		t.Fatal(err)
	}

	if err := root.Remove("dir/file.txt"); err != nil {
		t.Fatal(err)
	}

	if err := root.RemoveAll("dir"); err != nil {
		t.Fatal(err)
	}
}

func TestMemFS_ReadAt_NegativeOffset(t *testing.T) {
	root := NewMemFS()
	f, err := root.CreateRW("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2)
	_, err = f.ReadAt(buf, -1)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("expected EINVAL for negative ReadAt offset, got %v", err)
	}
}

func TestMemFS_Truncate_Expand(t *testing.T) {
	root := NewMemFS()
	f, err := root.CreateRW("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	// Expand from 2 to 5: padding bytes must be zero.
	if err := f.Truncate(5); err != nil {
		t.Fatalf("Truncate expand: %v", err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := f.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi\x00\x00\x00" {
		t.Fatalf("expected 'hi\\x00\\x00\\x00', got %q", string(buf))
	}
}

func TestMemFS_Seek_BeyondEOF_ThenWrite(t *testing.T) {
	root := NewMemFS()
	f, err := root.CreateRW("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}

	// Seek past EOF, then write — should extend with zero padding.
	if _, err := f.Seek(5, io.SeekStart); err != nil {
		t.Fatalf("seek beyond EOF should not error: %v", err)
	}
	if _, err := f.Write([]byte("Z")); err != nil {
		t.Fatalf("write after seek beyond EOF: %v", err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := f.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "abc\x00\x00Z" {
		t.Fatalf("expected 'abc\\x00\\x00Z', got %q", string(buf))
	}
}
