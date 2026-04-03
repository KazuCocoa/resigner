package fs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func DirFS(root string) ReadWriteFS {
	return &dirFS{root: root}
}

type dirFS struct {
	root string
}

func (f *dirFS) path(name string) string {
	return filepath.Join(f.root, name)
}

func (f *dirFS) Open(name string) (File, error) {
	return os.Open(f.path(name))
}

func (f *dirFS) OpenRW(name string) (ReadWriteFile, error) {
	p := f.path(name)
	_, err := os.Stat(p)
	if err != nil {
		return nil, err
	}

	return os.OpenFile(p, os.O_RDWR, 0o755)
}

func (f *dirFS) Sub(name string) (FS, error) {
	return &dirFS{root: f.path(name)}, nil
}

func (f *dirFS) SubRW(name string) (ReadWriteFS, error) {
	return &dirFS{root: f.path(name)}, nil
}

func (f *dirFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(f.path(name))
}

func (f *dirFS) Create(name string) (File, error) {
	return os.Create(f.path(name))
}

func (f *dirFS) CreateRW(name string) (ReadWriteFile, error) {
	return os.Create(f.path(name))
}

func (f *dirFS) Mkdir(name string) error {
	return os.Mkdir(f.path(name), 0o700)
}

func (f *dirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(f.path(name))
}

func (f *dirFS) Truncate(name string, size int64) error {
	return os.Truncate(f.path(name), size)
}

func (f *dirFS) Remove(name string) error {
	return os.Remove(f.path(name))
}

func (f *dirFS) RemoveAll(name string) error {
	return os.RemoveAll(f.path(name))
}

var _ ReadWriteFS = (*dirFS)(nil)

func MkdirAll(f ReadWriteFS, name string) error {
	clean := filepath.Clean(name)
	if clean == "." {
		return nil
	}

	parts := splitPath(clean)
	cur := ""

	if filepath.IsAbs(clean) {
		cur = string(os.PathSeparator)
	}

	for _, part := range parts {
		cur = filepath.Join(cur, part)
		if err := f.Mkdir(cur); err != nil && !errors.Is(err, ErrExist) {
			return err
		}
	}

	return nil
}

func splitPath(name string) []string {
	parts := make([]string, 0)
	for {
		dir, file := filepath.Split(name)
		if file != "" {
			parts = append([]string{file}, parts...)
		}

		next := filepath.Clean(dir)
		if next == "." || next == string(os.PathSeparator) || next == name {
			if next == string(os.PathSeparator) {
				return parts
			}
			return parts
		}

		name = next
	}
}
