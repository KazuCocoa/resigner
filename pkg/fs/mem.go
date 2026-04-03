package fs

import (
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

type memFS struct {
	name string
	data map[string]interface{}
}

var _ ReadWriteFS = (*memFS)(nil)

func NewMemFS() ReadWriteFS {
	m := &memFS{
		name: "",
		data: make(map[string]interface{}),
	}

	m.data["."] = m

	return m
}

func newMemFS(parent *memFS, name string) ReadWriteFS {
	m := &memFS{
		name: name,
		data: make(map[string]interface{}),
	}

	m.data["."] = m
	m.data[".."] = parent

	return m
}

func (f *memFS) Sub(name string) (FS, error) {
	return f.dir(name)
}

func (f *memFS) SubRW(name string) (ReadWriteFS, error) {
	return f.dir(name)
}

func (f *memFS) Stat(name string) (FileInfo, error) {
	file, err := f.file(name)
	if err != nil {
		return nil, err
	}

	switch file := file.(type) {
	case *memFS:
		return memFileInfo{name: name, isDir: true, size: 0}, nil
	case *memFile:
		return memFileInfo{name: name, isDir: false, size: int64(len(file.data))}, nil
	}

	return nil, syscall.ENOENT
}

func (f *memFS) handle(name string) *memFSHandle {
	return &memFSHandle{
		name:  name,
		memFS: f,
	}
}

func (f *memFS) ReadDir(name string) ([]DirEntry, error) {
	dir, err := f.dir(name)
	if err != nil {
		return nil, err
	}

	entries := make([]DirEntry, 0, len(dir.data))

	for name, entry := range dir.data {
		if name == "." || name == ".." {
			continue
		}

		switch entry := entry.(type) {
		case *memFS:
			entries = append(entries, memFileInfo{name: name, isDir: true, size: 0})
		case *memFile:
			entries = append(entries, memFileInfo{name: name, isDir: false, size: int64(len(entry.data))})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	return entries, nil
}

func (f *memFS) dir(name string) (*memFS, error) {
	name = filepath.Clean(name)
	if name == "." {
		return f, nil
	}

	parent, dir := filepath.Split(name)

	if dir == "" {
		child, ok := f.data[filepath.Base(parent)]
		if !ok {
			return nil, ErrNotExist
		}

		childFS, ok := child.(*memFS)
		if !ok {
			return nil, syscall.ENOTDIR
		}
		return childFS, nil
	}

	parentFS, err := f.dir(parent)
	if err != nil {
		return nil, err
	}

	child, ok := parentFS.data[filepath.Base(dir)]
	if !ok {
		return nil, ErrNotExist
	}

	childFS, ok := child.(*memFS)
	if !ok {
		return nil, syscall.ENOTDIR
	}

	return childFS, nil
}

func (f *memFS) file(name string) (interface{}, error) {
	parent, file := filepath.Split(name)

	parentFS, err := f.dir(parent)
	if err != nil {
		return nil, err
	}

	child, ok := parentFS.data[file]
	if !ok {
		return nil, ErrNotExist
	}

	return child, nil
}

func (f *memFS) newFile(name string) (*memFile, error) {
	parent, err := f.dir(filepath.Dir(name))
	if err != nil {
		return nil, err
	}

	file := &memFile{}

	parent.data[filepath.Base(name)] = file
	return file, nil
}

func (f *memFS) Remove(name string) error {
	parent, err := f.dir(filepath.Dir(name))
	if err != nil {
		return err
	}

	file, err := f.file(name)
	if err != nil {
		return err
	}

	if _, ok := file.(*memFile); !ok {
		return ErrIsDir
	}

	delete(parent.data, filepath.Base(name))
	return nil
}

func (f *memFS) RemoveAll(name string) error {
	parent, err := f.dir(filepath.Dir(name))
	if err != nil {
		return err
	}

	delete(parent.data, filepath.Base(name))
	return nil
}

func (f *memFS) Create(name string) (File, error) {
	file, err := f.newFile(name)
	if err != nil {
		return nil, err
	}

	return file.handle(filepath.Base(name)), nil
}

func (f *memFS) CreateRW(name string) (ReadWriteFile, error) {
	file, err := f.newFile(name)
	if err != nil {
		return nil, err
	}

	return file.handle(filepath.Base(name)), nil
}

func (f *memFS) Open(name string) (File, error) {
	file, err := f.file(name)
	if err != nil {
		return nil, err
	}

	switch file := file.(type) {
	case *memFS:
		return file.handle(filepath.Base(name)), nil
	case *memFile:
		return file.handle(filepath.Base(name)), nil
	}

	return nil, ErrNotExist
}

func (f *memFS) OpenRW(name string) (ReadWriteFile, error) {
	file, err := f.file(name)
	if err != nil {
		return nil, err
	}

	rwFile, ok := file.(*memFile)
	if !ok {
		return nil, syscall.EISDIR
	}

	return rwFile.handle(filepath.Base(name)), nil
}

func (f *memFS) Mkdir(name string) error {
	parent, err := f.dir(filepath.Dir(name))
	if err != nil {
		return err
	}
	_, ok := parent.data[filepath.Base(name)]
	if ok {
		return ErrExist
	}

	parent.data[filepath.Base(name)] = newMemFS(parent, filepath.Base(name))

	return nil
}

type memFile struct {
	data []byte
}

func (f *memFile) handle(name string) *memFileHandle {
	return &memFileHandle{name: name, memFile: f}
}

type memFileHandle struct {
	*memFile
	name   string
	cursor int64
}

func (f *memFileHandle) Close() error {
	return nil
}

func (f *memFileHandle) Read(p []byte) (int, error) {
	if f.cursor == int64(len(f.data)) {
		return 0, io.EOF
	}

	if f.cursor+int64(len(p)) > int64(len(f.data)) {
		copy(p, f.data[f.cursor:])
		n := len(f.data) - int(f.cursor)
		f.cursor += int64(n)
		return n, nil
	}

	copy(p, f.data[f.cursor:f.cursor+int64(len(p))])
	f.cursor += int64(len(p))
	return len(p), nil
}

func (f *memFileHandle) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, syscall.EINVAL
	}
	if offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	if offset+int64(len(p)) > int64(len(f.data)) {
		n := copy(p, f.data[offset:])
		return n, io.EOF
	}

	copy(p, f.data[offset:offset+int64(len(p))])
	return len(p), nil
}

func (f *memFileHandle) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		if offset < 0 {
			return 0, syscall.EINVAL
		}
		f.cursor = offset
	case io.SeekCurrent:
		if f.cursor+offset < 0 {
			return 0, syscall.EINVAL
		}
		f.cursor += offset
	case io.SeekEnd:
		if int64(len(f.data))-offset < 0 {
			return 0, syscall.EINVAL
		}
		f.cursor = int64(len(f.data)) - offset
	default:
		return 0, syscall.EINVAL
	}

	return f.cursor, nil
}

func (f *memFileHandle) Truncate(size int64) error {
	if size < 0 {
		return syscall.EINVAL
	}
	if size > int64(len(f.data)) {
		f.data = append(f.data, make([]byte, size-int64(len(f.data)))...)
	} else {
		f.data = f.data[:size]
	}
	return nil
}

func (f *memFileHandle) Write(p []byte) (int, error) {
	if f.cursor+int64(len(p)) > int64(len(f.data)) {
		growth := int64(len(p)) - (int64(len(f.data)) - f.cursor)

		f.data = append(f.data, make([]byte, growth)...)
	}

	copy(f.data[f.cursor:], p)

	f.cursor += int64(len(p))

	return len(p), nil
}

func (f *memFileHandle) WriteAt(p []byte, offset int64) (int, error) {
	if int64(len(f.data)) < int64(len(p))+offset {
		f.data = append(f.data, make([]byte, int64(len(p))+offset-int64(len(f.data)))...)
	}

	copy((f.data)[offset:], p)

	return len(p), nil
}

func (f *memFileHandle) Stat() (FileInfo, error) {
	return memFileInfo{name: f.name, isDir: false, size: int64(len(f.data))}, nil
}

type memFSHandle struct {
	*memFS
	name    string
	entries []DirEntry
	cursor  int
}

func (f *memFSHandle) Close() error {
	return nil
}

func (f *memFSHandle) Stat() (FileInfo, error) {
	return memFileInfo{name: f.name, isDir: true, size: 0}, nil
}

func (f *memFSHandle) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (f *memFSHandle) ReadDir(n int) ([]DirEntry, error) {
	if f.entries == nil {
		entries, err := f.memFS.ReadDir(".")
		if err != nil {
			return nil, err
		}

		f.entries = entries

	}

	if n < 0 {
		return f.entries, nil
		//do all
	}

	if f.cursor == len(f.data) {
		return nil, io.EOF
	}

	if f.cursor+n > len(f.entries) {
		entries := f.entries[f.cursor:]
		f.cursor = len(f.entries)
		return entries, nil
	} else {
		entries := f.entries[f.cursor : f.cursor+n]
		f.cursor += n
		return entries, nil
	}
}

type memFileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (i memFileInfo) Name() string {
	return i.name
}

func (i memFileInfo) Size() int64 {
	return i.size
}

func (i memFileInfo) Type() fs.FileMode {
	if i.isDir {
		return fs.ModeDir
	}

	return 0
}

func (i memFileInfo) Mode() fs.FileMode {
	if i.isDir {
		return fs.ModeDir | 0o777
	}

	return 0o777
}

func (i memFileInfo) ModTime() time.Time {
	return time.Time{}
}

func (i memFileInfo) IsDir() bool {
	return i.isDir
}

func (i memFileInfo) Info() (fs.FileInfo, error) {
	return i, nil
}

func (i memFileInfo) Sys() interface{} {
	return nil
}
