package fs

import (
	"io"
	"io/fs"
	"syscall"
)

var ErrExist = fs.ErrExist

var ErrNotExist = fs.ErrNotExist

var ErrIsDir = syscall.EISDIR

var WalkDir = fs.WalkDir

var Glob = fs.Glob

var SkipDir = fs.SkipDir

var ReadFile = fs.ReadFile

type DirEntry = fs.DirEntry

type File = fs.File

type FileMode = fs.FileMode

type FileInfo = fs.FileInfo

const ModeDir = fs.ModeDir

type FS = fs.FS

type SubFS = fs.SubFS

type ReadDirFS = fs.ReadDirFS

type ReadDirFile = fs.ReadDirFile

type ReadWriteFS interface {
	fs.FS
	OpenRW(name string) (ReadWriteFile, error)

	fs.StatFS
	fs.ReadDirFS

	CreateFS
	CreateRW(name string) (ReadWriteFile, error)

	MkdirFS

	RemoveFS

	RemoveAllFS
}

type SubReadWriteFS interface {
	ReadWriteFS

	SubRW(name string) (ReadWriteFS, error)
}

type RemoveFS interface {
	FS

	Remove(name string) error
}

type RemoveAllFS interface {
	FS

	RemoveAll(name string) error
}

type CreateFS interface {
	FS

	Create(name string) (File, error)
}

type MkdirFS interface {
	FS

	Mkdir(name string) error
}

type TruncateFS interface {
	FS

	Truncate(name string, size int64) error
}

type Truncater interface {
	Truncate(size int64) error
}

type ReadWriteFile interface {
	File

	io.ReaderAt

	io.Writer
	io.WriterAt

	io.Seeker

	Truncater
}
