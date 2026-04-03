package codesign

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	stdfs "io/fs"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zip"

	"resigner/pkg/fs"
	"resigner/pkg/utils"
)

const zipCompatibilityVersion = 0x0a

func UnzipIPA(file io.ReaderAt, size int64, dst fs.ReadWriteFS, path string) (string, error) {
	archive, err := zip.NewReader(utils.NewBufReaderAt(file, 1<<20), size)
	if err != nil {
		return "", err
	}

	for _, entry := range archive.File {
		if err := extractArchiveEntry(dst, path, entry); err != nil {
			return "", err
		}
	}

	matches, err := stdfs.Glob(dst, filepath.Join("Payload", "*.app"))
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one app bundle, found %d", len(matches))
	}

	return matches[0], nil
}

func extractArchiveEntry(dst fs.ReadWriteFS, basePath string, entry *zip.File) error {
	if entry.FileInfo().IsDir() {
		dirPath, err := safeEntryPath(basePath, entry.Name)
		if err != nil {
			return err
		}
		if err := fs.MkdirAll(dst, dirPath); err != nil {
			return fmt.Errorf("could not create directory %s: %w", entry.Name, err)
		}
		return nil
	}

	parent, err := safeEntryPath(basePath, filepath.Dir(entry.Name))
	if err != nil {
		return err
	}
	if err := fs.MkdirAll(dst, parent); err != nil && !errors.Is(err, stdfs.ErrExist) {
		return fmt.Errorf("could not create directory %s: %w", filepath.Dir(entry.Name), err)
	}

	return copyEntry(dst, basePath, entry)
}

// safeEntryPath checks that joining basePath with entryName does not escape
// basePath (i.e. guards against zip-slip path traversal). It returns the
// cleaned joined path or an error.
func safeEntryPath(basePath, entryName string) (string, error) {
	rel := filepath.Clean(filepath.FromSlash(entryName))
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected in archive entry: %s", entryName)
	}
	return filepath.Join(basePath, rel), nil
}

func copyEntry(dst fs.ReadWriteFS, basePath string, entry *zip.File) (err error) {
	name, err := safeEntryPath(basePath, entry.Name)
	if err != nil {
		return err
	}
	out, err := dst.CreateRW(name)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := out.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	in, err := entry.Open()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := in.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, in)
	return err
}

// ZipIPA zips an ipa in a format readable by iOS. Special care is made to make
// sure the version is readable by older iOS/iPhone combinations. Some versions
// of iOS 13 are known to be unable to extract zip versions > 0x0a.
func ZipIPA(src fs.FS, path string, dst io.Writer) error {
	writer := bufio.NewWriterSize(dst, 1<<20)
	zw := zip.NewWriter(writer)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestSpeed)
	})

	walkErr := stdfs.WalkDir(src, path, func(subPath string, d stdfs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(path, subPath)
		if err != nil {
			return err
		}
		if relPath == "." || relPath == ".." {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if d.IsDir() {
			return addDirToZip(zw, relPath, info)
		}
		return addFileToZip(zw, src, subPath, relPath, info)
	})
	if walkErr != nil {
		return walkErr
	}

	if err := zw.Close(); err != nil {
		return err
	}
	return writer.Flush()
}

func addDirToZip(zw *zip.Writer, relPath string, info stdfs.FileInfo) error {
	h, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	h.Name = filepath.ToSlash(relPath + "/")
	h.Method = zip.Store
	h.CreatorVersion = zipCompatibilityVersion
	h.ReaderVersion = zipCompatibilityVersion
	h.CompressedSize64 = h.UncompressedSize64

	_, err = zw.CreateRaw(h)
	return err
}

func addFileToZip(zw *zip.Writer, src fs.FS, fullPath, relPath string, info stdfs.FileInfo) (err error) {
	in, err := src.Open(fullPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := in.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	h, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	h.Name = filepath.ToSlash(relPath)
	h.Method = zip.Deflate
	h.CreatorVersion = zipCompatibilityVersion
	h.ReaderVersion = zipCompatibilityVersion

	zout, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}

	_, err = io.Copy(zout, in)
	return err
}
