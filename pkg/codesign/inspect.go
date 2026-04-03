package codesign

import (
	"path/filepath"
	"sort"
	"strings"

	"resigner/pkg/fs"
	"resigner/pkg/macho"
)

// BundlePrintEntry is a printable summary of a discovered bundle.
type BundlePrintEntry struct {
	Path           string
	BundleID       string
	CodeIdentifier string
	TeamID         string
	Certificate    string
}

// CollectBundlePrintEntries walks an app bundle and returns printable signing metadata.
func CollectBundlePrintEntries(root fs.ReadWriteFS, path string) ([]BundlePrintEntry, error) {
	entries := make([]BundlePrintEntry, 0)

	err := fs.WalkDir(root, path, func(subPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !d.IsDir() || !isInspectableBundleDir(subPath) {
			return nil
		}

		entry, entryErr := readBundlePrintEntry(root, subPath)
		if entryErr != nil {
			return entryErr
		}

		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	return entries, nil
}

func isInspectableBundleDir(path string) bool {
	return strings.HasSuffix(path, ".app") ||
		strings.HasSuffix(path, ".xctest") ||
		strings.HasSuffix(path, ".appex") ||
		strings.HasSuffix(path, ".framework")
}

func readBundlePrintEntry(root fs.ReadWriteFS, path string) (BundlePrintEntry, error) {
	_, info, _, err := readInfo(root, path, SigningConfig{})
	if err != nil {
		return BundlePrintEntry{}, err
	}

	entry := BundlePrintEntry{
		Path:     path,
		BundleID: info.BundleIdentifier,
	}

	if info.BundleExecutable != "" {
		_ = fillSignatureMetadata(root, filepath.Join(path, info.BundleExecutable), &entry)
	}

	return entry, nil
}

func fillSignatureMetadata(root fs.ReadWriteFS, executablePath string, entry *BundlePrintEntry) error {
	binFile, err := root.OpenRW(executablePath)
	if err != nil {
		return err
	}
	defer binFile.Close()

	bin, err := macho.Parse(binFile, 0)
	if err != nil {
		return err
	}

	sigInfo := extractSignatureInfoFromBinary(bin, &SigningConfig{})
	entry.CodeIdentifier = sigInfo.BundleID
	entry.TeamID = sigInfo.TeamID

	_ = bin.Visit(func(val macho.Struct, visit func() error) error {
		sig, ok := val.(*macho.CodeSignatureCMSSignatureBlob)
		if ok && sig != nil && sig.SignedData != nil && entry.Certificate == "" {
			certs, certErr := sig.SignedData.X509Certificates()
			if certErr == nil && len(certs) > 0 {
				entry.Certificate = certs[len(certs)-1].Subject.CommonName
			}
		}
		return visit()
	})

	return nil
}
