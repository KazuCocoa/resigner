package macho

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"resigner/pkg/requirements"
	"resigner/pkg/utils"
)

const (
	FatMagic32 = 0xcafebabe
	FatCigam32 = 0xbebafeca

	FatMagic64 = 0xcafebabf
	FatCigam64 = 0xbfbafeca
)

type Fat interface {
	Struct

	Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error
}
type FatArch interface {
	Struct
}

const FatSize = int64(unsafe.Sizeof(FatRaw{}))

type FatRaw struct {
	Magic    uint32
	NFatArch uint32
}

type Fat32 struct {
	FatRaw

	ByteOrder binary.ByteOrder

	Archs []*FatArch32
}

func (h *Fat32) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return err
	}

	switch magic {
	case FatMagic32:
		h.ByteOrder = binary.BigEndian
	case FatCigam32:
		h.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, FatSize), h.ByteOrder, &h.FatRaw)
	if err != nil {
		return err
	}

	archOffset := FatSize
	for i := 0; i < int(h.NFatArch); i++ {
		var arch FatArch32
		arch.ByteOrder = h.ByteOrder

		err := walkFunc(&arch, func() error {
			return arch.Decode(r, archOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		h.Archs = append(h.Archs, &arch)

		archOffset += FatArch32Size
	}

	return nil
}

func (c *Fat32) Visit(walkFunc WalkFunc) error {
	for _, arch := range c.Archs {
		err := walkFunc(arch, func() error {
			return arch.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *Fat32) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	h.NFatArch = uint32(len(h.Archs))

	archHeaderOffset := FatSize

	archOffset := FatSize + (int64(h.NFatArch) * FatArch32Size)
	for _, arch := range h.Archs {
		align := int64(1 << arch.Align)
		mask := align - 1

		var loadCommands []LoadCommand
		switch header := arch.Header.(type) {
		case *Header32:
			loadCommands = header.LoadCommands
		case *Header64:
			loadCommands = header.LoadCommands
		}

		var maxArchSize int64
		for _, lc := range loadCommands {
			var segmentEnd int64
			switch lc := lc.(type) {
			case *Segment32:
				segmentEnd = int64(lc.FileOff) + int64(lc.FileSize)
			case *Segment64:
				segmentEnd = int64(lc.FileOff) + int64(lc.FileSize)
			}

			if segmentEnd > maxArchSize {
				maxArchSize = segmentEnd
			}
		}

		arch.Offset = uint32(archOffset + ((-archOffset) & mask))
		arch.Size = uint32(maxArchSize)
		err := walkFunc(arch, func() error {
			return arch.Encode(w, archHeaderOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		archOffset = int64(arch.Offset) + int64(arch.Size) + ((-int64(arch.Size)) & mask)
		archHeaderOffset += FatArch32Size
	}

	err := binary.Write(utils.NewSectionWriter(w, offset, FatSize), h.ByteOrder, h.FatRaw)
	if err != nil {
		return err
	}

	return nil
}

func (h *Fat32) Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error {
	for _, arch := range h.Archs {
		err := arch.Header.Sign(key, chain, entitlements, reqs, walkFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

const FatArch32Size = int64(unsafe.Sizeof(FatArch32Raw{}))

type FatArch32Raw struct {
	CPUType    uint32
	CPUSubType uint32
	Offset     uint32
	Size       uint32
	Align      uint32
}

type FatArch32 struct {
	FatArch32Raw

	ByteOrder binary.ByteOrder

	Header Header
}

func (h *FatArch32) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, int64(FatArch32Size)), h.ByteOrder, &h.FatArch32Raw)
	if err != nil {
		return err
	}

	magic, err := readMagic(r, int64(h.Offset))
	if err != nil {
		return fmt.Errorf("could not read mach-o magic: %w", err)
	}

	switch magic {
	case MachoMagic32, MachoCigam32:
		var header Header32

		err := walkFunc(&header, func() error {
			return header.Decode(io.NewSectionReader(r, int64(h.Offset), int64(h.Size)), 0, walkFunc)
		})
		if err != nil {
			return fmt.Errorf("could not decode 32-bit mach-o header: %w", err)
		}

		h.Header = &header
	case MachoMagic64, MachoCigam64:
		var header Header64
		err := walkFunc(&header, func() error {
			return header.Decode(io.NewSectionReader(r, int64(h.Offset), int64(h.Size)), 0, walkFunc)
		})
		if err != nil {
			return fmt.Errorf("could not decode 64-bit mach-o header: %w", err)
		}

		h.Header = &header
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	return nil
}

func (c *FatArch32) Visit(walkFunc WalkFunc) error {
	return walkFunc(c.Header, func() error {
		return c.Header.Visit(walkFunc)
	})
}

func (h *FatArch32) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(h.Header, func() error {
		return h.Header.Encode(utils.NewSectionWriter(w, int64(h.Offset), int64(h.Size)), 0, walkFunc)
	})
	if err != nil {
		return err
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, int64(FatArch32Size)), h.ByteOrder, &h.FatArch32Raw)
	if err != nil {
		return err
	}
	return nil
}

type Fat64 struct {
	FatRaw

	ByteOrder binary.ByteOrder

	Archs []*FatArch64
}

func (h *Fat64) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return err
	}

	switch magic {
	case FatMagic32:
		h.ByteOrder = binary.BigEndian
	case FatCigam32:
		h.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, FatSize), h.ByteOrder, &h.FatRaw)
	if err != nil {
		return err
	}

	archOffset := FatSize
	for i := 0; i < int(h.NFatArch); i++ {
		var arch FatArch64
		arch.ByteOrder = h.ByteOrder

		err := walkFunc(&arch, func() error {
			return arch.Decode(r, archOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		h.Archs = append(h.Archs, &arch)

		archOffset += FatArch32Size
	}

	return nil
}

func (c *Fat64) Visit(walkFunc WalkFunc) error {
	for _, arch := range c.Archs {
		err := walkFunc(arch, func() error {
			return arch.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *Fat64) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	h.NFatArch = uint32(len(h.Archs))

	archHeaderOffset := FatSize
	archOffset := FatSize + (int64(h.NFatArch) * FatArch32Size)
	for _, arch := range h.Archs {
		align := int64(1 << arch.Align)
		mask := align - 1

		arch.Offset = uint64(archOffset + ((-archOffset) & mask))
		err := walkFunc(arch, func() error {
			return arch.Encode(w, archHeaderOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		var loadCommands []LoadCommand
		switch header := arch.Header.(type) {
		case *Header32:
			loadCommands = header.LoadCommands
		case *Header64:
			loadCommands = header.LoadCommands
		}

		var maxArchSize int64
		for _, lc := range loadCommands {
			var segmentEnd int64
			switch lc := lc.(type) {
			case *Segment32:
				segmentEnd = int64(lc.FileOff) + int64(lc.FileSize)
			case *Segment64:
				segmentEnd = int64(lc.FileOff) + int64(lc.FileSize)
			}

			if segmentEnd > maxArchSize {
				maxArchSize = segmentEnd
			}
		}
		arch.Size = uint64(maxArchSize)
		archOffset = int64(arch.Offset) + int64(arch.Size) + ((-int64(arch.Size)) & mask)

		archHeaderOffset += FatArch32Size
	}

	err := binary.Write(utils.NewSectionWriter(w, offset, FatSize), h.ByteOrder, h.FatRaw)
	if err != nil {
		return err
	}

	return nil
}

func (h *Fat64) Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error {
	for _, arch := range h.Archs {
		err := arch.Header.Sign(key, chain, entitlements, reqs, walkFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

const FatArch64Size = unsafe.Sizeof(FatArch64Raw{})

type FatArch64Raw struct {
	CPUType    uint32
	CPUSubType uint32
	Offset     uint64
	Size       uint64
	Align      uint32
	Reserved   uint32
}

type FatArch64 struct {
	FatArch64Raw

	ByteOrder binary.ByteOrder

	Header Header
}

func (h *FatArch64) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, int64(FatArch64Size)), h.ByteOrder, &h.FatArch64Raw)
	if err != nil {
		return err
	}

	magic, err := readMagic(r, int64(h.Offset))
	if err != nil {
		return err
	}

	switch magic {
	case MachoMagic32, MachoCigam32:
		var header Header32

		err := walkFunc(&header, func() error {
			return header.Decode(io.NewSectionReader(r, int64(h.Offset), int64(h.Size)), 0, walkFunc)
		})
		if err != nil {
			return err
		}

		h.Header = &header
	case MachoMagic64, MachoCigam64:
		var header Header64

		err := walkFunc(&header, func() error {
			return header.Decode(io.NewSectionReader(r, int64(h.Offset), int64(h.Size)), 0, walkFunc)
		})
		if err != nil {
			return err
		}

		h.Header = &header
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	return nil
}

func (c *FatArch64) Visit(walkFunc WalkFunc) error {
	return walkFunc(c.Header, func() error {
		return c.Header.Visit(walkFunc)
	})
}

func (h *FatArch64) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(h.Header, func() error {
		return h.Header.Encode(utils.NewSectionWriter(w, int64(h.Offset), int64(h.Size)), 0, walkFunc)
	})
	if err != nil {
		return err
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, int64(FatArch64Size)), h.ByteOrder, &h.FatArch64Raw)
	if err != nil {
		return err
	}
	return nil
}
