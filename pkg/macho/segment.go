package macho

import (
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"resigner/pkg/utils"
)

//TODO: support editing sections

type Segment interface{}

type Section interface{}

const Segment32Size = int64(unsafe.Sizeof(Segment32CommandRaw{}))

type Segment32CommandRaw struct {
	BaseLoadCommandRaw
	SegName  [16]byte
	VMAddr   uint32
	VMSize   uint32
	FileOff  uint32
	FileSize uint32
	MaxProt  uint32
	InitProt uint32
	NSects   uint32
	Flags    uint32
}

type Segment32 struct {
	Segment32CommandRaw

	ByteOrder binary.ByteOrder

	Data Data

	Sections []*Section32
}

func (s *Segment32) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, Section32Size), s.ByteOrder, &s.Segment32CommandRaw)
	if err != nil {
		return err
	}

	err = walkFunc(&s.Data, func() error {
		s.Data = make(Data, s.FileSize)
		return s.Data.Decode(r, int64(s.FileOff), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read data: %w", err)
	}

	s.Sections = make([]*Section32, 0, s.NSects)
	sectionOffset := offset + Segment32Size
	for i := uint32(0); i < s.NSects; i++ {
		var section Section32
		section.ByteOrder = s.ByteOrder

		err := walkFunc(&section, func() error {
			return section.Decode(r, sectionOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		s.Sections = append(s.Sections, &section)

		offset += Section32Size
	}

	return nil
}

func (s *Segment32) Visit(walkFunc WalkFunc) error {
	err := walkFunc(&s.Data, func() error {
		return s.Data.Visit(walkFunc)
	})
	if err != nil {
		return err
	}

	for _, section := range s.Sections {
		err := walkFunc(section, func() error {
			return section.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Segment32) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(&s.Data, func() error {
		return s.Data.Encode(w, int64(s.FileOff), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not write data: %w", err)
	}

	s.FileSize = uint32(len(s.Data))
	if s.FileSize > s.VMSize {
		s.VMSize = (s.FileSize + (65536 - 1)) &^ (65536 - 1)
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, Segment32Size), s.ByteOrder, s.Segment32CommandRaw)
	if err != nil {
		return fmt.Errorf("could not write header: %w", err)
	}

	/* s.Sections = make([]*Section32, 0, s.NSects)
	sectionOffset := offset + Segment32Size
	for i := uint32(0); i < s.NSects; i++ {
		var section Section32
		section.ByteOrder = s.ByteOrder

		err := section.Decode(w, sectionOffset, walkFunc)
		if err != nil {
			return err
		}

		s.Sections = append(s.Sections, &section)

		sectionOffset += Section32Size
	}
	*/
	return nil
}

const Section32Size = int64(unsafe.Sizeof(Section32Raw{}))

type Section32Raw struct {
	SectName [16]byte
	SegName  [16]byte
	Addr     uint32
	Size     uint32
	Offset   uint32
	Align    uint32
	Reloff   uint32
	NReloc   uint32
	Flags    uint32

	Reserved1 uint32
	Reserved2 uint32
}

type Section32 struct {
	Section32Raw

	ByteOrder binary.ByteOrder

	Data Data
}

func (s *Section32) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, Section32Size), s.ByteOrder, &s.Section32Raw)
	if err != nil {
		return fmt.Errorf("could not read header: %w", err)
	}

	err = walkFunc(&s.Data, func() error {
		s.Data = make(Data, s.Size)
		return s.Data.Decode(r, int64(s.Offset), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read data: %w", err)
	}

	return nil
}

func (s *Section32) Visit(walkFunc WalkFunc) error {
	return walkFunc(&s.Data, func() error {
		return s.Data.Visit(walkFunc)
	})
}

func (s *Section32) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	return nil
}

const Segment64Size = int64(unsafe.Sizeof(Segment64CommandRaw{}))

type Segment64CommandRaw struct {
	BaseLoadCommandRaw
	SegName  [16]byte
	VMAddr   uint64
	VMSize   uint64
	FileOff  uint64
	FileSize uint64
	MaxProt  uint32
	InitProt uint32
	NSects   uint32
	Flags    uint32
}

type Segment64 struct {
	Segment64CommandRaw

	ByteOrder binary.ByteOrder

	Sections []*Section64

	Data Data
}

func (s *Segment64) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, Segment64Size), s.ByteOrder, &s.Segment64CommandRaw)
	if err != nil {
		return err
	}

	err = walkFunc(&s.Data, func() error {
		s.Data = make(Data, s.FileSize)
		return s.Data.Decode(io.NewSectionReader(r, int64(s.FileOff), int64(s.FileSize)), 0, walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read data: %w", err)
	}

	s.Sections = make([]*Section64, 0, s.NSects)
	sectionOffset := offset + Segment64Size
	for i := uint32(0); i < s.NSects; i++ {
		var section Section64
		section.ByteOrder = s.ByteOrder

		err := section.Decode(r, sectionOffset, walkFunc)
		if err != nil {
			return err
		}

		s.Sections = append(s.Sections, &section)

		sectionOffset += Section64Size
	}

	return nil
}

func (s *Segment64) Visit(walkFunc WalkFunc) error {
	err := walkFunc(&s.Data, func() error {
		return s.Data.Visit(walkFunc)
	})
	if err != nil {
		return err
	}

	for _, section := range s.Sections {
		err := walkFunc(section, func() error {
			return section.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Segment64) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(&s.Data, func() error {
		return s.Data.Encode(w, int64(s.FileOff), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not write data: %w", err)
	}

	s.FileSize = uint64(len(s.Data))
	if s.FileSize > s.VMSize {
		s.VMSize = (s.FileSize + (65536 - 1)) &^ (65536 - 1)
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, Segment64Size), s.ByteOrder, s.Segment64CommandRaw)
	if err != nil {
		return fmt.Errorf("could not write header: %w", err)
	}

	/* s.Sections = make([]*Section64, 0, s.NSects)
	sectionOffset := offset + Segment64Size
	for i := uint32(0); i < s.NSects; i++ {
		var section Section64
		section.ByteOrder = s.ByteOrder

		err := section.Decode(w, sectionOffset, walkFunc)
		if err != nil {
			return err
		}

		s.Sections = append(s.Sections, &section)

		sectionOffset += Section64Size
	}
	*/
	return nil
}

const Section64Size = int64(unsafe.Sizeof(Section64Raw{}))

type Section64Raw struct {
	SectName [16]byte
	SegName  [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	NReloc   uint32
	Flags    uint32

	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

type Section64 struct {
	Section64Raw

	ByteOrder binary.ByteOrder

	Data Data
}

func (s *Section64) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, Section64Size), s.ByteOrder, &s.Section64Raw)
	if err != nil {
		return fmt.Errorf("could not read header: %w", err)
	}

	err = walkFunc(&s.Data, func() error {
		s.Data = make(Data, s.Size)
		return s.Data.Decode(r, int64(s.Offset), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read data: %w", err)
	}

	return nil
}

func (s *Section64) Visit(walkFunc WalkFunc) error {
	return walkFunc(&s.Data, func() error {
		return s.Data.Visit(walkFunc)
	})
}

func (s *Section64) Encode(r io.WriterAt, offset int64, walkFunc WalkFunc) error {
	return nil
}
