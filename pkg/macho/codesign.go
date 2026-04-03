package macho

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
	"unsafe"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"howett.net/plist"

	"resigner/pkg/der"
	"resigner/pkg/requirements"
	"resigner/pkg/utils"
)

func codeSignatureDigestBlob(blob CodeSignatureBlob, hash crypto.Hash) ([]byte, error) {
	var buf Data
	hsh := hash.New()
	err := blob.Encode(&buf, 0, NewWalkFunc(&DefaultWalker{}))
	if err != nil {
		return nil, fmt.Errorf("could not encode blob: %w", err)
	}

	_, err = io.Copy(hsh, io.NewSectionReader(&buf, 0, int64(buf.Len())))
	if err != nil {
		return nil, fmt.Errorf("could not create digest: %w", err)
	}

	return hsh.Sum(nil), nil
}

const (
	CodeSignatureMagicRequirement = 0xfade0c00
	CodeSignatureCigamRequirement = 0x000cdefa

	CodeSignatureMagicRequirements = 0xfade0c01
	CodeSignatureCigamRequirements = 0x010cdefa

	CodeSignatureMagicCodeDirectory = 0xfade0c02
	CodeSignatureCigamCodeDirectory = 0x020cdefa

	CodeSignatureMagicEmbeddedSignature = 0xfade0cc0
	CodeSignatureCigamEmbeddedSignature = 0xc00cdefa

	CodeSignatureMagicDetachedSignature = 0xfade0cc1
	CodeSignatureCigamDetachedSignature = 0xc10cdefa

	CodeSignatureMagicEntitlements = 0xfade7171
	CodeSignatureCigamEntitlements = 0x7171defa

	CodeSignatureMagicEntitlementsDER = 0xfade7172
	CodeSignatureCigamEntitlementsDER = 0x7271defa

	CodeSignatureMagicBlobWrapper = 0xfade0b01
	CodeSignatureCigamBlobWrapper = 0x010bdefa
)

const (
	CodeSignatureSlotKindCodeDirectory   = 0
	CodeSignatureSlotKindInfo            = 1
	CodeSignatureSlotKindRequirements    = 2
	CodeSignatureSlotKindResourceDir     = 3
	CodeSignatureSlotKindApplication     = 4
	CodeSignatureSlotKindEntitlements    = 5
	CodeSignatureSlotKindEntitlementsDER = 7

	CodeSignatureSlotKindAlternateCodeDirectory = 0x1000
	CodeSignatureSlotKindCMSSignature           = 0x10000
)

const CodeSignatureSize = int64(unsafe.Sizeof(CodeSignatureRaw{}))

type CodeSignatureRaw LinkedITDataCommandRaw

type CodeSignature struct {
	CodeSignatureRaw

	ByteOrder binary.ByteOrder

	EmbeddedSignature CodeSignatureEmbeddedSignatureBlob
}

func (c *CodeSignature) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureSize), c.ByteOrder, &c.CodeSignatureRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	err = walkFunc(&c.EmbeddedSignature, func() error {
		return c.EmbeddedSignature.Decode(r, int64(c.DataOff), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not decode super blob: %w", err)
	}

	return nil
}

func (c *CodeSignature) Visit(walkFunc WalkFunc) error {
	return walkFunc(&c.EmbeddedSignature, func() error {
		return c.EmbeddedSignature.Visit(walkFunc)
	})
}

func (c *CodeSignature) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Cmd = LoadCommandKindCodeSignature
	c.CmdSize = uint32(CodeSignatureSize)

	err := walkFunc(&c.EmbeddedSignature, func() error {
		return c.EmbeddedSignature.Encode(w, int64(c.DataOff), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not encode super blob: %w", err)
	}

	c.DataSize = uint32(c.EmbeddedSignature.Size())

	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureSize), c.ByteOrder, c.CodeSignatureRaw)
	if err != nil {
		return fmt.Errorf("could not encode header: %w", err)
	}

	return nil
}

func (c *CodeSignature) Allocate(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, data []byte) error {
	c.EmbeddedSignature.ByteOrder = binary.BigEndian // NOTE: seems to be required
	c.EmbeddedSignature.Blobs = nil

	codeLimit := uint64(len(data))

	pageSize := 12
	nCodeSlots := (codeLimit + ((1 << pageSize) - 1)) / uint64(1<<pageSize)

	specialSlots := make(map[uint32]CodeSignatureBlob)
	nSpecialSlots := 7

	codeDirectory := &CodeSignatureCodeDirectoryBlob{}
	codeDirectory.ByteOrder = c.EmbeddedSignature.ByteOrder
	codeDirectory.HashType = crypto.SHA1

	codeDirectory.Flags = 0
	codeDirectory.Version = CodeSignatureCodeDirectorySupportsExecSeg
	codeDirectory.NSpecialSlots = 7
	codeDirectory.NCodeSlots = uint32(nCodeSlots)
	codeDirectory.Hashes = make(map[int][]byte)

	codeDirectory.PageSize = uint8(pageSize)
	codeDirectory.CodeLimit = uint32(codeLimit)
	codeDirectory.CodeLimit64 = codeLimit

	codeDirectory.SpecialSlots = specialSlots

	c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
		&CodeSignatureBlobIndex{
			CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
				Type: CodeSignatureSlotKindCodeDirectory,
			},
			ByteOrder: c.EmbeddedSignature.ByteOrder,
			Blob:      codeDirectory,
		})

	for i := -int(nSpecialSlots); i < int(nCodeSlots); i++ {
		codeDirectory.Hashes[i] = make([]byte, codeDirectory.HashType.Size())
	}

	if reqs != nil {
		requirementsBlob := &CodeSignatureRequirementsBlob{
			CodeSignatureSuperBlob: CodeSignatureSuperBlob{ByteOrder: c.EmbeddedSignature.ByteOrder},
			Requirements:           reqs,
		}

		specialSlots[CodeSignatureSlotKindRequirements] = requirementsBlob

		c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
			&CodeSignatureBlobIndex{
				CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
					Type: CodeSignatureSlotKindRequirements,
				},
				ByteOrder: c.EmbeddedSignature.ByteOrder,
				Blob:      requirementsBlob,
			})
	}

	if entitlements != nil {
		entitlementsBlob := &CodeSignatureEntitlementsBlob{
			ByteOrder:    c.EmbeddedSignature.ByteOrder,
			Entitlements: entitlements,
		}

		specialSlots[CodeSignatureSlotKindEntitlements] = entitlementsBlob

		c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
			&CodeSignatureBlobIndex{
				CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
					Type: CodeSignatureSlotKindEntitlements,
				},
				ByteOrder: c.EmbeddedSignature.ByteOrder,
				Blob:      entitlementsBlob,
			})

		entitlementsDERBlob := &CodeSignatureEntitlementsDERBlob{
			ByteOrder:    c.EmbeddedSignature.ByteOrder,
			Entitlements: entitlements,
		}

		specialSlots[CodeSignatureSlotKindEntitlementsDER] = entitlementsDERBlob

		c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
			&CodeSignatureBlobIndex{
				CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
					Type: CodeSignatureSlotKindEntitlementsDER,
				},
				ByteOrder: c.EmbeddedSignature.ByteOrder,
				Blob:      entitlementsDERBlob,
			})
	}

	alternateCodeDirectory := &CodeSignatureCodeDirectoryBlob{}
	alternateCodeDirectory.ByteOrder = c.EmbeddedSignature.ByteOrder
	alternateCodeDirectory.HashType = crypto.SHA256

	alternateCodeDirectory.Flags = 0
	alternateCodeDirectory.Version = CodeSignatureCodeDirectorySupportsExecSeg
	alternateCodeDirectory.NSpecialSlots = 7
	alternateCodeDirectory.NCodeSlots = uint32(nCodeSlots)
	alternateCodeDirectory.Hashes = make(map[int][]byte)

	alternateCodeDirectory.PageSize = uint8(pageSize)
	alternateCodeDirectory.CodeLimit = uint32(codeLimit)
	alternateCodeDirectory.CodeLimit64 = codeLimit

	alternateCodeDirectory.SpecialSlots = specialSlots

	for i := -int(nSpecialSlots); i < int(nCodeSlots); i++ {
		alternateCodeDirectory.Hashes[i] = make([]byte, alternateCodeDirectory.HashType.Size())
	}

	c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
		&CodeSignatureBlobIndex{
			CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
				Type: CodeSignatureSlotKindAlternateCodeDirectory,
			},
			ByteOrder: c.EmbeddedSignature.ByteOrder,
			Blob:      alternateCodeDirectory,
		})

	cmsSignature := &CodeSignatureCMSSignatureBlob{
		CodeSignatureBlobWrapperBlob: CodeSignatureBlobWrapperBlob{ByteOrder: c.EmbeddedSignature.ByteOrder},
	}

	c.EmbeddedSignature.Blobs = append(c.EmbeddedSignature.Blobs,
		&CodeSignatureBlobIndex{
			CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
				Type: CodeSignatureSlotKindCMSSignature,
			},
			ByteOrder: c.EmbeddedSignature.ByteOrder,
			Blob:      cmsSignature,
		})

	return nil
}

func (c *CodeSignature) Sign(key crypto.Signer, chain []*x509.Certificate, data []byte) error {
	var codeDirectories []*CodeSignatureCodeDirectoryBlob
	err := c.EmbeddedSignature.Visit(func(val Struct, visit func() error) error {
		switch val := val.(type) {
		case *CodeSignatureCodeDirectoryBlob:
			for i := 0; i < int(val.NCodeSlots); i++ {
				hsh := val.HashType.New()
				if (i+1)*(1<<val.PageSize) <= len(data) {
					_, err := hsh.Write(data[i*(1<<val.PageSize) : (i+1)*(1<<val.PageSize)])
					if err != nil {
						return err
					}
				} else {
					_, err := hsh.Write(data[i*(1<<val.PageSize):])
					if err != nil {
						return err
					}
				}
				val.Hashes[i] = hsh.Sum(nil)
			}
			codeDirectories = append(codeDirectories, val)
		case *CodeSignatureCMSSignatureBlob:
			err := val.Sign(key, chain, codeDirectories)
			if err != nil {
				return err
			}
		}

		return visit()
	})
	if err != nil {
		return err
	}
	return nil
}

const CodeSignatureSuperBlobSize = int64(unsafe.Sizeof(CodeSignatureSuperBlobRaw{}))

type CodeSignatureSuperBlobRaw struct {
	CodeSignatureBaseBlobRaw

	Count uint32
}

type CodeSignatureSuperBlob struct {
	CodeSignatureSuperBlobRaw

	magic, cigam uint32
	factory      func(uint32, uint32) CodeSignatureBlob

	ByteOrder binary.ByteOrder

	Blobs []*CodeSignatureBlobIndex
}

func (c *CodeSignatureSuperBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return err
	}

	switch magic {
	case c.magic:
		c.ByteOrder = binary.BigEndian
	case c.cigam:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureSuperBlobSize), c.ByteOrder, &c.CodeSignatureSuperBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	specialSlots := make(map[uint32]CodeSignatureBlob)

	blobOffset := CodeSignatureSuperBlobSize
	for i := uint32(0); i < c.Count; i++ {
		var blobIndex CodeSignatureBlobIndex
		blobIndex.ByteOrder = c.ByteOrder
		blobIndex.factory = c.factory

		err := walkFunc(&blobIndex, func() error {
			return blobIndex.Decode(io.NewSectionReader(r, offset, int64(c.Length)), blobOffset, walkFunc)
		})

		if err != nil {
			return fmt.Errorf("could not decode blob index: %w", err)
		}

		specialSlots[blobIndex.Type] = blobIndex.Blob

		switch blob := blobIndex.Blob.(type) {
		case *CodeSignatureCodeDirectoryBlob:
			delete(specialSlots, blobIndex.Type)
			blob.SpecialSlots = specialSlots
		case *CodeSignatureCMSSignatureBlob:
			delete(specialSlots, blobIndex.Type)
		}

		c.Blobs = append(c.Blobs, &blobIndex)

		blobOffset += CodeSignatureBlobIndexSize
	}

	return nil
}

func (c *CodeSignatureSuperBlob) Visit(walkFunc WalkFunc) error {
	for _, blobIndex := range c.Blobs {
		err := walkFunc(blobIndex, func() error {
			return blobIndex.Visit(walkFunc)
		})

		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CodeSignatureSuperBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Count = uint32(len(c.Blobs))

	blobIndexOffset := CodeSignatureSuperBlobSize
	blobOffset := CodeSignatureSuperBlobSize + (CodeSignatureBlobIndexSize * int64(c.Count))
	for _, blobIndex := range c.Blobs {
		blobIndex.Offset = uint32(blobOffset)

		err := walkFunc(blobIndex, func() error {
			return blobIndex.Encode(utils.NewSectionWriter(w, offset, 1<<32 /*no real limit here*/), blobIndexOffset, walkFunc)
		})
		if err != nil {
			return fmt.Errorf("could not encode blob index: %w", err)
		}

		blobOffset += blobIndex.Blob.Size()

		blobIndexOffset += CodeSignatureBlobIndexSize
	}

	c.Length = uint32(blobOffset)

	err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureSuperBlobSize), c.ByteOrder, c.CodeSignatureSuperBlobRaw)
	if err != nil {
		return fmt.Errorf("could not encode header: %w", err)
	}

	return nil
}

type CodeSignatureEmbeddedSignatureBlob struct {
	CodeSignatureSuperBlob
}

func (c *CodeSignatureEmbeddedSignatureBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	c.magic = CodeSignatureMagicEmbeddedSignature
	c.cigam = CodeSignatureCigamEmbeddedSignature
	c.factory = func(typ uint32, magic uint32) CodeSignatureBlob {
		switch typ {
		case CodeSignatureSlotKindCodeDirectory, CodeSignatureSlotKindAlternateCodeDirectory:
			return new(CodeSignatureCodeDirectoryBlob)
		case CodeSignatureSlotKindRequirements:
			switch magic {
			case CodeSignatureMagicRequirements, CodeSignatureCigamRequirements:
				return new(CodeSignatureRequirementsBlob)
			case CodeSignatureMagicRequirement, CodeSignatureCigamRequirement:
				return new(CodeSignatureRequirementBlob)
			}
		case CodeSignatureSlotKindEntitlements:
			return new(CodeSignatureEntitlementsBlob)
		case CodeSignatureSlotKindEntitlementsDER:
			return new(CodeSignatureEntitlementsDERBlob)
		case CodeSignatureSlotKindCMSSignature:
			return new(CodeSignatureCMSSignatureBlob)
		}

		return new(CodeSignatureBaseBlob)
	}

	return c.CodeSignatureSuperBlob.Decode(r, offset, walkFunc)
}

func (c *CodeSignatureEmbeddedSignatureBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicEmbeddedSignature

	err := c.CodeSignatureSuperBlob.Encode(w, offset, walkFunc)
	if err != nil {
		return err
	}

	return nil
}

const CodeSignatureBlobIndexSize = int64(unsafe.Sizeof(CodeSignatureBlobIndexRaw{}))

type CodeSignatureBlobIndexRaw struct {
	Type   uint32
	Offset uint32
}

type CodeSignatureBlobIndex struct {
	CodeSignatureBlobIndexRaw

	factory func(uint32, uint32) CodeSignatureBlob

	ByteOrder binary.ByteOrder

	Blob CodeSignatureBlob
}

func (c *CodeSignatureBlobIndex) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureBlobIndexSize), c.ByteOrder, &c.CodeSignatureBlobIndexRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	blobMagic, err := readMagic(r, int64(c.Offset))
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	blob := c.factory(c.Type, blobMagic)
	err = walkFunc(blob, func() error {
		return blob.Decode(r, int64(c.Offset), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read blob: %w", err)
	}
	c.Blob = blob

	return nil
}

func (c *CodeSignatureBlobIndex) Visit(walkFunc WalkFunc) error {
	return walkFunc(c.Blob, func() error {
		return c.Blob.Visit(walkFunc)
	})
}

func (c *CodeSignatureBlobIndex) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(c.Blob, func() error {
		return c.Blob.Encode(w, int64(c.Offset), walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not encode blob: %w", err)
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureBlobIndexSize), c.ByteOrder, c.CodeSignatureBlobIndexRaw)
	if err != nil {
		return fmt.Errorf("could not encode header: %w", err)
	}

	return nil
}

type CodeSignatureBlob interface {
	Struct

	Size() int64
}

const CodeSignatureBaseBlobSize = int64(unsafe.Sizeof(CodeSignatureBaseBlobRaw{}))

type CodeSignatureBaseBlobRaw struct {
	Magic  uint32
	Length uint32
}

func (b *CodeSignatureBaseBlobRaw) Size() int64 {
	return int64(b.Length)
}

type CodeSignatureBaseBlob struct {
	CodeSignatureBaseBlobRaw

	ByteOrder binary.ByteOrder

	Rest Data
}

func (c *CodeSignatureBaseBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureBaseBlobSize), c.ByteOrder, &c.CodeSignatureBaseBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	err = walkFunc(&c.Rest, func() error {
		c.Rest = make(Data, int64(c.Length)-CodeSignatureBaseBlobSize)
		return c.Rest.Decode(r, offset+CodeSignatureBaseBlobSize, walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not decode data: %w", err)
	}

	return nil
}

func (c *CodeSignatureBaseBlob) Visit(walkFunc WalkFunc) error {
	return walkFunc(&c.Rest, func() error {
		return c.Rest.Visit(walkFunc)
	})
}

func (c *CodeSignatureBaseBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureBaseBlobSize), c.ByteOrder, c.CodeSignatureBaseBlobRaw)
	if err != nil {
		return fmt.Errorf("could not encode header: %w", err)
	}

	err = walkFunc(&c.Rest, func() error {
		return c.Rest.Encode(w, offset+CodeSignatureBaseBlobSize, walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not encode data: %w", err)
	}

	return nil
}

type CodeSignatureCodeDirectoryVersion uint32

const (
	CodeSignatureCodeDirectoryEarliest            CodeSignatureCodeDirectoryVersion = 0x20000
	CodeSignatureCodeDirectorySupportsScatter     CodeSignatureCodeDirectoryVersion = 0x20100
	CodeSignatureCodeDirectorySupportsTeamID      CodeSignatureCodeDirectoryVersion = 0x20200
	CodeSignatureCodeDirectorySupportsCodeLimit64 CodeSignatureCodeDirectoryVersion = 0x20300
	CodeSignatureCodeDirectorySupportsExecSeg     CodeSignatureCodeDirectoryVersion = 0x20400
	CodeSignatureCodeDirectorySupportsRuntime     CodeSignatureCodeDirectoryVersion = 0x20500
	CodeSignatureCodeDirectorySupportsLinkage     CodeSignatureCodeDirectoryVersion = 0x20600
)

const (
	CodeSignatureCodeDirectoryBlobSizeEarliestVersion            = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobEarliest{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsScatterVersion     = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsScatter{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsTeamIDVersion      = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsTeamID{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsCodeLimit64Version = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsCodeLimit64{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsExecSegVersion     = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsExecSeg{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsRuntimeVersion     = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsRuntime{}))
	CodeSignatureCodeDirectoryBlobSizeSupportsLinkageVersion     = int64(unsafe.Sizeof(CodeSignatureCodeDirectoryBlobSupportsLinkage{}))
)

const (
	CodeSignatureCodeDirectoryFlagHost              = 0x00000001
	CodeSignatureCodeDirectoryFlagAdhoc             = 0x00000002
	CodeSignatureCodeDirectoryFlagForceHard         = 0x00000100
	CodeSignatureCodeDirectoryFlagForceKill         = 0x00000200
	CodeSignatureCodeDirectoryFlagForceExpiration   = 0x00000400
	CodeSignatureCodeDirectoryFlagRestrict          = 0x00000800
	CodeSignatureCodeDirectoryFlagEnforcement       = 0x00001000
	CodeSignatureCodeDirectoryFlagLibraryValidation = 0x00002000
	CodeSignatureCodeDirectoryFlagRuntime           = 0x00010000
	CodeSignatureCodeDirectoryFlagLinkerSigned      = 0x00020000
)

func (v CodeSignatureCodeDirectoryVersion) Normalize() CodeSignatureCodeDirectoryVersion {
	if v >= CodeSignatureCodeDirectorySupportsLinkage {
		return 0
	} else if v >= CodeSignatureCodeDirectorySupportsRuntime {
		return CodeSignatureCodeDirectorySupportsRuntime
	} else if v >= CodeSignatureCodeDirectorySupportsExecSeg {
		return CodeSignatureCodeDirectorySupportsExecSeg
	} else if v >= CodeSignatureCodeDirectorySupportsCodeLimit64 {
		return CodeSignatureCodeDirectorySupportsCodeLimit64
	} else if v >= CodeSignatureCodeDirectorySupportsTeamID {
		return CodeSignatureCodeDirectorySupportsTeamID
	} else if v >= CodeSignatureCodeDirectorySupportsScatter {
		return CodeSignatureCodeDirectorySupportsScatter
	} else if v >= CodeSignatureCodeDirectoryEarliest {
		return CodeSignatureCodeDirectoryEarliest
	}

	return 0
}

func (v CodeSignatureCodeDirectoryVersion) Size() int64 {
	switch v.Normalize() {
	case CodeSignatureCodeDirectoryEarliest:
		return CodeSignatureCodeDirectoryBlobSizeEarliestVersion
	case CodeSignatureCodeDirectorySupportsScatter:
		return CodeSignatureCodeDirectoryBlobSizeSupportsScatterVersion
	case CodeSignatureCodeDirectorySupportsTeamID:
		return CodeSignatureCodeDirectoryBlobSizeSupportsTeamIDVersion
	case CodeSignatureCodeDirectorySupportsCodeLimit64:
		return CodeSignatureCodeDirectoryBlobSizeSupportsCodeLimit64Version
	case CodeSignatureCodeDirectorySupportsExecSeg:
		return CodeSignatureCodeDirectoryBlobSizeSupportsExecSegVersion
	case CodeSignatureCodeDirectorySupportsRuntime:
		return CodeSignatureCodeDirectoryBlobSizeSupportsRuntimeVersion
	case CodeSignatureCodeDirectorySupportsLinkage:
		return CodeSignatureCodeDirectoryBlobSizeSupportsLinkageVersion
	}

	return 0
}

type CodeSignatureCodeDirectoryBlobEarliest struct {
	CodeSignatureBaseBlobRaw

	Version       CodeSignatureCodeDirectoryVersion
	Flags         uint32
	HashOffset    uint32
	IdentOffset   uint32
	NSpecialSlots uint32
	NCodeSlots    uint32
	CodeLimit     uint32
	HashSize      uint8
	HashType      uint8
	Spare1        uint8
	PageSize      uint8
	Spare2        uint32
}

type CodeSignatureCodeDirectoryBlobSupportsScatter struct {
	CodeSignatureCodeDirectoryBlobEarliest

	ScatterOffset uint32
}

type CodeSignatureCodeDirectoryBlobSupportsTeamID struct {
	CodeSignatureCodeDirectoryBlobSupportsScatter

	TeamIDOffset uint32
}

type CodeSignatureCodeDirectoryBlobSupportsCodeLimit64 struct {
	CodeSignatureCodeDirectoryBlobSupportsTeamID

	Spare3      uint32
	CodeLimit64 uint64
}

type CodeSignatureCodeDirectoryBlobSupportsExecSeg struct {
	CodeSignatureCodeDirectoryBlobSupportsCodeLimit64

	ExecSegBase  uint64
	ExecSegLimit uint64
	ExecSegFlags uint64
}

func (c *CodeSignatureCodeDirectoryBlobSupportsExecSeg) setupExecSegFlags(mainBinary bool, entitlements Entitlements) {
	c.ExecSegFlags = 0x0

	if !mainBinary {
		return
	}

	// https://opensource.apple.com/source/Security/Security-59754.80.3/OSX/libsecurity_codesigning/lib/signer.cpp
	c.ExecSegFlags |= 0x1

	if flag, ok := entitlements["get-task-allow"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0010
	}
	if flag, ok := entitlements["run-unsigned-code"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0010
	}
	if flag, ok := entitlements["com.apple.private.cs.debugger"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0020
	}
	if flag, ok := entitlements["dynamic-codesigning"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0040
	}
	if flag, ok := entitlements["com.apple.private.skip-library-validation"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0080
	}
	if flag, ok := entitlements["com.apple.private.amfi.can-load-cdhash"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0100
	}
	if flag, ok := entitlements["com.apple.private.amfi.can-execute-cdhash"].(bool); ok && flag {
		c.ExecSegFlags |= 0x0200
	}
}

type CodeSignatureCodeDirectoryBlobSupportsRuntime struct {
	CodeSignatureCodeDirectoryBlobSupportsExecSeg

	Runtime          uint32
	PreEncryptOffset uint32
}

type CodeSignatureCodeDirectoryBlobSupportsLinkage struct {
	CodeSignatureCodeDirectoryBlobSupportsRuntime

	LinkageHashType  uint8
	LinkageTruncated uint8
	Spare4           uint16
	LinkageOffset    uint32
	LinkageSize      uint32
}

type CodeSignatureCodeDirectoryBlob struct {
	CodeSignatureCodeDirectoryBlobSupportsLinkage

	ByteOrder binary.ByteOrder

	SpecialSlots map[uint32]CodeSignatureBlob

	HashType   crypto.Hash
	Hashes     map[int][]byte
	Identifier string
	TeamID     string
	Linkage    []byte
}

func (c *CodeSignatureCodeDirectoryBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	switch magic {
	case CodeSignatureMagicCodeDirectory:
		c.ByteOrder = binary.BigEndian
	case CodeSignatureCigamCodeDirectory:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeEarliestVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobEarliest)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	data, err := io.ReadAll(io.NewSectionReader(r, offset, int64(c.Length)))
	if err != nil {
		return fmt.Errorf("could not read header: %w", err)
	}

	identLen := clen(data[c.IdentOffset:])

	c.Identifier = string(data[c.IdentOffset : c.IdentOffset+uint32(identLen)])

	c.Hashes = make(map[int][]byte)

	for i := -int64(c.NSpecialSlots); i < int64(c.NCodeSlots); i++ {
		hashOffset := int64(c.HashOffset) + (i * int64(c.HashSize))

		c.Hashes[int(i)] = append([]byte{}, data[hashOffset:hashOffset+int64(c.HashSize)]...)
	}

	switch c.CodeSignatureCodeDirectoryBlobEarliest.HashType {
	case 1:
		c.HashType = crypto.SHA1
	case 2:
		c.HashType = crypto.SHA256
	}

	if c.Version > CodeSignatureCodeDirectorySupportsLinkage {
		return fmt.Errorf("code directory version too new")
	} else if c.Version < CodeSignatureCodeDirectoryEarliest {
		return fmt.Errorf("code directory version too old")
	}

	switch c.Version.Normalize() {
	case CodeSignatureCodeDirectoryEarliest:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeEarliestVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobEarliest)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsScatter:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsScatterVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsScatter)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsTeamID:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsTeamIDVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsTeamID)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsCodeLimit64:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsCodeLimit64Version), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsCodeLimit64)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsExecSeg:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsExecSegVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsExecSeg)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsRuntime:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsRuntimeVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsRuntime)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsLinkage:
		err := binary.Read(io.NewSectionReader(r, offset, CodeSignatureCodeDirectoryBlobSizeSupportsLinkageVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsLinkage)
		if err != nil {
			return fmt.Errorf("could not decode header: %w", err)
		}
	}

	if c.Version >= CodeSignatureCodeDirectorySupportsTeamID {
		if c.TeamIDOffset != 0 {
			teamIDLen := clen(data[c.TeamIDOffset:])

			c.TeamID = string(data[c.TeamIDOffset : c.TeamIDOffset+uint32(teamIDLen)])
		} else {
			c.TeamID = ""
		}
	}

	if c.ScatterOffset != 0 {
		return fmt.Errorf("scatter vector not yet supported")
	}

	if c.PreEncryptOffset != 0 {
		return fmt.Errorf("preencryption offset not yet supported")
	}

	if c.Version >= CodeSignatureCodeDirectorySupportsLinkage {
		c.Linkage = append([]byte{}, data[c.LinkageOffset:c.LinkageOffset+c.LinkageSize]...)
	}

	return nil
}

func (c *CodeSignatureCodeDirectoryBlob) Visit(walkFunc WalkFunc) error {
	return nil
}

func (c *CodeSignatureCodeDirectoryBlob) Digest() ([]byte, error) {
	return codeSignatureDigestBlob(c, c.HashType)
}

func (c *CodeSignatureCodeDirectoryBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicCodeDirectory

	switch c.HashType {
	case crypto.SHA1:
		c.CodeSignatureCodeDirectoryBlobEarliest.HashType = 1
		c.CodeSignatureCodeDirectoryBlobEarliest.HashSize = uint8(c.HashType.Size())
	case crypto.SHA256:
		c.CodeSignatureCodeDirectoryBlobEarliest.HashType = 2
		c.CodeSignatureCodeDirectoryBlobEarliest.HashSize = uint8(c.HashType.Size())
	default:
		return fmt.Errorf("invalid hash type %q", c.HashType)
	}

	for slot, blob := range c.SpecialSlots {
		digest, err := codeSignatureDigestBlob(blob, c.HashType)
		if err != nil {
			return err
		}

		c.Hashes[-int(slot)] = digest
	}

	c.Length = uint32(c.Version.Size())

	c.IdentOffset = c.Length
	c.Length += uint32(len(c.Identifier) + 1)

	_, err := io.WriteString(utils.NewSectionWriter(w, offset+int64(c.IdentOffset), int64(len(c.Identifier))), c.Identifier)
	if err != nil {
		return fmt.Errorf("could not encode identifier: %w", err)
	}

	_, err = w.WriteAt([]byte{0}, offset+int64(c.IdentOffset)+int64(len(c.Identifier)))
	if err != nil {
		return fmt.Errorf("could not encode identifier: %w", err)
	}

	if c.Version >= CodeSignatureCodeDirectorySupportsRuntime {
		if c.Runtime != 0 {
			c.Flags |= CodeSignatureCodeDirectoryFlagRuntime
		}
	}

	if c.Version >= CodeSignatureCodeDirectorySupportsTeamID {
		c.TeamIDOffset = c.Length
		_, err := io.WriteString(utils.NewSectionWriter(w, offset+int64(c.TeamIDOffset), int64(len(c.TeamID))), c.TeamID)
		if err != nil {
			return fmt.Errorf("could not encode team-id: %w", err)
		}

		_, err = w.WriteAt([]byte{0}, offset+int64(c.TeamIDOffset)+int64(len(c.TeamID)))
		if err != nil {
			return fmt.Errorf("could not encode team-id: %w", err)
		}

		c.Length += uint32(len(c.TeamID) + 1)
	}

	if c.Version >= CodeSignatureCodeDirectorySupportsLinkage {
		c.LinkageOffset = c.Length
		c.LinkageSize = uint32(len(c.Linkage))
		_, err = w.WriteAt(c.Linkage, offset+int64(c.LinkageOffset))
		if err != nil {
			return fmt.Errorf("could not encode linkage: %w", err)
		}

		c.Length += c.LinkageSize
	}

	if uint32(len(c.Hashes)) != c.NSpecialSlots+c.NCodeSlots {
		return fmt.Errorf("invalid number of slots %d (expected (%d + %d = %d))", len(c.Hashes), c.NSpecialSlots, c.NCodeSlots, c.NSpecialSlots+c.NCodeSlots)
	}

	pageSize := uint32(1 << c.PageSize)
	expected := (c.CodeLimit + (pageSize - 1)) / pageSize
	if c.NCodeSlots != expected {
		return fmt.Errorf("invalid number of code slots %d (expected %d)", c.NCodeSlots, expected)
	}

	c.HashOffset = c.Length + (uint32(c.HashSize) * c.NSpecialSlots)

	for i := -int(c.NSpecialSlots); i < int(c.NCodeSlots); i++ {
		_, err := w.WriteAt(c.Hashes[i], offset+int64(c.HashOffset)+(int64(i)*int64(c.HashSize)))
		if err != nil {
			return fmt.Errorf("could not encode hash: %w", err)
		}
	}
	c.Length += (c.NSpecialSlots + c.NCodeSlots) * uint32(c.HashSize)

	if c.ScatterOffset != 0 {
		return fmt.Errorf("scatter vector not yet supported")
	}

	switch c.Version.Normalize() {
	case CodeSignatureCodeDirectoryEarliest:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeEarliestVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobEarliest)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsScatter:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsScatterVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsScatter)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsTeamID:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsTeamIDVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsTeamID)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsCodeLimit64:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsCodeLimit64Version), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsCodeLimit64)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsExecSeg:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsExecSegVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsExecSeg)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsRuntime:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsRuntimeVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsRuntime)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	case CodeSignatureCodeDirectorySupportsLinkage:
		err := binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureCodeDirectoryBlobSizeSupportsLinkageVersion), c.ByteOrder, &c.CodeSignatureCodeDirectoryBlobSupportsLinkage)
		if err != nil {
			return fmt.Errorf("could not encode header: %w", err)
		}
	}

	return nil
}

type Entitlements map[string]interface{}

const CodeSignatureEntitlementsBlobSize = int64(unsafe.Sizeof(CodeSignatureEntitlementsBlobRaw{}))

type CodeSignatureEntitlementsBlobRaw struct {
	CodeSignatureBaseBlobRaw
}

type CodeSignatureEntitlementsBlob struct {
	CodeSignatureEntitlementsBlobRaw

	ByteOrder binary.ByteOrder

	Entitlements Entitlements
}

func (c *CodeSignatureEntitlementsBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	switch magic {
	case CodeSignatureMagicEntitlements:
		c.ByteOrder = binary.BigEndian
	case CodeSignatureCigamEntitlements:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureEntitlementsBlobSize), c.ByteOrder, &c.CodeSignatureEntitlementsBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	data, err := io.ReadAll(io.NewSectionReader(r, offset+CodeSignatureEntitlementsBlobSize, int64(c.Length)-CodeSignatureEntitlementsBlobSize))
	if err != nil {
		return fmt.Errorf("could not read entitlements data: %w", err)
	}

	_, err = plist.Unmarshal(data, &c.Entitlements)
	if err != nil {
		return fmt.Errorf("could not unmarshal entitlements data: %w", err)
	}

	return nil
}

func (c *CodeSignatureEntitlementsBlob) Visit(walkFunc WalkFunc) error {
	return nil
}

func (c *CodeSignatureEntitlementsBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicEntitlements

	data, err := plist.MarshalIndent(c.Entitlements, plist.XMLFormat, "\t")
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.Replace(lines[i], "\t", "", 1)
	}

	data = []byte(strings.Join(lines, "\n") + "\n")

	_, err = w.WriteAt(data, offset+CodeSignatureEntitlementsBlobSize)
	if err != nil {
		return err
	}

	c.Length = uint32(CodeSignatureEntitlementsBlobSize + int64(len(data)))

	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureEntitlementsBlobSize), c.ByteOrder, c.CodeSignatureEntitlementsBlobRaw)
	if err != nil {
		return err
	}

	return nil
}

const CodeSignatureEntitlementsDERBlobSize = int64(unsafe.Sizeof(CodeSignatureEntitlementsDERBlobRaw{}))

type CodeSignatureEntitlementsDERBlobRaw struct {
	CodeSignatureBaseBlobRaw
}

type CodeSignatureEntitlementsDERBlob struct {
	CodeSignatureEntitlementsDERBlobRaw

	ByteOrder binary.ByteOrder

	Entitlements Entitlements
}

func (c *CodeSignatureEntitlementsDERBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	switch magic {
	case CodeSignatureMagicEntitlementsDER:
		c.ByteOrder = binary.BigEndian
	case CodeSignatureCigamEntitlementsDER:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureEntitlementsDERBlobSize), c.ByteOrder, &c.CodeSignatureEntitlementsDERBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	data, err := io.ReadAll(io.NewSectionReader(r, offset+CodeSignatureEntitlementsDERBlobSize, int64(c.Length)-CodeSignatureEntitlementsDERBlobSize))
	if err != nil {
		return fmt.Errorf("could not read entitlements data: %w", err)
	}

	err = der.Unmarshal(data, &c.Entitlements)
	if err != nil {
		return fmt.Errorf("could not unmarshal entitlements data: %w", err)
	}

	return nil
}

func (c *CodeSignatureEntitlementsDERBlob) Visit(walkFunc WalkFunc) error {
	return nil
}

func (c *CodeSignatureEntitlementsDERBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicEntitlementsDER

	data, err := der.Marshal(c.Entitlements)
	if err != nil {
		return err
	}

	_, err = w.WriteAt(data, offset+CodeSignatureEntitlementsDERBlobSize)
	if err != nil {
		return err
	}

	c.Length = uint32(CodeSignatureBlobWrapperBlobSize + int64(len(data)))

	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureEntitlementsDERBlobSize), c.ByteOrder, c.CodeSignatureEntitlementsDERBlobRaw)
	if err != nil {
		return err
	}

	return nil
}

type CodeSignatureRequirementsBlob struct {
	CodeSignatureSuperBlob

	Requirements requirements.Requirements
}

func (c *CodeSignatureRequirementsBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	c.magic = CodeSignatureMagicRequirements
	c.cigam = CodeSignatureCigamRequirements
	c.factory = func(typ uint32, magic uint32) CodeSignatureBlob {
		return new(CodeSignatureRequirementBlob)
	}

	err := c.CodeSignatureSuperBlob.Decode(r, offset, walkFunc)
	if err != nil {
		return err
	}

	c.Requirements = make(requirements.Requirements)

	for _, reqIndex := range c.Blobs {
		req, ok := reqIndex.Blob.(*CodeSignatureRequirementBlob)
		if !ok {
			return fmt.Errorf("TODO: malformed requirements")
		}

		c.Requirements[requirements.RequirementType(reqIndex.Type)] = req.Expr
	}

	return nil
}

func (c *CodeSignatureRequirementsBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicRequirements

	c.Blobs = make([]*CodeSignatureBlobIndex, 0, len(c.Requirements))
	for reqType, expr := range c.Requirements {
		c.Blobs = append(c.Blobs, &CodeSignatureBlobIndex{
			CodeSignatureBlobIndexRaw: CodeSignatureBlobIndexRaw{
				Type: uint32(reqType),
			},

			ByteOrder: c.ByteOrder,

			Blob: &CodeSignatureRequirementBlob{
				CodeSignatureRequirementBlobRaw: CodeSignatureRequirementBlobRaw{
					CodeSignatureBaseBlobRaw: CodeSignatureBaseBlobRaw{
						Magic: CodeSignatureMagicRequirement,
					},

					ExprKind: 1, // This is an enum with one valid value (1) that indicates that this requirement is in expression form
				},

				ByteOrder: c.ByteOrder,

				Expr: expr,
			},
		})
	}

	err := c.CodeSignatureSuperBlob.Encode(w, offset, walkFunc)
	if err != nil {
		return err
	}

	return nil
}

const CodeSignatureRequirementBlobSize = int64(unsafe.Sizeof(CodeSignatureRequirementBlobRaw{}))

type CodeSignatureRequirementBlobRaw struct {
	CodeSignatureBaseBlobRaw

	ExprKind uint32
}

type CodeSignatureRequirementBlob struct {
	CodeSignatureRequirementBlobRaw

	ByteOrder binary.ByteOrder

	Expr requirements.Expr
}

func (c *CodeSignatureRequirementBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	switch magic {
	case CodeSignatureMagicRequirement:
		c.ByteOrder = binary.BigEndian
	case CodeSignatureCigamRequirement:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureRequirementBlobSize), c.ByteOrder, &c.CodeSignatureRequirementBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	c.Expr, _, err = requirements.DecodeExpr(r, offset+CodeSignatureRequirementBlobSize, c.ByteOrder)
	if err != nil {
		return fmt.Errorf("could not decode expr: %w", err)
	}

	return nil
}

func (c *CodeSignatureRequirementBlob) Visit(walkFunc WalkFunc) error {
	return nil
}

func (c *CodeSignatureRequirementBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicRequirement

	nExpr, err := requirements.EncodeExpr(c.Expr, w, offset+CodeSignatureRequirementBlobSize, c.ByteOrder)
	if err != nil {
		return err
	}

	c.Length = uint32(CodeSignatureRequirementBlobSize + nExpr)
	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureRequirementBlobSize), c.ByteOrder, c.CodeSignatureRequirementBlobRaw)
	if err != nil {
		return err
	}

	return nil
}

const CodeSignatureBlobWrapperBlobSize = int64(unsafe.Sizeof(CodeSignatureBlobWrapperBlobRaw{}))

type CodeSignatureBlobWrapperBlobRaw struct {
	CodeSignatureBaseBlobRaw
}

type CodeSignatureBlobWrapperBlob struct {
	CodeSignatureBlobWrapperBlobRaw

	ByteOrder binary.ByteOrder

	Data Data
}

func (c *CodeSignatureBlobWrapperBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return fmt.Errorf("could not read blob magic: %w", err)
	}

	switch magic {
	case CodeSignatureMagicBlobWrapper:
		c.ByteOrder = binary.BigEndian
	case CodeSignatureCigamBlobWrapper:
		c.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, CodeSignatureBlobWrapperBlobSize), c.ByteOrder, &c.CodeSignatureBlobWrapperBlobRaw)
	if err != nil {
		return fmt.Errorf("could not decode header: %w", err)
	}

	err = walkFunc(&c.Data, func() error {
		c.Data = make(Data, int64(c.Length)-CodeSignatureBlobWrapperBlobSize)
		return c.Data.Decode(r, offset+CodeSignatureBlobWrapperBlobSize, walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not read blob data: %w", err)
	}

	return nil
}

func (c *CodeSignatureBlobWrapperBlob) Visit(walkFunc WalkFunc) error {
	return walkFunc(&c.Data, func() error {
		return c.Data.Visit(walkFunc)
	})
}

func (c *CodeSignatureBlobWrapperBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	c.Magic = CodeSignatureMagicBlobWrapper

	err := walkFunc(&c.Data, func() error {
		return c.Data.Encode(w, offset+CodeSignatureBlobWrapperBlobSize, walkFunc)
	})
	if err != nil {
		return err
	}

	c.Length = uint32(CodeSignatureBlobWrapperBlobSize + int64(c.Data.Len()))
	err = binary.Write(utils.NewSectionWriter(w, offset, CodeSignatureBlobWrapperBlobSize), c.ByteOrder, c.CodeSignatureBlobWrapperBlobRaw)
	if err != nil {
		return err
	}

	return nil
}

type CodeSignatureCMSSignatureBlob struct {
	CodeSignatureBlobWrapperBlob

	SignedData *protocol.SignedData
}

func (c *CodeSignatureCMSSignatureBlob) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := c.CodeSignatureBlobWrapperBlob.Decode(r, offset, walkFunc)
	if err != nil {
		return err
	}

	if len(c.Data) != 0 {
		ci, err := protocol.ParseContentInfo(c.Data)
		if err != nil {
			return err
		}
		c.SignedData, err = ci.SignedDataContent()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CodeSignatureCMSSignatureBlob) Visit(walkFunc WalkFunc) error {
	return walkFunc(&c.Data, func() error {
		return c.Data.Visit(walkFunc)
	})
}

func (c *CodeSignatureCMSSignatureBlob) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	if c.SignedData != nil {
		der, err := c.SignedData.ContentInfoDER()
		if err != nil {
			return err
		}

		c.Data = append(c.Data[:0], der...)
	} else {
		c.Data = c.Data[:0]
	}

	err := c.CodeSignatureBlobWrapperBlob.Encode(w, offset, walkFunc)
	if err != nil {
		return err
	}

	return nil
}

func (c *CodeSignatureCMSSignatureBlob) Sign(key crypto.Signer, chain []*x509.Certificate, codeDirectories []*CodeSignatureCodeDirectoryBlob) error {
	eci := protocol.EncapsulatedContentInfo{
		EContentType: oid.ContentTypeData,
	}

	var err error
	c.SignedData, err = protocol.NewSignedData(eci)
	if err != nil {
		return err
	}

	for _, cert := range chain {
		if err = c.SignedData.AddCertificate(cert); err != nil {
			return err
		}
	}

	sid, err := protocol.NewIssuerAndSerialNumber(chain[0])
	if err != nil {
		return err
	}

	digestAlgorithm := digestAlgorithmForPublicKey(chain[0].PublicKey)
	if !digestAlgorithm.Algorithm.Equal(oid.DigestAlgorithmSHA256) {
		panic("bug: non-sha256 signature hashes unsupported")
	}

	signatureAlgorithm := oid.SignatureAlgorithmSHA256WithRSA // TODO: parse

	si := protocol.SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignedAttrs:        nil,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithm, Parameters: asn1.NullRawValue},
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := c.SignedData.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}

	// Digest the message.
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}

	// Build our SignedAttributes
	ctAttr, err := protocol.NewAttribute(oid.AttributeContentType, c.SignedData.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	stAttr, err := protocol.NewAttribute(oid.AttributeSigningTime, time.Now().UTC())
	if err != nil {
		return err
	}

	var cdHashesPlist struct {
		CDHashes [][]byte `plist:"cdhashes"`
	}

	var cdHashesDER []interface{}

	var messageDigest []byte

	for i, cd := range codeDirectories {
		cdHash, err := cd.Digest()
		if err != nil {
			return err
		}

		if i == 0 {
			messageDigest, err = codeSignatureDigestBlob(cd, crypto.SHA256)
			if err != nil {
				return err
			}
		}

		cdHashesPlist.CDHashes = append(cdHashesPlist.CDHashes, cdHash[:20])

		var cdHashDER struct {
			HashType asn1.ObjectIdentifier
			Hash     []byte
		}

		cdHashDER.HashType = oidForHash(cd.HashType)
		cdHashDER.Hash = cdHash

		cdHashDERData, err := asn1.Marshal(cdHashDER)
		if err != nil {
			return err
		}

		cdHashesDER = append(cdHashesDER, asn1.RawValue{FullBytes: cdHashDERData})
	}

	mdAttr, err := protocol.NewAttribute(oid.AttributeMessageDigest, messageDigest)
	if err != nil {
		return err
	}

	si.SignedAttrs = append(si.SignedAttrs, ctAttr, stAttr, mdAttr)

	cdHashesPlistData, err := plist.MarshalIndent(cdHashesPlist, plist.XMLFormat, "\t")
	if err != nil {
		return err
	}

	cdHashesDERAttr, err := NewMultiAttribute(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}, cdHashesDER...)
	if err != nil {
		return err
	}

	cdHashesPlistAttr, err := protocol.NewAttribute(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}, cdHashesPlistData)
	if err != nil {
		return err
	}

	si.SignedAttrs = append(si.SignedAttrs, cdHashesDERAttr, cdHashesPlistAttr)

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}

	smd := hash.New()
	if _, err := smd.Write(sm); err != nil {
		return err
	}
	if si.Signature, err = key.Sign(rand.Reader, smd.Sum(nil), hash); err != nil {
		return err
	}

	c.SignedData.DigestAlgorithms = []pkix.AlgorithmIdentifier{digestAlgorithm}

	c.SignedData.SignerInfos = append(c.SignedData.SignerInfos, si)

	return nil
}
