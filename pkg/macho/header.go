package macho

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"resigner/pkg/requirements"
	"resigner/pkg/utils"
)

type fakeKey uint64

func (k fakeKey) Public() crypto.PublicKey {
	return nil
}

func (k fakeKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, k/8), nil
}

type Binary interface {
	Struct

	Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error
}

const (
	MachoMagic32 = 0xfeedface
	MachoCigam32 = 0xcefaedfe

	MachoMagic64 = 0xfeedfacf
	MachoCigam64 = 0xcffaedfe
)

type FileType uint32

const (
	FileTypeExecute FileType = 0x02
)

type Header interface {
	Struct

	Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error
}

const Header32Size = int64(unsafe.Sizeof(Header32Raw{}))

type Header32Raw struct {
	Magic      uint32
	CPUType    uint32
	CPUSubType uint32
	FileType   FileType
	NCmds      uint32
	CmdsSize   uint32
	Flags      MachoHeaderFlag
}

type MachoHeaderFlag uint32

const (
	MachoHeaderDylibInCache MachoHeaderFlag = 0x80000000
)

type Header32 struct {
	Raw Data
	Header32Raw

	ByteOrder binary.ByteOrder

	LoadCommands []LoadCommand
}

func (h *Header32) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return err
	}

	switch magic {
	case MachoMagic32:
		h.ByteOrder = binary.BigEndian
	case MachoCigam32:
		h.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, int64(offset), int64(Header32Size)), h.ByteOrder, &h.Header32Raw)
	if err != nil {
		return err
	}

	lcOffset := offset + Header32Size
	for i := uint32(0); i < h.NCmds; i++ {
		var loadCommand BaseLoadCommand
		loadCommand.ByteOrder = h.ByteOrder

		err := loadCommand.decode(r, lcOffset)
		if err != nil {
			return fmt.Errorf("could not decode load command: %w", err)
		}

		switch loadCommand.Cmd {
		case LoadCommandKindSegment:
			var segment Segment32
			segment.ByteOrder = h.ByteOrder

			err := walkFunc(&segment, func() error {
				return segment.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode %v: %w", loadCommand.Cmd, err)
			}

			h.LoadCommands = append(h.LoadCommands, &segment)
		case LoadCommandKindCodeSignature:
			var codeSignature CodeSignature
			codeSignature.ByteOrder = h.ByteOrder

			err := walkFunc(&codeSignature, func() error {
				return codeSignature.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode %v: %w", loadCommand.Cmd, err)
			}

			h.LoadCommands = append(h.LoadCommands, &codeSignature)
		default:
			err := walkFunc(&loadCommand, func() error {
				return loadCommand.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode load command: %w", err)
			}
			h.LoadCommands = append(h.LoadCommands, &loadCommand)
		}

		lcOffset += int64(loadCommand.CmdSize)
	}

	return nil
}

func (h *Header32) Visit(walkFunc WalkFunc) error {
	for _, lc := range h.LoadCommands {
		err := walkFunc(lc, func() error {
			return lc.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *Header32) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	h.NCmds = uint32(len(h.LoadCommands))
	h.CmdsSize = 0

	lcOffset := offset + Header32Size
	for _, lc := range h.LoadCommands {
		err := walkFunc(lc, func() error {
			return lc.Encode(w, lcOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		h.CmdsSize += lc.Size()

		lcOffset += int64(lc.Size())
	}

	err := binary.Write(utils.NewSectionWriter(w, offset, Header32Size), h.ByteOrder, h.Header32Raw)
	if err != nil {
		return err
	}

	return nil
}

func (h *Header32) Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error {
	var codeSignature *CodeSignature
	var textSegment *Segment32
	var linkeditSegment *Segment32

	err := h.Visit(func(val Struct, visit func() error) error {
		switch val := val.(type) {
		case *CodeSignature:
			codeSignature = val
		case *Segment32:
			if strings.Trim(string(val.SegName[:]), "\x00") == "__LINKEDIT" {
				linkeditSegment = val
			} else if strings.Trim(string(val.SegName[:]), "\x00") == "__TEXT" {
				textSegment = val
			}
		}

		return visit()
	})
	if err != nil {
		return err
	}

	if linkeditSegment == nil {
		return fmt.Errorf("malformed macho (missing __LINKEDIT)")
	}

	var data Data
	err = h.Encode(&data, 0, func(val Struct, encode func() error) error {
		switch val.(type) {
		case *CodeSignature:
			return nil // skip code signature
		}

		return encode()
	})
	if err != nil {
		return err
	}

	if codeSignature == nil {
		codeSignature = &CodeSignature{
			CodeSignatureRaw: CodeSignatureRaw{
				BaseLoadCommandRaw: BaseLoadCommandRaw{
					Cmd:     LoadCommandKindCodeSignature,
					CmdSize: uint32(CodeSignatureSize),
				},
				DataOff: linkeditSegment.FileOff + linkeditSegment.FileSize,
			},

			ByteOrder: h.ByteOrder,
		}

		h.LoadCommands = append(h.LoadCommands, codeSignature)
	}

	err = codeSignature.Allocate(key, chain, entitlements, reqs, data[:codeSignature.DataOff])
	if err != nil {
		return err
	}

	err = codeSignature.Visit(walkFunc)
	if err != nil {
		return err
	}

	keySize := 2048
	if pubKey, ok := chain[0].PublicKey.(*rsa.PublicKey); ok {
		keySize = pubKey.Size() * 8
	}

	var codeDirectories []*CodeSignatureCodeDirectoryBlob
	err = codeSignature.Visit(func(val Struct, visit func() error) error {
		switch val := val.(type) {
		case *CodeSignatureCodeDirectoryBlob:
			val.ExecSegBase = uint64(textSegment.FileOff)
			val.ExecSegLimit = uint64(textSegment.FileSize)
			val.setupExecSegFlags(h.FileType == FileTypeExecute, entitlements)

			codeDirectories = append(codeDirectories, val)
		case *CodeSignatureCMSSignatureBlob:
			err := val.Sign(fakeKey(keySize), chain, codeDirectories)
			if err != nil {
				return err
			}
		}

		return visit()
	})
	if err != nil {
		return err
	}

	var sigData Data
	err = codeSignature.EmbeddedSignature.Encode(&sigData, 0, func(_ Struct, do func() error) error {
		return do()
	})
	if err != nil {
		return err
	}

	codeSignature.DataSize = uint32(sigData.Len())
	linkeditSegment.FileSize = uint32(codeSignature.DataOff) + uint32(sigData.Len()) - linkeditSegment.FileOff
	if linkeditSegment.FileSize > uint32(linkeditSegment.Data.Len()) {
		linkeditSegment.Data = append(linkeditSegment.Data, make([]byte, linkeditSegment.FileSize-uint32(linkeditSegment.Data.Len()))...)
	}
	linkeditSegment.Data = linkeditSegment.Data[:linkeditSegment.FileSize]

	data = data[:0]
	err = h.Encode(&data, 0, func(val Struct, encode func() error) error {
		switch val.(type) {
		}

		return encode()
	})
	if err != nil {
		return err
	}

	err = codeSignature.Sign(key, chain, data[:codeSignature.DataOff])
	if err != nil {
		return err
	}

	return nil
}

const Header64Size = int64(unsafe.Sizeof(Header64Raw{}))

type Header64Raw struct {
	Magic      uint32
	CPUType    uint32
	CPUSubType uint32
	FileType   FileType
	NCmds      uint32
	CmdsSize   uint32
	Flags      MachoHeaderFlag

	Reserved uint32
}

type Header64 struct {
	Header64Raw

	ByteOrder binary.ByteOrder

	LoadCommands []LoadCommand
}

func (h *Header64) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	magic, err := readMagic(r, offset)
	if err != nil {
		return err
	}

	switch magic {
	case MachoMagic64:
		h.ByteOrder = binary.BigEndian
	case MachoCigam64:
		h.ByteOrder = binary.LittleEndian
	default:
		return fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = binary.Read(io.NewSectionReader(r, offset, Header64Size), h.ByteOrder, &h.Header64Raw)
	if err != nil {
		return err
	}

	lcOffset := offset + Header64Size

	for i := uint32(0); i < h.NCmds; i++ {
		var loadCommand BaseLoadCommand
		loadCommand.ByteOrder = h.ByteOrder

		err := loadCommand.decode(r, lcOffset)
		if err != nil {
			return fmt.Errorf("could not decode load command: %w", err)
		}

		switch loadCommand.Cmd {
		case LoadCommandKindSegment64:
			var segment Segment64
			segment.ByteOrder = h.ByteOrder

			err := walkFunc(&segment, func() error {
				return segment.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode %v: %w", loadCommand.Cmd, err)
			}

			h.LoadCommands = append(h.LoadCommands, &segment)
		case LoadCommandKindCodeSignature:
			var codeSignature CodeSignature
			codeSignature.ByteOrder = h.ByteOrder

			err := walkFunc(&codeSignature, func() error {
				return codeSignature.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode %v: %w", loadCommand.Cmd, err)
			}

			h.LoadCommands = append(h.LoadCommands, &codeSignature)
		default:
			err := walkFunc(&loadCommand, func() error {
				return loadCommand.Decode(r, lcOffset, walkFunc)
			})
			if err != nil {
				return fmt.Errorf("could not decode load command: %w", err)
			}
			h.LoadCommands = append(h.LoadCommands, &loadCommand)
		}

		lcOffset += int64(loadCommand.CmdSize)
	}

	return nil
}

func (h *Header64) Visit(walkFunc WalkFunc) error {
	for _, lc := range h.LoadCommands {
		err := walkFunc(lc, func() error {
			return lc.Visit(walkFunc)
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *Header64) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	h.NCmds = uint32(len(h.LoadCommands))
	h.CmdsSize = 0

	lcOffset := offset + Header64Size
	for _, lc := range h.LoadCommands {
		err := walkFunc(lc, func() error {
			return lc.Encode(w, lcOffset, walkFunc)
		})
		if err != nil {
			return err
		}

		h.CmdsSize += lc.Size()
		lcOffset += int64(lc.Size())
	}

	err := binary.Write(utils.NewSectionWriter(w, offset, Header64Size), h.ByteOrder, h.Header64Raw)
	if err != nil {
		return err
	}

	return nil
}

func (h *Header64) Sign(key crypto.Signer, chain []*x509.Certificate, entitlements Entitlements, reqs requirements.Requirements, walkFunc WalkFunc) error {
	var codeSignature *CodeSignature
	var textSegment *Segment64
	var linkeditSegment *Segment64

	err := h.Visit(func(val Struct, visit func() error) error {
		switch val := val.(type) {
		case *CodeSignature:
			codeSignature = val
		case *Segment64:
			if strings.Trim(string(val.SegName[:]), "\x00") == "__LINKEDIT" {
				linkeditSegment = val
			} else if strings.Trim(string(val.SegName[:]), "\x00") == "__TEXT" {
				textSegment = val
			}
		}

		return visit()
	})
	if err != nil {
		return err
	}

	if linkeditSegment == nil {
		return fmt.Errorf("malformed macho (missing __LINKEDIT)")
	}

	var data Data
	err = h.Encode(&data, 0, func(val Struct, encode func() error) error {
		switch val.(type) {
		case *CodeSignatureEmbeddedSignatureBlob:
			return nil // skip code signature
		}

		return encode()
	})
	if err != nil {
		return err
	}

	if codeSignature == nil {
		codeSignature = &CodeSignature{
			CodeSignatureRaw: CodeSignatureRaw{
				BaseLoadCommandRaw: BaseLoadCommandRaw{
					Cmd:     LoadCommandKindCodeSignature,
					CmdSize: uint32(CodeSignatureSize),
				},
				DataOff: uint32(linkeditSegment.FileOff + linkeditSegment.FileSize),
			},

			ByteOrder: h.ByteOrder,
		}

		h.LoadCommands = append(h.LoadCommands, codeSignature)
	}

	err = codeSignature.Allocate(key, chain, entitlements, reqs, data[:codeSignature.DataOff])
	if err != nil {
		return err
	}

	err = codeSignature.Visit(walkFunc)
	if err != nil {
		return err
	}

	keySize := 2048
	if pubKey, ok := chain[0].PublicKey.(*rsa.PublicKey); ok {
		keySize = pubKey.Size() * 8
	}

	codeDirectories := make([]*CodeSignatureCodeDirectoryBlob, 0, 2)
	err = codeSignature.Visit(func(val Struct, visit func() error) error {
		switch val := val.(type) {
		case *CodeSignatureCodeDirectoryBlob:
			val.ExecSegBase = textSegment.FileOff
			val.ExecSegLimit = textSegment.FileSize
			val.setupExecSegFlags(h.FileType == FileTypeExecute, entitlements)

			codeDirectories = append(codeDirectories, val)
		case *CodeSignatureCMSSignatureBlob:
			err := val.Sign(fakeKey(keySize), chain, codeDirectories)
			if err != nil {
				return err
			}
		}

		return visit()
	})
	if err != nil {
		return err
	}

	var sigData Data
	err = codeSignature.EmbeddedSignature.Encode(&sigData, 0, func(_ Struct, do func() error) error {
		return do()
	})
	if err != nil {
		return err
	}

	codeSignature.DataSize = uint32(sigData.Len())
	linkeditSegment.FileSize = uint64(codeSignature.DataOff) + uint64(sigData.Len()) - linkeditSegment.FileOff
	if linkeditSegment.FileSize > uint64(linkeditSegment.Data.Len()) {
		linkeditSegment.Data = append(linkeditSegment.Data, make([]byte, linkeditSegment.FileSize-uint64(linkeditSegment.Data.Len()))...)
	}
	linkeditSegment.Data = linkeditSegment.Data[:linkeditSegment.FileSize]

	data = data[:0]
	err = h.Encode(&data, 0, func(val Struct, encode func() error) error {
		return encode()
	})
	if err != nil {
		return err
	}

	err = codeSignature.Sign(key, chain, data[:codeSignature.DataOff])
	if err != nil {
		return err
	}

	return nil
}

type LoadCommandKind uint32

func (k LoadCommandKind) String() string {
	switch k {
	case LoadCommandKindSegment:
		return "LC_SEGMENT"
	case LoadCommandKindSymtab:
		return "LC_SYMTAB"
	case LoadCommandKindSymseg:
		return "LC_SYMSEG"
	case LoadCommandKindThread:
		return "LC_THREAD"
	case LoadCommandKindUnixThread:
		return "LC_UNIXTHREAD"
	case LoadCommandKindLoadFVMLib:
		return "LC_LOADFVMLIB"
	case LoadCommandKindIDFVMLib:
		return "LC_IDFVMLIB"
	case LoadCommandKindIdent:
		return "LC_IDENT"
	case LoadCommandKindFVMFile:
		return "LC_FVMFILE"
	case LoadCommandKindPrePage:
		return "LC_PREPAGE"
	case LoadCommandKindDySymTab:
		return "LC_DYSYMTAB"
	case LoadCommandKindLoadDylib:
		return "LC_LOAD_DYLIB"
	case LoadCommandKindIDDylib:
		return "LC_ID_DYLIB"
	case LoadCommandKindLoadDylinker:
		return "LC_LOAD_DYLINKER"
	case LoadCommandKindIDDylinker:
		return "LC_ID_DYLINKER"
	case LoadCommandKindPreboundDylib:
		return "LC_PREBOUND_DYLIB"
	case LoadCommandKindRoutines:
		return "LC_ROUTINES"
	case LoadCommandKindSubFramework:
		return "LC_SUB_FRAMEWORK"
	case LoadCommandKindSubUmbrella:
		return "LC_SUB_UMBRELLA"
	case LoadCommandKindSubClient:
		return "LC_SUB_CLIENT"
	case LoadCommandKindSubLibrary:
		return "LC_SUB_LIBRARY"
	case LoadCommandKindTwolevelHints:
		return "LC_TWOLEVEL_HINTS"
	case LoadCommandKindPrebindCksum:
		return "LC_PREBIND_CKSUM"
	case LoadCommandKindLoadWeakDylib:
		return "LC_LOAD_WEAK_DYLIB"
	case LoadCommandKindSegment64:
		return "LC_SEGMENT_64"
	case LoadCommandKindRoutines64:
		return "LC_ROUTINES_64"
	case LoadCommandKindUUID:
		return "LC_UUID"
	case LoadCommandKindRpath:
		return "LC_RPATH"
	case LoadCommandKindCodeSignature:
		return "LC_CODE_SIGNATURE"
	case LoadCommandKindSegmentSplitInfo:
		return "LC_SEGMENT_SPLIT_INFO"
	case LoadCommandKindReexportDylib:
		return "LC_REEXPORT_DYLIB"
	case LoadCommandKindLazyLoadDylib:
		return "LC_LAZY_LOAD_DYLIB"
	case LoadCommandKindEncryptionInfo:
		return "LC_ENCRYPTION_INFO"
	case LoadCommandKindDYLDInfo:
		return "LC_DYLD_INFO"
	case LoadCommandKindDYLDInfoOnly:
		return "LC_DYLD_INFO_ONLY"
	case LoadCommandKindLoadUpwardDylib:
		return "LC_DYLD_LOAD_UPWARD_DYLIB"
	case LoadCommandKindVersionMinMacOSX:
		return "LC_VERSION_MIN_MACOSX"
	case LoadCommandKindVersionMinIPhoneOS:
		return "LC_VERSION_MIN_IPHONEOS"
	case LoadCommandKindFunctionStarts:
		return "LC_FUNCTION_STARTS"
	case LoadCommandKindDyldEnvironment:
		return "LC_DYLD_ENVIRONMENT"
	case LoadCommandKindMain:
		return "LC_MAIN"
	case LoadCommandKindDataInCode:
		return "LC_DATA_IN_CODE"
	case LoadCommandKindSourceVersion:
		return "LC_SOURCE_VERSION"
	case LoadCommandKindDylibCodeSignDRS:
		return "LC_DYLIB_CODE_SIGN_DRS"
	case LoadCommandKindEncryptionInfo64:
		return "LC_ENCRYPTION_INFO_64"
	case LoadCommandKindLinkerOption:
		return "LC_LINKER_OPTION"
	case LoadCommandKindLinkerOptimizationHint:
		return "LC_LINKER_OPTIMIZATION_HINT"
	case LoadCommandKindVersionMinTVOS:
		return "LC_VERSION_MIN_TVOS"
	case LoadCommandKindVersionMinWatchOS:
		return "LC_VERSION_MIN_WATCHOS"
	case LoadCommandKindNote:
		return "LC_NOTE"
	case LoadCommandKindBuildVersion:
		return "LC_BUILD_VERSION"
	case LoadCommandKindDyldExportsTrie:
		return "LC_DYLD_EXPORTS_TRIE"
	case LoadCommandKindDyldChainedFixups:
		return "LC_DYLD_CHAINED_FIXUPS"
	case LoadCommandKindFilesetEntry:
		return "LC_FILESET_ENTRY"
	default:
		return "LC_UNKNOWN"
	}
}

const (
	LoadCommandKindSegment       LoadCommandKind = 0x1
	LoadCommandKindSymtab        LoadCommandKind = 0x2
	LoadCommandKindSymseg        LoadCommandKind = 0x3
	LoadCommandKindThread        LoadCommandKind = 0x4
	LoadCommandKindUnixThread    LoadCommandKind = 0x5
	LoadCommandKindLoadFVMLib    LoadCommandKind = 0x6
	LoadCommandKindIDFVMLib      LoadCommandKind = 0x7
	LoadCommandKindIdent         LoadCommandKind = 0x8
	LoadCommandKindFVMFile       LoadCommandKind = 0x9
	LoadCommandKindPrePage       LoadCommandKind = 0xa
	LoadCommandKindDySymTab      LoadCommandKind = 0xb
	LoadCommandKindLoadDylib     LoadCommandKind = 0xc
	LoadCommandKindIDDylib       LoadCommandKind = 0xd
	LoadCommandKindLoadDylinker  LoadCommandKind = 0xe
	LoadCommandKindIDDylinker    LoadCommandKind = 0xf
	LoadCommandKindPreboundDylib LoadCommandKind = 0x10
	LoadCommandKindRoutines      LoadCommandKind = 0x11
	LoadCommandKindSubFramework  LoadCommandKind = 0x12
	LoadCommandKindSubUmbrella   LoadCommandKind = 0x13
	LoadCommandKindSubClient     LoadCommandKind = 0x14
	LoadCommandKindSubLibrary    LoadCommandKind = 0x15
	LoadCommandKindTwolevelHints LoadCommandKind = 0x16
	LoadCommandKindPrebindCksum  LoadCommandKind = 0x17
	LoadCommandKindLoadWeakDylib LoadCommandKind = 0x80000018

	LoadCommandKindSegment64              LoadCommandKind = 0x19
	LoadCommandKindRoutines64             LoadCommandKind = 0x1a
	LoadCommandKindUUID                   LoadCommandKind = 0x1b
	LoadCommandKindRpath                  LoadCommandKind = 0x8000001c
	LoadCommandKindCodeSignature          LoadCommandKind = 0x1d
	LoadCommandKindSegmentSplitInfo       LoadCommandKind = 0x1e
	LoadCommandKindReexportDylib          LoadCommandKind = 0x8000001f
	LoadCommandKindLazyLoadDylib          LoadCommandKind = 0x20
	LoadCommandKindEncryptionInfo         LoadCommandKind = 0x21
	LoadCommandKindDYLDInfo               LoadCommandKind = 0x22
	LoadCommandKindDYLDInfoOnly           LoadCommandKind = 0x80000022
	LoadCommandKindLoadUpwardDylib        LoadCommandKind = 0x80000023
	LoadCommandKindVersionMinMacOSX       LoadCommandKind = 0x24
	LoadCommandKindVersionMinIPhoneOS     LoadCommandKind = 0x25
	LoadCommandKindFunctionStarts         LoadCommandKind = 0x26
	LoadCommandKindDyldEnvironment        LoadCommandKind = 0x27
	LoadCommandKindMain                   LoadCommandKind = 0x80000028
	LoadCommandKindDataInCode             LoadCommandKind = 0x29
	LoadCommandKindSourceVersion          LoadCommandKind = 0x2a
	LoadCommandKindDylibCodeSignDRS       LoadCommandKind = 0x2b
	LoadCommandKindEncryptionInfo64       LoadCommandKind = 0x2c
	LoadCommandKindLinkerOption           LoadCommandKind = 0x2d
	LoadCommandKindLinkerOptimizationHint LoadCommandKind = 0x2e
	LoadCommandKindVersionMinTVOS         LoadCommandKind = 0x2f
	LoadCommandKindVersionMinWatchOS      LoadCommandKind = 0x30
	LoadCommandKindNote                   LoadCommandKind = 0x31
	LoadCommandKindBuildVersion           LoadCommandKind = 0x32
	LoadCommandKindDyldExportsTrie        LoadCommandKind = 0x80000033
	LoadCommandKindDyldChainedFixups      LoadCommandKind = 0x80000034
	LoadCommandKindFilesetEntry           LoadCommandKind = 0x80000035
)

const LoadCommandSize = int64(unsafe.Sizeof(BaseLoadCommandRaw{}))

type LoadCommand interface {
	Struct

	Kind() LoadCommandKind
	Size() uint32
}

type BaseLoadCommandRaw struct {
	Cmd     LoadCommandKind
	CmdSize uint32
}

type BaseLoadCommand struct {
	BaseLoadCommandRaw

	ByteOrder binary.ByteOrder

	Rest Data
}

func (c *BaseLoadCommandRaw) Kind() LoadCommandKind {
	return c.Cmd
}

func (c *BaseLoadCommandRaw) Size() uint32 {
	return c.CmdSize
}

func (c *BaseLoadCommand) decode(r io.ReaderAt, offset int64) error {
	err := binary.Read(io.NewSectionReader(r, offset, LoadCommandSize), c.ByteOrder, &c.BaseLoadCommandRaw)
	if err != nil {
		return fmt.Errorf("could not read header: %w", err)
	}

	return nil
}

func (c *BaseLoadCommand) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	err := c.decode(r, offset)
	if err != nil {
		return err
	}

	err = walkFunc(&c.Rest, func() error {
		c.Rest = make(Data, int64(c.CmdSize)-LoadCommandSize)
		return c.Rest.Decode(r, offset+LoadCommandSize, walkFunc)
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *BaseLoadCommand) Visit(walkFunc WalkFunc) error {
	return walkFunc(&c.Rest, func() error {
		return c.Rest.Visit(walkFunc)
	})
}

func (c *BaseLoadCommand) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	err := walkFunc(&c.Rest, func() error {
		return c.Rest.Encode(w, offset+LoadCommandSize, walkFunc)
	})
	if err != nil {
		return fmt.Errorf("could not write header data: %w", err)
	}

	err = binary.Write(utils.NewSectionWriter(w, offset, LoadCommandSize), c.ByteOrder, c.BaseLoadCommandRaw)
	if err != nil {
		return fmt.Errorf("could not write header: %w", err)
	}

	return nil
}

type DylibCommandRaw struct {
	BaseLoadCommandRaw
	PathOffset     uint32
	Timestamp      uint32
	CurrentVersion uint32
}

type DylibCommand struct {
	DylibCommandRaw

	Name string
}
