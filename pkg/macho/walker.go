package macho

import "fmt"

type WalkFunc func(Struct, func() error) error

var ErrStopWalk = fmt.Errorf("stop walking")

type Walker interface {
	Any(Struct, func() error) error

	Fat(Fat, func() error) error
	Fat32(*Fat32, func() error) error
	Fat64(*Fat64, func() error) error

	FatArch(FatArch, func() error) error
	FatArch32(*FatArch32, func() error) error
	FatArch64(*FatArch64, func() error) error

	Header(Header, func() error) error
	Header32(*Header32, func() error) error
	Header64(*Header64, func() error) error

	LoadCommand(LoadCommand, func() error) error
	BaseLoadCommand(*BaseLoadCommand, func() error) error
	CodeSignature(*CodeSignature, func() error) error

	CodeSignatureSuperBlob(*CodeSignatureSuperBlob, func() error) error
	CodeSignatureBlobIndex(*CodeSignatureBlobIndex, func() error) error
	CodeSignatureBaseBlob(*CodeSignatureBaseBlob, func() error) error

	CodeSignatureEmbeddedSignatureBlob(*CodeSignatureEmbeddedSignatureBlob, func() error) error
	CodeSignatureCodeDirectoryBlob(*CodeSignatureCodeDirectoryBlob, func() error) error
	CodeSignatureRequirementBlob(*CodeSignatureRequirementBlob, func() error) error
	CodeSignatureRequirementsBlob(*CodeSignatureRequirementsBlob, func() error) error
	CodeSignatureEntitlementsBlob(*CodeSignatureEntitlementsBlob, func() error) error
	CodeSignatureEntitlementsDERBlob(*CodeSignatureEntitlementsDERBlob, func() error) error
	CodeSignatureBlobWrapperBlob(*CodeSignatureBlobWrapperBlob, func() error) error
	CodeSignatureCMSSignatureBlob(*CodeSignatureCMSSignatureBlob, func() error) error

	Segment(Segment, func() error) error
	Segment32(*Segment32, func() error) error
	Segment64(*Segment64, func() error) error

	Section(Section, func() error) error
	Section32(*Section32, func() error) error
	Section64(*Section64, func() error) error

	Data(*Data, func() error) error
}

func NewWalkFunc(walker Walker) WalkFunc {
	walker = &WalkerWrapper{Walker: walker}
	return walker.Any
}

type DefaultWalker struct{}

func (w *DefaultWalker) Any(any Struct, do func() error) error {
	return do()
}

func (w *DefaultWalker) Fat(fat Fat, do func() error) error {
	return do()
}

func (w *DefaultWalker) Fat32(fat *Fat32, do func() error) error {
	return do()
}

func (w *DefaultWalker) Fat64(fat *Fat64, do func() error) error {
	return do()
}

func (w *DefaultWalker) FatArch(fatArch FatArch, do func() error) error {
	return do()
}

func (w *DefaultWalker) FatArch32(fatArch *FatArch32, do func() error) error {
	return do()
}

func (w *DefaultWalker) FatArch64(fatArch *FatArch64, do func() error) error {
	return do()
}

func (w *DefaultWalker) Header(header Header, do func() error) error {
	return do()
}

func (w *DefaultWalker) Header32(header *Header32, do func() error) error {
	return do()
}

func (w *DefaultWalker) Header64(header *Header64, do func() error) error {
	return do()
}

func (w *DefaultWalker) LoadCommand(lc LoadCommand, do func() error) error {
	return do()
}

func (w *DefaultWalker) BaseLoadCommand(lc *BaseLoadCommand, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignature(lc *CodeSignature, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureSuperBlob(superBlob *CodeSignatureSuperBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureBlobIndex(index *CodeSignatureBlobIndex, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureBaseBlob(blob *CodeSignatureBaseBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureCodeDirectoryBlob(codeDirectoryBlob *CodeSignatureCodeDirectoryBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureEmbeddedSignatureBlob(requirementsBlob *CodeSignatureEmbeddedSignatureBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureRequirementBlob(requirementsBlob *CodeSignatureRequirementBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureRequirementsBlob(requirementsBlob *CodeSignatureRequirementsBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureEntitlementsBlob(entitlementsBlob *CodeSignatureEntitlementsBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureEntitlementsDERBlob(entitlementsDERBlob *CodeSignatureEntitlementsDERBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureBlobWrapperBlob(blobWrapperBlob *CodeSignatureBlobWrapperBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) CodeSignatureCMSSignatureBlob(CMSSignatureBlob *CodeSignatureCMSSignatureBlob, do func() error) error {
	return do()
}

func (w *DefaultWalker) Segment(segment Segment, do func() error) error {
	return do()
}

func (w *DefaultWalker) Segment32(segment *Segment32, do func() error) error {
	return do()
}

func (w *DefaultWalker) Segment64(segment *Segment64, do func() error) error {
	return do()
}

func (w *DefaultWalker) Section(section Section, do func() error) error {
	return do()
}

func (w *DefaultWalker) Section32(section *Section32, do func() error) error {
	return do()
}

func (w *DefaultWalker) Section64(section *Section64, do func() error) error {
	return do()
}

func (w *DefaultWalker) Data(data *Data, do func() error) error {
	return do()
}

type WalkerWrapper struct {
	Walker
}

func (w *WalkerWrapper) Fat(fat Fat, do func() error) error {
	switch fat := fat.(type) {
	case *Fat32:
		return w.Fat32(fat, do)
	case *Fat64:
		return w.Fat64(fat, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", fat))
}

func (w *WalkerWrapper) FatArch(fatArch FatArch, do func() error) error {
	switch fatArch := fatArch.(type) {
	case *FatArch32:
		return w.FatArch32(fatArch, do)
	case *FatArch64:
		return w.FatArch64(fatArch, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", fatArch))
}

func (w *WalkerWrapper) Header(header Header, do func() error) error {
	switch header := header.(type) {
	case *Header32:
		return w.Header32(header, do)
	case *Header64:
		return w.Header64(header, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", header))
}

func (w *WalkerWrapper) LoadCommand(lc LoadCommand, do func() error) error {
	switch lc := lc.(type) {
	case *BaseLoadCommand:
		return w.BaseLoadCommand(lc, do)
	case *CodeSignature:
		return w.CodeSignature(lc, do)
	case *Segment32:
		return w.Segment(lc, do)
	case *Segment64:
		return w.Segment(lc, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", lc))
}

func (w *WalkerWrapper) Segment(segment Segment, do func() error) error {
	switch segment := segment.(type) {
	case *Segment32:
		return w.Segment32(segment, do)
	case *Segment64:
		return w.Segment64(segment, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", segment))
}

func (w *WalkerWrapper) Section(section Section, do func() error) error {
	switch section := section.(type) {
	case *Section32:
		return w.Section32(section, do)
	case *Section64:
		return w.Section64(section, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", section))
}

func (w *WalkerWrapper) Any(data Struct, do func() error) error {
	switch data := data.(type) {
	case *Fat32:
		return w.Fat(data, do)
	case *Fat64:
		return w.Fat(data, do)
	case *FatArch32:
		return w.FatArch(data, do)
	case *FatArch64:
		return w.FatArch(data, do)
	case *Header32:
		return w.Header(data, do)
	case *Header64:
		return w.Header(data, do)
	case *BaseLoadCommand:
		return w.BaseLoadCommand(data, do)
	case *CodeSignature:
		return w.CodeSignature(data, do)
	case *CodeSignatureSuperBlob:
		return w.CodeSignatureSuperBlob(data, do)
	case *CodeSignatureBlobIndex:
		return w.CodeSignatureBlobIndex(data, do)
	case *CodeSignatureBaseBlob:
		return w.CodeSignatureBaseBlob(data, do)
	case *CodeSignatureEmbeddedSignatureBlob:
		return w.CodeSignatureEmbeddedSignatureBlob(data, do)
	case *CodeSignatureCodeDirectoryBlob:
		return w.CodeSignatureCodeDirectoryBlob(data, do)
	case *CodeSignatureRequirementBlob:
		return w.CodeSignatureRequirementBlob(data, do)
	case *CodeSignatureRequirementsBlob:
		return w.CodeSignatureRequirementsBlob(data, do)
	case *CodeSignatureEntitlementsBlob:
		return w.CodeSignatureEntitlementsBlob(data, do)
	case *CodeSignatureEntitlementsDERBlob:
		return w.CodeSignatureEntitlementsDERBlob(data, do)
	case *CodeSignatureBlobWrapperBlob:
		return w.CodeSignatureBlobWrapperBlob(data, do)
	case *CodeSignatureCMSSignatureBlob:
		return w.CodeSignatureCMSSignatureBlob(data, do)
	case *Segment32:
		return w.Segment(data, do)
	case *Segment64:
		return w.Segment(data, do)
	case *Section32:
		return w.Section(data, do)
	case *Section64:
		return w.Section(data, do)
	case *Data:
		return w.Data(data, do)
	}

	panic(fmt.Sprintf("bug: unrecognized type: %T", data))
}
