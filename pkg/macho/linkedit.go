package macho

import (
	"unsafe"
)

const LinkedITDataCommandSize = unsafe.Sizeof(LinkedITDataCommandRaw{})

type LinkedITDataCommandRaw struct {
	BaseLoadCommandRaw
	DataOff  uint32
	DataSize uint32
}
