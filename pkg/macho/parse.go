package macho

import (
	"errors"
	"fmt"
	"io"
)

var ErrUnrecoginizedMagic = errors.New("unrecognized magic")
var ErrNotEnoughData = errors.New("not enough data")

func Walk(r io.ReaderAt, offset int64, walkFunc WalkFunc) (Binary, error) {
	magic, err := readMagic(r, offset)
	if err != nil {
		return nil, err
	}

	var header Binary
	switch magic {
	case FatMagic32, FatCigam32:
		header = new(Fat32)
	case FatMagic64, FatCigam64:
		header = new(Fat64)
	case MachoMagic32, MachoCigam32:
		header = new(Header32)
	case MachoMagic64, MachoCigam64:
		header = new(Header64)
	default:
		return nil, fmt.Errorf("unrecognized magic number %x: %w", magic, ErrUnrecoginizedMagic)
	}

	err = walkFunc(header, func() error {
		return header.Decode(r, offset, walkFunc)
	})
	if err != nil {
		return nil, err
	}
	return header, nil
}

func Parse(r io.ReaderAt, offset int64) (Binary, error) {
	return Walk(r, offset, NewWalkFunc(&DefaultWalker{}))
}
