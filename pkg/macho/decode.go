package macho

import "io"

type Decoder interface {
	Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error
}

type Encoder interface {
	Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error
}

type Visitor interface {
	Visit(walkFunc WalkFunc) error
}

type Struct interface {
	Decoder
	Encoder
	Visitor
}
