package macho

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"io"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
)

func readMagic(r io.ReaderAt, offset int64) (uint32, error) {
	var magic uint32
	err := binary.Read(io.NewSectionReader(r, offset, 4), binary.BigEndian, &magic)
	if err != nil {
		return 0, err
	}

	return magic, nil
}
func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

type Data []byte

func (d *Data) WriteAt(p []byte, offset int64) (int, error) {
	if int64(len(*d)) < int64(len(p))+offset {
		*d = append(*d, make([]byte, int64(len(p))+offset-int64(len(*d)))...)
	}

	copy((*d)[offset:], p)

	return len(p), nil
}

func (d *Data) ReadAt(p []byte, offset int64) (int, error) {
	if int64(len(*d)) < int64(len(p))+offset {
		return 0, io.EOF
	}

	copy(p, (*d)[offset:])

	return len(p), nil
}

func (d *Data) Len() int {
	return len(*d)
}

func (d *Data) Decode(r io.ReaderAt, offset int64, walkFunc WalkFunc) error {
	_, err := r.ReadAt(*d, offset)
	if err != nil {
		return nil
	}

	return nil
}

func (d *Data) Visit(walkFunc WalkFunc) error {
	return nil
}

func (d *Data) Encode(w io.WriterAt, offset int64, walkFunc WalkFunc) error {
	_, err := w.WriteAt(*d, offset)
	if err != nil {
		return nil
	}

	return nil
}

func digestAlgorithmForPublicKey(pub crypto.PublicKey) pkix.AlgorithmIdentifier {
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecPub.Curve {
		case elliptic.P384():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA384, Parameters: asn1.NullRawValue}
		case elliptic.P521():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA512, Parameters: asn1.NullRawValue}
		}
	}

	return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA256, Parameters: asn1.NullRawValue}
}

func oidForHash(hash crypto.Hash) asn1.ObjectIdentifier {
	switch hash {
	case crypto.SHA1:
		return oid.DigestAlgorithmSHA1
	case crypto.SHA256:
		return oid.DigestAlgorithmSHA256
	default:
		return nil
	}
}

func NewMultiAttribute(typ asn1.ObjectIdentifier, vals ...interface{}) (attr protocol.Attribute, err error) {
	rvs := make([]asn1.RawValue, len(vals))
	for i, val := range vals {
		var der []byte
		if der, err = asn1.Marshal(val); err != nil {
			return
		}

		if _, err = asn1.Unmarshal(der, &rvs[i]); err != nil {
			return
		}
	}

	if err = protocol.NewAnySet(rvs...).Encode(&attr.RawValue); err != nil {
		return
	}

	attr.Type = typ

	return
}
