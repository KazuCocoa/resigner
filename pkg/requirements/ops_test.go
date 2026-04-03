package requirements

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

type growableWriterAt struct {
	buf []byte
}

func (w *growableWriterAt) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(w.buf) {
		w.buf = append(w.buf, make([]byte, end-len(w.buf))...)
	}
	copy(w.buf[off:], p)
	return len(p), nil
}

func TestEncodeDecodeExprRoundTrip(t *testing.T) {
	oid := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
	cases := []Expr{
		NullaryExpr{Op: ExprOpTrue},
		UnaryExpr{Op: ExprOpNot, Arg: NullaryExpr{Op: ExprOpFalse}},
		BinaryExpr{Op: ExprOpAnd, Left: DataExpr{Op: ExprOpIdent, Data: []byte("com.example.app")}, Right: NullaryExpr{Op: ExprOpAppleGenericAnchor}},
		DataExpr{Op: ExprOpCDHash, Data: []byte{1, 2, 3, 4}},
		FieldValueExpr{Op: ExprOpInfoKeyValue, Field: []byte("CFBundleIdentifier"), Value: []byte("com.example.app")},
		FieldExpr{Op: ExprOpInfoKeyField, Field: []byte("CFBundleVersion"), Match: Match{Op: MatchOpEqual, Value: []byte("1")}},
		CertExpr{Op: ExprOpTrustedCert, Slot: -1},
		CertValueExpr{Op: ExprOpAnchorHash, Slot: 0, Value: []byte{9, 8, 7}},
		CertFieldExpr{Op: ExprOpCertGeneric, Slot: 1, Field: oid, Match: Match{Op: MatchOpExists}},
	}

	for _, expr := range cases {
		w := &growableWriterAt{}
		n, err := EncodeExpr(expr, w, 0, binary.BigEndian)
		if err != nil {
			t.Fatalf("encode failed for %T: %v", expr, err)
		}

		decoded, nDecoded, err := DecodeExpr(bytes.NewReader(w.buf), 0, binary.BigEndian)
		if err != nil {
			t.Fatalf("decode failed for %T: %v", expr, err)
		}

		if nDecoded != n {
			t.Fatalf("expected equal lengths, encoded=%d decoded=%d", n, nDecoded)
		}

		if !reflect.DeepEqual(decoded, expr) {
			t.Fatalf("roundtrip mismatch for %T\nwant: %#v\ngot:  %#v", expr, expr, decoded)
		}

		if strer, ok := decoded.(interface{ String() string }); ok {
			if strer.String() == "" {
				t.Fatalf("expected non-empty String() for %T", decoded)
			}
		} else if certValue, ok := decoded.(CertValueExpr); ok {
			if (&certValue).String() == "" {
				t.Fatalf("expected non-empty String() for %T", decoded)
			}
		}
	}
}

func TestDecodeExpr_UnknownOpcode(t *testing.T) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(999))

	_, _, err := DecodeExpr(bytes.NewReader(buf), 0, binary.BigEndian)
	if err == nil {
		t.Fatal("expected unknown opcode error")
	}

	if !strings.Contains(err.Error(), "unknown requirements opcode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStringAndOIDHelpers(t *testing.T) {
	oid := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
	certExpr := CertFieldExpr{Op: ExprOpCertGeneric, Slot: 1, Field: oid, Match: Match{Op: MatchOpExists}}

	if got := certExpr.String(); !strings.Contains(got, "1.2.840.113635.100.6.2.1") {
		t.Fatalf("expected OID string in output, got %q", got)
	}

	if got := Slot(0).String(); got != "leaf" {
		t.Fatalf("unexpected slot string: %q", got)
	}
	if got := Slot(-1).String(); got != "anchor" {
		t.Fatalf("unexpected slot string: %q", got)
	}

	if got := (Match{Op: MatchOpExists}).String(); got != "/* exists */" {
		t.Fatalf("unexpected match string: %q", got)
	}
	if got := (Match{Op: MatchOpGreaterEqual, Value: []byte("2")}).String(); got != " >= 2" {
		t.Fatalf("unexpected match string: %q", got)
	}

	if toOID([]byte{0x80}) != "" {
		t.Fatal("expected invalid oid data to return empty string")
	}
}
