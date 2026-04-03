package requirements

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"resigner/pkg/utils"
)

type Requirements map[RequirementType]Expr

type RequirementType uint32

const (
	HostRequirementType       RequirementType = 1
	GuestRequirementType      RequirementType = 2
	DesignatedRequirementType RequirementType = 3
	LibraryRequirementType    RequirementType = 4
	PluginRequirementType     RequirementType = 5
)

type ExprOp uint32

const (
	ExprOpFalse              ExprOp = iota // unconditionally false
	ExprOpTrue                             // unconditionally true
	ExprOpIdent                            // match canonical code [string]
	ExprOpAppleAnchor                      // signed by Apple as Apple's product
	ExprOpAnchorHash                       // match anchor [cert hash]
	ExprOpInfoKeyValue                     // *legacy* - use ExprOpInfoKeyField [key; value]
	ExprOpAnd                              // binary prefix expr AND expr [expr; expr]
	ExprOpOr                               // binary prefix expr OR expr [expr; expr]
	ExprOpCDHash                           // match hash of CodeDirectory directly [cd hash]
	ExprOpNot                              // logical inverse [expr]
	ExprOpInfoKeyField                     // Info.plist key field [string; match suffix]
	ExprOpCertField                        // Certificate field [cert index; field name; match suffix]
	ExprOpTrustedCert                      // require trust settings to approve one particular cert [cert index]
	ExprOpTrustedCerts                     // require trust settings to approve the cert chain
	ExprOpCertGeneric                      // Certificate component by OID [cert index; oid; match suffix]
	ExprOpAppleGenericAnchor               // signed by Apple in any capacity
	ExprOpEntitlementField                 // entitlement dictionary field [string; match suffix]
	ExprOpCertPolicy                       // Certificate policy by OID [cert index; oid; match suffix]
	ExprOpNamedAnchor                      // named anchor type
	ExprOpNamedCode                        // named subroutine
	ExprOpOpCount                          // (total opcode count in use)
)

type MatchOp uint32

const (
	MatchOpExists       MatchOp = iota // anything but explicit "false" - no value stored
	MatchOpEqual                       // equal (CFEqual)
	MatchOpContains                    // partial MatchOp (substring)
	MatchOpBeginsWith                  // partial MatchOp (initial substring)
	MatchOpEndsWith                    // partial MatchOp (terminal substring)
	MatchOpLessThan                    // less than (string with numeric comparison)
	MatchOpGreaterThan                 // greater than (string with numeric comparison)
	MatchOpLessEqual                   // less or equal (string with numeric comparison)
	MatchOpGreaterEqual                // greater or equal (string with numeric comparison)
)

type Expr interface{}

func DecodeExpr(r io.ReaderAt, offset int64, byteOrder binary.ByteOrder) (Expr, int64, error) {
	var op ExprOp
	err := binary.Read(io.NewSectionReader(r, offset, 4), byteOrder, &op)
	if err != nil {
		return nil, 0, err
	}

	switch op {
	case ExprOpFalse, ExprOpTrue, ExprOpTrustedCerts, ExprOpAppleAnchor, ExprOpAppleGenericAnchor:
		return NullaryExpr{Op: op}, 4, nil
	case ExprOpNot:
		arg, nArg, err := DecodeExpr(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return UnaryExpr{
			Op:  op,
			Arg: arg,
		}, 4 + nArg, nil
	case ExprOpOr, ExprOpAnd:
		left, nLeft, err := DecodeExpr(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		right, nRight, err := DecodeExpr(r, offset+4+nLeft, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return BinaryExpr{
			Op:    op,
			Left:  left,
			Right: right,
		}, 4 + nLeft + nRight, nil
	case ExprOpIdent, ExprOpCDHash, ExprOpNamedAnchor, ExprOpNamedCode:
		data, nData, err := decodeData(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return DataExpr{
			Op:   op,
			Data: data,
		}, 4 + nData, nil
	case ExprOpInfoKeyValue:
		field, nField, err := decodeData(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		value, nValue, err := decodeData(r, offset+4+nField, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return FieldValueExpr{
			Op:    op,
			Field: field,
			Value: value,
		}, 4 + nField + nValue, nil
	case ExprOpInfoKeyField, ExprOpEntitlementField:
		field, nField, err := decodeData(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		match, nMatch, err := decodeMatch(r, offset+4+nField, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return FieldExpr{
			Op:    op,
			Field: field,
			Match: match,
		}, 4 + nField + nMatch, nil
	case ExprOpTrustedCert:
		slot, nSlot, err := decodeCertSlot(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return CertExpr{
			Op:   op,
			Slot: slot,
		}, 4 + nSlot, nil
	case ExprOpAnchorHash:
		slot, nSlot, err := decodeCertSlot(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		value, nValue, err := decodeData(r, offset+4+nSlot, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return CertValueExpr{
			Op:    op,
			Slot:  slot,
			Value: value,
		}, 4 + nSlot + nValue, nil

	case ExprOpCertField, ExprOpCertPolicy, ExprOpCertGeneric:
		slot, nSlot, err := decodeCertSlot(r, offset+4, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		field, nField, err := decodeData(r, offset+4+nSlot, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		match, nMatch, err := decodeMatch(r, offset+4+nSlot+nField, byteOrder)
		if err != nil {
			return nil, 0, err
		}

		return CertFieldExpr{
			Op:    op,
			Slot:  slot,
			Field: field,
			Match: match,
		}, 4 + nSlot + nField + nMatch, nil
	default: // TODO: weird flag parsing
		return nil, 0, fmt.Errorf("unknown requirements opcode")
	}
}

func EncodeExpr(expr Expr, w io.WriterAt, offset int64, byteOrder binary.ByteOrder) (int64, error) {

	switch expr := expr.(type) {
	case NullaryExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		return 4, nil
	case UnaryExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		argN, err := EncodeExpr(expr.Arg, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + argN, nil
	case BinaryExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		leftN, err := EncodeExpr(expr.Left, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		rightN, err := EncodeExpr(expr.Right, w, offset+4+leftN, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + leftN + rightN, nil
	case DataExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nData, err := encodeData(expr.Data, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nData, nil
	case FieldValueExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nField, err := encodeData(expr.Field, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		nValue, err := encodeData(expr.Value, w, offset+4+nField, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nField + nValue, nil
	case FieldExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nField, err := encodeData(expr.Field, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		nMatch, err := encodeMatch(expr.Match, w, offset+4+nField, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nField + nMatch, nil
	case CertExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nSlot, err := encodeCertSlot(expr.Slot, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nSlot, nil
	case CertValueExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nSlot, err := encodeCertSlot(expr.Slot, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		nValue, err := encodeData(expr.Value, w, offset+4+nSlot, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nSlot + nValue, nil
	case CertFieldExpr:
		err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, expr.Op)
		if err != nil {
			return 0, err
		}

		nSlot, err := encodeCertSlot(expr.Slot, w, offset+4, byteOrder)
		if err != nil {
			return 0, err
		}

		nField, err := encodeData(expr.Field, w, offset+4+nSlot, byteOrder)
		if err != nil {
			return 0, err
		}

		nMatch, err := encodeMatch(expr.Match, w, offset+4+nSlot+nField, byteOrder)
		if err != nil {
			return 0, err
		}

		return 4 + nSlot + nField + nMatch, nil
	}

	return 0, nil
}

func decodeData(r io.ReaderAt, offset int64, byteOrder binary.ByteOrder) ([]byte, int64, error) {
	var length uint32
	err := binary.Read(io.NewSectionReader(r, offset, 4), byteOrder, &length)
	if err != nil {
		return nil, 0, err
	}

	alignedLength := ((length + 3) >> 2) << 2

	data := make([]byte, length)
	_, err = r.ReadAt(data, offset+4)
	if err != nil {
		return nil, 0, err
	}

	return data, 4 + int64(alignedLength), nil
}

func encodeData(data []byte, w io.WriterAt, offset int64, byteOrder binary.ByteOrder) (int64, error) {
	err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, uint32(len(data)))
	if err != nil {
		return 0, err
	}

	alignedLength := ((len(data) + 3) >> 2) << 2
	alignedData := make([]byte, alignedLength)

	copy(alignedData, data)

	_, err = w.WriteAt(alignedData, offset+4)
	if err != nil {
		return 0, err
	}

	return 4 + int64(alignedLength), nil
}

func decodeCertSlot(r io.ReaderAt, offset int64, byteOrder binary.ByteOrder) (Slot, int64, error) {
	var slot Slot
	err := binary.Read(io.NewSectionReader(r, offset, 4), byteOrder, &slot)
	if err != nil {
		return 0, 0, err
	}
	return slot, 4, nil
}

func encodeCertSlot(slot Slot, w io.WriterAt, offset int64, byteOrder binary.ByteOrder) (int64, error) {
	err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, slot)
	if err != nil {
		return 0, err
	}
	return 4, nil
}

func decodeMatchOp(r io.ReaderAt, offset int64, byteOrder binary.ByteOrder) (MatchOp, int64, error) {
	var matchOp MatchOp
	err := binary.Read(io.NewSectionReader(r, offset, 4), byteOrder, &matchOp)
	if err != nil {
		return 0, 0, err
	}
	return matchOp, 4, nil
}

func encodeMatchOp(matchOp MatchOp, w io.WriterAt, offset int64, byteOrder binary.ByteOrder) (int64, error) {
	err := binary.Write(utils.NewSectionWriter(w, offset, 4), byteOrder, matchOp)
	if err != nil {
		return 0, err
	}
	return 4, nil
}

func decodeMatch(r io.ReaderAt, offset int64, byteOrder binary.ByteOrder) (Match, int64, error) {
	matchOp, nMatchOp, err := decodeMatchOp(r, offset, byteOrder)
	if err != nil {
		return Match{}, 0, err
	}

	switch matchOp {
	case MatchOpExists:
		return Match{Op: matchOp, Value: nil}, nMatchOp, nil
	default:
		match, nMatch, err := decodeData(r, offset+nMatchOp, byteOrder)
		if err != nil {
			return Match{}, 0, err
		}

		return Match{Op: matchOp, Value: match}, nMatchOp + nMatch, nil
	}
}

func encodeMatch(match Match, w io.WriterAt, offset int64, byteOrder binary.ByteOrder) (int64, error) {
	nMatchOp, err := encodeMatchOp(match.Op, w, offset, byteOrder)
	if err != nil {
		return 0, err
	}

	switch match.Op {
	case MatchOpExists:
		return nMatchOp, nil
	default:
		nMatch, err := encodeData(match.Value, w, offset+nMatchOp, byteOrder)
		if err != nil {
			return 0, err
		}

		return nMatchOp + nMatch, nil
	}
}

type NullaryExpr struct {
	Op ExprOp
}

func (e NullaryExpr) String() string {
	switch e.Op {
	case ExprOpFalse:
		return "never"
	case ExprOpTrue:
		return "always"
	case ExprOpTrustedCerts:
		return "anchor trusted"
	case ExprOpAppleAnchor:
		return "anchor apple"
	case ExprOpAppleGenericAnchor:
		return "anchor apple generic"
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type UnaryExpr struct {
	Op  ExprOp
	Arg Expr
}

func (e UnaryExpr) String() string {
	switch e.Op {
	case ExprOpNot:
		return fmt.Sprintf("! %s", e.Arg)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type BinaryExpr struct {
	Op    ExprOp
	Left  Expr
	Right Expr
}

func (e BinaryExpr) String() string {
	switch e.Op {
	case ExprOpOr:
		return fmt.Sprintf("%s or %s", e.Left, e.Right)
	case ExprOpAnd:
		return fmt.Sprintf("%s and %s", e.Left, e.Right)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type DataExpr struct {
	Op   ExprOp
	Data []byte
}

func (e DataExpr) String() string {
	switch e.Op {
	case ExprOpIdent:
		return fmt.Sprintf("identifier \"%s\"", e.Data)
	case ExprOpCDHash:
		return fmt.Sprintf("cdhash %s", e.Data)
	case ExprOpNamedAnchor:
		return fmt.Sprintf("apple anchor %s", e.Data)
	case ExprOpNamedCode:
		return fmt.Sprintf("(%s)", e.Data)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type FieldValueExpr struct {
	Op    ExprOp
	Field []byte
	Value []byte
}

func (e FieldValueExpr) String() string {
	switch e.Op {
	case ExprOpInfoKeyValue:
		return fmt.Sprintf("info[%s] = %s", e.Field, e.Value)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type FieldExpr struct {
	Op    ExprOp
	Field []byte
	Match Match
}

func (e FieldExpr) String() string {
	switch e.Op {
	case ExprOpInfoKeyField:
		return fmt.Sprintf("info[%s] %s", e.Field, e.Match)
	case ExprOpEntitlementField:
		return fmt.Sprintf("entitlements[%s] %s", e.Field, e.Match)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type CertExpr struct {
	Op   ExprOp
	Slot Slot
}

func (e CertExpr) String() string {
	switch e.Op {
	case ExprOpTrustedCert:
		return fmt.Sprintf("certificate %s trusted", e.Slot)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type CertValueExpr struct {
	Op    ExprOp
	Slot  Slot
	Value []byte
}

func (e *CertValueExpr) String() string {
	switch e.Op {
	case ExprOpAnchorHash:
		return fmt.Sprintf("certificate %s = %s", e.Slot, e.Value)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type CertFieldExpr struct {
	Op    ExprOp
	Slot  Slot
	Field []byte
	Match Match
}

func (e CertFieldExpr) String() string {
	switch e.Op {
	case ExprOpCertField:
		return fmt.Sprintf("certificate %s[%s] %s", e.Slot, e.Field, e.Match)
	case ExprOpCertGeneric:
		return fmt.Sprintf("certificate %s[field.%s] %s", e.Slot, toOID(e.Field), e.Match)
	case ExprOpCertPolicy:
		return fmt.Sprintf("certificate %s[policy.%s] %s", e.Slot, toOID(e.Field), e.Match)
	default:
		return fmt.Sprintf("<unknown: %#v>", e)
	}
}

type Match struct {
	Op    MatchOp
	Value []byte
}

func (m Match) String() string {
	switch m.Op {
	case MatchOpExists:
		return "/* exists */"
	case MatchOpEqual:
		return fmt.Sprintf(" = \"%s\"", m.Value)
	case MatchOpContains:
		return fmt.Sprintf(" ~ %s", m.Value)
	case MatchOpBeginsWith:
		return fmt.Sprintf(" = %s*", m.Value)
	case MatchOpEndsWith:
		return fmt.Sprintf(" = *%s", m.Value)
	case MatchOpLessThan:
		return fmt.Sprintf(" < %s", m.Value)
	case MatchOpGreaterThan:
		return fmt.Sprintf(" > %s", m.Value)
	case MatchOpLessEqual:
		return fmt.Sprintf(" <= %s", m.Value)
	case MatchOpGreaterEqual:
		return fmt.Sprintf(" >= %s", m.Value)
	default:
		return fmt.Sprintf("<unknown: %#v>", m)
	}
}

type Slot int32

func (s Slot) String() string {
	switch s {
	case 0:
		return "leaf"
	case -1:
		return "anchor"
	default:
		return fmt.Sprintf("%d", s)
	}
}

// NOTE:
// ref https://opensource.apple.com/source/Security/Security-59306.80.4/
// ref http://oid-info.com/get/1.2.840.113635.100.6.2.6
func toOID(data []byte) string {
	var oidStr string

	r := bytes.NewReader(data)

	oid1, err := getOid(r)
	if err != nil {
		return ""
	}

	q1 := uint32(math.Min(float64(oid1)/40, 2))
	oidStr += fmt.Sprintf("%d.%d", q1, oid1-q1*40)

	for {
		oid, err := getOid(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}

		oidStr += fmt.Sprintf(".%d", uint32(oid))
	}

	return oidStr
}

func getOid(r *bytes.Reader) (uint32, error) {
	var result uint32

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return 0, err
		}
		if err != nil {
			return 0, fmt.Errorf("could not parse OID value: %v", err)
		}

		result = uint32(result*128) + uint32(b&0x7f)

		// If high order bit is 1.
		if (b & 0x80) == 0 {
			break
		}
	}

	return result, nil
}
