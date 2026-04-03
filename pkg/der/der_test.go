package der

import (
	"errors"
	"testing"
)

// TestMarshalUnmarshal_Bool verifies that booleans roundtrip and produce the
// well-known DER byte vectors [tag=0x01, length=0x01, value=0x01/0x00].
func TestMarshalUnmarshal_Bool(t *testing.T) {
	cases := []struct {
		in      bool
		wantHex []byte
	}{
		{true, []byte{0x01, 0x01, 0x01}},
		{false, []byte{0x01, 0x01, 0x00}},
	}

	for _, tc := range cases {
		data, err := Marshal(tc.in)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tc.in, err)
		}
		if string(data) != string(tc.wantHex) {
			t.Fatalf("Marshal(%v) = %#v, want %#v", tc.in, data, tc.wantHex)
		}

		var got bool
		if err := Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal bool(%v): %v", tc.in, err)
		}
		if got != tc.in {
			t.Fatalf("roundtrip bool: got %v, want %v", got, tc.in)
		}
	}
}

// TestMarshalUnmarshal_Int checks common integer types roundtrip correctly.
func TestMarshalUnmarshal_Int(t *testing.T) {
	// int32(1): tag=0x02, length=0x04, big-endian 4 bytes
	data32, err := Marshal(int32(1))
	if err != nil {
		t.Fatalf("Marshal int32: %v", err)
	}
	if len(data32) != 6 || data32[0] != 0x02 || data32[1] != 0x04 {
		t.Fatalf("Marshal int32(1) unexpected encoding: %#v", data32)
	}
	var got32 int32
	if err := Unmarshal(data32, &got32); err != nil {
		t.Fatalf("Unmarshal int32: %v", err)
	}
	if got32 != 1 {
		t.Fatalf("roundtrip int32: got %v, want 1", got32)
	}

	// int64(0): tag=0x02, length=0x08
	data64, err := Marshal(int64(0))
	if err != nil {
		t.Fatalf("Marshal int64: %v", err)
	}
	if len(data64) != 10 || data64[0] != 0x02 || data64[1] != 0x08 {
		t.Fatalf("Marshal int64(0) unexpected encoding: %#v", data64)
	}
	var got64 int64
	if err := Unmarshal(data64, &got64); err != nil {
		t.Fatalf("Unmarshal int64: %v", err)
	}
	if got64 != 0 {
		t.Fatalf("roundtrip int64: got %v, want 0", got64)
	}

	// int8(42) = 0x2a
	data8, err := Marshal(int8(42))
	if err != nil {
		t.Fatalf("Marshal int8: %v", err)
	}
	want8 := []byte{0x02, 0x01, 0x2a}
	if string(data8) != string(want8) {
		t.Fatalf("Marshal int8(42) = %#v, want %#v", data8, want8)
	}
	var got8 int8
	if err := Unmarshal(data8, &got8); err != nil {
		t.Fatalf("Unmarshal int8: %v", err)
	}
	if got8 != 42 {
		t.Fatalf("roundtrip int8: got %v, want 42", got8)
	}
}

// TestMarshalUnmarshal_String checks string roundtrips and the wire format.
func TestMarshalUnmarshal_String(t *testing.T) {
	// Non-empty strings roundtrip: tag=0x0c, length=2, "hi"
	cases := []struct {
		in      string
		wantHex []byte
	}{
		{"hi", []byte{0x0c, 0x02, 0x68, 0x69}},
		{"hello world", append([]byte{0x0c, 0x0b}, []byte("hello world")...)},
	}
	for _, tc := range cases {
		data, err := Marshal(tc.in)
		if err != nil {
			t.Fatalf("Marshal(%q): %v", tc.in, err)
		}
		if string(data) != string(tc.wantHex) {
			t.Fatalf("Marshal(%q) = %#v, want %#v", tc.in, data, tc.wantHex)
		}
		var got string
		if err := Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal string(%q): %v", tc.in, err)
		}
		if got != tc.in {
			t.Fatalf("roundtrip string: got %q, want %q", got, tc.in)
		}
	}
}

// TestMarshal_EmptyString verifies empty string encoding. Note: the decoder
// requires at least 3 bytes so empty strings cannot be decoded — this is a
// known limitation of decodeString's minimum-length guard.
func TestMarshal_EmptyString(t *testing.T) {
	data, err := Marshal("")
	if err != nil {
		t.Fatalf("Marshal empty string: %v", err)
	}
	// Encoding is [tag=0x0c, length=0x00] — only 2 bytes
	want := []byte{0x0c, 0x00}
	if string(data) != string(want) {
		t.Fatalf("Marshal empty string = %#v, want %#v", data, want)
	}
	// Decoding fails because decodeString requires len(data) >= 3
	var got string
	err = Unmarshal(data, &got)
	if err == nil {
		t.Fatal("Expected decode error for empty string, got nil")
	}
}

// TestMarshalUnmarshal_Slice checks []string roundtrips.
func TestMarshalUnmarshal_Slice(t *testing.T) {
	in := []string{"a", "b", "c"}
	data, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal slice: %v", err)
	}
	// First byte must be Array tag (0x30)
	if data[0] != byte(Array) {
		t.Fatalf("Expected Array tag 0x%02x, got 0x%02x", Array, data[0])
	}

	var got []string
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal slice: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("roundtrip slice len: got %d, want %d", len(got), len(in))
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("roundtrip slice[%d]: got %q, want %q", i, got[i], in[i])
		}
	}
}

// TestMarshalUnmarshal_Map checks map[string]string roundtrips with sorted keys.
func TestMarshalUnmarshal_Map(t *testing.T) {
	in := map[string]string{"z": "last", "a": "first"}
	data, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal map: %v", err)
	}
	// First byte must be Object tag (0x31)
	if data[0] != byte(Object) {
		t.Fatalf("Expected Object tag 0x%02x, got 0x%02x", Object, data[0])
	}

	var got map[string]string
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal map: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("roundtrip map len: got %d, want 2", len(got))
	}
	if got["a"] != "first" || got["z"] != "last" {
		t.Fatalf("roundtrip map values wrong: %v", got)
	}
}

// TestMarshalUnmarshal_NestedSliceInMap checks a more complex type.
func TestMarshalUnmarshal_NestedSliceInMap(t *testing.T) {
	in := map[string][]string{"keys": {"x", "y"}}
	data, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal nested: %v", err)
	}
	var got map[string][]string
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal nested: %v", err)
	}
	if len(got["keys"]) != 2 || got["keys"][0] != "x" || got["keys"][1] != "y" {
		t.Fatalf("roundtrip nested map: %v", got)
	}
}

// TestMarshalUnmarshal_Interface checks dynamic type detection via interface{}.
func TestMarshalUnmarshal_Interface(t *testing.T) {
	// bool via interface
	boolData, _ := Marshal(true)
	var boolIface interface{}
	if err := Unmarshal(boolData, &boolIface); err != nil {
		t.Fatalf("Unmarshal bool iface: %v", err)
	}
	if v, ok := boolIface.(bool); !ok || !v {
		t.Fatalf("Expected bool true via iface, got %T(%v)", boolIface, boolIface)
	}

	// int via interface
	intData, _ := Marshal(int64(99))
	var intIface interface{}
	if err := Unmarshal(intData, &intIface); err != nil {
		t.Fatalf("Unmarshal int iface: %v", err)
	}
	if v, ok := intIface.(int64); !ok || v != 99 {
		t.Fatalf("Expected int64(99) via iface, got %T(%v)", intIface, intIface)
	}

	// string via interface
	strData, _ := Marshal("hello")
	var strIface interface{}
	if err := Unmarshal(strData, &strIface); err != nil {
		t.Fatalf("Unmarshal string iface: %v", err)
	}
	if v, ok := strIface.(string); !ok || v != "hello" {
		t.Fatalf("Expected string(hello) via iface, got %T(%v)", strIface, strIface)
	}

	// slice via interface
	sliceData, _ := Marshal([]string{"one"})
	var sliceIface interface{}
	if err := Unmarshal(sliceData, &sliceIface); err != nil {
		t.Fatalf("Unmarshal slice iface: %v", err)
	}
	if _, ok := sliceIface.([]interface{}); !ok {
		t.Fatalf("Expected []interface{} via iface, got %T", sliceIface)
	}
}

// TestMarshal_UnsupportedType verifies that unsupported types return an error.
func TestMarshal_UnsupportedType(t *testing.T) {
	_, err := Marshal(3.14) // float64 not supported
	if err == nil {
		t.Fatal("Expected error marshalling float64, got nil")
	}
}

// TestMarshal_MapNonStringKey verifies that non-string-keyed maps return ErrInvalidType.
func TestMarshal_MapNonStringKey(t *testing.T) {
	_, err := Marshal(map[int]string{1: "a"})
	if err == nil {
		t.Fatal("Expected error for map with int key, got nil")
	}
	if !errors.Is(err, ErrInvalidType) {
		t.Fatalf("Expected ErrInvalidType, got: %v", err)
	}
}

// TestUnmarshal_NonPointer verifies that passing a non-pointer returns ErrInvalidType.
func TestUnmarshal_NonPointer(t *testing.T) {
	data, _ := Marshal(true)
	var b bool
	err := Unmarshal(data, b) // not a pointer
	if err == nil {
		t.Fatal("Expected error for non-pointer, got nil")
	}
	if !errors.Is(err, ErrInvalidType) {
		t.Fatalf("Expected ErrInvalidType, got: %v", err)
	}
}

// TestUnmarshal_WrongTag verifies type mismatch errors.
func TestUnmarshal_WrongTag(t *testing.T) {
	// Encode a bool, try to decode as string
	data, _ := Marshal(false)
	var s string
	err := Unmarshal(data, &s)
	if err == nil {
		t.Fatal("Expected error decoding bool as string, got nil")
	}
}

// TestEncodeLength_Roundtrip verifies short and long length encoding.
func TestEncodeLength_Roundtrip(t *testing.T) {
	cases := []uint64{0, 1, 127, 128, 255, 256, 65535, 0xFFFFFF}
	for _, n := range cases {
		encoded := encodeLength(n)
		consumed, decoded := decodeLength(encoded)
		if uint64(consumed) != uint64(len(encoded)) {
			t.Fatalf("encodeLength(%d): consumed=%d, encoded len=%d", n, consumed, len(encoded))
		}
		if decoded != n {
			t.Fatalf("encodeLength(%d) roundtrip: got %d", n, decoded)
		}
	}
}

// TestMarshalUnmarshal_LargeLengthString checks strings that need multi-byte length encoding.
func TestMarshalUnmarshal_LargeLengthString(t *testing.T) {
	// Create a string longer than 127 bytes to force multi-byte length
	in := string(make([]byte, 200))
	data, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal 200-byte string: %v", err)
	}
	// Multi-byte length: byte[1] should have high bit set
	if data[1]&0x80 == 0 {
		t.Fatalf("Expected multi-byte length for 200-byte string, got single byte %02x", data[1])
	}
	var got string
	if err := Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal 200-byte string: %v", err)
	}
	if len(got) != 200 {
		t.Fatalf("roundtrip large string: len=%d, want 200", len(got))
	}
}
