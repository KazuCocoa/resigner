package der

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// marshalFixture mirrors the JSON in testdata/marshal_vectors.json.
type marshalFixture struct {
	Description string          `json:"description"`
	GoType      string          `json:"go_type"`
	Value       json.RawMessage `json:"value"`
	EncodedHex  string          `json:"encoded_hex"`
}

// TestGoldenMarshalVectors loads testdata/marshal_vectors.json and verifies
// that each hex vector can be decoded without error. For non-integer types
// (bool, string, slice, map) it also verifies that re-encoding the decoded value
// produces the exact same bytes.
//
// NOTE: Integer vectors are intentionally size-dependent. The generic interface{}
// decode path always returns int64, so re-encoding an int8/int16/int32 golden
// vector via interface{} will produce an 8-byte encoding instead of the original
// 1/2/4-byte encoding. A re-implementor must track the numeric type separately
// to reproduce the exact bytes — the golden file documents the expected encoding
// for each specific Go type+size.
func TestGoldenMarshalVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/marshal_vectors.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	var fixtures []marshalFixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no fixtures found")
	}

	for _, f := range fixtures {
		f := f
		t.Run(f.Description, func(t *testing.T) {
			raw, err := hex.DecodeString(f.EncodedHex)
			if err != nil {
				t.Fatalf("decode hex: %v", err)
			}

			// Decode using the generic interface{} path — must not error.
			var v interface{}
			if err := Unmarshal(raw, &v); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}

			// For types where the interface{} re-encode is lossless, verify it.
			switch f.GoType {
			case "bool", "string", "[]string", "map[string]string":
				encoded, err := Marshal(v)
				if err != nil {
					t.Fatalf("Marshal: %v", err)
				}
				if got := hex.EncodeToString(encoded); got != f.EncodedHex {
					t.Fatalf("re-encoded mismatch:\ngot:  %s\nwant: %s", got, f.EncodedHex)
				}
			}
		})
	}
}
