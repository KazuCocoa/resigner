package requirements

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorFixture mirrors the JSON structure in testdata/expr_vectors.json.
type vectorFixture struct {
	Description string `json:"description"`
	Type        string `json:"type"`
	EncodedHex  string `json:"encoded_hex"`
}

// TestGoldenExprVectors loads testdata/expr_vectors.json and verifies that
// DecodeExpr produces valid expressions and that re-encoding them reproduces
// the exact same byte sequence. This file is intentionally machine-readable so
// that a re-implementation in another language can consume the same vectors.
func TestGoldenExprVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/expr_vectors.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	var fixtures []vectorFixture
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

			// Decode the expression from the golden bytes.
			expr, nDecoded, err := DecodeExpr(bytes.NewReader(raw), 0, binary.BigEndian)
			if err != nil {
				t.Fatalf("DecodeExpr: %v", err)
			}
			if int(nDecoded) != len(raw) {
				t.Fatalf("consumed %d bytes, want %d", nDecoded, len(raw))
			}

			// Re-encode and compare.
			w := &growableWriterAt{}
			nEncoded, err := EncodeExpr(expr, w, 0, binary.BigEndian)
			if err != nil {
				t.Fatalf("EncodeExpr: %v", err)
			}
			if nEncoded != nDecoded {
				t.Fatalf("re-encoded %d bytes, want %d", nEncoded, nDecoded)
			}
			if got := hex.EncodeToString(w.buf[:nEncoded]); got != f.EncodedHex {
				t.Fatalf("re-encoded hex mismatch:\ngot:  %s\nwant: %s", got, f.EncodedHex)
			}
		})
	}
}
