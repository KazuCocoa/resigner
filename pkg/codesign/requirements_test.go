package codesign

import (
	"testing"

	"resigner/pkg/requirements"
)

func TestDefaultRequirementsShape(t *testing.T) {
	bundleID := "com.example.app"
	commonName := "Apple Development: Jane Doe"

	reqs := DefaultRequirements(bundleID, commonName)

	expr, ok := reqs[requirements.DesignatedRequirementType]
	if !ok {
		t.Fatal("expected designated requirement")
	}

	topAnd, ok := expr.(requirements.BinaryExpr)
	if !ok || topAnd.Op != requirements.ExprOpAnd {
		t.Fatal("expected top-level AND expression")
	}

	ident, ok := topAnd.Left.(requirements.DataExpr)
	if !ok || ident.Op != requirements.ExprOpIdent || string(ident.Data) != bundleID {
		t.Fatal("expected identifier expression with bundle id")
	}

	anchorAnd, ok := topAnd.Right.(requirements.BinaryExpr)
	if !ok || anchorAnd.Op != requirements.ExprOpAnd {
		t.Fatal("expected anchor branch AND expression")
	}

	anchor, ok := anchorAnd.Left.(requirements.NullaryExpr)
	if !ok || anchor.Op != requirements.ExprOpAppleGenericAnchor {
		t.Fatal("expected apple generic anchor check")
	}

	certAnd, ok := anchorAnd.Right.(requirements.BinaryExpr)
	if !ok || certAnd.Op != requirements.ExprOpAnd {
		t.Fatal("expected certificate checks AND expression")
	}

	leafCN, ok := certAnd.Left.(requirements.CertFieldExpr)
	if !ok {
		t.Fatal("expected leaf common-name certificate field check")
	}

	if leafCN.Op != requirements.ExprOpCertField || leafCN.Slot != 0 {
		t.Fatal("unexpected leaf certificate field operator/slot")
	}

	if string(leafCN.Field) != "subject.CN" {
		t.Fatal("unexpected leaf certificate field")
	}

	if leafCN.Match.Op != requirements.MatchOpEqual || string(leafCN.Match.Value) != commonName {
		t.Fatal("unexpected common-name match")
	}

	intermediateOID, ok := certAnd.Right.(requirements.CertFieldExpr)
	if !ok {
		t.Fatal("expected intermediate certificate generic field check")
	}

	if intermediateOID.Op != requirements.ExprOpCertGeneric || intermediateOID.Slot != 1 {
		t.Fatal("unexpected intermediate certificate operator/slot")
	}

	expectedOID := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}
	if string(intermediateOID.Field) != string(expectedOID) {
		t.Fatal("unexpected intermediate certificate OID")
	}

	if intermediateOID.Match.Op != requirements.MatchOpExists {
		t.Fatal("expected OID existence match")
	}
}
