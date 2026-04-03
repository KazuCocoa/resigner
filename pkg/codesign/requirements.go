package codesign

import "resigner/pkg/requirements"

var developerIDCAExtensionOID = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01}

func DefaultRequirements(bundleID string, commonName string) requirements.Requirements {
	root := andExpr(
		identifierExpr(bundleID),
		andExpr(
			requirements.NullaryExpr{Op: requirements.ExprOpAppleGenericAnchor},
			andExpr(certCommonNameExpr(commonName), issuerExtensionExpr()),
		),
	)

	return requirements.Requirements{
		requirements.DesignatedRequirementType: root,
	}
}

func andExpr(left, right requirements.Expr) requirements.BinaryExpr {
	return requirements.BinaryExpr{Op: requirements.ExprOpAnd, Left: left, Right: right}
}

func identifierExpr(bundleID string) requirements.DataExpr {
	return requirements.DataExpr{Op: requirements.ExprOpIdent, Data: []byte(bundleID)}
}

func certCommonNameExpr(commonName string) requirements.CertFieldExpr {
	return requirements.CertFieldExpr{
		Op:    requirements.ExprOpCertField,
		Slot:  0,
		Field: []byte("subject.CN"),
		Match: requirements.Match{Op: requirements.MatchOpEqual, Value: []byte(commonName)},
	}
}

func issuerExtensionExpr() requirements.CertFieldExpr {
	return requirements.CertFieldExpr{
		Op:    requirements.ExprOpCertGeneric,
		Slot:  1,
		Field: append([]byte(nil), developerIDCAExtensionOID...),
		Match: requirements.Match{Op: requirements.MatchOpExists},
	}
}
