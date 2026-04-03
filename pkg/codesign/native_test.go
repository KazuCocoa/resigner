package codesign_test

import (
	"errors"
	"testing"

	"resigner/pkg/codesign"
)

type hintStringExpectation struct {
	name  string
	hint  codesign.VerificationFailureHint
	want  string
}

func singleHintCases() []hintStringExpectation {
	return []hintStringExpectation{
		{name: "none", hint: 0, want: "none"},
		{name: "expired", hint: codesign.VerificationFailureHintProfileExpired, want: "profile expired"},
		{name: "missing udid", hint: codesign.VerificationFailureHintProfileMissingUDID, want: "profile missing UDID"},
		{name: "team mismatch", hint: codesign.VerificationFailureHintProfileTeamMismatch, want: "profile team mismatch"},
		{name: "bundle mismatch", hint: codesign.VerificationFailureHintProfileBundleIDMismatch, want: "profile bundle ID mismatch"},
		{name: "identifier mismatch", hint: codesign.VerificationFailureHintProfileIdentifierMismatch, want: "profile identifier mismatch"},
		{name: "missing cert", hint: codesign.VerificationFailureHintProfileMissingCertificate, want: "profile missing certificate"},
		{name: "recursive", hint: codesign.VerificationFailureHintRecursiveVerificationFailed, want: "recursive verification failed"},
		{name: "unknown", hint: 4096, want: "unknown (4096)"},
	}
}

func allHintsCase() hintStringExpectation {
	all := codesign.VerificationFailureHintProfileExpired |
		codesign.VerificationFailureHintProfileMissingUDID |
		codesign.VerificationFailureHintProfileTeamMismatch |
		codesign.VerificationFailureHintProfileBundleIDMismatch |
		codesign.VerificationFailureHintProfileIdentifierMismatch |
		codesign.VerificationFailureHintProfileMissingCertificate |
		codesign.VerificationFailureHintRecursiveVerificationFailed |
		4096

	return hintStringExpectation{
		name: "combined flags",
		hint: all,
		want: "profile expired | profile missing UDID | profile team mismatch | profile bundle ID mismatch | profile identifier mismatch | profile missing certificate | recursive verification failed | unknown (4096)",
	}
}

func assertHintString(t *testing.T, tc hintStringExpectation) {
	t.Helper()
	got := tc.hint.String()
	if got != tc.want {
		t.Fatalf("unexpected string for %s: want %q, got %q", tc.name, tc.want, got)
	}
}

func TestVerificationFailureHintString(t *testing.T) {
	for _, tc := range singleHintCases() {
		t.Run(tc.name, func(t *testing.T) {
			assertHintString(t, tc)
		})
	}

	t.Run("combined", func(t *testing.T) {
		assertHintString(t, allHintsCase())
	})
}

func TestVerificationFailureError(t *testing.T) {
	cause := errors.New("inner verify error")
	err := &codesign.VerificationFailureError{
		Path:  "Payload/My.app",
		Hint:  codesign.VerificationFailureHintProfileExpired,
		Cause: cause,
	}

	if !errors.Is(err, cause) {
		t.Fatal("expected unwrap to expose cause")
	}

	msg := err.Error()
	if msg == "" {
		t.Fatal("expected non-empty error string")
	}
}
