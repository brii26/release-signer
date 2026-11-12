package profile_test

import (
	"testing"

	"github.com/brii26/release-signer/pkg/profile"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		wantProf  profile.Profile
		wantvalid bool
	}{
		{"rsa-pss-sha256", profile.RSAPSS, true},
		{"ecdsa-p256-sha256", profile.ECDSA, true},
		{"ed25519", profile.Ed25519, true},
		{"", "", false},
		{"rsa-pkcs1-sha256", "", false},
		{"rsa-pss-sha512", "", false},
		{"ecdsa-p384-sha256", "", false},
		{"ed25519ph", "", false},
		{"ED25519", "", false},
	}

	for _, tc := range tests {
		gotProf, ok := profile.Parse(tc.input)
		if ok != tc.wantvalid {
			t.Errorf("Parse(%q) validity = %v, want %v", tc.input, ok, tc.wantvalid)
		}
		if gotProf != tc.wantProf {
			t.Errorf("Parse(%q) = %q, want %q", tc.input, gotProf, tc.wantProf)
		}
	}
}

func TestSignatureLen(t *testing.T) {
	if got := profile.RSAPSS.SignatureLen(); got != 384 {
		t.Errorf("RSAPSS SignatureLen %d, want 384", got)
	}
	if got := profile.ECDSA.SignatureLen(); got != 64 {
		t.Errorf("ECDSA SignatureLen %d, want 64", got)
	}
	if got := profile.Ed25519.SignatureLen(); got != 64 {
		t.Errorf("Ed25519 SignatureLen %d, want 64", got)
	}
	if got := profile.Profile("unknown").SignatureLen(); got != 0 {
		t.Errorf("unknown SignatureLen %d, want 0", got)
	}
}
