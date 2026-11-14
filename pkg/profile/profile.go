package profile

// Profile names a signature profile (Table 2.1). The value is also used as the
// algorithm field of the release manifest.
type Profile string

// The three supported signature profiles.
const (
	RSAPSS  Profile = "rsa-pss-sha256"
	ECDSA   Profile = "ecdsa-p256-sha256"
	Ed25519 Profile = "ed25519"
)

// Parse returns the Profile named s. The second result is false for any value that
// is not exactly one of the three supported profiles.
func Parse(s string) (Profile, bool) {
	switch Profile(s) {
	case RSAPSS, ECDSA, Ed25519:
		return Profile(s), true
	default:
		return "", false
	}
}

// SignatureLen returns the signature length in bytes: 384 for rsa-pss-sha256,
// 64 for ecdsa-p256-sha256 and ed25519, and 0 for an unknown profile.
func (p Profile) SignatureLen() int {
	switch p {
	case RSAPSS:
		return 384
	case ECDSA, Ed25519:
		return 64
	default:
		return 0
	}
}
