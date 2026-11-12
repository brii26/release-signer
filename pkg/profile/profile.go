package profile

type Profile string

const (
	RSAPSS  Profile = "rsa-pss-sha256"
	ECDSA   Profile = "ecdsa-p256-sha256"
	Ed25519 Profile = "ed25519"
)

func Parse(s string) (Profile, bool) {
	switch Profile(s) {
	case RSAPSS, ECDSA, Ed25519:
		return Profile(s), true
	default:
		return "", false
	}
}

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
