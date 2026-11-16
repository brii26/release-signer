package profile

// Profile adalah nama signature profile (Tabel 2.1), sekaligus isi field algorithm manifest.
type Profile string

// Tiga profile yang didukung.
const (
	RSAPSS  Profile = "rsa-pss-sha256"
	ECDSA   Profile = "ecdsa-p256-sha256"
	Ed25519 Profile = "ed25519"
)

// Parse return Profile dari s, false kalau bukan salah satu dari tiga profile.
func Parse(s string) (Profile, bool) {
	switch Profile(s) {
	case RSAPSS, ECDSA, Ed25519:
		return Profile(s), true
	default:
		return "", false
	}
}

// SignatureLen return panjang signature (byte): 384 RSA-PSS, 64 ECDSA dan Ed25519, 0 kalau tidak dikenal.
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
