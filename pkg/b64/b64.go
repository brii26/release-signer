package b64

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrInvalid = errors.New("invalid base64")

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// StdEncoding diam-diam membuang \r dan \n, jadi alfabet dicek manual dulu.
func DecodeStrict(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !inAlphabet(s[i]) {
			return nil, fmt.Errorf("%w: illegal byte at offset %d", ErrInvalid, i)
		}
	}
	if len(s)%4 != 0 {
		return nil, fmt.Errorf("%w: length is not a multiple of 4", ErrInvalid)
	}

	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if Encode(b) != s {
		return nil, fmt.Errorf("%w: not canonical", ErrInvalid)
	}
	return b, nil
}

func inAlphabet(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return c == '+' || c == '/' || c == '='
}
