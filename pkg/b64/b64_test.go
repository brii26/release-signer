package b64

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecodeStrictAccepts(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Zm9v", "foo"},
		{"Zm8=", "fo"},
		{"Zg==", "f"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := DecodeStrict(tc.in)
			if err != nil {
				t.Fatalf("DecodeStrict(%q): %v", tc.in, err)
			}
			if !bytes.Equal(got, []byte(tc.want)) {
				t.Fatalf("DecodeStrict(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDecodeStrictRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"trailing newline", "Zm9v\n"},
		{"space inside", "Zm 9v"},
		{"leading crlf", "\r\nZm9v"},
		{"missing padding", "Zm9"},
		{"extra padding", "Zm9v===="},
		{"short padding", "Zg="},
		{"nonzero trailing bits", "Zm9="},
		{"url alphabet", "Zm-_"},
		{"padding after full quad", "Zm9v="},
		{"padding in the middle", "Zg==Zm9v"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeStrict(tc.in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("DecodeStrict(%q) error = %v, want ErrInvalid", tc.in, err)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	for n := 0; n <= 70; n++ {
		raw := bytes.Repeat([]byte{0xff, 0x00, 0x7f}, n)[:n]
		got, err := DecodeStrict(Encode(raw))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("round trip of %d bytes failed: %v", n, err)
		}
	}
}
