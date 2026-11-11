// Package strictjson adalah parser JSON strict yang menolak duplicate key.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxSafeInt = 9007199254740991

// Batas nesting supaya input jahat tidak menghabiskan stack.
const maxDepth = 64

var (
	ErrDuplicateKey = errors.New("duplicate key")
	ErrTooLarge     = errors.New("input too large")
	ErrBOM          = errors.New("byte order mark not allowed")
	ErrInvalidUTF8  = errors.New("invalid utf-8")
	ErrTrailingData = errors.New("trailing data after json value")
	ErrType         = errors.New("unexpected type")
	ErrSyntax       = errors.New("invalid json syntax")
	ErrTooDeep      = errors.New("json nesting too deep")
)

type Kind int

const (
	Object Kind = iota
	Array
	String
	Number
	Bool
	Null
)

func (k Kind) String() string {
	switch k {
	case Object:
		return "object"
	case Array:
		return "array"
	case String:
		return "string"
	case Number:
		return "number"
	case Bool:
		return "bool"
	case Null:
		return "null"
	}
	return "unknown"
}

type Member struct {
	Key string
	Val Value
}

type Value struct {
	Kind Kind
	Str  string
	Num  json.Number
	Bool bool
	Arr  []Value
	Obj  []Member
}

// Parse urutan cek: size, BOM, UTF-8, syntax + duplicate key, trailing data.
func Parse(data []byte, maxSize int) (Value, error) {
	if len(data) > maxSize {
		return Value{}, ErrTooLarge
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return Value{}, ErrBOM
	}
	if !utf8.Valid(data) {
		return Value{}, ErrInvalidUTF8
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	v, err := parseValue(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Value{}, ErrTrailingData
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (Value, error) {
	if depth > maxDepth {
		return Value{}, ErrTooDeep
	}
	tok, err := dec.Token()
	if err != nil {
		return Value{}, fmt.Errorf("%w: %v", ErrSyntax, err)
	}

	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return parseObject(dec, depth)
		case '[':
			return parseArray(dec, depth)
		}
		return Value{}, fmt.Errorf("%w: unexpected %q", ErrSyntax, rune(t))
	case string:
		return Value{Kind: String, Str: t}, nil
	case json.Number:
		return Value{Kind: Number, Num: t}, nil
	case bool:
		return Value{Kind: Bool, Bool: t}, nil
	case nil:
		return Value{Kind: Null}, nil
	}
	return Value{}, fmt.Errorf("%w: unexpected token", ErrSyntax)
}

func parseObject(dec *json.Decoder, depth int) (Value, error) {
	v := Value{Kind: Object}
	seen := make(map[string]struct{})

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return Value{}, fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return Value{}, fmt.Errorf("%w: object key must be a string", ErrSyntax)
		}
		if _, dup := seen[key]; dup {
			return Value{}, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
		}
		seen[key] = struct{}{}

		val, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		v.Obj = append(v.Obj, Member{Key: key, Val: val})
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return v, nil
}

func parseArray(dec *json.Decoder, depth int) (Value, error) {
	v := Value{Kind: Array}
	for dec.More() {
		el, err := parseValue(dec, depth+1)
		if err != nil {
			return Value{}, err
		}
		v.Arr = append(v.Arr, el)
	}
	if _, err := dec.Token(); err != nil {
		return Value{}, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	return v, nil
}

func (v Value) Field(key string) (Value, bool) {
	if v.Kind != Object {
		return Value{}, false
	}
	for _, m := range v.Obj {
		if m.Key == key {
			return m.Val, true
		}
	}
	return Value{}, false
}

func ExpectKeys(v Value, keys ...string) error {
	if v.Kind != Object {
		return fmt.Errorf("%w: want object, got %s", ErrType, v.Kind)
	}
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		want[k] = struct{}{}
	}
	for _, m := range v.Obj {
		if _, ok := want[m.Key]; !ok {
			return fmt.Errorf("%w: unexpected key %q", ErrType, m.Key)
		}
	}
	for _, k := range keys {
		if _, ok := v.Field(k); !ok {
			return fmt.Errorf("%w: missing key %q", ErrType, k)
		}
	}
	return nil
}

func AsString(v Value) (string, error) {
	if v.Kind != String {
		return "", fmt.Errorf("%w: want string, got %s", ErrType, v.Kind)
	}
	return v.Str, nil
}

func AsArray(v Value) ([]Value, error) {
	if v.Kind != Array {
		return nil, fmt.Errorf("%w: want array, got %s", ErrType, v.Kind)
	}
	return v.Arr, nil
}

// AsSafeInt hanya menerima plain integer tanpa sign, fraction, exponent, atau leading zero.
func AsSafeInt(v Value) (int64, error) {
	if v.Kind != Number {
		return 0, fmt.Errorf("%w: want number, got %s", ErrType, v.Kind)
	}
	s := string(v.Num)
	if !isPlainInt(s) {
		return 0, fmt.Errorf("%w: %q is not a plain non-negative integer", ErrType, s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > MaxSafeInt {
		return 0, fmt.Errorf("%w: %q exceeds %d", ErrType, s, int64(MaxSafeInt))
	}
	return n, nil
}

func isPlainInt(s string) bool {
	if s == "" {
		return false
	}
	if s == "0" {
		return true
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
