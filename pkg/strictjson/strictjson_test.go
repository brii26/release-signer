package strictjson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const big = 1 << 20

func num(lit string) Value { return Value{Kind: Number, Num: json.Number(lit)} }

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want error
	}{
		{"duplicate key", `{"a":1,"a":2}`, big, ErrDuplicateKey},
		{"nested duplicate key", `{"x":{"b":1,"b":1}}`, big, ErrDuplicateKey},
		{"duplicate key inside array", `[{"a":1,"a":2}]`, big, ErrDuplicateKey},
		{"duplicate key via escape", `{"a":1,"a":2}`, big, ErrDuplicateKey},
		{"bom", "\xEF\xBB\xBF{}", big, ErrBOM},
		{"invalid utf8", "{\"a\":\"\xff\"}", big, ErrInvalidUTF8},
		{"two values", `{"a":1} {"b":2}`, big, ErrTrailingData},
		{"garbage after value", `{"a":1}x`, big, ErrTrailingData},
		{"one byte over limit", `{"a":1}`, len(`{"a":1}`) - 1, ErrTooLarge},
		{"truncated object", `{"a":1`, big, ErrSyntax},
		{"empty input", ``, big, ErrSyntax},
		{"leading zero number", `{"a":01}`, big, ErrSyntax},
		{"too deep", strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2), big, ErrTooDeep},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.in), tc.max)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) error = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

func TestParseAccepts(t *testing.T) {
	in := `{"a":1,"b":[true,null,"x"],"c":{"d":"e"}}`
	v, err := Parse([]byte(in), len(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if v.Kind != Object || len(v.Obj) != 3 {
		t.Fatalf("unexpected value: %+v", v)
	}
	order := []string{v.Obj[0].Key, v.Obj[1].Key, v.Obj[2].Key}
	if strings.Join(order, ",") != "a,b,c" {
		t.Fatalf("member order not preserved: %v", order)
	}
	arr, _ := v.Field("b")
	els, err := AsArray(arr)
	if err != nil || len(els) != 3 || els[0].Kind != Bool || els[1].Kind != Null || els[2].Kind != String {
		t.Fatalf("array parsed wrong: %+v err=%v", els, err)
	}
}

func TestTooLargeIsCheckedBeforeParsing(t *testing.T) {
	_, err := Parse([]byte("not json at all"), 3)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}

func TestFieldIsExactAndCaseSensitive(t *testing.T) {
	v, err := Parse([]byte(`{"Schema":"x"}`), big)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Field("schema"); ok {
		t.Fatal(`Field("schema") matched key "Schema"`)
	}
	if got, ok := v.Field("Schema"); !ok || got.Str != "x" {
		t.Fatalf(`Field("Schema") = %+v, %v`, got, ok)
	}
	if _, ok := (Value{Kind: String}).Field("a"); ok {
		t.Fatal("Field on a non-object must report not found")
	}
}

func TestAsStringRejectsNullAndOtherTypes(t *testing.T) {
	v, err := Parse([]byte(`{"a":null,"b":1,"c":"ok"}`), big)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"a", "b"} {
		f, _ := v.Field(k)
		if _, err := AsString(f); !errors.Is(err, ErrType) {
			t.Fatalf("AsString(%s) error = %v, want ErrType", k, err)
		}
	}
	f, _ := v.Field("c")
	if s, err := AsString(f); err != nil || s != "ok" {
		t.Fatalf("AsString(c) = %q, %v", s, err)
	}
}

func TestAsArrayRejectsNonArray(t *testing.T) {
	for _, in := range []string{`null`, `"x"`, `{}`, `1`} {
		v, err := Parse([]byte(in), big)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := AsArray(v); !errors.Is(err, ErrType) {
			t.Fatalf("AsArray(%s) error = %v, want ErrType", in, err)
		}
	}
}

func TestAsSafeInt(t *testing.T) {
	reject := []struct {
		name string
		v    Value
	}{
		{"bool true", Value{Kind: Bool, Bool: true}},
		{"string 1", Value{Kind: String, Str: "1"}},
		{"null", Value{Kind: Null}},
		{"leading zero", num("01")},
		{"fraction", num("1.0")},
		{"exponent", num("1e3")},
		{"negative", num("-1")},
		{"plus sign", num("+1")},
		{"negative zero", num("-0")},
		{"2^53", num("9007199254740992")},
		{"overflows int64", num("99999999999999999999")},
		{"empty", num("")},
	}
	for _, tc := range reject {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if n, err := AsSafeInt(tc.v); !errors.Is(err, ErrType) {
				t.Fatalf("AsSafeInt = %d, %v, want ErrType", n, err)
			}
		})
	}

	accept := []struct {
		lit  string
		want int64
	}{
		{"0", 0},
		{"7", 7},
		{"1048576", 1048576},
		{"9007199254740991", MaxSafeInt},
	}
	for _, tc := range accept {
		t.Run("accept "+tc.lit, func(t *testing.T) {
			v, err := Parse([]byte(tc.lit), big)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := AsSafeInt(v); err != nil || n != tc.want {
				t.Fatalf("AsSafeInt = %d, %v, want %d", n, err, tc.want)
			}
		})
	}
}

func TestExpectKeys(t *testing.T) {
	parse := func(s string) Value {
		v, err := Parse([]byte(s), big)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	if err := ExpectKeys(parse(`{"b":1,"a":2}`), "a", "b"); err != nil {
		t.Fatalf("exact keys in any order must pass: %v", err)
	}
	if err := ExpectKeys(parse(`{}`)); err != nil {
		t.Fatalf("empty object with no expected keys must pass: %v", err)
	}
	if err := ExpectKeys(parse(`{"a":1,"b":2,"c":3}`), "a", "b"); !errors.Is(err, ErrType) {
		t.Fatalf("extra key: error = %v, want ErrType", err)
	}
	if err := ExpectKeys(parse(`{"a":1}`), "a", "b"); !errors.Is(err, ErrType) {
		t.Fatalf("missing key: error = %v, want ErrType", err)
	}
	if err := ExpectKeys(parse(`[1]`), "a"); !errors.Is(err, ErrType) {
		t.Fatalf("non-object: error = %v, want ErrType", err)
	}
}
