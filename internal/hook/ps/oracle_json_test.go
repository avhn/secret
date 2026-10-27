package ps

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// encoding/json repairs invalid Unicode and accepts duplicate keys. Neither is
// usable as independent oracle evidence. Bound the token walk before the typed
// decoder and field-presence walk allocate their projections.
func validateOracleJSON(data []byte, maxDepth, maxTokens int) error {
	invalid := errors.New("oracle invalid JSON")
	if !utf8.Valid(data) || !oraclePairedSurrogates(data) {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	next := func() (json.Token, error) {
		if maxTokens <= 0 {
			return nil, invalid
		}
		maxTokens--
		return decoder.Token()
	}
	var value func(int) error
	value = func(depth int) error {
		token, err := next()
		if err != nil {
			return invalid
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		if depth >= maxDepth || (delim != '{' && delim != '[') {
			return invalid
		}
		keys := map[string]bool{}
		for decoder.More() {
			if delim == '{' {
				key, err := next()
				name, ok := key.(string)
				// Typed struct fields are matched case-insensitively by
				// encoding/json, so folded duplicates can overwrite evidence too.
				name = oracleJSONKey(name)
				if err != nil || !ok || keys[name] {
					return invalid
				}
				keys[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		end, err := next()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return invalid
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("oracle trailing JSON")
	}
	return nil
}

func oracleJSONKey(name string) string {
	return strings.Map(func(r rune) rune {
		key := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < key {
				key = next
			}
		}
		return key
	}, name)
}

// Check raw escapes, before Token replaces an unpaired UTF-16 surrogate with
// U+FFFD. Skip escaped backslashes and quotes so literal \\u text is unchanged.
// The token decoder independently checks the rest of the JSON string grammar.
func oraclePairedSurrogates(data []byte) bool {
	unit := func(offset int) (uint64, error) {
		if offset+4 > len(data) {
			return 0, io.ErrUnexpectedEOF
		}
		return strconv.ParseUint(string(data[offset:offset+4]), 16, 16)
	}
	quoted := false
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted {
				continue
			}
			i++
			if i >= len(data) {
				return false
			}
			if data[i] != 'u' {
				continue
			}
			first, err := unit(i + 1)
			if err != nil || first >= 0xdc00 && first <= 0xdfff {
				return false
			}
			i += 4
			if first < 0xd800 || first > 0xdbff {
				continue
			}
			if i+2 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			second, err := unit(i + 3)
			if err != nil || second < 0xdc00 || second > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func TestOracleJSONValidation(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"empty object", `{}`, true},
		{"scalars", `[null,true,false,123,-1.25e10,"text"]`, true},
		{"replacement character", `{"value":"�"}`, true},
		{"non-BMP UTF-8", `{"value":"𐐀"}`, true},
		{"surrogate pair", `{"value":"\ud801\udc00"}`, true},
		{"escaped surrogate text", `{"value":"\\ud800\"\\udc00"}`, true},
		{"separate keys", `{"a":{"key":1},"b":{"key":2}}`, true},
		{"duplicate root key", `{"unsupported":["UnexpectedNode"],"unsupported":[]}`, false},
		{"duplicate nested key", `[{"nested":{"key":1,"key":2}}]`, false},
		{"duplicate folded field", `{"unsupported":["UnexpectedNode"],"Unsupported":[]}`, false},
		{"duplicate Unicode folded field", `{"unsupported":["UnexpectedNode"],"unſupported":[]}`, false},
		{"duplicate escaped key", `{"key":1,"\u006bey":2}`, false},
		{"duplicate surrogate key", `{"𐐀":1,"\ud801\udc00":2}`, false},
		{"invalid UTF-8", "{\"value\":\"\xff\"}", false},
		{"high surrogate", `{"value":"\ud800"}`, false},
		{"low surrogate", `{"value":"\udc00"}`, false},
		{"reversed pair", `{"value":"\udc00\ud800"}`, false},
		{"separated pair", `{"value":"\ud800x\udc00"}`, false},
		{"high before scalar", `{"value":"\ud800\u0061"}`, false},
		{"surrogate key", `{"\ud800":1}`, false},
		{"truncated escape", `{"value":"\ud80`, false},
		{"bad hex", `{"value":"\uXYZ0"}`, false},
		{"trailing document", `{} []`, false},
		{"malformed object", `{"a" 1}`, false},
		{"malformed array", `[1,]`, false},
		{"empty", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOracleJSON([]byte(tc.data), 128, 1024); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}

func TestOracleJSONValidationBounds(t *testing.T) {
	for _, tc := range []struct {
		name, data    string
		depth, tokens int
		valid         bool
	}{
		{"depth at cap", `[[0]]`, 2, 5, true},
		{"depth past cap", `[[[0]]]`, 2, 7, false},
		{"empty container past cap", `[[[]]]`, 2, 6, false},
		{"tokens at cap", `{"a":[1,2]}`, 2, 7, true},
		{"tokens past cap", `{"a":[1,2]}`, 2, 6, false},
		{"deep input", strings.Repeat("[", 10000) + "0" + strings.Repeat("]", 10000), 128, 30000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateOracleJSON([]byte(tc.data), tc.depth, tc.tokens); (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
		})
	}
}
