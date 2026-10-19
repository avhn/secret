package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// TestKeychainCommands checks -g decoding, -i transport, validation and errors on every OS.
func TestKeychainCommands(t *testing.T) {
	const value = "synthetic-é-$TOKEN"
	var calls []string
	var supplied []byte
	p := keychain{path: "/tmp/disposable.keychain-db", valid: true}
	p.run = func(name string, args []string, input []byte) ([]byte, []byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "security" {
			t.Error("wrong executable")
		}
		switch args[0] {
		case "-i":
			supplied = bytes.Clone(input)
			return nil, nil, nil
		case "find-generic-password":
			return nil, []byte("keychain: synthetic\npassword: 0x" + hex.EncodeToString([]byte(value)) + "\n"), nil
		}
		return nil, nil, nil
	}
	if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN/env=dev", []byte(value)); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(supplied, []byte("add-generic-password -U -s secret/demo -a "+testAccount+" -l secret/demo/TOKEN/env=dev -X ")) || !bytes.HasSuffix(supplied, []byte(" /tmp/disposable.keychain-db\n")) || bytes.Contains(supplied, []byte(value)) {
		t.Error("unsafe -i input")
	}
	if len(supplied) > 4000 {
		t.Error("long security command")
	}
	if err := p.Delete("secret/demo", testAccount); err != nil {
		t.Fatal(err)
	}
	want := []string{"security -i", "security find-generic-password -s secret/demo -a " + testAccount + " -g /tmp/disposable.keychain-db", "security delete-generic-password -s secret/demo -a " + testAccount + " /tmp/disposable.keychain-db"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	for _, tc := range []struct{ raw, want string }{
		{"password: \"synthetic\"\n", "synthetic"},
		{"password: \"0x6162\"\n", "0x6162"},
		{"password: 0x6162\n", "ab"},
		{"password: 0xC3A9 other text\n", "é"},
	} {
		got, err := parseKeychainPassword([]byte(tc.raw))
		if err != nil || string(got) != tc.want {
			t.Errorf("parse format failed: %v", err)
		}
	}
	for _, raw := range []string{"password: garbage", "password: 0xzz", "password: 0xabc", "no password here"} {
		if _, err := parseKeychainPassword([]byte(raw)); err == nil {
			t.Error("malformed -g response accepted")
		}
	}
	failure := keychain{path: p.path, valid: true, run: func(string, []string, []byte) ([]byte, []byte, error) { return nil, []byte(value), errors.New(value) }}
	if _, err := failure.Get("secret/demo", testAccount); err == nil || strings.Contains(err.Error(), value) {
		t.Error("lookup leaked value")
	}
	if err := failure.Put("secret/demo", testAccount, "secret/demo/TOKEN", []byte(value)); err == nil || strings.Contains(err.Error(), value) {
		t.Error("put leaked value")
	}
	if err := failure.Delete("secret/demo", testAccount); err == nil || strings.Contains(err.Error(), value) {
		t.Error("delete leaked value")
	}
	for _, bad := range []string{"synthetic\tcontrol", "\xffsynthetic", "synthetic\u0085control", strings.Repeat("q", 1801)} {
		if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN", []byte(bad)); err == nil {
			t.Error("invalid keychain value accepted")
		}
	}
	if _, err := (keychain{run: p.run, valid: false}).Get("secret/demo", testAccount); err == nil {
		t.Error("invalid path accepted")
	}
}

// TestKeychainByteRoundTrips compares every wire byte without calling a provider.
func TestKeychainByteRoundTrips(t *testing.T) {
	for _, path := range []string{"", "/disposable/explicit.keychain-db"} {
		for _, tc := range []struct {
			name  string
			value []byte
			hex   bool
		}{
			{"text", []byte("synthetic-$TOKEN-\\-\"-tail"), false},
			{"hex", []byte("synthetic-é-界-\U00010348"), true},
			{"replacement-rune", []byte("synthetic-�"), true},
			{"hex-looking-text", []byte("0x6162"), false},
		} {
			t.Run(tc.name+path, func(t *testing.T) {
				calls := 0
				p := keychain{path: path, valid: true}
				p.run = func(name string, args []string, input []byte) ([]byte, []byte, error) {
					calls++
					if name != "security" {
						t.Fatal("wrong executable")
					}
					if calls == 1 {
						if !reflect.DeepEqual(args, []string{"-i"}) {
							t.Error("value transport changed argv")
						}
						want := []byte("add-generic-password -U -s secret/demo -a " + testAccount + " -l secret/demo/TOKEN -X ")
						want = hex.AppendEncode(want, tc.value)
						if path != "" {
							want = append(want, ' ')
							want = append(want, path...)
						}
						want = append(want, '\n')
						if !bytes.Equal(input, want) {
							t.Error("interactive wire bytes changed")
						}
						secure.Clear(want)
						return nil, nil, nil
					}
					want := []string{"find-generic-password", "-s", "secret/demo", "-a", testAccount, "-g"}
					if path != "" {
						want = append(want, path)
					}
					if !reflect.DeepEqual(args, want) || input != nil {
						t.Error("readback argv or stdin changed")
					}
					raw := []byte("keychain: synthetic\npassword: ")
					if tc.hex {
						raw = append(raw, "0x"...)
						raw = hex.AppendEncode(raw, tc.value)
						raw = append(raw, " ignored text"...)
					} else {
						raw = append(raw, '"')
						raw = append(raw, tc.value...)
						raw = append(raw, '"')
					}
					return nil, append(raw, '\n'), nil
				}
				input := append(bytes.Clone(tc.value), '\n')
				before := bytes.Clone(input)
				if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN", input); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(input, before) {
					t.Error("put changed borrowed input")
				}
				got, err := p.Get("secret/demo", testAccount)
				if err != nil || !bytes.Equal(got, tc.value) || calls != 3 {
					t.Fatal("byte round trip failed", err)
				}
				secure.Clear(got)
				secure.Clear(input)
				secure.Clear(before)
			})
		}
	}
}

func TestKeychainTextBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
		valid bool
	}{
		{"ascii", []byte("synthetic"), true},
		{"unicode", []byte("é界\U00010348�"), true},
		{"invalid-byte", []byte{0xff}, false},
		{"truncated", []byte{0xe2, 0x82}, false},
		{"overlong", []byte{0xc0, 0xaf}, false},
		{"surrogate", []byte{0xed, 0xa0, 0x80}, false},
		{"outside-unicode", []byte{0xf4, 0x90, 0x80, 0x80}, false},
		{"nul", []byte("a\x00b"), false},
		{"tab", []byte("a\tb"), false},
		{"delete", []byte("a\x7fb"), false},
		{"c1-control", []byte("a\u0085b"), false},
		{"line-separator", []byte("a b"), false},
		{"paragraph-separator", []byte("a b"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if keychainText(tc.value) != tc.valid {
				t.Error("incorrect byte validation")
			}
			if tc.valid {
				return
			}
			p := keychain{valid: true, run: func(string, []string, []byte) ([]byte, []byte, error) {
				t.Fatal("invalid input reached provider")
				return nil, nil, nil
			}}
			before := bytes.Clone(tc.value)
			if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN", tc.value); err == nil || err.Error() != "backend put failed" {
				t.Error("invalid text did not return fixed put error")
			}
			if !bytes.Equal(tc.value, before) {
				t.Error("validation changed borrowed input")
			}
		})
	}
}

func TestKeychainByteLimits(t *testing.T) {
	for _, tc := range []struct {
		name      string
		valueSize int
		lineSize  int
		tooLarge  bool
	}{
		{"value-at-limit", 1800, 0, false},
		{"value-over-limit", 1801, 0, true},
		{"command-at-limit", 1800, 4000, false},
		{"command-over-limit", 1800, 4001, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := bytes.Repeat([]byte{'q'}, tc.valueSize)
			defer secure.Clear(value)
			path := "/disposable.keychain-db"
			label := "secret/demo/TOKEN"
			if tc.lineSize != 0 {
				base := len("add-generic-password -U -s secret/demo -a "+testAccount+" -l "+label+" -X "+" "+path+"\n") + hex.EncodedLen(len(value))
				label += strings.Repeat("x", tc.lineSize-base)
			}
			calls := 0
			p := keychain{valid: true, path: path, run: func(_ string, args []string, input []byte) ([]byte, []byte, error) {
				calls++
				if args[0] == "-i" {
					if tc.lineSize != 0 && len(input) != tc.lineSize {
						t.Error("incorrect command length")
					}
					return nil, nil, nil
				}
				raw := append([]byte("password: \""), value...)
				return nil, append(raw, '"', '\n'), nil
			}}
			err := p.Put("secret/demo", testAccount, label, value)
			if tc.tooLarge {
				if !errors.Is(err, ErrValueTooLarge) || calls != 0 {
					t.Error("oversize input did not fail before provider access")
				}
			} else if err != nil || calls != 2 {
				t.Fatal("boundary input failed", err)
			}
		})
	}
}

// TestKeychainBufferCleanup retains runner-owned allocations to inspect cleanup,
// including capacity tails and failures that return output alongside an error.
func TestKeychainBufferCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		op        string
		raw       []byte
		failCall  int
		wantError string
	}{
		{"get-text", "get", []byte("password: \"synthetic\"\n"), 0, ""},
		{"get-hex", "get", []byte("password: 0x73796e746865746963\n"), 0, ""},
		{"get-failure", "get", []byte("synthetic-stderr"), 1, "backend lookup failed"},
		{"get-bad-hex-prefix", "get", []byte("password: 0x73796e74zz\n"), 0, "backend lookup failed"},
		{"get-odd-hex", "get", []byte("password: 0x73796e7\n"), 0, "backend lookup failed"},
		{"get-invalid-value", "get", []byte("password: \" synthetic\"\n"), 0, "backend lookup failed"},
		{"get-normalized-mismatch", "get", []byte("password: 0x73796e7468657469630a\n"), 0, "backend lookup failed"},
		{"put", "put", []byte("password: \"synthetic\"\n"), 0, ""},
		{"put-failure", "put", nil, 1, "backend put failed"},
		{"put-readback-failure", "put", []byte("synthetic-stderr"), 2, "backend put failed"},
		{"put-readback-mismatch", "put", []byte("password: \"different\"\n"), 0, "backend put failed"},
		{"delete", "delete", nil, 0, ""},
		{"delete-failure", "delete", nil, 1, "backend delete failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffers [][]byte
			capture := func(data []byte) []byte {
				b := bytes.Repeat([]byte{'s'}, len(data)+17)
				copy(b, data)
				buffers = append(buffers, b)
				return b[:len(data)]
			}
			calls := 0
			p := keychain{valid: true, run: func(_ string, args []string, input []byte) ([]byte, []byte, error) {
				calls++
				if input != nil {
					buffers = append(buffers, input[:cap(input)])
				}
				out := capture([]byte("synthetic-stdout"))
				raw := tc.raw
				if args[0] != "find-generic-password" {
					raw = []byte("synthetic-stderr")
				}
				stderr := capture(raw)
				if tc.failCall == calls {
					return out, stderr, errors.New("synthetic-provider-error")
				}
				return out, stderr, nil
			}}
			var got []byte
			var err error
			value := []byte("synthetic")
			switch tc.op {
			case "get":
				got, err = p.Get("secret/demo", testAccount)
			case "put":
				err = p.Put("secret/demo", testAccount, "secret/demo/TOKEN", value)
			case "delete":
				err = p.Delete("secret/demo", testAccount)
			}
			if (err == nil) != (tc.wantError == "") || (err != nil && err.Error() != tc.wantError) {
				t.Fatal("incorrect fixed result", err)
			}
			for i, b := range buffers {
				for _, v := range b {
					if v != 0 {
						t.Fatalf("owned transport buffer %d was not cleared", i)
					}
				}
			}
			if !bytes.Equal(value, []byte("synthetic")) {
				t.Error("cleanup changed borrowed put input")
			}
			if tc.op == "get" && err == nil && !bytes.Equal(got, value) {
				t.Error("cleanup changed returned owned value")
			}
			secure.Clear(got)
		})
	}
}

func TestParseKeychainPasswordOwnership(t *testing.T) {
	for _, encoded := range []bool{false, true} {
		raw := []byte("password: \"synthetic\"\n")
		if encoded {
			raw = []byte("password: 0x73796e746865746963\n")
		}
		got, err := parseKeychainPassword(raw)
		if err != nil {
			t.Fatal(err)
		}
		secure.Clear(raw)
		if !bytes.Equal(got, []byte("synthetic")) {
			t.Error("decoded value aliases captured output")
		}
		secure.Clear(got)
	}
}

// TestKeychainIntegration uses a temporary explicit keychain without changing the search list.
func TestKeychainIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_KEYCHAIN") != "1" {
		t.Skip("isolated macOS Keychain CI only")
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("macOS is required")
	}
	if _, err := exec.LookPath("security"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "disposable.keychain-db")
	if !keychainPath.MatchString(path) {
		t.Fatal("unsafe temporary keychain path")
	}
	security := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "security", args...)
		if err := cmd.Run(); err != nil {
			return errors.New("temporary keychain operation failed")
		}
		return nil
	}
	if err := security("create-keychain", "-p", "synthetic-test-pass", path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := security("delete-keychain", path); err != nil {
			t.Error(err)
		}
	})
	if err := security("unlock-keychain", "-p", "synthetic-test-pass", path); err != nil {
		t.Fatal(err)
	}
	if err := security("set-keychain-settings", path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_KEYCHAIN", path)
	t.Setenv("HOME", filepath.Join(root, "home"))
	dir := filepath.Join(root, "home", ".secrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	const value = "synthetic-é-$TOKEN"
	if err := Stash(dir, "keychain:demo", "TOKEN", map[string]string{"env": "dev"}, []byte(value), nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.ReadManifest(filepath.Join(dir, "demo.keys"), "keychain")
	if err != nil || len(records) != 1 {
		t.Fatalf("manifest: %v", err)
	}
	p, _, _, err := Dispatch("keychain:demo")
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Get("secret/demo", records[0].Account)
	if err != nil || !bytes.Equal(got, []byte(value)) {
		t.Fatal("roundtrip failed", err)
	}
	if _, err := p.Get("secret/other", records[0].Account); err == nil {
		t.Error("wrong service resolved")
	}
	if err := p.Delete("secret/demo", records[0].Account); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get("secret/demo", records[0].Account); err == nil {
		t.Error("deleted item resolved")
	}
}
