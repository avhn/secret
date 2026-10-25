package feature

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func TestImporterPreflightNoValueCalls(t *testing.T) {
	for _, name := range []string{"unsafe op", "unsafe bw", "relative dotenv", "bare target", "relative target", "unsupported target", "missing map", "bad field", "bad bw field", "bad key", "duplicate field", "duplicate key", "collision", "dry"} {
		t.Run(name, func(t *testing.T) {
			operator := newTestOperator(t)
			provider := &operatorProvider{}
			operator.Providers["libsecret:target"] = provider
			calls := 0
			operator.runImport = func(context.Context, string, []string) ([]byte, error) {
				calls++
				return nil, errors.New("synthetic-provider-stderr-sentinel")
			}
			request := ImportRequest{Source: "op:opaque-item", Target: "libsecret:target", Mappings: []FieldMapping{{Field: "password", Key: "TOKEN"}}}
			switch name {
			case "unsafe op":
				request.Source = "op:--reveal"
			case "unsafe bw":
				request.Source = "bw:some/id?token=unsafe"
			case "relative dotenv":
				request.Source = "dotenv:relative"
			case "bare target":
				request.Target = "target"
			case "relative target":
				request.Target = "file:relative"
			case "unsupported target":
				request.Target = "unknown:target"
			case "missing map":
				request.Mappings = nil
			case "bad field":
				request.Mappings[0].Field = "--reveal"
			case "bad bw field":
				request.Source = "bw:opaque-item"
				request.Mappings[0].Field = "login"
			case "bad key":
				request.Mappings[0].Key = "bad-key"
			case "duplicate field":
				request.Mappings = append(request.Mappings, FieldMapping{Field: "password", Key: "OTHER"})
			case "duplicate key":
				request.Mappings = append(request.Mappings, FieldMapping{Field: "username", Key: "TOKEN"})
			case "collision":
				writeOperatorManifest(t, operator.SecretsDir, request.Target, []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
			case "dry":
				request.DryRun = true
				operator.Confirm = func(OperatorResult) error { t.Fatal("dry run asked for consent"); return nil }
			}
			result, err := operator.Import(context.Background(), request)
			if name == "dry" {
				if err != nil || len(result.Records) != 1 {
					t.Fatal("dry-run names missing")
				}
			} else if err == nil {
				t.Fatal("invalid import accepted")
			}
			if calls+provider.gets+provider.puts+provider.deletes != 0 {
				t.Fatal("invalid preflight or dry run reached value provider")
			}
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestImporterProvidersPrivateBytesAndArgv(t *testing.T) {
	cases := []struct {
		name, source string
		fields       []FieldMapping
		output       []byte
	}{
		{"op", "op:opaque-item", []FieldMapping{{"password", "TOKEN"}, {"user", "USER"}}, []byte(`{"id":"opaque-item","fields":[{"id":"password","value":"synthetic-value-sentinel"},{"id":"user","value":"synthetic-user"}],"ignored":{"value":"never-import"}}`)},
		{"bw", "bw:opaque-item", []FieldMapping{{"login.password", "TOKEN"}, {"fields.custom", "CUSTOM"}}, []byte(`{"login":{"password":"synthetic-value-sentinel"},"fields":[{"name":"custom","value":"synthetic-custom"}],"notes":"never-import"}`)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			operator := newTestOperator(t)
			provider := &operatorProvider{}
			operator.Providers["libsecret:target"] = provider
			confirmed := false
			operator.Confirm = func(result OperatorResult) error {
				confirmed = true
				if len(result.Records) != 2 {
					t.Fatal("wrong identities confirmed")
				}
				return nil
			}
			var owned []byte
			operator.runImport = func(_ context.Context, name string, args []string) ([]byte, error) {
				if !confirmed {
					t.Fatal("provider called before consent")
				}
				want := []string{"item", "get", "opaque-item", "--format=json"}
				if test.name == "bw" {
					want = []string{"get", "item", "opaque-item"}
				}
				if name != test.name || !reflect.DeepEqual(args, want) {
					t.Fatal("provider argv was not fixed metadata only")
				}
				owned = secure.Clone(test.output)
				return owned, nil
			}
			request := ImportRequest{Source: test.source, Target: "libsecret:target", Mappings: test.fields, Labels: map[string]string{"env": "prod"}}
			result, err := operator.Import(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if provider.puts != 2 || provider.gets != 2 {
				t.Fatal("batch was not put and verified")
			}
			assertOperatorZeroed(t, owned)
			assertOperatorZeroed(t, provider.reads...)
			assertNoOperatorLeak(t, result, err)
			manifest, err := store.ReadManifest(filepath.Join(operator.SecretsDir, "target.keys"), "libsecret")
			if err != nil || len(manifest) != 2 {
				t.Fatal("batch publication missing")
			}
		})
	}
}

func TestImporterDotenvParsingAndMappings(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		t.Run(map[bool]string{false: "all names", true: "mapping"}[mapped], func(t *testing.T) {
			operator := newTestOperator(t)
			path := filepath.Join(t.TempDir(), "synthetic.env")
			data := []byte("# synthetic\r\nTOKEN=old\r\nexport TOKEN='synthetic-value-sentinel'\r\nUSER=synthetic-user\r\n")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "imported.env")
			request := ImportRequest{Source: "dotenv:" + path, Target: "file:" + target, Labels: map[string]string{"env": "prod"}}
			if mapped {
				request.Mappings = []FieldMapping{{"TOKEN", "RENAMED"}}
			}
			result, err := operator.Import(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if mapped {
				want = 1
			}
			if len(result.Records) != want {
				t.Fatal("incorrect name selection")
			}
			output, err := os.ReadFile(target)
			defer secure.Clear(output)
			if err != nil {
				t.Fatal(err)
			}
			records, _ := store.Parse(output)
			defer func() {
				for _, record := range records {
					secure.Clear(record.Value)
				}
			}()
			if len(records) != want || !bytes.Equal(records[0].Value, []byte("synthetic-value-sentinel")) || records[0].Labels["env"] != "prod" {
				t.Fatal("dotenv parse, mapping or last-wins semantics changed")
			}
			info, _ := os.Stat(target)
			if info.Mode().Perm() != 0600 {
				t.Fatal("import target is not private")
			}
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestImporterMalformedOrIncompleteInputDoesNotPublish(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"fields":[{"id":"password","value":"synthetic-value-sentinel"}]} trailing`),
		[]byte(`{"fields":[{"id":"password","value":"a","value":"b"}]}`),
		[]byte(`{"fields":[{"id":"password","value":"a"},{"id":"password","value":"b"}]}`),
		[]byte(`{"fields":[{"id":"other","value":"a"}]}`),
		[]byte(`{"fields":[{"id":"password","value":123}]}`),
		[]byte(`{"fields":[{"id":"password","value":"line\ninternal"}]}`),
		[]byte(`{"fields":[{"id":"password","value":"\ud800"}]}`),
		append([]byte(`{"fields":[],"bad":"`), 0xff, '"', '}'),
		bytes.Repeat([]byte("x"), MaxImporterOutputBytes+1),
	} {
		operator := newTestOperator(t)
		provider := &operatorProvider{}
		operator.Providers["libsecret:target"] = provider
		var owned []byte
		operator.runImport = func(context.Context, string, []string) ([]byte, error) { owned = secure.Clone(data); return owned, nil }
		result, err := operator.Import(context.Background(), ImportRequest{Source: "op:opaque-item", Target: "libsecret:target", Mappings: []FieldMapping{{"password", "TOKEN"}}})
		if err == nil || provider.gets+provider.puts+provider.deletes != 0 {
			t.Fatal("malformed input reached destination provider")
		}
		assertOperatorZeroed(t, owned)
		assertNoOperatorLeak(t, result, err)
	}
}

func TestImporterDotenvPreflightRejectsMalformedAndAlias(t *testing.T) {
	for _, data := range [][]byte{[]byte("BAD='unfinished\n"), []byte("[env=prod]\nTOKEN=synthetic\n"), []byte("not an assignment\n"), nil, bytes.Repeat([]byte("x"), MaxOperatorBytes+1)} {
		operator := newTestOperator(t)
		path := filepath.Join(t.TempDir(), "synthetic.env")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := operator.PreflightImport(ImportRequest{Source: "dotenv:" + path, Target: "file:" + filepath.Join(t.TempDir(), "out")}); err == nil {
			t.Fatal("invalid dotenv accepted")
		}
	}
	operator := newTestOperator(t)
	path := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(path, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := path + "-alias"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.PreflightImport(ImportRequest{Source: "dotenv:" + alias, Target: "file:" + filepath.Join(t.TempDir(), "out")}); err == nil {
		t.Fatal("final input alias accepted")
	}
}

func TestImporterDeclineCancellationFailureAndCleanup(t *testing.T) {
	for _, mode := range []string{"decline", "nil consent", "canceled", "canceled during consent", "runner failure", "locked collision"} {
		t.Run(mode, func(t *testing.T) {
			operator := newTestOperator(t)
			provider := &operatorProvider{}
			operator.Providers["libsecret:target"] = provider
			calls := 0
			var owned []byte
			operator.runImport = func(context.Context, string, []string) ([]byte, error) {
				calls++
				owned = []byte(`{"fields":[{"id":"password","value":"synthetic-value-sentinel"}]}`)
				if mode == "runner failure" {
					return owned, errors.New("synthetic-provider-stderr-sentinel")
				}
				return owned, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := secure.ErrConsent
			switch mode {
			case "decline":
				operator.Confirm = func(OperatorResult) error { return secure.ErrConsent }
			case "nil consent":
				operator.Confirm = nil
			case "canceled":
				cancel()
				want = secure.ErrTransaction
			case "canceled during consent":
				operator.Confirm = func(OperatorResult) error { cancel(); return nil }
				want = secure.ErrTransaction
			case "runner failure":
				want = secure.ErrTransaction
			case "locked collision":
				operator.Confirm = func(OperatorResult) error {
					writeOperatorManifest(t, operator.SecretsDir, "libsecret:target", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
					return nil
				}
				want = secure.ErrConflict
			}
			result, err := operator.Import(ctx, ImportRequest{Source: "op:opaque-item", Target: "libsecret:target", Mappings: []FieldMapping{{"password", "TOKEN"}}})
			if err != want {
				t.Fatalf("got %v, want %v", err, want)
			}
			if mode != "runner failure" && mode != "locked collision" && calls != 0 {
				t.Fatal("import provider called before consent or after cancellation")
			}
			if provider.puts != 0 {
				t.Fatal("invalid or colliding import reached destination")
			}
			assertOperatorZeroed(t, owned)
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestPrivateJSONByteStringsAndCleanup(t *testing.T) {
	data := []byte(`{"fields":[{"id":"password","value":"synthetic-é-𐐀-\/\\\""}],"atoms":[true,false,null,-1.25e+2]}`)
	// Construct escapes as bytes so both byte UTF-8 and surrogate-pair decoding
	// are tested without converting provider values through Go strings.
	data = bytes.ReplaceAll(data, []byte("é"), []byte{92, 'u', '0', '0', 'e', '9'})
	data = bytes.ReplaceAll(data, []byte("𐐀"), []byte{92, 'u', 'd', '8', '0', '1', 92, 'u', 'd', 'c', '0', '0'})
	node, err := parsePrivateJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	value, err := importJSONField(node, "op", "password")
	if err != nil || !bytes.Equal(value, []byte("synthetic-é-𐐀-/\\\"")) {
		t.Fatal("byte JSON unicode/escape decode failed")
	}
	node.clear()
	assertOperatorZeroed(t, value)
	for _, bad := range [][]byte{[]byte(`{"a":01}`), []byte(`{"a":1.}`), []byte(`{"a":1e}`), []byte(`{"a":NaN}`), []byte(`{"a":true,}`), []byte(`[]`), bytes.Repeat([]byte("["), 18)} {
		if node, err := parsePrivateJSON(bad); err == nil {
			node.clear()
			t.Fatal("invalid JSON accepted")
		}
	}
}

func TestImporterRunnerBoundsCancellationAndStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess helper timing covered on Unix")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_IMPORTER_TEST_HELPER", "1")
	for _, mode := range []string{"success", "stdout overflow", "stderr overflow", "failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if mode == "cancel" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			start := time.Now()
			output, err := runImporter(ctx, executable, []string{"-test.run=^TestImporterHelperProcess$", "--", mode})
			defer secure.Clear(output)
			if mode == "success" {
				if err != nil || !bytes.Equal(output, []byte("synthetic-value-sentinel")) {
					t.Fatal("private stdout capture failed")
				}
			} else if err != secure.ErrTransaction || len(output) != 0 {
				t.Fatal("provider error or overflow was not fixed and private")
			}
			if mode == "cancel" && time.Since(start) > 3*time.Second {
				t.Fatal("provider cancellation exceeded bound")
			}
		})
	}
}

func TestImporterHelperProcess(t *testing.T) {
	if os.Getenv("SECRET_IMPORTER_TEST_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "success":
		_, _ = os.Stdout.Write([]byte("synthetic-value-sentinel"))
		_, _ = os.Stderr.Write([]byte("synthetic-provider-stderr-sentinel"))
		os.Exit(0)
	case "stdout overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), MaxImporterOutputBytes+1))
		os.Exit(0)
	case "stderr overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), MaxImporterOutputBytes+1))
		os.Exit(0)
	case "failure":
		_, _ = os.Stdout.Write([]byte("synthetic-value-sentinel"))
		_, _ = os.Stderr.Write([]byte("synthetic-provider-stderr-sentinel"))
		os.Exit(1)
	case "cancel":
		for {
			time.Sleep(time.Second)
		}
	}
	os.Exit(2)
}

func FuzzPrivateImporterJSON(f *testing.F) {
	for _, seed := range [][]byte{[]byte(`{}`), []byte(`{"fields":[{"id":"password","value":"synthetic"}]}`), []byte(`{"login":{"password":"synthetic"}}`), []byte(`{"value":"\ud800"}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		node, err := parsePrivateJSON(data)
		if err != nil {
			if err != secure.ErrInvalidRequest {
				t.Fatal("nonfixed parser error")
			}
			return
		}
		defer node.clear()
		_, _ = importJSONField(node, "op", "password")
		_, _ = importJSONField(node, "bw", "login.password")
	})
}
