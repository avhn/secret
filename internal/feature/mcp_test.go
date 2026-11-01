package feature

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

const mcpTestInitialize = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic-client","version":"1"}}}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"

func mcpTestServer(t *testing.T) *MCPServer {
	t.Helper()
	server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{"libsecret:synthetic"}, Directory: testutil.TempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	server.read = func(reference, directory string) (store.Metadata, error) {
		return store.Metadata{Version: 1, Reference: reference, Backend: "libsecret", Records: []store.MetadataRecord{
			{Key: "TOKEN", Labels: map[string]string{}, Account: "0123456789abcdef0123456789abcdef"},
			{Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: "fedcba9876543210fedcba9876543210"},
			{Key: "ONLY_PROD", Labels: map[string]string{"env": "prod"}, Account: "11111111111111111111111111111111"},
		}}, nil
	}
	return server
}

func mcpTestCall(id int, name string, arguments any) string {
	data, _ := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"2.0", id, "tools/call", struct {
		Name      string `json:"name"`
		Arguments any    `json:"arguments"`
	}{name, arguments}})
	return string(data) + "\n"
}

func mcpTestServe(t *testing.T, server *MCPServer, input string) ([]mcpResponse, []byte, error) {
	t.Helper()
	var output bytes.Buffer
	err := server.Serve(strings.NewReader(input), &output)
	responses := make([]mcpResponse, 0)
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for decoder.More() {
		var response mcpResponse
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	return responses, output.Bytes(), err
}

func TestMCPSchemaGolden(t *testing.T) {
	server := mcpTestServer(t)
	input := mcpTestInitialize + `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	input += mcpTestCall(2, "list", map[string]any{})
	input += mcpTestCall(3, "show", map[string]any{"reference": "libsecret:synthetic", "selectors": map[string]string{"env": "dev"}})
	input += mcpTestCall(4, "diff", map[string]any{"left": "libsecret:synthetic", "right": "libsecret:synthetic", "left_selectors": map[string]string{"env": "prod"}, "right_selectors": map[string]string{"env": "dev"}})
	input += mcpTestCall(5, "health", map[string]any{})
	input += mcpTestCall(6, "get", map[string]any{"reference": "libsecret:synthetic"})
	input += mcpTestCall(7, "show", map[string]any{"reference": "libsecret:outside"})
	responses, output, err := mcpTestServe(t, server, input)
	if err != nil || len(responses) != 8 {
		t.Fatalf("MCP session: %v, %d responses", err, len(responses))
	}
	// Golden outer JSON is normalized, but text content remains exact wire JSON.
	var documents []json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(output))
	for decoder.More() {
		var document json.RawMessage
		if err := decoder.Decode(&document); err != nil {
			t.Fatal(err)
		}
		documents = append(documents, document)
	}
	got, err := json.MarshalIndent(documents, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "feature", "mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Fatalf("MCP schema differs:\n%s", got)
	}
}

func TestMCPInitializationNotificationParams(t *testing.T) {
	initialize := strings.SplitN(mcpTestInitialize, "\n", 2)[0] + "\n"
	for _, tt := range []struct {
		name   string
		params string
		ready  bool
	}{
		{"omitted", "", true},
		{"empty object", `,"params":{}`, true},
		{"spaces", `,"params": { }`, true},
		{"tabs and carriage return", ",\"params\":\t{ \t } \r", true},
		{"nonempty object", `,"params":{"unexpected":true}`, false},
		{"null", `,"params":null`, false},
		{"array", `,"params":[]`, false},
		{"string", `,"params":""`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := initialize + `{"jsonrpc":"2.0","method":"notifications/initialized"` + tt.params + "}\n"
			input += `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
			input += mcpTestCall(2, "health", map[string]any{})
			responses, _, err := mcpTestServe(t, mcpTestServer(t), input)
			if err != nil || len(responses) != 3 {
				t.Fatalf("MCP handshake: %v, %d responses", err, len(responses))
			}
			if responses[0].Error != nil {
				t.Fatal("initialization failed")
			}
			for _, response := range responses[1:] {
				if (response.Error == nil) != tt.ready {
					t.Fatalf("notification readiness = %t, want %t", response.Error == nil, tt.ready)
				}
			}
		})
	}
}

func TestMCPAllowlistAndForbiddenMethods(t *testing.T) {
	server := mcpTestServer(t)
	calls := 0
	server.read = func(string, string) (store.Metadata, error) {
		calls++
		return store.Metadata{}, errors.New("synthetic-provider-stderr-sentinel")
	}
	input := mcpTestInitialize
	for _, method := range []string{"get", "stash", "run", "exec", "import", "export", "rotate", "rename", "delete", "resources/read", "resources/list", "prompts/list", "unknown"} {
		input += `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"reference":"libsecret:synthetic","value":"synthetic-secret-sentinel","argv":"synthetic-child-argv-sentinel"}}` + "\n"
		input += mcpTestCall(2, method, map[string]any{"reference": "libsecret:synthetic"})
	}
	for _, ref := range []string{"libsecret:synthetic-other", "libsecret:../synthetic", "LIBSECRET:synthetic", "keychain:synthetic", "file:" + filepath.Join(testutil.TempDir(t), "outside.secret"), "synthetic"} {
		input += mcpTestCall(3, "show", map[string]any{"reference": ref})
		input += mcpTestCall(4, "diff", map[string]any{"left": "libsecret:synthetic", "right": ref})
	}
	for _, arguments := range []map[string]any{
		{"reference": "libsecret:synthetic", "value": "synthetic-secret-sentinel"},
		{"reference": "libsecret:synthetic", "selectors": map[string]string{"bad-name": "prod"}},
		{"reference": "libsecret:synthetic", "left": "libsecret:synthetic"},
	} {
		input += mcpTestCall(5, "show", arguments)
	}
	input += mcpTestCall(6, "health", map[string]any{"reference": "libsecret:synthetic"})
	input += mcpTestCall(7, "list", map[string]any{"reference": "libsecret:synthetic"})
	responses, output, err := mcpTestServe(t, server, input)
	if err != nil || calls != 0 {
		t.Fatalf("forbidden method or reference read metadata: %v, %d calls", err, calls)
	}
	for _, response := range responses[1:] {
		if response.Error == nil {
			t.Fatal("unsupported metadata request succeeded")
		}
	}
	for _, sentinel := range []string{"synthetic-secret-sentinel", "synthetic-child-argv-sentinel", "synthetic-provider-stderr-sentinel", "outside.secret"} {
		if bytes.Contains(output, []byte(sentinel)) {
			t.Fatal("MCP echoed untrusted diagnostic or parameters")
		}
	}
	// Provider failures become fixed errors, not provider stderr.
	responses, output, err = mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "show", map[string]any{"reference": "libsecret:synthetic"}))
	if err != nil || calls != 1 || responses[1].Error == nil || bytes.Contains(output, []byte("synthetic-provider-stderr-sentinel")) {
		t.Fatal("provider diagnostic escaped")
	}
}

func TestMCPConfigurationAndOwnership(t *testing.T) {
	for _, config := range []MCPConfig{
		{}, {Stores: []string{"libsecret:synthetic"}},
		{Enabled: true}, {Enabled: true, Stores: []string{"file:relative"}},
		{Enabled: true, Stores: []string{"libsecret:synthetic"}},
		{Enabled: true, Stores: []string{"libsecret:../escape"}, Directory: testutil.TempDir(t)},
		{Enabled: true, Stores: []string{"libsecret:synthetic", "libsecret:synthetic"}, Directory: testutil.TempDir(t)},
		{Enabled: true, Stores: []string{"file:" + filepath.Join(testutil.TempDir(t), "bad\npath")}},
	} {
		if _, err := NewMCPServer(config); err == nil {
			t.Fatal("invalid MCP configuration accepted")
		}
	}
	refs := []string{"libsecret:synthetic"}
	server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: refs, Directory: testutil.TempDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	refs[0] = "libsecret:outside"
	if server.references[0] != "libsecret:synthetic" || server.allowed["libsecret:outside"] {
		t.Fatal("allowlist aliases caller storage")
	}
	server.read = func(string, string) (store.Metadata, error) {
		metadata := syntheticMetadata([]byte("TOKEN=synthetic\n"))
		return metadata, nil
	}
	responses, _, err := mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "show", map[string]any{"reference": "libsecret:synthetic"}))
	if err != nil || responses[1].Error == nil {
		t.Fatal("accepted metadata for a different reference")
	}
}

func TestMCPProtocolBoundsAndFraming(t *testing.T) {
	server := mcpTestServer(t)
	calls := 0
	server.read = func(string, string) (store.Metadata, error) { calls++; return store.Metadata{}, nil }
	for _, input := range []string{
		`{`, `[]`, `null`, `{"jsonrpc":"2.0","id":1,"method":"ping"} {}`,
		`{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"show","arguments":{"reference":"libsecret:synthetic","reference":"libsecret:outside"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"show","arguments":{"selectors":{"env":"prod","env":"dev"}}}}`,
		`{"jsonrpc":"2.0","id":-1,"method":"ping"}`, `{"jsonrpc":"2.0","id":9007199254740992,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"unsafe/id/synthetic-sentinel","method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":null}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","extra":"synthetic-sentinel"}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\xff\"}",
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":` + strings.Repeat(`[`, 34) + `0` + strings.Repeat(`]`, 34) + `}`,
	} {
		responses, output, err := mcpTestServe(t, server, input+"\n")
		if err != nil || len(responses) != 1 || responses[0].Error == nil || calls != 0 {
			t.Fatalf("invalid frame accepted: %v", err)
		}
		if bytes.Contains(output, []byte("synthetic-sentinel")) {
			t.Fatal("invalid frame echoed")
		}
	}
	// Notifications, including forbidden methods, cause no output or metadata I/O.
	responses, _, err := mcpTestServe(t, server, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get"}}`+"\n")
	if err != nil || len(responses) != 0 || calls != 0 {
		t.Fatal("notification invoked store")
	}
	for _, size := range []int{MaxMCPInputBytes, MaxMCPInputBytes + 1} {
		frame := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
		frame += strings.Repeat(" ", size-len(frame))
		responses, output, err := mcpTestServe(t, server, frame+"\n")
		if size == MaxMCPInputBytes {
			if err != nil || len(responses) != 1 || responses[0].Error != nil {
				t.Fatal("exact input ceiling rejected")
			}
		} else if !errors.Is(err, ErrMCPProtocol) || len(output) == 0 {
			t.Fatal("oversized input not rejected")
		}
	}
	responses, _, err = mcpTestServe(t, server, `{"jsonrpc":"2.0","id":"opaque_1","method":"ping"}`)
	if err != nil || len(responses) != 1 || responses[0].Error != nil {
		t.Fatal("final EOF frame or string ID rejected")
	}
	// Metadata tools are unavailable until the handshake completes.
	responses, _, err = mcpTestServe(t, server, mcpTestCall(1, "health", map[string]any{}))
	if err != nil || responses[0].Error == nil {
		t.Fatal("uninitialized tools allowed")
	}
}

type mcpFailWriter struct{}

func (mcpFailWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic-output-error") }

type mcpShortWriter struct{}

func (mcpShortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

type mcpFailReader struct{}

func (mcpFailReader) Read([]byte) (int, error) { return 0, errors.New("synthetic-input-error") }

func TestMCPTransportAndResponseBounds(t *testing.T) {
	server := mcpTestServer(t)
	for _, writer := range []io.Writer{mcpFailWriter{}, mcpShortWriter{}} {
		if err := server.Serve(strings.NewReader(mcpTestInitialize), writer); !errors.Is(err, ErrMCPIO) {
			t.Fatal("write failure lost")
		}
	}
	if err := server.Serve(mcpFailReader{}, io.Discard); !errors.Is(err, ErrMCPIO) {
		t.Fatal("read failure lost")
	}
	if err := (*MCPServer)(nil).Serve(strings.NewReader(""), io.Discard); !errors.Is(err, ErrMCPDisabled) {
		t.Fatal("nil MCP enabled")
	}
	var output bytes.Buffer
	if err := server.writeResponse(&output, mcpResponse{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: strings.Repeat("x", MaxMCPOutputBytes)}); err != nil {
		t.Fatal(err)
	}
	if output.Len() > MaxMCPOutputBytes || !bytes.Contains(output.Bytes(), []byte("Metadata response exceeds limit")) {
		t.Fatal("output ceiling not enforced")
	}
}

func TestCompletionAndMCPNeverFetchProviderValues(t *testing.T) {
	dir := testutil.TempDir(t)
	if runtime.GOOS != "windows" {
		tools := filepath.Join(dir, "tools")
		if err := testutil.Mkdir(tools, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(dir, "provider-called")
		for _, name := range []string{"security", "secret-tool"} {
			if err := testutil.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\nprintf called > \"$SYNTH_ITEM7_PROVIDER_MARKER\"\nprintf synthetic-provider-stderr-sentinel >&2\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", tools)
		t.Setenv("SYNTH_ITEM7_PROVIDER_MARKER", marker)
		t.Cleanup(func() {
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Error("names-only feature invoked a value provider")
			}
		})
	}
	for _, backend := range []string{"libsecret", "keychain"} {
		manifest := []byte("secret-manifest-v1\nbackend=" + backend + "\nTOKEN\t\t0123456789abcdef0123456789abcdef\n")
		if err := testutil.WriteFile(filepath.Join(dir, "synthetic.keys"), manifest, 0600); err != nil {
			t.Fatal(err)
		}
		ref := backend + ":synthetic"
		metadata, err := ReadMetadata(ref, dir)
		if err != nil {
			t.Fatal(err)
		}
		if keys, err := Complete(CompletionRequest{Flag: "--key"}, []store.Metadata{metadata}); err != nil || !reflect.DeepEqual(keys, []string{"TOKEN"}) {
			t.Fatal("provider key completion")
		}
		server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{ref}, Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		input := mcpTestInitialize + mcpTestCall(1, "list", map[string]any{}) + mcpTestCall(2, "show", map[string]any{"reference": ref}) + mcpTestCall(3, "diff", map[string]any{"left": ref, "right": ref}) + mcpTestCall(4, "health", map[string]any{})
		responses, output, err := mcpTestServe(t, server, input)
		if err != nil || len(responses) != 5 {
			t.Fatal("provider metadata MCP")
		}
		for _, response := range responses {
			if response.Error != nil {
				t.Fatal("provider metadata method failed")
			}
		}
		if bytes.Contains(output, []byte("synthetic-provider-stderr-sentinel")) {
			t.Fatal("provider stderr in MCP")
		}
	}
	// File values are parsed privately and never affect metadata responses.
	path := filepath.Join(dir, "synthetic.secret")
	ref := "file:" + path
	server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{ref}})
	if err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for _, value := range [][]byte{[]byte("synthetic-secret-sentinel"), []byte("changed-longer-synthetic-secret-sentinel")} {
		data := append(append([]byte("TOKEN="), value...), '\n')
		if err := testutil.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, output, err := mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "list", map[string]any{}))
		if err != nil || bytes.Contains(output, value) {
			t.Fatal("file value exposed by MCP")
		}
		if previous != nil && !bytes.Equal(previous, output) {
			t.Fatal("changing values changed MCP metadata")
		}
		previous = append([]byte(nil), output...)
	}
}

func FuzzMCPProtocol(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"get","params":{"value":"synthetic"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxMCPInputBytes+1 {
			t.Skip()
		}
		server := &MCPServer{references: []string{"libsecret:synthetic"}, allowed: map[string]bool{"libsecret:synthetic": true}, read: func(reference, directory string) (store.Metadata, error) {
			if reference != "libsecret:synthetic" {
				t.Fatal("protocol expanded the configured allowlist")
			}
			return store.Metadata{Version: 1, Reference: reference, Backend: "libsecret", Records: []store.MetadataRecord{}}, nil
		}}
		var output bytes.Buffer
		_ = server.Serve(bytes.NewReader(data), &output)
		decoder := json.NewDecoder(&output)
		for decoder.More() {
			var response mcpResponse
			if err := decoder.Decode(&response); err != nil {
				t.Fatal("invalid response JSON")
			}
		}
	})
}

func TestMCPInitializeAcceptsClientExtensions(t *testing.T) {
	for _, tt := range []struct {
		name   string
		params string
		ok     bool
	}{
		{"current client fields", `{"protocolVersion":"2025-11-25","capabilities":{"roots":{}},"clientInfo":{"name":"claude-code","version":"2.1","title":"Claude","websiteUrl":"https://example.invalid","icons":[]},"_meta":{"progressToken":1}}`, true},
		{"missing client name", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"version":"1"}}`, false},
		{"non-string client name", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":7}}`, false},
		{"missing protocol version", `{"capabilities":{},"clientInfo":{"name":"c"}}`, false},
		{"unknown top-level field", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c"},"unexpected":true}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":` + tt.params + "}\n"
			responses, _, err := mcpTestServe(t, mcpTestServer(t), input)
			if err != nil || len(responses) != 1 {
				t.Fatalf("initialize: %v, %d responses", err, len(responses))
			}
			if (responses[0].Error == nil) != tt.ok {
				t.Fatalf("accepted = %v, want %v", responses[0].Error == nil, tt.ok)
			}
		})
	}
}
