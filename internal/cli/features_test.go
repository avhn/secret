package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func featureFixture(t *testing.T) (string, string) {
	t.Helper()
	// Audit rejects ancestor aliases, including the system /var alias on macOS.
	// Use the physical disposable root rather than relaxing production checks.
	home, err := filepath.EvalSymlinks(testutil.TempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "stores")
	if err := testutil.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "synthetic.secret")
	if err := testutil.WriteFile(path, []byte("TOKEN=synthetic-private-one\n[env=prod]\nTOKEN=synthetic-private-two\nOTHER=synthetic-private-three\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", dir)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "absent"))
	return dir, "file:" + path
}

func TestFeatureDispatchNamesOnly(t *testing.T) {
	_, ref := featureFixture(t)
	for _, args := range [][]string{
		{"list", "--format=json"},
		{"show", "--format", "json", "--env", "prod", ref},
		{"diff", "--format=json", "--env", "dev", "--env", "prod", ref},
		{"doctor", "--format=json", ref},
		{"completion", "--command", "show", "--flag=--key", "-f", ref},
	} {
		var out, diagnostic bytes.Buffer
		if status := Main(args, nil, &out, &diagnostic); status != 0 {
			t.Fatalf("%s: status %d: %s", args[0], status, diagnostic.String())
		}
		if strings.Contains(out.String(), "synthetic-private") {
			t.Fatal("metadata contains a value")
		}
		if args[0] != "completion" && !json.Valid(out.Bytes()) {
			t.Fatal("invalid metadata JSON")
		}
	}
	var out, diagnostic bytes.Buffer
	if status := Main([]string{"completion", "--command", "import", "--flag=--from", "-f", ref}, nil, &out, &diagnostic); status != 0 || strings.TrimSpace(out.String()) != "dotenv:"+strings.TrimPrefix(ref, "file:") {
		t.Fatal("import source completion not wired")
	}
}

func TestOperatorDispatchRefusesBeforeAccess(t *testing.T) {
	home := testutil.TempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", filepath.Join(home, "not-created"))
	for _, sub := range []string{"import", "export", "rotate", "delete", "rename"} {
		var out, diagnostic bytes.Buffer
		if status := Main([]string{sub, "--yes", "--format=json", "--audit-dir", filepath.Join(home, "audit")}, nil, &out, &diagnostic); status != 1 {
			t.Fatal("nonterminal operator accepted")
		}
		want := secure.ErrTerminalRequired
		if diagnostic.String() != "secret: "+want.Error()+"\n" {
			t.Fatalf("gate did not precede parsing: %s", diagnostic.String())
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("refusal created state")
	}
}

func TestFeatureArgumentRejection(t *testing.T) {
	_, ref := featureFixture(t)
	for _, args := range [][]string{
		{"show", "--format=raw", ref}, {"list", "--format=json", ref},
		{"diff", "--env", "prod", ref}, {"diff", "--format=json"},
		{"diff", "--env", "a", "--env", "b", "--env", "c", ref},
		{"doctor", "--format=raw"}, {"mcp"}, {"mcp", "--store", ref, "--get"},
		{"completion", "--yes"}, {"completion", "unexpected"}, {"audit"},
	} {
		var out, diagnostic bytes.Buffer
		if Main(args, nil, &out, &diagnostic) != 1 || out.Len() != 0 {
			t.Fatalf("invalid request accepted: %v", args)
		}
	}
}

func TestFeatureMCPDispatch(t *testing.T) {
	_, ref := featureFixture(t)
	input, err := os.CreateTemp(testutil.TempDir(t), "protocol")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	frames := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"synthetic\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{ }}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
	if _, err := input.WriteString(frames); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if Main([]string{"mcp", "--store", ref}, input, &out, &diagnostic) != 0 || strings.Contains(out.String(), "synthetic-private") {
		t.Fatal("MCP dispatch failed")
	}
	decoder := json.NewDecoder(&out)
	for _, id := range []int{1, 2} {
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := decoder.Decode(&response); err != nil || response.ID != id || len(response.Error) != 0 || len(response.Result) == 0 {
			t.Fatal("MCP handshake or tool listing failed")
		}
		if id == 2 {
			var result struct {
				Tools []struct{ Name string } `json:"tools"`
			}
			if json.Unmarshal(response.Result, &result) != nil || len(result.Tools) != 4 {
				t.Fatal("MCP metadata tool list missing")
			}
		}
	}
}

type eventSpy struct{ events []store.AuditEvent }

func (s *eventSpy) Record(event store.AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestOperatorAuditBridge(t *testing.T) {
	result := feature.OperatorResult{Action: store.ActionRename, Target: "libsecret:synthetic", Records: []feature.OperatorRecord{{Key: "OLD", NewKey: "NEW", Labels: map[string]string{"env": "prod"}}, {Key: "OTHER", NewKey: "NEXT", Labels: map[string]string{}}}}
	for _, tc := range []struct {
		err     error
		outcome store.AuditOutcome
	}{{nil, store.AuditSuccess}, {secure.ErrConsent, store.AuditDeclined}, {secure.ErrRecovery, store.AuditRecovery}, {errors.New("synthetic-private-error"), store.AuditFailure}} {
		spy := &eventSpy{}
		if err := recordOperatorEvents(spy, result, tc.err); err != nil {
			t.Fatal(err)
		}
		if len(spy.events) != 2 || spy.events[0].Outcome != tc.outcome || strings.Join(spy.events[0].Keys, ",") != "OLD,NEW" || spy.events[0].Labels["env"] != "prod" || len(spy.events[1].Labels) != 0 {
			t.Fatal("audit lost exact identities")
		}
		data, _ := json.Marshal(spy.events)
		if bytes.Contains(data, []byte("synthetic-private")) {
			t.Fatal("audit includes error text")
		}
	}
}

func TestOperatorCLIIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix operator persistence")
	}
	dir, ref := featureFixture(t)
	var out, diagnostic bytes.Buffer
	c := command{out: &out, errOut: &diagnostic, dir: dir}
	auditDir := filepath.Join(filepath.Dir(dir), "audit")
	request := OperatorRequest{Action: store.ActionRename, Target: ref, Keys: []string{"TOKEN", "RENAMED"}, Labels: map[string]string{"env": "prod"}}
	challenge, err := operatorChallenge(request)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &OperatorTerminal{console: &fakeOperatorConsole{inputs: [][]byte{challenge}}}
	if c.operateTerminal("rename", []string{ref, "TOKEN", "RENAMED", "--env", "prod", "--audit-dir", auditDir}, terminal) != 0 {
		t.Fatalf("rename failed: %s", diagnostic.String())
	}
	metadata, err := feature.ReadMetadata(ref, dir)
	if err != nil || metadata.Records[1].Key != "RENAMED" || metadata.Records[0].Key != "TOKEN" {
		t.Fatal("rename did not preserve exact labels")
	}
	log, err := feature.OpenAudit(feature.AuditConfig{Enabled: true, Directory: auditDir})
	if err != nil {
		t.Fatal(err)
	}
	events, err := log.Query(feature.AuditQuery{})
	if err != nil || len(events.Events) != 1 || events.Events[0].Outcome != store.AuditSuccess || strings.Join(events.Events[0].Keys, ",") != "TOKEN,RENAMED" {
		t.Fatal("operator audit not persisted")
	}
	out.Reset()
	diagnostic.Reset()
	if c.operateTerminal("delete", []string{ref, "TOKEN", "--yes"}, terminal) != 1 {
		t.Fatal("bypass flag accepted")
	}
	if c.operateTerminal("rotate", []string{ref, "TOKEN", "--format=json"}, terminal) != 1 {
		t.Fatal("operator JSON accepted")
	}
}

func TestOperatorCLIAuditAncestorAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix operator persistence")
	}
	dir, ref := featureFixture(t)
	parent := filepath.Dir(dir)
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	path := strings.TrimPrefix(ref, "file:")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request := OperatorRequest{Action: store.ActionRename, Target: ref, Keys: []string{"TOKEN", "RENAMED"}}
	challenge, err := operatorChallenge(request)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &OperatorTerminal{console: &fakeOperatorConsole{inputs: [][]byte{challenge}}}
	var out, diagnostic bytes.Buffer
	c := command{out: &out, errOut: &diagnostic, dir: dir}
	if c.operateTerminal("rename", []string{ref, "TOKEN", "RENAMED", "--audit-dir", filepath.Join(alias, "audit")}, terminal) != 1 || !strings.Contains(diagnostic.String(), secure.ErrAudit.Error()) {
		t.Fatal("operator accepted an audit ancestor alias")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected audit configuration mutated the store")
	}
	if _, err := os.Lstat(filepath.Join(parent, "audit")); !os.IsNotExist(err) {
		t.Fatal("rejected audit configuration created the audit directory")
	}
}
