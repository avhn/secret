package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/input"
)

func TestAudit24Envelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit24.json")
}

func TestAudit24MissingCredentialTargets(t *testing.T) {
	requireBashAnalysis(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "RIPGREP_CONFIG_PATH"} {
		t.Setenv(key, "")
	}
	for _, profile := range []struct{ directory, file string }{
		{".aws", "credentials"}, {".aws", "config"}, {".ssh", "id_rsa"},
		{".kube", "config"}, {".docker", "config.json"}, {".cargo", "credentials.toml"},
		{".terraform.d", "credentials.tfrc.json"}, {".config/gh", "hosts.yml"},
	} {
		for _, empty := range []bool{false, true} {
			work := t.TempDir()
			dir := filepath.Join(work, filepath.FromSlash(profile.directory))
			if empty {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, command := range []struct {
				text string
				deny bool
			}{{"cat " + profile.file, true}, {"cat public.txt", false}, {"stat " + profile.file, false}} {
				for _, shape := range []string{"cd", "workdir", "cwd"} {
					cwd := work
					fields := map[string]string{"command": command.text}
					switch shape {
					case "cd":
						fields["command"] = "tar xf public.tar && cd " + profile.directory + " && " + command.text
					case "workdir":
						fields["workdir"] = dir
					case "cwd":
						cwd = dir
					}
					body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd, "tool_input": fields})
					if err != nil {
						t.Fatal(err)
					}
					for _, host := range []string{"claude", "codex"} {
						var output bytes.Buffer
						if err := Decide(host, bytes.NewReader(body), &output); err != nil {
							t.Fatal(err)
						}
						if deny := strings.Contains(output.String(), `"permissionDecision":"deny"`); deny != command.deny {
							t.Errorf("%s empty=%v %s %s: %s want deny=%v", host, empty, profile.directory, shape, output.String(), command.deny)
						}
					}
				}
			}
		}
	}
}

func TestAudit24StdinReadDeadline(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	for _, host := range []string{"claude", "codex"} {
		for _, source := range []string{"", `{"tool_name":`, `{"tool_name":"Bash","cwd":` + string(mustAudit24JSON(t, root)) + `,"tool_input":{"command":"echo public"}}`} {
			reader, writer := io.Pipe()
			// Own and release both ends even on an assertion failure. The input
			// remains open until after Decide returns, including valid safe JSON.
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			written := make(chan struct{})
			go func() {
				_, _ = io.WriteString(writer, source)
				close(written)
			}()
			var output bytes.Buffer
			start := time.Now()
			if err := Decide(host, reader, &output); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			if elapsed < input.ReadTimeout || elapsed > 4*time.Second {
				t.Errorf("%s read took %s, want 2 to 4 seconds", host, elapsed)
			}
			if strings.Count(output.String(), `"permissionDecision":"deny"`) != 1 {
				t.Errorf("%s timeout did not deny exactly once: %s", host, output.String())
			}
			_ = writer.Close()
			_ = reader.Close()
			<-written
		}
	}
	var output bytes.Buffer
	if err := Decide("claude", strings.NewReader(""), &output); err != nil || output.Len() != 0 {
		t.Errorf("closed empty input changed: err=%v output=%s", err, output.String())
	}
}

func mustAudit24JSON(t *testing.T, value string) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
