package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// This is a source gate, not an environment variable or a build tag. Enabling it
// requires licensing review and isolated real-provider evidence, including whoami.
const onePasswordEnabled = false

func OnePasswordEnabled() bool { return onePasswordEnabled }

var ErrReadOnly = errors.New("onepassword backend is read-only")
var errOnePassword = errors.New("onepassword read failed")

// onePassword is bound to one validated manifest snapshot, executable, environment
// and invocation deadline. No provider-wide lookup or retargeting is possible.
type onePassword struct {
	ctx         context.Context
	executable  string
	environment []string
	service     string
	records     map[string]store.OnePasswordReference
	account     string
	verified    bool
}

func newOnePassword(ctx context.Context, service string, records []store.ManifestV2Record, executable string, environment []string) (*onePassword, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(executable) || len(records) == 0 {
		return nil, errOnePassword
	}
	if _, err := store.EncodeManifestV2(records, "onepassword"); err != nil {
		return nil, errOnePassword
	}
	env, err := onePasswordEnvironment(environment)
	if err != nil {
		return nil, err
	}
	p := &onePassword{ctx: ctx, executable: executable, environment: env, service: service, records: make(map[string]store.OnePasswordReference), account: records[0].Provider.AccountUUID}
	for _, r := range records {
		if !validProviderPair(service, r.ID) {
			return nil, errOnePassword
		}
		p.records[r.ID] = r.Provider
	}
	return p, nil
}
func onePasswordEnvironment(environment []string) ([]string, error) {
	result := make([]string, 0, len(environment)+3)
	token := false
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.HasPrefix(key, "OP_CONNECT_") || strings.HasPrefix(key, "OP_SESSION_") || key == "OP_ACCOUNT" {
			return nil, errOnePassword
		}
		if key == "OP_SERVICE_ACCOUNT_TOKEN" {
			if value == "" || token {
				return nil, errOnePassword
			}
			token = true
			result = append(result, entry)
			continue
		}
		if strings.HasPrefix(key, "OP_") && key != "OP_CONFIG_DIR" {
			continue
		}
		result = append(result, entry)
	}
	if !token {
		return nil, errOnePassword
	}
	return append(result, "OP_BIOMETRIC_UNLOCK_ENABLED=false", "OP_DEBUG=false", "OP_CACHE=false"), nil
}

// The candidate whoami contract is synthetic-only until a sanitized fixture from
// an owner-pinned CLI v2 (2.18.0 or later) proves it. The dispatch gate stays closed.
// Reject missing, unknown and duplicate identity fields rather than guessing.
func onePasswordIdentity(data []byte, account string) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	token, err = decoder.Token()
	if err != nil || token != "account_uuid" {
		return false
	}
	var identity string
	if decoder.Decode(&identity) != nil || identity != account || decoder.More() {
		return false
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func (p *onePassword) Get(service, id string) ([]byte, error) {
	reference, ok := p.records[id]
	if !ok || service != p.service || p.ctx.Err() != nil {
		return nil, errOnePassword
	}
	if !p.verified {
		output, err := p.run([]string{"whoami", "--format", "json"})
		valid := err == nil && onePasswordIdentity(output, p.account)
		secure.Clear(output)
		if !valid {
			return nil, errOnePassword
		}
		p.verified = true
	}
	output, err := p.run([]string{"read", "--no-newline", reference.Reference})
	if err != nil {
		secure.Clear(output)
		return nil, errOnePassword
	}
	defer secure.Clear(output)
	return onePasswordValue(output)
}
func (*onePassword) Put(string, string, string, []byte) error { return ErrReadOnly }
func (*onePassword) Delete(string, string) error              { return ErrReadOnly }

// onePasswordValue never applies stash's terminal-LF trimming to a
// provider value. Both the raw output and normalized scratch have explicit owners.
func onePasswordValue(raw []byte) ([]byte, error) {
	if bytes.ContainsAny(raw, "\x00\r\n") {
		return nil, errOnePassword
	}
	normalized, err := store.NormalizeValue(raw)
	defer secure.Clear(normalized)
	if err != nil || !bytes.Equal(normalized, raw) {
		return nil, errOnePassword
	}
	return secure.Clone(raw), nil
}

// Fixed backing storage avoids leaving value prefixes in reallocated buffers.
type onePasswordOutput struct {
	data   []byte
	count  int
	cancel context.CancelFunc
	failed bool
}

func (w *onePasswordOutput) Write(data []byte) (int, error) {
	if len(data) > len(w.data)-w.count {
		w.failed = true
		w.cancel()
		return 0, errOnePassword
	}
	copy(w.data[w.count:], data)
	w.count += len(data)
	return len(data), nil
}
func (p *onePassword) run(args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.executable, args...)
	if !configureOnePasswordProcess(cmd) {
		return nil, secure.ErrUnsupported
	}
	cmd.Env = p.environment
	cmd.Stdin = bytes.NewReader(nil)
	cmd.WaitDelay = 250 * time.Millisecond
	stdout := &onePasswordOutput{data: make([]byte, providerOutputLimit), cancel: cancel}
	stderr := &onePasswordOutput{data: make([]byte, providerOutputLimit), cancel: cancel}
	defer secure.Clear(stderr.data)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		stopProviderProcess(cmd)
	}
	if err != nil || ctx.Err() != nil || stdout.failed || stderr.failed {
		secure.Clear(stdout.data)
		return nil, errOnePassword
	}
	result := secure.Clone(stdout.data[:stdout.count])
	secure.Clear(stdout.data)
	return result, nil
}
