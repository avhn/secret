package ps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	oracleBatchLimit       = 250
	oracleInputLimit       = 8 << 20
	oracleBatchOutputLimit = 64 << 20
	oracleBatchTimeout     = 2 * time.Minute
	oracleJSONDepthLimit   = 128
	oracleJSONTokenLimit   = 8 << 20
)

type oracleSourceError struct {
	ID   string `json:"id"`
	Line int    `json:"line"`
}

type oracleResult struct {
	Index      int                `json:"index"`
	Projection *nativeProjection  `json:"projection"`
	Error      *oracleSourceError `json:"error"`
}

func (r oracleResult) value() (*nativeProjection, error) {
	if r.Error != nil {
		return nil, fmt.Errorf("oracle source failed index=%d id=%s line=%d", r.Index, r.Error.ID, r.Error.Line)
	}
	return r.Projection, nil
}

// Partition by both source count and exact JSON bytes, including escaping. No
// corpus or generated row is dropped, including duplicates and empty sources.
func oracleBatches(sources []string) [][]string {
	var batches [][]string
	for len(sources) > 0 {
		end, size := 0, 2 // JSON array brackets
		for end < len(sources) && end < oracleBatchLimit {
			encoded, _ := json.Marshal(sources[end])
			if size+len(encoded)+1 > oracleInputLimit {
				break
			}
			size += len(encoded) + 1
			end++
		}
		// Invalid oversized sources still reach runBatch and fail closed.
		if end == 0 {
			end = 1
		}
		batches = append(batches, sources[:end])
		sources = sources[end:]
	}
	return batches
}

func (r oracleRunner) runBatch(sources []string) ([]oracleResult, error) {
	if len(sources) == 0 || len(sources) > oracleBatchLimit {
		return nil, errors.New("oracle batch count limit")
	}
	for _, source := range sources {
		if len(source) > MaxSource || !utf8.ValidString(source) {
			return nil, errors.New("oracle source limit or encoding")
		}
	}
	input, err := json.Marshal(sources)
	if err != nil || len(input) > oracleInputLimit {
		return nil, errors.New("oracle input limit")
	}
	// Startup is paid once per batch, with bounded extra projection time and
	// capture space per source. These test-only limits never change hook budgets.
	timeout := min(r.timeout+time.Duration(len(sources)-1)*250*time.Millisecond, oracleBatchTimeout)
	outputLimit := min(r.outputLimit*len(sources), oracleBatchOutputLimit)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := append(append([]string{}, r.prefix...), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", r.script)
	cmd := exec.CommandContext(ctx, r.executable, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = r.directory, r.environment, bytes.NewReader(input)
	cmd.WaitDelay = time.Second
	configureOracleProcess(cmd)
	stdout, stderr := &boundedCapture{limit: outputLimit}, &boundedCapture{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("oracle timeout: %w", ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("oracle output limit")
	}
	if err != nil {
		if diagnostic := oracleDiagnostic(stderr.data.Bytes()); diagnostic != "" {
			return nil, fmt.Errorf("oracle process failed: %w (%s)", err, diagnostic)
		}
		return nil, fmt.Errorf("oracle process failed: %w", err)
	}
	if stderr.data.Len() != 0 {
		return nil, errors.New("oracle unexpected stderr")
	}
	var results []oracleResult
	data := stdout.data.Bytes()
	if err := validateOracleJSON(data, oracleJSONDepthLimit, oracleJSONTokenLimit); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&results); err != nil {
		return nil, errors.New("oracle invalid JSON")
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF {
		return nil, errors.New("oracle trailing JSON")
	}
	if len(results) != len(sources) {
		return nil, errors.New("oracle result count mismatch")
	}
	// Zero-valued fields are valid evidence only when explicitly present. This
	// also checks nested spans, binding flags and nullable fields, not just slices.
	if !oracleFieldsPresent(data, reflect.TypeFor[[]oracleResult]()) {
		return nil, errors.New("oracle incomplete projection")
	}
	for i, result := range results {
		if result.Index != i {
			return nil, errors.New("oracle result order mismatch")
		}
		if (result.Projection == nil) == (result.Error == nil) {
			return nil, errors.New("oracle incomplete projection or error")
		}
		if result.Error != nil && (!oracleErrorID(result.Error.ID) || result.Error.Line < 1) {
			return nil, errors.New("oracle invalid source error")
		}
	}
	return results, nil
}

// A single final CRLF/LF is the script's WriteLine, not printable diagnostic
// content. Suppress controls, non-ASCII and long stderr rather than echoing it.
func oracleDiagnostic(data []byte) string {
	if len(data) > 512 {
		return ""
	}
	text := string(data)
	if strings.HasSuffix(text, "\r\n") {
		text = strings.TrimSuffix(text, "\r\n")
	} else {
		text = strings.TrimSuffix(text, "\n")
	}
	for _, c := range text {
		if c < 32 || c > 126 {
			return ""
		}
	}
	return text
}

func oracleErrorID(id string) bool {
	if len(id) == 0 || len(id) > 160 {
		return false
	}
	for _, c := range id {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:,+-", c)) {
			return false
		}
	}
	return true
}

// Decoding already validates types and unknown fields. Check presence separately
// because encoding/json otherwise accepts absent fields and null scalar values.
func oracleFieldsPresent(data json.RawMessage, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			return true
		}
		return oracleFieldsPresent(data, typ.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return false
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.Anonymous {
				if !oracleFieldsPresent(data, field.Type) {
					return false
				}
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			value, ok := fields[name]
			if !ok || !oracleFieldsPresent(value, field.Type) {
				return false
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return false
		}
		for _, value := range values {
			if !oracleFieldsPresent(value, typ.Elem()) {
				return false
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(data, &values) != nil {
			return false
		}
		for _, value := range values {
			if !oracleFieldsPresent(value, typ.Elem()) {
				return false
			}
		}
	}
	return true
}

func compareOracleBatch(runner oracleRunner, sources []string) ([]error, error) {
	results, err := runner.runBatch(sources)
	if err != nil {
		return nil, &oracleInfrastructureError{err}
	}
	comparisons := make([]error, len(sources))
	for i, result := range results {
		native, err := result.value()
		if err != nil {
			comparisons[i] = &oracleInfrastructureError{err}
		} else {
			comparisons[i] = compareOracleProjection(sources[i], native)
		}
	}
	return comparisons, nil
}
