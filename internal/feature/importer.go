package feature

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const MaxImporterOutputBytes = 1 << 20

// FieldMapping names an exact input field and destination key. op uses field IDs;
// bw supports login.username, login.password, login.totp, notes and fields.NAME.
// No provider field is imported implicitly. Dotenv mappings use exact key names;
// without mappings all unlabeled dotenv keys are imported, last identity wins.
type FieldMapping struct{ Field, Key string }

// ImportRequest accepts dotenv:ABS_PATH, op:OPAQUE_ID or bw:OPAQUE_ID. Labels
// apply to every imported identity. File targets must use file:ABS_PATH.
type ImportRequest struct {
	Source, Target string
	Labels         map[string]string
	Mappings       []FieldMapping
	DryRun         bool
}

func validOpaqueItem(item string) bool {
	if len(item) == 0 || len(item) > 128 {
		return false
	}
	for i := range item {
		b := item[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			continue
		}
		if i > 0 && (b == '_' || b == '-') {
			continue
		}
		return false
	}
	return true
}

func validImportField(kind, field string) bool {
	if len(field) == 0 || len(field) > 256 {
		return false
	}
	if kind == "dotenv" {
		return store.ValidateIdentity(field, nil) == nil
	}
	if kind == "bw" {
		switch field {
		case "login.username", "login.password", "login.totp", "notes":
			return true
		}
		if !strings.HasPrefix(field, "fields.") {
			return false
		}
		field = strings.TrimPrefix(field, "fields.")
	}
	return validOpaqueItem(field)
}

func validateImportRequest(request ImportRequest) (string, string, error) {
	if err := backend.ReadOnlyReference(request.Target); err != nil {
		return "", "", err
	}
	kind, item, ok := strings.Cut(request.Source, ":")
	if !ok || !validOperatorReference(request.Target) || store.ValidateIdentity("KEY", request.Labels) != nil || len(request.Mappings) > maxOperatorRecords {
		return "", "", secure.ErrInvalidRequest
	}
	switch kind {
	case "dotenv":
		if !validOperatorReference("file:"+item) || request.Target == "file:"+item {
			return "", "", secure.ErrInvalidRequest
		}
	case "op", "bw":
		if !validOpaqueItem(item) || len(request.Mappings) == 0 {
			return "", "", secure.ErrInvalidRequest
		}
	default:
		return "", "", secure.ErrInvalidRequest
	}
	fields, keys := make(map[string]bool), make(map[string]bool)
	for _, mapping := range request.Mappings {
		if !validImportField(kind, mapping.Field) || store.ValidateIdentity(mapping.Key, request.Labels) != nil || fields[mapping.Field] || keys[mapping.Key] {
			return "", "", secure.ErrInvalidRequest
		}
		fields[mapping.Field], keys[mapping.Key] = true, true
	}
	return kind, item, nil
}

func (operator Operator) importPlan(request ImportRequest) (OperatorResult, []store.Mutation, error) {
	if err := backend.ReadOnlyReference(request.Target); err != nil {
		return OperatorResult{}, nil, err
	}
	if err := operator.validate(); err != nil {
		return OperatorResult{}, nil, err
	}
	kind, item, err := validateImportRequest(request)
	if err != nil {
		return OperatorResult{}, nil, err
	}
	mappings := request.Mappings
	if kind == "dotenv" {
		data, err := readOperatorFile(item, false)
		defer secure.Clear(data)
		if err != nil {
			return OperatorResult{}, nil, err
		}
		metadata, warnings := store.ParseMetadata(data)
		// Unlike legacy show, import refuses ignored/malformed input instead of
		// silently publishing only a subset. Duplicate assignment warnings are OK.
		for _, warning := range warnings {
			if warning.Key == "" {
				return OperatorResult{}, nil, secure.ErrInvalidRequest
			}
		}
		available := make(map[string]bool)
		for _, record := range metadata {
			if len(record.Labels) != 0 {
				return OperatorResult{}, nil, secure.ErrInvalidRequest
			}
			if !available[record.Key] && len(request.Mappings) == 0 {
				mappings = append(mappings, FieldMapping{Field: record.Key, Key: record.Key})
			}
			available[record.Key] = true
		}
		for _, mapping := range mappings {
			if !available[mapping.Field] {
				return OperatorResult{}, nil, secure.ErrNotFound
			}
		}
	}
	if len(mappings) == 0 || len(mappings) > maxOperatorRecords {
		return OperatorResult{}, nil, secure.ErrInvalidRequest
	}
	mutations := make([]store.Mutation, 0, len(mappings))
	for _, mapping := range mappings {
		mutations = append(mutations, store.Mutation{Kind: store.MutationPut, Key: mapping.Key, Labels: copyMetadataLabels(request.Labels)})
	}
	destination, err := operator.destinationMetadata(request.Target)
	if err != nil {
		return OperatorResult{}, nil, err
	}
	result := operatorResult(store.ActionImport, request.Source, request.Target, mutations, destination.Records)
	if err := store.CheckMutationConflicts(destination.Records, mutations, true, false); err != nil {
		return result, nil, err
	}
	return result, mutations, nil
}

// PreflightImport derives names and conflicts without calling an external item or
// value provider. Dotenv is bounded and parsed in metadata mode. For op/bw, field
// existence is deliberately unknown until the explicitly mapped item is fetched.
func (operator Operator) PreflightImport(request ImportRequest) (OperatorResult, error) {
	result, _, err := operator.importPlan(request)
	return result, err
}

// Import repeats preflight after real-terminal consent and publishes one
// insert-only batch. Provider stdout stays in bounded, owned byte buffers and is
// never passed to encoding/json, errors, argv or a diagnostic. No shell is used.
func (operator Operator) Import(ctx context.Context, request ImportRequest) (OperatorResult, error) {
	result, mutations, err := operator.importPlan(request)
	if err != nil || request.DryRun {
		return result, err
	}
	defer clearOperatorMutations(mutations)
	if ctx == nil || ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	if err := operator.confirm(result); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	kind, item, _ := strings.Cut(request.Source, ":")
	if kind == "dotenv" {
		data, err := readOperatorFile(item, false)
		defer secure.Clear(data)
		if err != nil {
			return result, err
		}
		records, _ := store.Parse(data)
		defer func() {
			for _, record := range records {
				secure.Clear(record.Value)
			}
		}()
		values := make(map[string][]byte)
		for _, record := range records {
			if len(record.Labels) == 0 {
				values[record.Key] = record.Value
			}
		}
		for i := range mutations {
			field := mutations[i].Key
			if len(request.Mappings) != 0 {
				field = request.Mappings[i].Field
			}
			value, ok := values[field]
			if !ok {
				return result, secure.ErrNotFound
			}
			mutations[i].Value = secure.Clone(value)
		}
	} else {
		run := operator.runImport
		if run == nil {
			run = runImporter
		}
		args := []string{"item", "get", item, "--format=json"}
		if kind == "bw" {
			args = []string{"get", "item", item}
		}
		data, err := run(ctx, kind, args)
		defer secure.Clear(data)
		if err != nil || len(data) > MaxImporterOutputBytes {
			return result, secure.ErrTransaction
		}
		node, err := parsePrivateJSON(data)
		if node != nil {
			defer node.clear()
		}
		if err != nil {
			return result, err
		}
		for i, mapping := range request.Mappings {
			value, err := importJSONField(node, kind, mapping.Field)
			if err != nil {
				return result, err
			}
			mutations[i].Value = secure.Clone(value)
		}
	}
	for _, mutation := range mutations {
		if len(mutation.Value) > MaxOperatorValueBytes {
			return result, secure.ErrInvalidRequest
		}
	}
	if err := store.ValidateMutations(mutations); err != nil {
		return result, operatorError(err)
	}
	if ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	return result, operatorError(operator.transaction(request.Target, true, false).Apply(mutations))
}

// destinationMetadata checks pending recovery and dispatch configuration before
// a source value fetch. Apply still repeats all conflict/recovery checks locked.
func (operator Operator) destinationMetadata(reference string) (store.Metadata, error) {
	if strings.HasPrefix(reference, "file:") && store.ValidateDirectory(filepath.Dir(strings.TrimPrefix(reference, "file:"))) != nil {
		return store.Metadata{}, secure.ErrInvalidRequest
	}
	metadata, err := operator.metadata(reference, true)
	if err != nil {
		return store.Metadata{}, err
	}
	if !strings.HasPrefix(reference, "file:") {
		if _, _, err := operator.provider(reference); err != nil {
			return store.Metadata{}, err
		}
		kind, name, _ := strings.Cut(reference, ":")
		_, err := store.ReadRecovery(filepath.Join(operator.SecretsDir, name+".keys"), kind)
		if err == nil || !os.IsNotExist(err) {
			return store.Metadata{}, secure.ErrRecovery
		}
	}
	return metadata, nil
}

// importerOutput has one fixed backing allocation. Stderr is counted and
// discarded, not retained. Overflow cancels the command rather than truncating it.
type importerOutput struct {
	data    []byte
	count   int
	discard bool
	cancel  context.CancelFunc
	failed  bool
}

func (output *importerOutput) Write(data []byte) (int, error) {
	if len(data) > MaxImporterOutputBytes-output.count {
		output.failed = true
		output.cancel()
		return 0, secure.ErrTransaction
	}
	if !output.discard {
		copy(output.data[output.count:], data)
	}
	output.count += len(data)
	return len(data), nil
}

func runImporter(ctx context.Context, name string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	configureImporterProcess(command)
	command.WaitDelay = 250 * time.Millisecond
	stdout := &importerOutput{data: make([]byte, MaxImporterOutputBytes), cancel: cancel}
	stderr := &importerOutput{discard: true, cancel: cancel}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		stopImporterProcess(command)
	}
	if err != nil || stdout.failed || stderr.failed || ctx.Err() != nil {
		secure.Clear(stdout.data)
		return nil, secure.ErrTransaction
	}
	return stdout.data[:stdout.count], nil
}

// privateJSON is a bounded byte-only parser tree. Even member names and ignored
// strings remain bytes. Unknown provider JSON is never decoded into Go strings
// or interfaces. Object duplicates, malformed UTF-8 and trailing data fail.
type privateJSON struct {
	kind    byte
	text    []byte
	members []privateJSONMember
	items   []*privateJSON
}
type privateJSONMember struct {
	name  []byte
	value *privateJSON
}

func (node *privateJSON) clear() {
	secure.Clear(node.text)
	for _, member := range node.members {
		secure.Clear(member.name)
		member.value.clear()
	}
	for _, item := range node.items {
		item.clear()
	}
}
func (node *privateJSON) get(name string) *privateJSON {
	if node == nil || node.kind != '{' {
		return nil
	}
	for _, member := range node.members {
		if bytes.Equal(member.name, []byte(name)) {
			return member.value
		}
	}
	return nil
}

type privateJSONParser struct {
	data      []byte
	at, nodes int
}

func (parser *privateJSONParser) space() {
	for parser.at < len(parser.data) && bytes.ContainsRune([]byte(" \t\r\n"), rune(parser.data[parser.at])) {
		parser.at++
	}
}
func parsePrivateJSON(data []byte) (*privateJSON, error) {
	if len(data) == 0 || len(data) > MaxImporterOutputBytes {
		return nil, secure.ErrInvalidRequest
	}
	parser := privateJSONParser{data: data}
	node, err := parser.value(0)
	parser.space()
	if err != nil || parser.at != len(data) || node.kind != '{' {
		if node != nil {
			node.clear()
		}
		return nil, secure.ErrInvalidRequest
	}
	return node, nil
}
func (parser *privateJSONParser) value(depth int) (_ *privateJSON, err error) {
	parser.space()
	parser.nodes++
	if depth > 16 || parser.nodes > 32768 || parser.at >= len(parser.data) {
		return nil, secure.ErrInvalidRequest
	}
	node := &privateJSON{kind: parser.data[parser.at]}
	defer func() {
		if err != nil {
			node.clear()
		}
	}()
	switch node.kind {
	case '"':
		node.text, err = parser.stringBytes()
		return node, err
	case '{', '[':
		parser.at++
		parser.space()
		end := byte('}')
		if node.kind == '[' {
			end = ']'
		}
		if parser.at < len(parser.data) && parser.data[parser.at] == end {
			parser.at++
			return node, nil
		}
		for {
			if len(node.members)+len(node.items) >= maxOperatorRecords {
				return nil, secure.ErrInvalidRequest
			}
			var name []byte
			if node.kind == '{' {
				name, err = parser.stringBytes()
				if err != nil {
					return nil, err
				}
				for _, member := range node.members {
					if bytes.Equal(member.name, name) {
						secure.Clear(name)
						return nil, secure.ErrInvalidRequest
					}
				}
				parser.space()
				if parser.at >= len(parser.data) || parser.data[parser.at] != ':' {
					secure.Clear(name)
					return nil, secure.ErrInvalidRequest
				}
				parser.at++
			}
			child, childErr := parser.value(depth + 1)
			if childErr != nil {
				secure.Clear(name)
				return nil, childErr
			}
			if node.kind == '{' {
				node.members = append(node.members, privateJSONMember{name, child})
			} else {
				node.items = append(node.items, child)
			}
			parser.space()
			if parser.at >= len(parser.data) {
				return nil, secure.ErrInvalidRequest
			}
			next := parser.data[parser.at]
			parser.at++
			if next == end {
				return node, nil
			}
			if next != ',' {
				return nil, secure.ErrInvalidRequest
			}
			parser.space()
		}
	default:
		// Numbers and literal atoms may occur in unselected metadata. Validate
		// syntax without allocating or retaining their source representation.
		start := parser.at
		for parser.at < len(parser.data) && !bytes.ContainsRune([]byte(" \t\r\n,]}"), rune(parser.data[parser.at])) {
			parser.at++
		}
		atom := parser.data[start:parser.at]
		if !validPrivateAtom(atom) {
			return nil, secure.ErrInvalidRequest
		}
		node.kind = 'a'
		return node, nil
	}
}
func validPrivateAtom(data []byte) bool {
	if bytes.Equal(data, []byte("null")) || bytes.Equal(data, []byte("true")) || bytes.Equal(data, []byte("false")) {
		return true
	}
	i := 0
	if i < len(data) && data[i] == '-' {
		i++
	}
	if i >= len(data) {
		return false
	}
	if data[i] == '0' {
		i++
	} else {
		if data[i] < '1' || data[i] > '9' {
			return false
		}
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
	}
	if i < len(data) && data[i] == '.' {
		i++
		start := i
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	if i < len(data) && (data[i] == 'e' || data[i] == 'E') {
		i++
		if i < len(data) && (data[i] == '+' || data[i] == '-') {
			i++
		}
		start := i
		for i < len(data) && data[i] >= '0' && data[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	return i == len(data)
}

func (parser *privateJSONParser) stringBytes() ([]byte, error) {
	parser.space()
	if parser.at >= len(parser.data) || parser.data[parser.at] != '"' {
		return nil, secure.ErrInvalidRequest
	}
	start := parser.at + 1
	end := start
	for end < len(parser.data) {
		if parser.data[end] == '"' {
			break
		}
		if parser.data[end] == '\\' {
			end++
		}
		end++
	}
	if end >= len(parser.data) {
		return nil, secure.ErrInvalidRequest
	}
	result := make([]byte, 0, end-start)
	fail := func() ([]byte, error) { secure.Clear(result); return nil, secure.ErrInvalidRequest }
	for i := start; i < end; {
		b := parser.data[i]
		i++
		if b < 32 {
			return fail()
		}
		if b != '\\' {
			if b >= utf8.RuneSelf {
				_, size := utf8.DecodeRune(parser.data[i-1 : end])
				if size == 1 {
					return fail()
				}
				result = append(result, parser.data[i-1:i-1+size]...)
				i += size - 1
			} else {
				result = append(result, b)
			}
			continue
		}
		if i >= end {
			return fail()
		}
		escaped := parser.data[i]
		i++
		switch escaped {
		case '"', '\\', '/':
			result = append(result, escaped)
		case 'b':
			result = append(result, '\b')
		case 'f':
			result = append(result, '\f')
		case 'n':
			result = append(result, '\n')
		case 'r':
			result = append(result, '\r')
		case 't':
			result = append(result, '\t')
		case 'u':
			r, ok := privateHexRune(parser.data[i:end])
			if !ok {
				return fail()
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if r > 0xdbff || i+6 > end || parser.data[i] != '\\' || parser.data[i+1] != 'u' {
					return fail()
				}
				low, ok := privateHexRune(parser.data[i+2 : end])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return fail()
				}
				r = utf16.DecodeRune(r, low)
				i += 6
			}
			result = utf8.AppendRune(result, r)
		default:
			return fail()
		}
	}
	parser.at = end + 1
	return result, nil
}
func privateHexRune(data []byte) (rune, bool) {
	if len(data) < 4 {
		return 0, false
	}
	var result rune
	for _, b := range data[:4] {
		result <<= 4
		switch {
		case b >= '0' && b <= '9':
			result += rune(b - '0')
		case b >= 'a' && b <= 'f':
			result += rune(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			result += rune(b - 'A' + 10)
		default:
			return 0, false
		}
	}
	return result, true
}

func importJSONField(root *privateJSON, kind, field string) ([]byte, error) {
	var value *privateJSON
	if kind == "bw" && strings.HasPrefix(field, "login.") {
		value = root.get("login").get(strings.TrimPrefix(field, "login."))
	} else if kind == "bw" && field == "notes" {
		value = root.get("notes")
	} else {
		list := root.get("fields")
		if list == nil || list.kind != '[' {
			return nil, secure.ErrNotFound
		}
		name, wanted := "id", field
		if kind == "bw" {
			name, wanted = "name", strings.TrimPrefix(field, "fields.")
		}
		for _, item := range list.items {
			id := item.get(name)
			if id != nil && id.kind == '"' && bytes.Equal(id.text, []byte(wanted)) {
				if value != nil {
					return nil, secure.ErrInvalidRequest
				}
				value = item.get("value")
				if value == nil {
					return nil, secure.ErrInvalidRequest
				}
			}
		}
	}
	if value == nil {
		return nil, secure.ErrNotFound
	}
	if value.kind != '"' || len(value.text) > MaxOperatorValueBytes {
		return nil, secure.ErrInvalidRequest
	}
	return value.text, nil
}

// Ensure subprocess writers have only the bounded Write path, not io.ReaderFrom.
var _ io.Writer = (*importerOutput)(nil)
