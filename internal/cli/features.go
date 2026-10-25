package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// featureOptions accepts only each command's explicit grammar. It never includes
// argument text in errors, and is not used by the legacy compatibility commands.
func featureOptions(args []string, specification string) (map[string][]string, []string, error) {
	allowed := make(map[string]string)
	for _, option := range strings.Fields(specification) {
		name := strings.TrimRight(option, "*?")
		allowed[name] = strings.TrimPrefix(option, name)
	}
	options := make(map[string][]string)
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name, value, equal := strings.Cut(arg, "=")
		kind, ok := allowed[name]
		if !ok || (len(options[name]) != 0 && kind != "*") {
			return nil, nil, secure.ErrInvalidRequest
		}
		if kind == "?" {
			if equal {
				return nil, nil, secure.ErrInvalidRequest
			}
			value = "true"
		} else if !equal {
			if i+1 == len(args) {
				return nil, nil, errOptionArgument
			}
			i++
			value = args[i]
		}
		if value == "" {
			return nil, nil, secure.ErrInvalidRequest
		}
		options[name] = append(options[name], value)
	}
	return options, positional, nil
}

func option(options map[string][]string, name string) string {
	if len(options[name]) == 0 {
		return ""
	}
	return options[name][0]
}

func featureSelectors(options map[string][]string) (store.Selectors, error) {
	selectors := store.Selectors{}
	for _, name := range []string{"--env", "--label"} {
		for _, value := range options[name] {
			if err := selectors.AddSelector(name, value); err != nil {
				return nil, secure.ErrInvalidRequest
			}
		}
	}
	return selectors, nil
}

func (c command) jsonDocument(document any) int {
	if json.NewEncoder(c.out).Encode(document) != nil {
		return c.fail("metadata output failed", 1)
	}
	return 0
}

func (c command) featureCommand(sub string, args []string) (int, bool) {
	switch sub {
	case "register":
		return c.register(args), true
	case "import", "export", "rename", "rotate", "delete":
		return c.operate(sub, args), true
	case "diff":
		return c.diff(args), true
	case "doctor":
		return c.doctor(args), true
	case "completion":
		return c.completion(args), true
	case "audit":
		return c.audit(args), true
	case "mcp":
		return c.mcp(args), true
	case "list", "show":
		// Only opt into the new parser when format is explicitly requested. The
		// original text path, ordering, warnings and byte lengths stay unchanged.
		for _, arg := range args {
			if arg == "--format" || strings.HasPrefix(arg, "--format=") {
				return c.inventory(sub, args), true
			}
		}
	}
	return 0, false
}

func (c command) metadataReferences(names []string, discover bool) ([]string, error) {
	if len(names) == 0 && discover {
		return c.defaults()
	}
	refs := make([]string, 0, len(names))
	for _, name := range names {
		ref, err := c.loc.Resolve(name)
		if err != nil {
			return nil, feature.ErrMetadata
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (c command) inventory(sub string, args []string) int {
	spec := "--format"
	if sub == "show" {
		spec += " --env* --label*"
	}
	options, names, err := featureOptions(args, spec)
	if err != nil {
		return c.failure(err)
	}
	if option(options, "--format") != "json" || (sub == "list" && len(names) != 0) {
		return c.failure(secure.ErrInvalidRequest)
	}
	sel, err := featureSelectors(options)
	if err != nil {
		return c.failure(err)
	}
	refs, err := c.metadataReferences(names, true)
	if err != nil {
		return c.failure(err)
	}
	document, err := feature.LoadInventory(refs, c.dir, sel)
	if err != nil {
		return c.failure(err)
	}
	return c.jsonDocument(document)
}

func (c command) diff(args []string) int {
	options, names, err := featureOptions(args, "--format --env* --left-label* --right-label*")
	if err != nil {
		return c.failure(err)
	}
	format := option(options, "--format")
	if (format != "" && format != "json") || len(names) < 1 || len(names) > 2 || (len(options["--env"]) != 0 && len(options["--env"]) != 2) {
		return c.failure(secure.ErrInvalidRequest)
	}
	left, right := store.Selectors{}, store.Selectors{}
	if envs := options["--env"]; len(envs) == 2 {
		if left.AddSelector("--env", envs[0]) != nil || right.AddSelector("--env", envs[1]) != nil {
			return c.failure(secure.ErrInvalidRequest)
		}
	}
	for _, side := range []struct {
		name      string
		selectors store.Selectors
	}{{"--left-label", left}, {"--right-label", right}} {
		for _, label := range options[side.name] {
			if side.selectors.AddSelector("--label", label) != nil {
				return c.failure(secure.ErrInvalidRequest)
			}
		}
	}
	refs, err := c.metadataReferences(names, false)
	if err != nil {
		return c.failure(err)
	}
	l, err := feature.ReadMetadata(refs[0], c.dir)
	if err != nil {
		return c.failure(err)
	}
	r := l
	if len(refs) == 2 {
		r, err = feature.ReadMetadata(refs[1], c.dir)
		if err != nil {
			return c.failure(err)
		}
	}
	document, err := feature.DiffMetadata(l, r, left, right)
	if err != nil {
		return c.failure(err)
	}
	if format == "json" {
		return c.jsonDocument(document)
	}
	for _, record := range document.Records {
		if _, err := fmt.Fprintf(c.out, "%s left=%t [%s] right=%t [%s]\n", record.Key, record.Left.Present, store.CanonicalLabels(record.Left.Labels), record.Right.Present, store.CanonicalLabels(record.Right.Labels)); err != nil {
			return c.fail("metadata output failed", 1)
		}
	}
	return 0
}

func (c command) doctor(args []string) int {
	options, refs, err := featureOptions(args, "--format --path* --ripgrep-config")
	if err != nil {
		return c.failure(err)
	}
	if format := option(options, "--format"); format != "" && format != "json" {
		return c.failure(secure.ErrInvalidRequest)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return c.failure(secure.ErrInvalidRequest)
	}
	report, err := feature.RunDoctor(feature.DoctorOptions{Home: c.loc.Home, Cwd: cwd, SecretsDir: c.dir, Paths: options["--path"], References: refs, RipgrepConfig: option(options, "--ripgrep-config")})
	if err != nil {
		return c.failure(err)
	}
	return c.jsonDocument(report)
}

func (c command) completion(args []string) int {
	options, rest, err := featureOptions(args, "--command --flag --prefix -f* --env* --label*")
	if err != nil {
		return c.failure(err)
	}
	if len(rest) != 0 {
		return c.failure(secure.ErrInvalidRequest)
	}
	sel, err := featureSelectors(options)
	if err != nil {
		return c.failure(err)
	}
	// Completion has no ambient discovery. Only explicit -f scopes may be read.
	refs, err := c.metadataReferences(options["-f"], false)
	if err != nil {
		return c.failure(err)
	}
	metadata := make([]store.Metadata, 0, len(refs))
	for _, ref := range refs {
		item, err := feature.ReadMetadata(ref, c.dir)
		if err != nil {
			return c.failure(err)
		}
		metadata = append(metadata, item)
	}
	candidates, err := feature.Complete(feature.CompletionRequest{Command: option(options, "--command"), Flag: option(options, "--flag"), Prefix: option(options, "--prefix"), Selectors: sel}, metadata)
	if err != nil {
		return c.failure(err)
	}
	for _, candidate := range candidates {
		if _, err := fmt.Fprintln(c.out, candidate); err != nil {
			return c.fail("metadata output failed", 1)
		}
	}
	return 0
}

func (c command) audit(args []string) int {
	options, rest, err := featureOptions(args, "--directory --format --action --target --key --outcome --limit --since --until")
	if err != nil {
		return c.failure(err)
	}
	if len(rest) != 0 || option(options, "--directory") == "" || (option(options, "--format") != "" && option(options, "--format") != "json") {
		return c.failure(secure.ErrInvalidRequest)
	}
	query := feature.AuditQuery{Action: store.OperatorAction(option(options, "--action")), Target: option(options, "--target"), Key: option(options, "--key"), Outcome: store.AuditOutcome(option(options, "--outcome"))}
	if value := option(options, "--limit"); value != "" {
		query.Limit, err = strconv.Atoi(value)
		if err != nil {
			return c.failure(secure.ErrInvalidRequest)
		}
	}
	for _, bound := range []struct {
		name   string
		target *time.Time
	}{{"--since", &query.Since}, {"--until", &query.Until}} {
		if value := option(options, bound.name); value != "" {
			*bound.target, err = time.Parse(time.RFC3339, value)
			if err != nil {
				return c.failure(secure.ErrInvalidRequest)
			}
		}
	}
	log, err := feature.OpenAudit(feature.AuditConfig{Enabled: true, Directory: option(options, "--directory")})
	if err != nil {
		return c.failure(err)
	}
	document, err := log.Query(query)
	if err != nil {
		return c.failure(err)
	}
	return c.jsonDocument(document)
}

func (c command) mcp(args []string) int {
	options, rest, err := featureOptions(args, "--store*")
	if err != nil {
		return c.failure(err)
	}
	if len(rest) != 0 {
		return c.failure(secure.ErrInvalidRequest)
	}
	server, err := feature.NewMCPServer(feature.MCPConfig{Enabled: len(options["--store"]) != 0, Stores: options["--store"], Directory: c.dir})
	if err != nil {
		return c.failure(err)
	}
	if err := server.Serve(c.in, c.out); err != nil {
		return c.failure(err)
	}
	return 0
}

// operatorRequests keeps exact labels separate, including heterogeneous export
// batches. Every identity is confirmed before the feature fetches any values.
func operatorRequests(result feature.OperatorResult) []OperatorRequest {
	requests := make([]OperatorRequest, 0, len(result.Records))
	for _, record := range result.Records {
		keys := []string{record.Key}
		if record.NewKey != "" {
			keys = append(keys, record.NewKey)
		}
		requests = append(requests, OperatorRequest{Action: result.Action, Source: result.Source, Target: result.Target, Keys: keys, Labels: record.Labels})
	}
	return requests
}

func recordOperatorEvents(sink store.AuditSink, result feature.OperatorResult, operationErr error) error {
	if sink == nil {
		return nil
	}
	outcome := store.AuditSuccess
	switch {
	case errors.Is(operationErr, secure.ErrConsent):
		outcome = store.AuditDeclined
	case errors.Is(operationErr, secure.ErrRecovery):
		outcome = store.AuditRecovery
	case operationErr != nil:
		outcome = store.AuditFailure
	}
	for _, request := range operatorRequests(result) {
		if err := sink.Record(store.AuditEvent{Version: store.MetadataVersion, Time: time.Now().UTC(), Action: request.Action, Source: request.Source, Target: request.Target, Keys: request.Keys, Labels: request.Labels, Outcome: outcome}); err != nil {
			return secure.ErrAudit
		}
	}
	return nil
}

func (c command) operate(sub string, args []string) int {
	if err := preflightOnePasswordOperator(args); err != nil {
		return c.failure(err)
	}
	// This gate precedes parsing, path resolution, metadata reads and audit setup.
	terminal, err := RequireOperatorTerminal(c.in, c.out)
	if err != nil {
		return c.failure(err)
	}
	defer terminal.Close()
	return c.operateTerminal(sub, args, terminal)
}

func (c command) operateTerminal(sub string, args []string, terminal *OperatorTerminal) int {
	spec := "--env* --label* --audit-dir --age-identity"
	switch sub {
	case "import":
		spec += " --from --into --map* --dry-run?"
	case "export":
		spec += " --from --to --key* --on-conflict --dry-run?"
	}
	options, rest, err := featureOptions(args, spec)
	if err != nil {
		return c.failure(err)
	}
	c.ageIdentity = option(options, "--age-identity")
	if c.ageIdentity != "" && !backend.ValidateAgeIdentityPath(c.loc.Home, c.ageIdentity) {
		return c.failure(secure.ErrInvalidRequest)
	}
	sel, err := featureSelectors(options)
	if err != nil {
		return c.failure(err)
	}
	var audit *feature.AuditLog
	var auditErr error
	operator := feature.Operator{SecretsDir: c.dir, Age: c.ageConfig(), Confirm: func(result feature.OperatorResult) error {
		// Validate and open opt-in persistence before mutation. Invalid or dry-run
		// requests never create audit files. Declines are recorded after return.
		if directory := option(options, "--audit-dir"); directory != "" {
			audit, auditErr = feature.OpenAudit(feature.AuditConfig{Enabled: true, Directory: directory})
			if auditErr != nil {
				return auditErr
			}
		}
		for _, request := range operatorRequests(result) {
			if err := terminal.Confirm(request); err != nil {
				return err
			}
		}
		return nil
	}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dryRun := option(options, "--dry-run") != ""
	var result feature.OperatorResult
	switch sub {
	case "import":
		if len(rest) != 0 {
			return c.failure(secure.ErrInvalidRequest)
		}
		mappings := make([]feature.FieldMapping, 0, len(options["--map"]))
		for _, mapping := range options["--map"] {
			field, key, ok := strings.Cut(mapping, "=")
			if !ok {
				return c.failure(secure.ErrInvalidRequest)
			}
			mappings = append(mappings, feature.FieldMapping{Field: field, Key: key})
		}
		result, err = operator.Import(ctx, feature.ImportRequest{Source: option(options, "--from"), Target: option(options, "--into"), Labels: sel, Mappings: mappings, DryRun: dryRun})
	case "export":
		if len(rest) != 0 {
			return c.failure(secure.ErrInvalidRequest)
		}
		result, err = operator.Export(ctx, feature.ExportRequest{Source: option(options, "--from"), Target: option(options, "--to"), Selectors: sel, Keys: options["--key"], OnConflict: option(options, "--on-conflict"), DryRun: dryRun})
	default:
		count := 2
		if sub == "rename" {
			count = 3
		}
		if len(rest) != count {
			return c.failure(secure.ErrInvalidRequest)
		}
		request := feature.LifecycleRequest{Action: store.OperatorAction(sub), Reference: rest[0], Key: rest[1], Labels: sel}
		if sub == "rename" {
			request.NewKey = rest[2]
		}
		var readValue func() ([]byte, error)
		if sub == "rotate" {
			readValue = terminal.ReadValue
		}
		result, err = operator.Lifecycle(request, readValue)
	}
	if auditErr != nil {
		return c.failure(secure.ErrAudit)
	}
	if audit != nil {
		if recordErr := recordOperatorEvents(audit, result, err); recordErr != nil {
			if err == nil {
				return c.fail("operation completed; audit recording failed (no rollback claimed)", 1)
			}
			fmt.Fprintln(c.errOut, "secret: audit recording failed")
		}
	}
	if dryRun && (err == nil || errors.Is(err, secure.ErrConflict)) {
		for _, record := range result.Records {
			if _, writeErr := fmt.Fprintf(c.out, "dry-run %s %s %s [%s] conflict=%t\n", result.Action, result.Target, record.Key, store.CanonicalLabels(record.Labels), record.Conflict); writeErr != nil {
				return c.fail("operator output failed", 1)
			}
		}
	}
	if err != nil {
		return c.failure(err)
	}
	if !dryRun {
		if _, err := fmt.Fprintf(c.out, "%s completed: %s\n", result.Action, result.Target); err != nil {
			return c.fail("operator output failed", 1)
		}
	}
	return 0
}
