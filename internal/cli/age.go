package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func ageRef(reference string) bool { return strings.HasPrefix(reference, "age:") }
func (c command) ageConfig() backend.AgeConfig {
	return backend.AgeConfig{Home: c.loc.Home, SecretsDir: c.dir, IdentityFile: c.ageIdentity}
}

// ageIdentityOption removes only our option, never anything after a child marker.
// It performs syntax checks only. Key files are opened solely by value workflows.
func ageIdentityOption(args []string, home string) ([]string, string, error) {
	var result []string
	identity := ""
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			result = append(result, args[i:]...)
			break
		}
		if arg != "--age-identity" && !strings.HasPrefix(arg, "--age-identity=") {
			result = append(result, arg)
			continue
		}
		if identity != "" {
			return nil, "", secure.ErrInvalidRequest
		}
		_, value, equal := strings.Cut(arg, "=")
		if !equal {
			i++
			if i == len(args) {
				return nil, "", errOptionArgument
			}
			value = args[i]
		}
		if !backend.ValidateAgeIdentityPath(home, value) {
			return nil, "", secure.ErrInvalidRequest
		}
		identity = value
	}
	return result, identity, nil
}
func (c command) ageNames(reference string) ([]store.ManifestRecord, error) {
	path, err := store.AgePath(c.dir, reference)
	if err != nil {
		return nil, store.ErrAge
	}
	envelope, err := store.ReadAgeEnvelope(path)
	if err != nil {
		return nil, store.ErrAge
	}
	return envelope.Records, nil
}
func (c command) ageList(args []string) int {
	options, rest, err := featureOptions(args, "--backend --format")
	if err != nil {
		return c.failure(err)
	}
	if len(rest) != 0 || option(options, "--backend") != "age" || (option(options, "--format") != "" && option(options, "--format") != "json") {
		return c.failure(secure.ErrInvalidRequest)
	}
	// Listing is explicit and age-only. Validate every discovered envelope rather
	// than silently omitting an invalid target. Default discovery remains unchanged.
	root, err := store.OpenPrivateDirectory(c.dir)
	if err != nil {
		return c.failure(err)
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return c.failure(store.ErrAge)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return c.failure(store.ErrAge)
	}
	var refs []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".secret.age") {
			continue
		}
		ref := "age:" + strings.TrimSuffix(entry.Name(), ".secret.age")
		if _, err := c.ageNames(ref); err != nil {
			return c.failure(err)
		}
		refs = append(refs, ref)
	}
	// Keep filesystem order out of this explicit inventory.
	sort.Strings(refs)
	if option(options, "--format") == "json" {
		document, err := feature.LoadInventory(refs, c.dir, nil)
		if err != nil {
			return c.failure(err)
		}
		return c.jsonDocument(document)
	}
	for _, ref := range refs {
		fmt.Fprintln(c.out, ref)
	}
	return 0
}

func (c command) ageOperate(sub string, args []string) int {
	terminal, err := RequireOperatorTerminal(c.in, c.out)
	if err != nil {
		return c.failure(err)
	}
	defer terminal.Close()
	spec := "--age-identity --age-recipients --audit-dir"
	if sub == "age-rekey" {
		spec += " --age-new-identity"
	}
	options, rest, err := featureOptions(args, spec)
	if err != nil {
		return c.failure(err)
	}
	if len(rest) != 1 || !ageRef(rest[0]) {
		return c.failure(secure.ErrInvalidRequest)
	}
	if _, err := store.AgePath(c.dir, rest[0]); err != nil {
		return c.failure(secure.ErrInvalidRequest)
	}
	for _, name := range []string{"--age-identity", "--age-recipients"} {
		if !backend.ValidateAgeIdentityPath(c.loc.Home, option(options, name)) {
			return c.failure(secure.ErrInvalidRequest)
		}
	}
	if sub == "age-rekey" && !backend.ValidateAgeIdentityPath(c.loc.Home, option(options, "--age-new-identity")) {
		return c.failure(secure.ErrInvalidRequest)
	}
	request := OperatorRequest{Action: store.OperatorAction(sub), Target: rest[0]}
	// No identity or recipient file is touched before exact target confirmation.
	err = terminal.Confirm(request)
	var audit *feature.AuditLog
	if directory := option(options, "--audit-dir"); directory != "" {
		var openErr error
		audit, openErr = feature.OpenAudit(feature.AuditConfig{Enabled: true, Directory: directory})
		if openErr != nil {
			return c.failure(openErr)
		}
	}
	if err == nil {
		config := c.ageConfig()
		config.IdentityFile = option(options, "--age-identity")
		if sub == "age-init" {
			if err = store.InitializeAgeDirectories(c.loc.Home, c.dir); err == nil {
				err = config.Init(rest[0], option(options, "--age-recipients"))
			}
		} else {
			err = config.Rekey(rest[0], option(options, "--age-recipients"), option(options, "--age-new-identity"))
		}
	}
	if audit != nil {
		outcome := store.AuditSuccess
		if err == secure.ErrConsent {
			outcome = store.AuditDeclined
		} else if err != nil {
			outcome = store.AuditFailure
		}
		if audit.Record(store.AuditEvent{Version: store.MetadataVersion, Time: time.Now().UTC(), Action: request.Action, Target: request.Target, Outcome: outcome}) != nil {
			if err == nil {
				return c.fail("operation completed; audit recording failed (no rollback claimed)", 1)
			}
			return c.failure(secure.ErrAudit)
		}
	}
	if err != nil {
		return c.failure(err)
	}
	fmt.Fprintf(c.out, "%s completed: %s\n", sub, rest[0])
	return 0
}
