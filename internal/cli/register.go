package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func (c command) openProviderRead(ctx context.Context, reference string) ([]store.ManifestRecord, backend.Provider, string, error) {
	if c.openRead != nil {
		return c.openRead(ctx, c.dir, reference)
	}
	return backend.OpenRead(ctx, c.dir, reference)
}
func parseRegister(args []string) (feature.RegisterRequest, error) {
	if len(args) < 2 {
		return feature.RegisterRequest{}, secure.ErrInvalidRequest
	}
	request := feature.RegisterRequest{Target: args[0], Key: args[1]}
	options, rest, err := featureOptions(args[2:], "--reference --account --auth --label*")
	if err != nil || len(rest) != 0 {
		return feature.RegisterRequest{}, secure.ErrInvalidRequest
	}
	labels, err := featureSelectors(options)
	if err != nil {
		return feature.RegisterRequest{}, secure.ErrInvalidRequest
	}
	request.Labels = labels
	request.Provider = store.OnePasswordReference{Reference: option(options, "--reference"), AccountUUID: option(options, "--account"), Auth: option(options, "--auth")}
	return request, feature.ValidateRegisterRequest(request)
}

// Registration has its own challenge rather than extending writable-operator
// consent. Validate all fields before rendering, then compare the entire line.
func registrationChallenge(request feature.RegisterRequest) ([]byte, error) {
	if feature.ValidateRegisterRequest(request) != nil {
		return nil, secure.ErrInvalidRequest
	}
	challenge := "register " + request.Target + " key=" + request.Key + " labels=" + store.CanonicalLabels(request.Labels) + " reference=" + request.Provider.Reference + " account=" + request.Provider.AccountUUID + " auth=" + request.Provider.Auth
	if len(challenge) > 16384 {
		return nil, secure.ErrInvalidRequest
	}
	return []byte(challenge), nil
}
func (terminal *OperatorTerminal) confirmRegistration(request feature.RegisterRequest) error {
	if terminal == nil {
		return secure.ErrTerminal
	}
	terminal.confirmed = false
	if terminal.console == nil {
		return secure.ErrTerminal
	}
	challenge, err := registrationChallenge(request)
	if err != nil {
		return err
	}
	defer secure.Clear(challenge)
	answer, readErr := terminal.console.readPassword(fmt.Sprintf("Type exactly to confirm (input hidden):\n%s\n> ", challenge), len(challenge))
	defer secure.Clear(answer)
	_, writeErr := io.WriteString(terminal.console, "\n")
	if readErr == secure.ErrTerminal {
		return secure.ErrTerminal
	}
	if readErr != nil || writeErr != nil || !bytes.Equal(answer, challenge) {
		return secure.ErrConsent
	}
	terminal.confirmed = true
	return nil
}
func (c command) register(args []string) int {
	if !backend.OnePasswordEnabled() {
		return c.failure(backend.ErrUnsupported)
	}
	terminal, err := RequireOperatorTerminal(c.in, c.out)
	if err != nil {
		return c.failure(err)
	}
	defer terminal.Close()
	request, err := parseRegister(args)
	if err != nil {
		return c.failure(err)
	}
	registrar := feature.Registrar{SecretsDir: c.dir, Confirm: terminal.confirmRegistration}
	if err := registrar.Register(request); err != nil {
		return c.failure(err)
	}
	_, err = fmt.Fprintf(c.out, "registered %s in %s\n", request.Key, request.Target)
	if err != nil {
		return c.fail("operator output failed", 1)
	}
	return 0
}

// preflightOnePasswordOperator rejects both export directions. Read-only export
// is deferred as a workflow, even though explicit get/run reads are scaffolded.
func preflightOnePasswordOperator(args []string) error {
	for _, arg := range args {
		_, value, ok := strings.Cut(arg, "=")
		if ok {
			arg = value
		}
		if err := backend.ReadOnlyReference(arg); err != nil {
			return err
		}
	}
	return nil
}
