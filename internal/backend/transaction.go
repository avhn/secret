package backend

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// Transaction publishes a whole provider batch through fresh random accounts.
// SecretsDir is the shared lock/manifest directory. Reference is an explicit
// keychain:NAME or libsecret:NAME. A nil Provider uses production dispatch;
// injected providers are for isolated tests, never environment-selected in a
// production build. The CLI must obtain operator consent before Apply.
// FailOnConflict makes put insert-only for import/export. RequireExisting makes
// put replace-only for rotation. These policies are mutually exclusive.
type Transaction struct {
	SecretsDir      string
	Reference       string
	Provider        Provider
	FailOnConflict  bool
	RequireExisting bool
}

var _ store.Transaction = Transaction{}

// transactionSteps permits deterministic phase failures and random collisions
// in tests without process-global hooks or production failure switches.
type transactionSteps struct {
	account    func() (string, error)
	checkpoint func(phase string, index int) error
}

func (steps transactionSteps) check(phase string, index int) error {
	if steps.checkpoint != nil {
		return steps.checkpoint(phase, index)
	}
	return nil
}

func (transaction Transaction) Apply(mutations []store.Mutation) error {
	return transaction.apply(mutations, transactionSteps{account: store.NewAccount})
}

func (transaction Transaction) apply(mutations []store.Mutation, steps transactionSteps) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(transaction.SecretsDir) || (transaction.FailOnConflict && transaction.RequireExisting) {
		return secure.ErrInvalidRequest
	}
	if err := store.ValidateMutations(mutations); err != nil {
		return err
	}
	provider, kind, service, err := DispatchWith(transaction.Reference, transaction.Provider)
	if err != nil {
		return secure.ErrInvalidRequest
	}
	_, name, _ := strings.Cut(transaction.Reference, ":")
	path := filepath.Join(transaction.SecretsDir, name+".keys")
	return store.WithManifestLock(path, kind, func(editor *store.ManifestEditor) error {
		previous := editor.Records()
		metadata := make([]store.MetadataRecord, len(previous))
		for i, record := range previous {
			metadata[i] = store.MetadataRecord{Key: record.Key, Labels: record.Labels, Account: record.Account}
		}
		if err := store.CheckMutationConflicts(metadata, mutations, transaction.FailOnConflict, transaction.RequireExisting); err != nil {
			return err
		}
		plan, err := planTransaction(previous, mutations, steps)
		if err != nil {
			return err
		}
		if steps.check("intent", 0) != nil {
			return secure.ErrTransaction
		}
		intent := store.RecoveryIntent{Version: store.MetadataVersion, Backend: kind, Prepared: plan.prepared, Obsolete: plan.obsolete}
		if err := editor.PersistRecovery(intent); err != nil {
			return err
		}
		// From this point failures leave tracked candidates, never a rollback
		// claim. The previous manifest remains intact until the one publication.
		for i, mutation := range mutations {
			if mutation.Kind == store.MutationDelete {
				continue
			}
			if steps.check("prepare", i) != nil {
				return secure.ErrRecovery
			}
			if err := prepareAccount(provider, kind, name, service, mutation, plan.fresh[i], plan.old[i], steps, i); err != nil {
				return secure.ErrRecovery
			}
		}
		if steps.check("publish", 0) != nil || stubPublishFailure(provider) != nil {
			return secure.ErrRecovery
		}
		if err := editor.Publish(plan.records); err != nil {
			return secure.ErrRecovery
		}
		if steps.check("published", 0) != nil {
			return secure.ErrRecovery
		}
		for i, record := range plan.obsolete {
			if steps.check("cleanup", i) != nil || provider.Delete(service, record.Account) != nil {
				return secure.ErrRecovery
			}
		}
		if steps.check("complete", 0) != nil {
			return secure.ErrRecovery
		}
		return editor.ClearRecovery()
	})
}

type transactionPlan struct {
	records  []store.ManifestRecord
	prepared []store.ManifestRecord
	obsolete []store.ManifestRecord
	fresh    []store.ManifestRecord
	old      []store.ManifestRecord
}

func planTransaction(previous []store.ManifestRecord, mutations []store.Mutation, steps transactionSteps) (transactionPlan, error) {
	plan := transactionPlan{fresh: make([]store.ManifestRecord, len(mutations)), old: make([]store.ManifestRecord, len(mutations))}
	accounts := make(map[string]bool)
	identities := make(map[string]store.ManifestRecord)
	for _, record := range previous {
		accounts[record.Account] = true
		identities[record.Key+"\x00"+store.CanonicalLabels(record.Labels)] = record
	}
	replacements := make(map[string]store.ManifestRecord)
	removed := make(map[string]bool)
	for i, mutation := range mutations {
		identity := mutation.Key + "\x00" + store.CanonicalLabels(mutation.Labels)
		old, exists := identities[identity]
		plan.old[i] = old
		if exists {
			plan.obsolete = append(plan.obsolete, old)
		}
		if mutation.Kind == store.MutationDelete {
			removed[identity] = true
			continue
		}
		account, err := freshAccount(accounts, steps.account)
		if err != nil {
			return transactionPlan{}, err
		}
		key := mutation.Key
		if mutation.Kind == store.MutationRename {
			key = mutation.NewKey
		}
		record := store.ManifestRecord{Key: key, Labels: mutation.Labels, Account: account}
		plan.fresh[i] = record
		plan.prepared = append(plan.prepared, record)
		if exists {
			replacements[identity] = record
		} else {
			plan.records = append(plan.records, record)
		}
	}
	inserted := plan.records
	plan.records = nil
	for _, record := range previous {
		identity := record.Key + "\x00" + store.CanonicalLabels(record.Labels)
		if removed[identity] {
			continue
		}
		if replacement, ok := replacements[identity]; ok {
			record = replacement
		}
		plan.records = append(plan.records, record)
	}
	plan.records = append(plan.records, inserted...)
	return plan, nil
}

func freshAccount(accounts map[string]bool, generate func() (string, error)) (string, error) {
	if generate == nil {
		generate = store.NewAccount
	}
	for attempt := 0; attempt < 16; attempt++ {
		account, err := generate()
		if err != nil || !providerAccount.MatchString(account) {
			return "", secure.ErrTransaction
		}
		if !accounts[account] {
			accounts[account] = true
			return account, nil
		}
	}
	return "", secure.ErrConflict
}

func prepareAccount(provider Provider, kind, name, service string, mutation store.Mutation, fresh, old store.ManifestRecord, steps transactionSteps, index int) error {
	var value []byte
	if mutation.Kind == store.MutationRename {
		got, err := provider.Get(service, old.Account)
		defer secure.Clear(got)
		if err != nil {
			return secure.ErrTransaction
		}
		value, err = store.NormalizeValue(got)
		if err != nil || !bytes.Equal(value, got) {
			secure.Clear(value)
			return secure.ErrTransaction
		}
	} else {
		var err error
		value, err = store.NormalizeValue(mutation.Value)
		if err != nil {
			return secure.ErrInvalidRequest
		}
	}
	defer secure.Clear(value)
	label := "secret/" + name + "/" + fresh.Key
	labels := store.CanonicalLabels(fresh.Labels)
	if kind == "libsecret" {
		label = "secret " + name + " " + fresh.Key
		if labels != "" {
			label += " [" + labels + "]"
		}
	} else if labels != "" {
		label += "/" + labels
	}
	if provider.Put(service, fresh.Account, label, value) != nil {
		return secure.ErrTransaction
	}
	if steps.check("verify", index) != nil {
		return secure.ErrTransaction
	}
	got, err := provider.Get(service, fresh.Account)
	defer secure.Clear(got)
	if err != nil || !bytes.Equal(got, value) {
		return secure.ErrTransaction
	}
	return nil
}
