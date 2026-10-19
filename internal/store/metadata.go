package store

import "time"

// MetadataVersion is the schema version for M3 names-only documents and events.
const MetadataVersion = 1

// MetadataRecord is a names-only record. It deliberately has no value, length,
// digest or equality field. Labels is independently owned. Line and LabeledStore
// preserve file parser ordering and scope semantics; Account is an opaque provider
// ID, empty for file records. Provider metadata comes from manifests, never Get.
type MetadataRecord struct {
	Key          string            `json:"key"`
	Labels       map[string]string `json:"labels"`
	Line         int               `json:"line,omitempty"`
	LabeledStore bool              `json:"labeled_store,omitempty"`
	Account      string            `json:"account,omitempty"`
}

// Metadata describes one store without fetching provider values. Reference is an
// explicit store reference; Backend is file, keychain or libsecret. Records retain
// source order and duplicates until the consuming interface applies selection.
type Metadata struct {
	Version   int              `json:"version"`
	Reference string           `json:"reference"`
	Backend   string           `json:"backend"`
	Records   []MetadataRecord `json:"records"`
}

// ParseMetadata shares Parse's grammar, warnings, duplicates and label semantics
// without copying or retaining value bytes. It borrows data only during the call:
// the caller still owns and must clear the input. Returned names and label maps
// are independent of data and of one another. Metadata cannot support legacy text
// show byte lengths; that compatibility path must continue using Parse.
func ParseMetadata(data []byte) ([]MetadataRecord, []Warning) {
	records, warnings := parse(data, false)
	if records == nil {
		return nil, warnings
	}
	result := make([]MetadataRecord, len(records))
	for i, record := range records {
		result[i] = MetadataRecord{Key: record.Key, Labels: record.Labels, Line: record.Line, LabeledStore: record.LabeledStore}
	}
	return result, warnings
}

// MutationKind identifies an exact-identity transaction operation.
type MutationKind string

const (
	// MutationPut inserts or replaces an exact key and canonical-label identity.
	MutationPut MutationKind = "put"
	// MutationDelete removes an exact key and canonical-label identity.
	MutationDelete MutationKind = "delete"
	// MutationRename changes Key to NewKey, preserving labels and existing bytes.
	MutationRename MutationKind = "rename"
)

// Mutation supplies one operation to a Transaction. Key and Labels identify an
// exact record, not a selector. NewKey is used only for rename; Value only for put.
// Value is borrowed for the synchronous Apply call, never retained or serialized.
// Its owner clears it after Apply, on success and failure. Implementations clear
// their own copies and all provider readback buffers. Do not log Mutation.
type Mutation struct {
	Kind   MutationKind
	Key    string
	Labels map[string]string
	NewKey string
	Value  []byte `json:"-"`
}

// Transaction is a single-target batch publisher configured with an explicit
// store reference by its implementation. Apply validates the whole batch, acquires
// the existing write lock, rechecks conflicts, prepares and verifies fresh provider
// accounts, persists names-only recovery intent before provider mutation, publishes
// once, then garbage-collects exact old accounts. Pre-publication failure preserves
// the previous store/manifest. A failure after publication may need manual recovery;
// it must not be reported as a rollback. No values are persisted as recovery data.
// Apply is synchronous, borrows mutations and never retains Value or Labels. It
// returns fixed names-only errors, never provider output. Implementations reject
// unsupported permission-dependent platforms before side effects. Consent is the
// CLI caller's prerequisite, not a bypass flag accepted by this interface.
type Transaction interface {
	Apply(mutations []Mutation) error
}

// OperatorAction is an allowlisted operator name, never arbitrary command text.
type OperatorAction string

const (
	ActionImport OperatorAction = "import"
	ActionExport OperatorAction = "export"
	ActionRotate OperatorAction = "rotate"
	ActionRename OperatorAction = "rename"
	ActionDelete OperatorAction = "delete"
)

// Valid reports whether the action is an M3 consent-gated operator.
func (action OperatorAction) Valid() bool {
	switch action {
	case ActionImport, ActionExport, ActionRotate, ActionRename, ActionDelete:
		return true
	}
	return false
}

// AuditOutcome classifies results without error text or provider diagnostics.
type AuditOutcome string

const (
	AuditSuccess  AuditOutcome = "success"
	AuditFailure  AuditOutcome = "failure"
	AuditDeclined AuditOutcome = "declined"
	AuditRecovery AuditOutcome = "recovery_required"
)

// AuditEvent is a versioned names-only operator event, never a value-use event.
// Source and Target are explicit names-only references; Keys and Labels contain
// validated names. No child argv, value, size, digest, error text or provider stderr
// belongs here. Time is the operator event time, not a provider retrieval timestamp.
type AuditEvent struct {
	Version int               `json:"version"`
	Time    time.Time         `json:"time"`
	Action  OperatorAction    `json:"action"`
	Source  string            `json:"source,omitempty"`
	Target  string            `json:"target"`
	Keys    []string          `json:"keys"`
	Labels  map[string]string `json:"labels"`
	Outcome AuditOutcome      `json:"outcome"`
}

// AuditSink accepts validated names-only events synchronously. Implementations
// must copy any borrowed Keys/Labels they retain and return only fixed errors.
// A nil sink means disabled; callers must never enable persistence implicitly.
type AuditSink interface {
	Record(event AuditEvent) error
}
