// Package feature implements opt-in workflows and names-only interfaces.
package feature

import (
	"errors"
	"os"
	"strings"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// Inventory is the versioned names-only document shared by list, show and MCP.
// Stores and records retain input order, including unselected duplicate records.
type Inventory struct {
	Version int              `json:"version"`
	Stores  []InventoryStore `json:"stores"`
}

// InventoryStore describes a store without consulting its value provider.
type InventoryStore struct {
	Reference string            `json:"reference"`
	Backend   string            `json:"backend"`
	Records   []InventoryRecord `json:"records"`
}

// InventoryRecord has no value, byte length, digest or equality information.
// Present is false for a known key with no qualifying record under selection.
type InventoryRecord struct {
	Key     string            `json:"key"`
	Labels  map[string]string `json:"labels"`
	Present bool              `json:"present"`
	Account string            `json:"account,omitempty"`
}

// MetadataSelection mirrors store.Select's subset, specificity, duplicate and
// ambiguity rules without constructing value-bearing records. Keys includes
// unmatched names in first-appearance order. Returned labels are independently owned.
type MetadataSelection struct {
	Keys    []string
	Matched map[string]store.MetadataRecord
}

// MetadataScope identifies one side of a diff and its explicit selectors.
type MetadataScope struct {
	Reference string            `json:"reference"`
	Backend   string            `json:"backend"`
	Selectors map[string]string `json:"selectors"`
}

// MetadataPresence reports only selected labels and presence, never account
// changes or source line changes that could be mistaken for value comparisons.
type MetadataPresence struct {
	Present bool              `json:"present"`
	Labels  map[string]string `json:"labels"`
}

// MetadataDifference reports a key on both sides, even when neither side selects it.
type MetadataDifference struct {
	Key   string           `json:"key"`
	Left  MetadataPresence `json:"left"`
	Right MetadataPresence `json:"right"`
}

// MetadataDiff deliberately has no value equality, hash, size or changed field.
// Backend information is reported once per scope. Records use left-first key order.
type MetadataDiff struct {
	Version int                  `json:"version"`
	Left    MetadataScope        `json:"left"`
	Right   MetadataScope        `json:"right"`
	Records []MetadataDifference `json:"records"`
}

var (
	ErrMetadataRead      = errors.New("cannot read store metadata")
	ErrMetadata          = errors.New("invalid store metadata")
	ErrMetadataAmbiguous = errors.New("ambiguous metadata selection")
)

// ReadMetadata accepts a resolved file path, file:PATH, keychain:NAME,
// libsecret:NAME, pass:NAME or wincred:NAME. Directory is the explicit manifest directory, never discovered
// from ambient provider configuration. Provider records come only from manifests;
// these reads never invoke a value provider. File bytes are cleared after parsing.
// Parser warnings are names-only and omitted here; legacy text show remains separate.
func ReadMetadata(reference, directory string) (store.Metadata, error) {
	if strings.HasPrefix(reference, "onepassword:") {
		if !backend.OnePasswordEnabled() {
			return store.Metadata{}, secure.ErrUnsupported
		}
		return readOnePasswordMetadata(reference, directory)
	}
	result := store.Metadata{Version: store.MetadataVersion, Reference: reference, Backend: "file", Records: make([]store.MetadataRecord, 0)}
	if store.ProviderReference(reference) {
		if _, err := (store.Locator{}).Resolve(reference); err != nil {
			return store.Metadata{}, ErrMetadata
		}
		backend, _, _ := strings.Cut(reference, ":")
		if directory == "" {
			return store.Metadata{}, ErrMetadata
		}
		path, err := store.ManifestPath(directory, reference)
		if err != nil {
			return store.Metadata{}, ErrMetadata
		}
		records, err := store.ReadManifest(path, backend)
		if err != nil {
			return store.Metadata{}, ErrMetadataRead
		}
		result.Backend = backend
		for _, record := range records {
			result.Records = append(result.Records, store.MetadataRecord{Key: record.Key, Labels: copyMetadataLabels(record.Labels), Account: record.Account})
		}
		return result, nil
	}
	if strings.HasPrefix(reference, "age:") {
		path, err := store.AgePath(directory, reference)
		if err != nil {
			return store.Metadata{}, ErrMetadata
		}
		envelope, err := store.ReadAgeEnvelope(path)
		if err != nil {
			return store.Metadata{}, ErrMetadataRead
		}
		result.Backend = "age"
		for _, record := range envelope.Records {
			result.Records = append(result.Records, store.MetadataRecord{Key: record.Key, Labels: copyMetadataLabels(record.Labels), Account: record.Account})
		}
		return result, nil
	}
	path := strings.TrimPrefix(reference, "file:")
	if path == "" {
		return store.Metadata{}, ErrMetadata
	}
	// Match the legacy file reader's regular-file check, but never retain values.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return store.Metadata{}, ErrMetadataRead
	}
	data, err := store.ReadFile(path)
	defer secure.Clear(data)
	if err != nil {
		return store.Metadata{}, ErrMetadataRead
	}
	if store.IsAgeStoreBytes(data) {
		return store.Metadata{}, ErrMetadata
	}
	records, _ := store.ParseMetadata(data)
	result.Records = append(result.Records, records...)
	return result, nil
}

// LoadInventory reads explicit resolved references and builds the common JSON
// document. Discovery and CLI name resolution remain the caller's responsibility.
func LoadInventory(references []string, directory string, selectors store.Selectors) (Inventory, error) {
	if err := validateMetadataSelectors(selectors); err != nil {
		return Inventory{}, err
	}
	metadata := make([]store.Metadata, 0, len(references))
	for _, reference := range references {
		item, err := ReadMetadata(reference, directory)
		if err != nil {
			return Inventory{}, err
		}
		metadata = append(metadata, item)
	}
	return BuildInventory(metadata, selectors)
}

// BuildInventory copies metadata into the stable names-only schema. With no
// selectors it retains every source record, including duplicates. With selectors
// it emits one entry per known key, with explicit absence for unmatched names.
// Legacy text show must continue using its value-aware compatibility path.
func BuildInventory(metadata []store.Metadata, selectors store.Selectors) (Inventory, error) {
	if err := validateMetadataSelectors(selectors); err != nil {
		return Inventory{}, err
	}
	result := Inventory{Version: store.MetadataVersion, Stores: make([]InventoryStore, 0, len(metadata))}
	for _, item := range metadata {
		if err := validateMetadata(item); err != nil {
			return Inventory{}, err
		}
		output := InventoryStore{Reference: item.Reference, Backend: item.Backend, Records: make([]InventoryRecord, 0, len(item.Records))}
		if len(selectors) == 0 {
			for _, record := range item.Records {
				output.Records = append(output.Records, inventoryRecord(record, true))
			}
		} else {
			selection, err := SelectMetadata(item, selectors)
			if err != nil {
				return Inventory{}, err
			}
			for _, key := range selection.Keys {
				record, present := selection.Matched[key]
				record.Key = key
				output.Records = append(output.Records, inventoryRecord(record, present))
			}
		}
		result.Stores = append(result.Stores, output)
	}
	return result, nil
}

// SelectMetadata applies explicit AND selectors. An empty selector selects only
// unlabeled records; equal-identity duplicates are last-wins, distinct tied label
// sets are ambiguous. A later more-specific record resolves an earlier tie.
func SelectMetadata(metadata store.Metadata, selectors store.Selectors) (MetadataSelection, error) {
	if err := validateMetadata(metadata); err != nil {
		return MetadataSelection{}, err
	}
	if err := validateMetadataSelectors(selectors); err != nil {
		return MetadataSelection{}, err
	}
	result := MetadataSelection{Keys: make([]string, 0), Matched: make(map[string]store.MetadataRecord)}
	seen, ambiguous := make(map[string]bool), make(map[string]bool)
	for _, record := range metadata.Records {
		if !seen[record.Key] {
			seen[record.Key] = true
			result.Keys = append(result.Keys, record.Key)
		}
		qualifies := true
		for name, value := range record.Labels {
			if selectors[name] != value {
				qualifies = false
				break
			}
		}
		if !qualifies {
			continue
		}
		prior, exists := result.Matched[record.Key]
		if !exists || len(prior.Labels) < len(record.Labels) {
			result.Matched[record.Key] = record
			delete(ambiguous, record.Key)
		} else if len(prior.Labels) == len(record.Labels) {
			if store.CanonicalLabels(prior.Labels) != store.CanonicalLabels(record.Labels) {
				ambiguous[record.Key] = true
			}
			result.Matched[record.Key] = record
		}
	}
	for _, key := range result.Keys {
		if ambiguous[key] {
			return MetadataSelection{}, ErrMetadataAmbiguous
		}
		if record, ok := result.Matched[key]; ok {
			record.Labels = copyMetadataLabels(record.Labels)
			result.Matched[key] = record
		}
	}
	return result, nil
}

// DiffMetadata compares names and selected presence only. It can compare two
// selections in one store or two different stores, without any value fetch.
func DiffMetadata(left, right store.Metadata, leftSelectors, rightSelectors store.Selectors) (MetadataDiff, error) {
	l, err := SelectMetadata(left, leftSelectors)
	if err != nil {
		return MetadataDiff{}, err
	}
	r, err := SelectMetadata(right, rightSelectors)
	if err != nil {
		return MetadataDiff{}, err
	}
	result := MetadataDiff{
		Version: store.MetadataVersion,
		Left:    MetadataScope{Reference: left.Reference, Backend: left.Backend, Selectors: copyMetadataLabels(leftSelectors)},
		Right:   MetadataScope{Reference: right.Reference, Backend: right.Backend, Selectors: copyMetadataLabels(rightSelectors)},
		Records: make([]MetadataDifference, 0),
	}
	seen := make(map[string]bool)
	for _, keys := range [][]string{l.Keys, r.Keys} {
		for _, key := range keys {
			if seen[key] {
				continue
			}
			seen[key] = true
			lr, lp := l.Matched[key]
			rr, rp := r.Matched[key]
			result.Records = append(result.Records, MetadataDifference{
				Key:   key,
				Left:  MetadataPresence{Present: lp, Labels: copyMetadataLabels(lr.Labels)},
				Right: MetadataPresence{Present: rp, Labels: copyMetadataLabels(rr.Labels)},
			})
		}
	}
	return result, nil
}

func inventoryRecord(record store.MetadataRecord, present bool) InventoryRecord {
	return InventoryRecord{Key: record.Key, Labels: copyMetadataLabels(record.Labels), Present: present, Account: record.Account}
}

func copyMetadataLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for name, value := range labels {
		result[name] = value
	}
	return result
}

func validateMetadataSelectors(selectors store.Selectors) error {
	if store.ValidateIdentity("KEY", selectors) != nil {
		return store.ErrInvalidSelector
	}
	return nil
}

func validateMetadata(metadata store.Metadata) error {
	if metadata.Version != store.MetadataVersion || (metadata.Backend != "file" && metadata.Backend != "onepassword" && metadata.Backend != "age" && !store.ProviderReference(metadata.Backend+":name")) {
		return ErrMetadata
	}
	if metadata.Reference == "" {
		return ErrMetadata
	}
	if metadata.Backend != "file" {
		backend, _, ok := strings.Cut(metadata.Reference, ":")
		if !ok || backend != metadata.Backend {
			return ErrMetadata
		}
		if _, err := (store.Locator{}).Resolve(metadata.Reference); err != nil {
			return ErrMetadata
		}
	}
	for _, record := range metadata.Records {
		if store.ValidateIdentity(record.Key, record.Labels) != nil {
			return ErrMetadata
		}
		if metadata.Backend == "file" {
			if record.Account != "" {
				return ErrMetadata
			}
		} else if len(record.Account) != 32 || strings.Trim(record.Account, "0123456789abcdef") != "" {
			return ErrMetadata
		}
	}
	return nil
}
