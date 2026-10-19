package feature

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const (
	MaxAuditEventBytes = 16 << 10
	maxAuditFileBytes  = 16 << 20
	maxAuditFiles      = 16
	maxAuditResults    = 10000
)

// AuditConfig is explicit opt-in configuration. Directory must be absolute, with
// existing non-symlinked ancestors. Only the final 0700 directory may be created.
// MaxBytes defaults to 1 MiB per file, MaxFiles to four files including the active
// file. Limits are capped at 16 MiB and 16 files. No ambient settings enable audit.
type AuditConfig struct {
	Enabled   bool
	Directory string
	MaxBytes  int
	MaxFiles  int
}

// AuditLog implements store.AuditSink. Disabled and nil logs are no-ops. Enabled
// persistence is unsupported on Windows until private ACL support exists.
// A separate private lock serializes processes; stale locks are never stolen.
type AuditLog struct {
	config AuditConfig
	mu     sync.Mutex
}

var _ store.AuditSink = (*AuditLog)(nil)

// AuditQuery filters operator metadata only. Since and Until are inclusive.
// Limit defaults to 1000, capped at 10000; results retain recording order and
// contain the most recent matching events when the limit is reached.
type AuditQuery struct {
	Action  store.OperatorAction
	Target  string
	Key     string
	Outcome store.AuditOutcome
	Since   time.Time
	Until   time.Time
	Limit   int
}

// AuditRecords is the versioned names-only query document.
type AuditRecords struct {
	Version int                `json:"version"`
	Events  []store.AuditEvent `json:"events"`
}

// OpenAudit validates explicit configuration. Disabled logs perform no filesystem
// access, even if the other configuration fields are invalid.
func OpenAudit(config AuditConfig) (*AuditLog, error) {
	log := &AuditLog{config: config}
	if !config.Enabled {
		return log, nil
	}
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = 1 << 20
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 4
	}
	if !absoluteMetadataPath(config.Directory) || config.Directory == string(filepath.Separator) || !safeMetadataText(config.Directory, 4096, false) || config.MaxBytes < 256 || config.MaxBytes > maxAuditFileBytes || config.MaxFiles < 1 || config.MaxFiles > maxAuditFiles {
		return nil, secure.ErrAudit
	}
	log.config = config
	root, err := openAuditDirectory(config.Directory, true)
	if err != nil {
		return nil, secure.ErrAudit
	}
	defer root.Close()
	if err := log.validateFiles(root); err != nil {
		return nil, err
	}
	return log, nil
}

// Record validates and serializes only AuditEvent's allowlisted metadata. It never
// accepts free-form errors, commands or argv. Events larger than the per-event or
// per-file ceiling fail without publication. Each append is an atomic replacement
// of the active file; rotation never grows beyond MaxFiles and MaxBytes per file.
func (log *AuditLog) Record(event store.AuditEvent) error {
	if log == nil || !log.config.Enabled {
		return nil
	}
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !validAuditEvent(event) {
		return secure.ErrAudit
	}
	if event.Keys == nil {
		event.Keys = []string{}
	}
	if event.Labels == nil {
		event.Labels = map[string]string{}
	}
	data, err := json.Marshal(event)
	if err != nil || len(data)+1 > MaxAuditEventBytes || len(data)+1 > log.config.MaxBytes {
		return secure.ErrAudit
	}
	data = append(data, '\n')
	return log.withLock(func(root *os.Root) error {
		if err := log.validateFiles(root); err != nil {
			return err
		}
		previous, _, err := readAuditFile(root, auditName(0), log.config.MaxBytes)
		if err != nil {
			return err
		}
		if len(previous)+len(data) > log.config.MaxBytes {
			if err := log.rotate(root); err != nil {
				return err
			}
			previous = nil
		}
		return replaceAuditFile(root, append(previous, data...))
	})
}

// Query reads only bounded, validated audit events. Unknown fields, malformed
// events, insecure files and partial records cause a fixed error, never raw data.
func (log *AuditLog) Query(query AuditQuery) (AuditRecords, error) {
	result := AuditRecords{Version: store.MetadataVersion, Events: make([]store.AuditEvent, 0)}
	if !validAuditQuery(query) {
		return AuditRecords{}, secure.ErrAudit
	}
	if log == nil || !log.config.Enabled {
		return result, nil
	}
	if runtime.GOOS == "windows" {
		return AuditRecords{}, secure.ErrUnsupported
	}
	if query.Limit == 0 {
		query.Limit = 1000
	}
	oldest := 0
	err := log.withLock(func(root *os.Root) error {
		if err := log.validateFiles(root); err != nil {
			return err
		}
		for index := log.config.MaxFiles - 1; index >= 0; index-- {
			data, _, err := readAuditFile(root, auditName(index), log.config.MaxBytes)
			if err != nil {
				return err
			}
			for len(data) != 0 {
				line, rest, ok := bytes.Cut(data, []byte{'\n'})
				if !ok || len(line)+1 > MaxAuditEventBytes {
					return secure.ErrAudit
				}
				var event store.AuditEvent
				if decodeNamesJSON(line, &event) != nil || !validAuditEvent(event) {
					return secure.ErrAudit
				}
				if auditMatches(event, query) {
					if len(result.Events) < query.Limit {
						result.Events = append(result.Events, event)
					} else {
						result.Events[oldest] = event
						oldest = (oldest + 1) % query.Limit
					}
				}
				data = rest
			}
		}
		return nil
	})
	if err != nil {
		return AuditRecords{}, secure.ErrAudit
	}
	if oldest != 0 {
		ordered := append([]store.AuditEvent(nil), result.Events[oldest:]...)
		result.Events = append(ordered, result.Events[:oldest]...)
	}
	return result, nil
}

func validAuditOutcome(outcome store.AuditOutcome) bool {
	switch outcome {
	case store.AuditSuccess, store.AuditFailure, store.AuditDeclined, store.AuditRecovery:
		return true
	}
	return false
}

func validAuditEvent(event store.AuditEvent) bool {
	if event.Version != store.MetadataVersion || event.Time.IsZero() || !event.Action.Valid() || !validAuditOutcome(event.Outcome) || !explicitMetadataReference(event.Target) || len(event.Keys) == 0 || len(event.Keys) > 1024 || len(event.Labels) > 128 || store.ValidateIdentity("KEY", event.Labels) != nil {
		return false
	}
	if event.Source != "" && !explicitMetadataReference(event.Source) {
		if event.Action != store.ActionImport || !validAuditImportSource(event.Source) {
			return false
		}
	}
	for _, key := range event.Keys {
		if len(key) > 256 || store.ValidateIdentity(key, nil) != nil {
			return false
		}
	}
	return true
}

func validAuditImportSource(source string) bool {
	if !safeMetadataText(source, 4096, false) {
		return false
	}
	kind, name, _ := strings.Cut(source, ":")
	if kind == "dotenv" {
		return absoluteMetadataPath(name)
	}
	return (kind == "op" || kind == "bw") && name != "" && len(name) <= 256 && strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") == "" && name != "." && name != ".."
}

func validAuditQuery(query AuditQuery) bool {
	return (query.Action == "" || query.Action.Valid()) && (query.Target == "" || explicitMetadataReference(query.Target)) && (query.Key == "" || store.ValidateIdentity(query.Key, nil) == nil) && (query.Outcome == "" || validAuditOutcome(query.Outcome)) && query.Limit >= 0 && query.Limit <= maxAuditResults && (query.Since.IsZero() || query.Until.IsZero() || !query.Since.After(query.Until))
}

func auditMatches(event store.AuditEvent, query AuditQuery) bool {
	if (query.Action != "" && query.Action != event.Action) || (query.Target != "" && query.Target != event.Target) || (query.Outcome != "" && query.Outcome != event.Outcome) || (!query.Since.IsZero() && event.Time.Before(query.Since)) || (!query.Until.IsZero() && event.Time.After(query.Until)) {
		return false
	}
	if query.Key != "" {
		for _, key := range event.Keys {
			if key == query.Key {
				return true
			}
		}
		return false
	}
	return true
}

func auditName(index int) string {
	if index == 0 {
		return "audit.jsonl"
	}
	return "audit." + strconv.Itoa(index) + ".jsonl"
}

// openAuditDirectory walks anchored components without accepting ancestor aliases.
// Parents may have ordinary home-directory modes; only the audit leaf is private.
func openAuditDirectory(path string, create bool) (*os.Root, error) {
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, secure.ErrAudit
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) > 256 {
		root.Close()
		return nil, secure.ErrAudit
	}
	for index, name := range parts {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) && create && index == len(parts)-1 {
			err = root.Mkdir(name, 0700)
			if err == nil || os.IsExist(err) {
				info, err = root.Lstat(name)
			}
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (index == len(parts)-1 && info.Mode().Perm() != 0700) {
			root.Close()
			return nil, secure.ErrAudit
		}
		next, err := root.OpenRoot(name)
		if err != nil {
			root.Close()
			return nil, secure.ErrAudit
		}
		opened, err := next.Stat(".")
		current, statErr := root.Lstat(name)
		root.Close()
		if err != nil || statErr != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, opened) || !os.SameFile(info, current) {
			next.Close()
			return nil, secure.ErrAudit
		}
		root = next
	}
	return root, nil
}

func (log *AuditLog) withLock(work func(*os.Root) error) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	root, err := openAuditDirectory(log.config.Directory, false)
	if err != nil {
		return secure.ErrAudit
	}
	defer root.Close()
	const lock = ".audit-lock"
	if root.Mkdir(lock, 0700) != nil {
		return secure.ErrAudit
	}
	info, err := root.Lstat(lock)
	if err != nil {
		return secure.ErrAudit
	}
	defer func() {
		if current, err := root.Lstat(lock); err == nil && os.SameFile(info, current) {
			_ = root.Remove(lock)
		}
	}()
	return work(root)
}

func readAuditFile(root *os.Root, name string, limit int) ([]byte, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > int64(limit) {
		return nil, nil, secure.ErrAudit
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, secure.ErrAudit
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 {
		return nil, nil, secure.ErrAudit
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	current, statErr := root.Lstat(name)
	if err != nil || len(data) > limit || statErr != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
		return nil, nil, secure.ErrAudit
	}
	return data, info, nil
}

func (log *AuditLog) validateFiles(root *os.Root) error {
	// A smaller configuration must not silently leave older managed rotations
	// outside its retention cap. Refuse until the owner explicitly removes them.
	for index := log.config.MaxFiles; index < maxAuditFiles; index++ {
		if _, err := root.Lstat(auditName(index)); !os.IsNotExist(err) {
			return secure.ErrAudit
		}
	}
	for index := 0; index < log.config.MaxFiles; index++ {
		data, _, err := readAuditFile(root, auditName(index), log.config.MaxBytes)
		if err != nil {
			return err
		}
		for len(data) != 0 {
			line, rest, ok := bytes.Cut(data, []byte{'\n'})
			var event store.AuditEvent
			if !ok || len(line)+1 > MaxAuditEventBytes || decodeNamesJSON(line, &event) != nil || !validAuditEvent(event) {
				return secure.ErrAudit
			}
			data = rest
		}
	}
	return nil
}

func (log *AuditLog) rotate(root *os.Root) error {
	if err := root.Remove(auditName(log.config.MaxFiles - 1)); err != nil && !os.IsNotExist(err) {
		return secure.ErrAudit
	}
	for index := log.config.MaxFiles - 2; index >= 0; index-- {
		if err := root.Rename(auditName(index), auditName(index+1)); err != nil && !os.IsNotExist(err) {
			return secure.ErrAudit
		}
	}
	return nil
}

func replaceAuditFile(root *os.Root, data []byte) error {
	name := ".audit-" + rand.Text()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return secure.ErrAudit
	}
	defer root.Remove(name)
	if file.Chmod(0600) != nil {
		file.Close()
		return secure.ErrAudit
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	info, statErr := file.Stat()
	closeErr := file.Close()
	current, currentErr := root.Lstat(name)
	if writeErr != nil || syncErr != nil || closeErr != nil || statErr != nil || currentErr != nil || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 || !os.SameFile(info, current) {
		return secure.ErrAudit
	}
	if _, _, err := readAuditFile(root, auditName(0), maxAuditFileBytes); err != nil {
		return err
	}
	if root.Rename(name, auditName(0)) != nil {
		return secure.ErrAudit
	}
	parent, err := root.Open(".")
	if err != nil {
		return secure.ErrAudit
	}
	defer parent.Close()
	if parent.Sync() != nil {
		return secure.ErrAudit
	}
	return nil
}
