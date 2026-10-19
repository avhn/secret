package feature

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/search"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// DoctorArtifact identifies a public install artifact, never a store or a value
// digest. ExpectedSHA256 must come from a separately trusted, pinned manifest.
// An empty expected digest reports unavailable rather than inventing verification.
// Kinds are bash_guard, go_launcher, claude_config and codex_config.
type DoctorArtifact struct{ Kind, Path, ExpectedSHA256 string }

// DoctorOptions contains explicit metadata targets. No store discovery, provider
// lookup, host invocation, repair or deletion occurs. Artifacts and RipgrepConfig
// are the only public file contents read. Paths are inspected by stat only.
type DoctorOptions struct {
	Home, Cwd, SecretsDir, RipgrepConfig string
	Paths                                []string
	References                           []string
	Artifacts                            []DoctorArtifact
}

// DoctorCheck contains a fixed category/status/explanation and names-only target.
// A present config is not proof of active host protection or trusted execution.
type DoctorCheck struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// DoctorCandidate is a tracked recovery account requiring manual verification,
// not a proven orphan. No provider enumeration or value fetch is performed.
type DoctorCandidate struct {
	Reference string            `json:"reference"`
	Phase     string            `json:"phase"`
	Key       string            `json:"key"`
	Labels    map[string]string `json:"labels"`
	Account   string            `json:"account"`
}

type DoctorReport struct {
	Version    int               `json:"version"`
	Checks     []DoctorCheck     `json:"checks"`
	Candidates []DoctorCandidate `json:"candidates"`
}

// RunDoctor emits versioned metadata-only evidence. M4 launcher/config trust and
// host failure behavior are explicitly unavailable or unverified here. Backend
// availability means executable presence only, never an unlocked service probe.
func RunDoctor(options DoctorOptions) (DoctorReport, error) {
	return runDoctor(options, exec.LookPath)
}

func runDoctor(options DoctorOptions, lookPath func(string) (string, error)) (DoctorReport, error) {
	if len(options.Paths) > 128 || len(options.References) > 128 || len(options.Artifacts) > 4 {
		return DoctorReport{}, secure.ErrInvalidRequest
	}
	for _, path := range append(append([]string{}, options.Paths...), options.Home, options.Cwd, options.SecretsDir, options.RipgrepConfig) {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path || !validOperatorText(path)) {
			return DoctorReport{}, secure.ErrInvalidRequest
		}
	}
	for _, reference := range options.References {
		if !validOperatorReference(reference) {
			return DoctorReport{}, secure.ErrInvalidRequest
		}
	}
	seen := make(map[string]bool)
	for _, artifact := range options.Artifacts {
		if artifact.Kind != "bash_guard" && artifact.Kind != "go_launcher" && artifact.Kind != "claude_config" && artifact.Kind != "codex_config" {
			return DoctorReport{}, secure.ErrInvalidRequest
		}
		if seen[artifact.Kind] || !filepath.IsAbs(artifact.Path) || filepath.Clean(artifact.Path) != artifact.Path || !validOperatorText(artifact.Path) {
			return DoctorReport{}, secure.ErrInvalidRequest
		}
		seen[artifact.Kind] = true
		if artifact.ExpectedSHA256 != "" && (len(artifact.ExpectedSHA256) != 64 || strings.Trim(artifact.ExpectedSHA256, "0123456789abcdef") != "") {
			return DoctorReport{}, secure.ErrInvalidRequest
		}
	}
	result := DoctorReport{Version: store.MetadataVersion, Checks: make([]DoctorCheck, 0), Candidates: make([]DoctorCandidate, 0)}
	add := func(kind, target, status, detail string) {
		result.Checks = append(result.Checks, DoctorCheck{kind, target, status, detail})
	}
	if runtime.GOOS == "windows" {
		add("compatibility", "windows", "unsupported", "private operator persistence awaits the Windows permission gate")
	} else {
		add("compatibility", runtime.GOOS, "limited", "Go operators are staged; the installed Bash CLI and guard remain unchanged")
	}
	for _, path := range options.Paths {
		doctorPath(path, add)
	}
	if options.SecretsDir != "" {
		doctorPath(options.SecretsDir, add)
	}
	for _, kind := range []string{"bash_guard", "go_launcher", "claude_config", "codex_config"} {
		var selected *DoctorArtifact
		for i := range options.Artifacts {
			if options.Artifacts[i].Kind == kind {
				selected = &options.Artifacts[i]
				break
			}
		}
		if selected == nil {
			add("artifact", kind, "unavailable", "no explicit installed artifact supplied")
			add("checksum", kind, "unavailable", "no trusted pinned checksum supplied")
		} else {
			doctorArtifact(*selected, options, add)
		}
	}
	add("hook_activation", "claude", "unverified", "host activation and failure blocking require actual-host evidence")
	add("hook_activation", "codex", "unverified", "Bash guard retained; host hook failures are not proven to block")
	add("trust", "m4", "unavailable", "release provenance and verified launcher cutover are not installed by M3")
	if options.RipgrepConfig == "" {
		add("config_certification", "ripgrep", "unavailable", "no explicit ripgrep config supplied")
	} else if doctorAlias(options.RipgrepConfig) != "direct" {
		add("config_certification", options.RipgrepConfig, "unsafe", "config path is missing, aliased or inaccessible")
	} else {
		status, _ := search.Config(options.RipgrepConfig, options.Cwd, options.Home)
		switch status {
		case 0:
			add("config_certification", options.RipgrepConfig, "certified", "current static ripgrep exclusions certified; not a host protection claim")
		case 1:
			add("config_certification", options.RipgrepConfig, "partial", "required static ripgrep exclusions are incomplete")
		default:
			add("config_certification", options.RipgrepConfig, "unsafe", "ripgrep configuration cannot be certified")
		}
	}
	for _, kind := range []string{"libsecret", "keychain"} {
		tool := "secret-tool"
		supported := runtime.GOOS == "linux"
		if kind == "keychain" {
			tool, supported = "security", runtime.GOOS == "darwin"
		}
		if !supported {
			add("backend", kind, "unsupported", "provider is not supported on this platform")
			continue
		}
		if _, err := lookPath(tool); err != nil {
			add("backend", kind, "unavailable", "provider executable not found; no service or unlock probe performed")
		} else {
			add("backend", kind, "present", "provider executable found; no service or unlock probe performed")
		}
	}
	for _, reference := range options.References {
		if strings.HasPrefix(reference, "file:") {
			doctorPath(strings.TrimPrefix(reference, "file:"), add)
			continue
		}
		if options.SecretsDir == "" {
			add("recovery", reference, "unavailable", "explicit manifest directory required")
			continue
		}
		kind, name, _ := strings.Cut(reference, ":")
		path := filepath.Join(options.SecretsDir, name+".keys")
		doctorPath(path, add)
		if runtime.GOOS == "windows" {
			add("recovery", reference, "unsupported", "private recovery inspection awaits the Windows permission gate")
			continue
		}
		// Inspect ancestors before opening a names-only recovery record. Never
		// follow aliases into an unrequested manifest namespace.
		alias := doctorAlias(path + ".recovery")
		if alias == "missing" {
			add("recovery", reference, "none_tracked", "no recovery intent; historical orphan completeness is unknown")
			continue
		}
		if alias != "direct" {
			add("recovery", reference, "unsafe", "recovery path is aliased or inaccessible; verify manually")
			continue
		}
		intent, err := store.ReadRecovery(path, kind)
		if err != nil {
			add("recovery", reference, "invalid", "tracked recovery cannot be validated; verify manually")
			continue
		}
		add("recovery", reference, "manual_verification", "compare tracked accounts with the current manifest and provider before any manual removal; never blindly delete")
		for _, group := range []struct {
			phase   string
			records []store.ManifestRecord
		}{{"prepared", intent.Prepared}, {"obsolete", intent.Obsolete}} {
			for _, record := range group.records {
				result.Candidates = append(result.Candidates, DoctorCandidate{Reference: reference, Phase: group.phase, Key: record.Key, Labels: copyMetadataLabels(record.Labels), Account: record.Account})
			}
		}
	}
	return result, nil
}

// doctorAlias performs metadata-only ancestor inspection without resolving or
// following a symlink. Missing is not proof that a historical orphan is absent.
func doctorAlias(path string) string {
	volume := filepath.VolumeName(path) + string(filepath.Separator)
	current := volume
	for _, part := range strings.Split(strings.TrimPrefix(path, volume), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return "missing"
		}
		if err != nil {
			return "inaccessible"
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "alias"
		}
	}
	return "direct"
}

func doctorPath(path string, add func(string, string, string, string)) {
	alias := doctorAlias(path)
	add("alias", path, alias, "metadata-only ancestor inspection; concurrent changes remain possible")
	if alias != "direct" {
		add("mode", path, "unavailable", "mode not certified for missing, aliased or inaccessible paths")
		return
	}
	info, err := os.Lstat(path)
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		add("mode", path, "unsafe", "path is not a regular file or directory")
		return
	}
	if runtime.GOOS == "windows" {
		add("mode", path, "unsupported", "Unix modes do not certify Windows private ACLs")
		return
	}
	status := "private"
	if info.Mode().Perm()&0077 != 0 {
		status = "insecure"
	}
	add("mode", path, status, fmt.Sprintf("mode %04o; owner identity and host trust are not certified", info.Mode().Perm()))
}

func doctorArtifact(artifact DoctorArtifact, options DoctorOptions, add func(string, string, string, string)) {
	alias := doctorAlias(artifact.Path)
	if alias == "missing" {
		add("artifact", artifact.Kind, "not_installed", "explicit artifact path does not exist")
		add("checksum", artifact.Kind, "unavailable", "artifact is not installed")
		return
	}
	if alias != "direct" || paths.Protected(artifact.Path, options.Cwd, "", options.Home) {
		add("artifact", artifact.Kind, "unsafe", "artifact is aliased, inaccessible or a protected content path")
		add("checksum", artifact.Kind, "unavailable", "unsafe artifact is not opened")
		return
	}
	info, err := os.Lstat(artifact.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		add("artifact", artifact.Kind, "unsafe", "artifact must be regular and not group or world writable")
		add("checksum", artifact.Kind, "unavailable", "unsafe artifact is not opened")
		return
	}
	add("artifact", artifact.Kind, "present", "presence and mode are not activation or provenance verification")
	if artifact.ExpectedSHA256 == "" {
		add("checksum", artifact.Kind, "unavailable", "no trusted pinned checksum supplied")
		return
	}
	root, err := openOperatorParent(artifact.Path)
	if err != nil {
		add("checksum", artifact.Kind, "unavailable", "artifact could not be read safely")
		return
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(artifact.Path))
	if err != nil {
		add("checksum", artifact.Kind, "unavailable", "artifact could not be read safely")
		return
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() > 128<<20 {
		add("checksum", artifact.Kind, "unavailable", "artifact changed or exceeded the checksum bound")
		return
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, (128<<20)+1))
	if err != nil || n > 128<<20 {
		add("checksum", artifact.Kind, "unavailable", "artifact changed or exceeded the checksum bound")
		return
	}
	if hex.EncodeToString(hash.Sum(nil)) != artifact.ExpectedSHA256 {
		add("checksum", artifact.Kind, "mismatch", "artifact does not match the supplied pinned checksum")
		return
	}
	add("checksum", artifact.Kind, "matched", "matches supplied digest only; provenance and host trust require separate verification")
}
