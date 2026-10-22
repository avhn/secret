package feature

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func doctorTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func doctorGoldenReport(t *testing.T) DoctorReport {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode, alias and recovery golden")
	}
	root := doctorTestRoot(t)
	directory := filepath.Join(root, "stores")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"private.env", "insecure.env"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("TOKEN=synthetic-value-sentinel\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "insecure.env"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "private.env"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(filepath.Join(root, "guard"), artifact, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	writeOperatorManifest(t, directory, "libsecret:tracked", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
	intent := store.RecoveryIntent{Version: 1, Backend: "libsecret", Prepared: []store.ManifestRecord{{Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: operatorAccountB}}, Obsolete: []store.ManifestRecord{{Key: "TOKEN", Labels: map[string]string{}, Account: operatorAccountA}}}
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tracked.keys.recovery"), data, 0600); err != nil {
		t.Fatal(err)
	}
	options := DoctorOptions{Home: root, Cwd: root, SecretsDir: directory, Paths: []string{filepath.Join(root, "private.env"), filepath.Join(root, "insecure.env"), filepath.Join(root, "alias")}, References: []string{"libsecret:tracked"}, Artifacts: []DoctorArtifact{{Kind: "bash_guard", Path: filepath.Join(root, "guard"), ExpectedSHA256: hex.EncodeToString(digest[:])}, {Kind: "go_launcher", Path: filepath.Join(root, "missing-launcher")}}}
	report, err := runDoctor(options, func(string) (string, error) { return "", errors.New("synthetic-provider-stderr-sentinel") })
	if err != nil {
		t.Fatal(err)
	}
	for i := range report.Checks {
		check := &report.Checks[i]
		check.Target = strings.ReplaceAll(check.Target, root, "<root>")
		if check.Kind == "compatibility" {
			check.Target = "<platform>"
		}
		if check.Kind == "backend" {
			check.Status, check.Detail = "<platform>", "<platform>"
		}
	}
	return report
}

func TestDoctorGolden(t *testing.T) {
	report := doctorGoldenReport(t)
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		t.Fatal(err)
	}
	data := output.Bytes()
	golden, err := os.ReadFile("../../testdata/feature/doctor.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, golden) {
		t.Fatalf("doctor golden mismatch; actual names-only report:\n%s", data)
	}
	if bytes.Contains(data, []byte("synthetic-value-sentinel")) || bytes.Contains(data, []byte("synthetic-provider-stderr-sentinel")) {
		t.Fatal("doctor leaked value/provider output")
	}
}

func TestDoctorMetadataOnlyAndNoInventedVerification(t *testing.T) {
	root := doctorTestRoot(t)
	path := filepath.Join(root, "unreadable.env")
	if err := os.WriteFile(path, []byte("TOKEN=synthetic-value-sentinel\n"), 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	calls := 0
	report, err := runDoctor(DoctorOptions{Paths: []string{path}}, func(name string) (string, error) { calls++; return filepath.Join(root, name), nil })
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if calls != 0 {
			t.Fatal("Windows probed unsupported providers")
		}
	} else if calls != 1 {
		t.Fatal("availability must perform only one supported executable presence check")
	}
	for _, check := range report.Checks {
		if check.Kind == "hook_activation" && check.Status != "unverified" {
			t.Fatal("doctor invented host activation")
		}
		if check.Kind == "checksum" && check.Status != "unavailable" {
			t.Fatal("doctor invented checksum verification")
		}
		if check.Kind == "trust" && (check.Status != "unverified" || !strings.Contains(check.Detail, "do not prove provenance or activation")) {
			t.Fatal("doctor invented M4 trust or omitted the evidence boundary")
		}
	}
	data, _ := json.Marshal(report)
	if bytes.Contains(data, []byte("synthetic-value-sentinel")) {
		t.Fatal("doctor read values")
	}
}

func TestDoctorArtifactChecksumAndAliases(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix artifact modes and aliases")
	}
	root := doctorTestRoot(t)
	path := filepath.Join(root, "public-binary")
	if err := os.WriteFile(path, []byte("synthetic public artifact"), 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(root, ".env")
	if err := os.WriteFile(protected, []byte("TOKEN=synthetic-value-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic public artifact"))
	cache := filepath.Join(root, ".cache", "secret", "v0.2.2")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, path, digest, want string }{
		{"matching digest", path, hex.EncodeToString(digest[:]), "matched"},
		{"missing digest", path, "", "unavailable"},
		{"mismatch", path, strings.Repeat("0", 64), "mismatch"},
		{"alias", alias, strings.Repeat("0", 64), "unavailable"},
		{"protected", protected, strings.Repeat("0", 64), "unavailable"},
		{"not installed", filepath.Join(root, "missing"), strings.Repeat("0", 64), "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := runDoctor(DoctorOptions{Home: root, Cwd: root, Paths: []string{cache}, Artifacts: []DoctorArtifact{{Kind: "go_launcher", Path: test.path, ExpectedSHA256: test.digest}}}, func(string) (string, error) { return "", os.ErrNotExist })
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, check := range report.Checks {
				if (check.Kind == "trust" || check.Kind == "hook_activation") && check.Status != "unverified" {
					t.Fatal("artifact digest or cache presence invented provenance or activation")
				}
				if check.Kind == "checksum" && check.Target == "go_launcher" {
					found = true
					if check.Status != test.want {
						t.Fatalf("checksum status %s, want %s", check.Status, test.want)
					}
				}
			}
			if !found {
				t.Fatal("checksum evidence missing")
			}
		})
	}
}

func TestDoctorRecoveryGuidanceNotOrphanProof(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix recovery metadata")
	}
	root := doctorTestRoot(t)
	for _, mode := range []string{"missing", "invalid", "insecure", "alias", "ancestor alias"} {
		t.Run(mode, func(t *testing.T) {
			directory := filepath.Join(root, strings.ReplaceAll(mode, " ", "-"))
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "target.keys.recovery")
			switch mode {
			case "invalid":
				if err := os.WriteFile(path, []byte("synthetic invalid intent"), 0600); err != nil {
					t.Fatal(err)
				}
			case "insecure":
				if err := os.WriteFile(path, []byte("synthetic invalid intent"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.Symlink(filepath.Join(root, "nonexistent"), path); err != nil {
					t.Fatal(err)
				}
			case "ancestor alias":
				alias := directory + "-alias"
				if err := os.Symlink(directory, alias); err != nil {
					t.Fatal(err)
				}
				directory = alias
			}
			report, err := runDoctor(DoctorOptions{SecretsDir: directory, References: []string{"libsecret:target"}}, func(string) (string, error) { return "", os.ErrNotExist })
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Candidates) != 0 {
				t.Fatal("doctor invented orphan accounts")
			}
			want := "invalid"
			if mode == "missing" {
				want = "none_tracked"
			}
			if mode == "alias" || mode == "ancestor alias" {
				want = "unsafe"
			}
			found := false
			for _, check := range report.Checks {
				if check.Kind == "recovery" {
					found = true
					if check.Status != want {
						t.Fatalf("recovery status %s, want %s", check.Status, want)
					}
				}
			}
			if !found {
				t.Fatal("recovery evidence missing")
			}
		})
	}
}

func TestDoctorConfigCertificationAndInvalidPreflight(t *testing.T) {
	root := doctorTestRoot(t)
	config := filepath.Join(root, "ripgreprc")
	if err := os.WriteFile(config, []byte("--hidden\n--iglob=!.env\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := runDoctor(DoctorOptions{Home: root, Cwd: root, RipgrepConfig: config}, func(string) (string, error) { return "", os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range report.Checks {
		if check.Kind == "config_certification" && check.Status != "partial" {
			t.Fatalf("partial config certified as %s", check.Status)
		}
	}
	for _, options := range []DoctorOptions{
		{References: []string{"bare"}}, {Paths: []string{"relative"}},
		{Artifacts: []DoctorArtifact{{Kind: "arbitrary", Path: config}}},
		{Artifacts: []DoctorArtifact{{Kind: "go_launcher", Path: config, ExpectedSHA256: "bad"}}},
		{Artifacts: []DoctorArtifact{{Kind: "go_launcher", Path: config}, {Kind: "go_launcher", Path: config}}},
	} {
		if _, err := runDoctor(options, func(string) (string, error) {
			t.Fatal("invalid doctor request probed provider availability")
			return "", nil
		}); err != secure.ErrInvalidRequest {
			t.Fatal("doctor accepted invalid metadata target")
		}
	}
}
