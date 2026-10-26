package ps

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOracleRunnerRoundTrip(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := oracleRunner{executable: executable, script: "unused", directory: t.TempDir(), environment: []string{"SECRET_PS_FAULT_HELPER=valid"}, prefix: []string{"-test.run=^TestOracleFaultHelper$", "--"}, timeout: 15 * time.Second, outputLimit: oracleOutputLimit}
	// A fabricated subprocess tests capture/decoding/comparison wiring only.
	// It cannot establish anything about the actual PowerShell grammar.
	if err := compareOracle(runner, "Write-Output literal"); err != nil {
		t.Fatal(err)
	}
}

func TestOracleConfigurationGate(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, oracle, required, want string
		fail                         bool
	}{
		{"optional missing", "", "", "native PowerShell oracle unavailable", false},
		{"required missing", "", "1", "SECRET_PS_ORACLE_REQUIRED=1", true},
		{"configured missing", filepath.Join(t.TempDir(), "missing-oracle.exe"), "", "executable unavailable", true},
		{"relative", "relative-oracle.exe", "1", "absolute executable", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestOracleConfigurationHelper$", "-test.v")
			command.Env = []string{"SECRET_PS_CONFIGURATION_HELPER=1", "SECRET_PS_ORACLE=" + tc.oracle, "SECRET_PS_ORACLE_REQUIRED=" + tc.required}
			output, err := command.CombinedOutput()
			if (err != nil) != tc.fail || !strings.Contains(string(output), tc.want) {
				t.Fatalf("configuration gate: err=%v output=%s", err, output)
			}
		})
	}
}
func TestOracleConfigurationHelper(t *testing.T) {
	if os.Getenv("SECRET_PS_CONFIGURATION_HELPER") == "1" {
		configuredOracle(t)
	}
}

// This is a fabricated metadata unit fixture, never native evidence or a golden
// AST. Mutating it demonstrates that each binding-contract field gates the test.
func syntheticNativeMetadata(t *testing.T) *nativeProjection {
	t.Helper()
	projected, err := Project([]byte("Write-Output literal"), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	native := &nativeProjection{Projection: *projected, Aliases: map[string]string{}}
	for alias, name := range aliases {
		native.Aliases[alias] = name
	}
	for i := range native.Metadata {
		command := &native.Metadata[i]
		for j := range command.Sets[0].Parameters {
			parameter := &command.Sets[0].Parameters[j]
			parameter.FromPipeline, parameter.FromProperty = nativeParameterInput(command.Name, psParameter(*parameter))
		}
		switch command.Name {
		case "Out-Null", "Out-File", "ForEach-Object":
			command.Sets[0].Parameters = append(command.Sets[0].Parameters, ParameterMetadata{Name: "InputObject", Position: -1, Kind: "word", FromPipeline: true})
		}
	}
	return native
}
func psParameter(p ParameterMetadata) parameter {
	return parameter{name: p.Name, position: p.Position, kind: p.Kind}
}
func TestOracleMetadataComparison(t *testing.T) {
	if err := compareNativeRoles(syntheticNativeMetadata(t)); err != nil {
		t.Fatalf("unit metadata fixture invalid: %v", err)
	}
	for _, field := range []string{"position", "kind", "pipeline", "property", "alias", "set", "receiver"} {
		t.Run(field, func(t *testing.T) {
			native := syntheticNativeMetadata(t)
			for i := range native.Metadata {
				command := &native.Metadata[i]
				if command.Name != "Write-Output" {
					continue
				}
				parameter := &command.Sets[0].Parameters[0]
				switch field {
				case "position":
					parameter.Position++
				case "kind":
					parameter.Kind = "block"
				case "pipeline":
					parameter.FromPipeline = !parameter.FromPipeline
				case "property":
					parameter.FromProperty = !parameter.FromProperty
				case "alias":
					native.Aliases["gc"] = "Out-Null"
				case "set":
					command.Sets = nil
				case "receiver":
					for j := range native.Metadata {
						if native.Metadata[j].Name == "Out-Null" {
							native.Metadata[j].Sets[0].Parameters = nil
						}
					}
				}
			}
			if err := compareNativeRoles(native); err == nil {
				t.Fatalf("incorrect %s evidence passed", field)
			}
		})
	}
}
