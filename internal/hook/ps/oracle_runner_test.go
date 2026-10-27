package ps

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
			// Fixed 5.1/7.x contracts, not the Go projection's optional flags.
			// Get-ChildItem's Path set has no mandatory parameters; its
			// LiteralPath set does require LiteralPath. Copy-Item requires
			// Path/LiteralPath, but Destination is optional natively.
			switch parameter.Name {
			case "Path":
				parameter.Mandatory = command.Name != "Get-ChildItem"
			case "LiteralPath", "Pattern", "Value", "FilePath", "Process", "InputObject":
				parameter.Mandatory = true
			}
		}
		switch command.Name {
		case "Out-Null", "Out-File", "ForEach-Object":
			command.Sets[0].Parameters = append(command.Sets[0].Parameters, ParameterMetadata{Name: "InputObject", Position: -1, Kind: "word", FromPipeline: true})
		}
		// Path and LiteralPath never belong to the same native set. Keep
		// this fabricated fixture small, but preserve that mandatory choice.
		hasPath := false
		for _, parameter := range command.Sets[0].Parameters {
			hasPath = hasPath || parameter.Name == "Path"
		}
		if hasPath {
			pathSet := ParameterSetMetadata{Name: "synthetic-path", Parameters: []ParameterMetadata{}}
			literalSet := ParameterSetMetadata{Name: "synthetic-literal-path", Parameters: []ParameterMetadata{}}
			for _, parameter := range command.Sets[0].Parameters {
				if parameter.Name != "LiteralPath" {
					pathSet.Parameters = append(pathSet.Parameters, parameter)
				}
				if parameter.Name != "Path" {
					literalSet.Parameters = append(literalSet.Parameters, parameter)
				}
			}
			command.Sets = []ParameterSetMetadata{pathSet, literalSet}
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

func TestOracleRunnerBatch(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := oracleRunner{executable: executable, script: "unused", directory: t.TempDir(), environment: []string{"SECRET_PS_FAULT_HELPER=valid"}, prefix: []string{"-test.run=^TestOracleFaultHelper$", "--"}, timeout: 15 * time.Second, outputLimit: oracleOutputLimit}
	sources := []string{"", "Write-Output literal", "Write-Output 'it''s data'", "Write-Output '𐐀'", "Write-Output '�'", "# comment\r\nWrite-Output other", "Write-Output literal"}
	comparisons, err := compareOracleBatch(runner, sources)
	if err != nil {
		t.Fatal(err)
	}
	for i, err := range comparisons {
		if err != nil {
			t.Fatalf("batch index=%d: %v", i, err)
		}
	}
	runner.environment = []string{"SECRET_PS_FAULT_HELPER=mixed"}
	comparisons, err = compareOracleBatch(runner, sources)
	if err != nil {
		t.Fatal(err)
	}
	for i, err := range comparisons {
		var infrastructure *oracleInfrastructureError
		if i == 1 {
			if !errors.As(err, &infrastructure) || !strings.Contains(err.Error(), "index=1 id=OracleSyntheticFailure line=42") {
				t.Fatalf("missing indexed failure: %v", err)
			}
		} else if err != nil {
			t.Fatalf("failure crossed index=%d: %v", i, err)
		}
	}
}

func TestOracleBatchPartition(t *testing.T) {
	for _, sources := range [][]string{
		make([]string, oracleBatchLimit+1),
		strings.Split(strings.Repeat(strings.Repeat("\x00", MaxSource)+"|", oracleBatchLimit), "|")[:oracleBatchLimit],
	} {
		batches := oracleBatches(sources)
		if len(batches) < 2 {
			t.Fatal("batch boundary was not exercised")
		}
		var flattened []string
		for _, batch := range batches {
			encoded, err := json.Marshal(batch)
			if err != nil || len(encoded) > oracleInputLimit || len(batch) > oracleBatchLimit || len(batch) == 0 {
				t.Fatal("unbounded batch")
			}
			flattened = append(flattened, batch...)
		}
		if !reflect.DeepEqual(flattened, sources) {
			t.Fatal("partition changed count, order or source")
		}
	}
}

func TestOracleBatchInputLimits(t *testing.T) {
	for _, sources := range [][]string{
		nil, make([]string, oracleBatchLimit+1), {strings.Repeat("x", MaxSource+1)}, {"\xff"},
		strings.Split(strings.Repeat(strings.Repeat("\x00", MaxSource)+"|", oracleBatchLimit), "|")[:oracleBatchLimit],
	} {
		// No executable: a validation failure must happen before process startup.
		if got, err := (oracleRunner{}).runBatch(sources); err == nil || got != nil || strings.Contains(err.Error(), "process failed") {
			t.Fatalf("invalid input reached process: %v", err)
		}
	}
}

func TestOracleRunnerDiagnostics(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"nonzero-diagnostic", "nonzero-control", "nonzero-long", "nonzero-nonascii"} {
		runner := oracleRunner{executable: executable, script: "unused", directory: t.TempDir(), environment: []string{"SECRET_PS_FAULT_HELPER=" + mode}, prefix: []string{"-test.run=^TestOracleFaultHelper$", "--"}, timeout: 2 * time.Second, outputLimit: oracleOutputLimit}
		_, err := runner.run("Write-Output literal")
		if err == nil || !strings.Contains(err.Error(), "process failed") {
			t.Fatalf("missing process failure: %v", err)
		}
		if strings.Contains(err.Error(), "suppressed") || (mode == "nonzero-diagnostic") != strings.Contains(err.Error(), "id=PropertyNotFoundStrict line=42") {
			t.Fatalf("incorrect diagnostic capture: %v", err)
		}
	}
	for _, text := range []string{"line\nsecond", "\tline", "\x00", "line\r", strings.Repeat("x", 513)} {
		if got := oracleDiagnostic([]byte(text)); got != "" {
			t.Fatalf("unsafe diagnostic accepted: %q", got)
		}
	}
	if got := oracleDiagnostic([]byte("fixed id=Test line=42\r\n")); got != "fixed id=Test line=42" {
		t.Fatalf("lost WriteLine diagnostic: %q", got)
	}
}

func TestOracleBatchIsolation(t *testing.T) {
	runner := configuredOracle(t)
	for _, source := range []string{"", "Write-Output 'public literal'"} {
		if err := compareOracle(runner, source); err != nil {
			t.Fatalf("fresh batch of one: %v", err)
		}
	}
	// Alias evidence is captured before any metadata lookup or binder can load
	// Management, including in this fresh process with an empty first source.
	// The middle input exceeds the oracle token cap, not the source-byte cap.
	sources := []string{"", strings.Repeat("Out-Null;", MaxTokens), "Write-Output 'public literal'"}
	results, err := runner.runBatch(sources)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 2} {
		native, err := results[i].value()
		if err != nil {
			t.Fatalf("unrelated index=%d failed: %v", i, err)
		}
		if err := compareOracleProjection(sources[i], native); err != nil {
			t.Fatalf("index=%d: %v", i, err)
		}
	}
	if native, err := results[1].value(); err == nil || native != nil || !strings.Contains(err.Error(), "index=1") {
		t.Fatalf("source fault not isolated: %v", err)
	}
}
