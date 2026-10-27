package ps

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const oracleOutputLimit = 4 << 20

type oracleRunner struct {
	executable, script, directory string
	environment, prefix           []string
	timeout                       time.Duration
	outputLimit                   int
}

type oracleInfrastructureError struct{ err error }

func (e *oracleInfrastructureError) Error() string { return e.err.Error() }
func (e *oracleInfrastructureError) Unwrap() error { return e.err }

type nativeProjection struct {
	Projection
	Aliases map[string]string `json:"aliases"`
}

// No inherited HOME, user module path, profile or candidate-controlled PATH.
// All source is synthetic and goes to a fixed script over stdin, never argv.
func configuredOracle(t *testing.T) oracleRunner {
	t.Helper()
	executable := os.Getenv("SECRET_PS_ORACLE")
	required := os.Getenv("SECRET_PS_ORACLE_REQUIRED") == "1"
	if executable == "" {
		if required {
			t.Fatal("SECRET_PS_ORACLE_REQUIRED=1 but SECRET_PS_ORACLE is missing")
		}
		t.Skip("native PowerShell oracle unavailable: set SECRET_PS_ORACLE to an absolute executable; required Windows CI runs both editions")
	}
	if !filepath.IsAbs(executable) {
		t.Fatal("SECRET_PS_ORACLE must be an absolute executable path")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("PowerShell oracle executable unavailable: %v", err)
	}
	script, err := filepath.Abs("../../../tests/powershell-ast.ps1")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	environment := []string{"HOME=" + directory, "USERPROFILE=" + directory, "LOCALAPPDATA=" + directory, "APPDATA=" + directory, "TEMP=" + directory, "TMP=" + directory, "TMPDIR=" + directory, "PSModulePath=" + filepath.Join(filepath.Dir(executable), "Modules"), "POWERSHELL_TELEMETRY_OPTOUT=1", "POWERSHELL_UPDATECHECK=Off"}
	// Windows process startup requires these OS-owned directories, not user state.
	for _, key := range []string{"SystemRoot", "WINDIR"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return oracleRunner{executable: executable, script: script, directory: directory, environment: environment, timeout: 30 * time.Second, outputLimit: oracleOutputLimit}
}

type boundedCapture struct {
	data     bytes.Buffer
	limit    int
	overflow bool
}

func (w *boundedCapture) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.data.Len()
	if n > remaining {
		w.overflow = true
		p = p[:remaining]
	}
	_, _ = w.data.Write(p)
	// Drain without allocating: even a hostile helper cannot block an output pipe.
	return n, nil
}

// Keep all single-source comparisons and fault injection on the batch protocol.
func (r oracleRunner) run(source string) (*nativeProjection, error) {
	results, err := r.runBatch([]string{source})
	if err != nil {
		return nil, err
	}
	return results[0].value()
}

func corpusSources(t *testing.T) []string {
	t.Helper()
	var sources []string
	for _, name := range []string{"cases.jsonl", "replay.jsonl"} {
		file, err := os.Open(filepath.Join("../../../testdata/hook/powershell", name))
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), MaxSource*6+4096)
		for scanner.Scan() {
			var row struct {
				Source string `json:"source"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				file.Close()
				t.Fatalf("%s: %v", name, err)
			}
			sources = append(sources, row.Source)
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(sources) == 0 {
		t.Fatal("empty PowerShell corpus")
	}
	return sources
}

func TestOracleGoldenFixtures(t *testing.T) {
	runner := configuredOracle(t)
	var sources []string
	var indices []int
	for i, source := range corpusSources(t) {
		if Classify([]byte(source), fakeContext()).Allow {
			sources = append(sources, source)
			indices = append(indices, i)
		}
	}
	if len(sources) == 0 {
		t.Fatal("no Go-accepted oracle cases")
	}
	offset := 0
	for _, batch := range oracleBatches(sources) {
		comparisons, err := compareOracleBatch(runner, batch)
		if err != nil {
			t.Fatalf("oracle corpus batch at accepted index=%d: %v", offset, err)
		}
		for j, err := range comparisons {
			i := indices[offset+j]
			t.Run(fmt.Sprintf("case-%04d", i), func(t *testing.T) {
				if err != nil {
					t.Fatalf("corpus index=%d: %v", i, err)
				}
			})
		}
		offset += len(batch)
	}
	t.Logf("native oracle %s: %d Go-accepted corpus/replay cases", runner.executable, len(sources))
}

func compareOracle(runner oracleRunner, source string) error {
	native, err := runner.run(source)
	if err != nil {
		return &oracleInfrastructureError{err}
	}
	return compareOracleProjection(source, native)
}

func compareOracleProjection(source string, native *nativeProjection) error {
	goSide, err := Project([]byte(source), context.Background())
	if err != nil {
		return err
	}
	if len(native.ParseErrors) != 0 || native.ScriptRequirements != nil || len(native.Unsupported) != 0 {
		return errors.New("native parse errors, requirements or unsupported AST node")
	}
	for _, binding := range native.Bindings {
		if len(binding.Exceptions) != 0 {
			return fmt.Errorf("native binding exception at %+v: %v", binding.Span, binding.Exceptions)
		}
	}
	if !reflect.DeepEqual(goSide.Tokens, native.Tokens) {
		return fmt.Errorf("token mismatch: Go=%+v native=%+v", goSide.Tokens, native.Tokens)
	}
	if !reflect.DeepEqual(goSide.Statements, native.Statements) {
		return fmt.Errorf("AST mismatch: Go=%+v native=%+v", goSide.Statements, native.Statements)
	}
	if !reflect.DeepEqual(goSide.Bindings, native.Bindings) {
		return fmt.Errorf("binding mismatch: Go=%+v native=%+v", goSide.Bindings, native.Bindings)
	}
	return compareNativeRoles(native)
}

// A restricted role is not the whole native parameter set. Every accepted
// combination must fit one native set. Native implicit path/property binding is
// deliberately NOT authorization: readers forbid pipeline input and writers
// consume only their certified Value/InputObject channel, never a filename.
func compareNativeRoles(native *nativeProjection) error {
	metadata := map[string]CommandMetadata{}
	models := map[string]commandRole{}
	receivers := map[string]string{}
	for _, command := range native.Metadata {
		metadata[strings.ToLower(command.Name)] = command
	}
	for alias, canonical := range aliases {
		if !strings.EqualFold(native.Aliases[alias], canonical) {
			return fmt.Errorf("native alias %s != %s", alias, canonical)
		}
	}
	for _, role := range roleTable {
		command, ok := metadata[strings.ToLower(role.name)]
		if !ok || len(command.Sets) == 0 {
			return fmt.Errorf("missing native command metadata %s", role.name)
		}
		for _, modeled := range role.parameters {
			found := false
			for _, set := range command.Sets {
				for _, parameter := range set.Parameters {
					if parameter.Name != modeled.name {
						continue
					}
					fromPipeline, fromProperty := nativeParameterInput(role.name, modeled)
					if parameter.Position != modeled.position || parameter.Kind != modeled.kind || parameter.FromPipeline != fromPipeline || parameter.FromProperty != fromProperty {
						return fmt.Errorf("native role mismatch %s.%s in %s: %+v", role.name, modeled.name, set.Name, parameter)
					}
					found = true
				}
			}
			if !found {
				return fmt.Errorf("missing native parameter %s.%s", role.name, modeled.name)
			}
		}
		receiver := ""
		switch role.input {
		case "value":
			receiver = "Value"
		case "required", "optional":
			receiver = "InputObject"
		case "none":
		default:
			return fmt.Errorf("unmodeled input role %s", role.name)
		}
		models[strings.ToLower(role.name)] = role
		receivers[strings.ToLower(role.name)] = receiver
		if receiver != "" {
			found := false
			for _, set := range command.Sets {
				for _, p := range set.Parameters {
					if p.Name == receiver {
						if !p.FromPipeline || p.FromProperty != (receiver == "Value") {
							return fmt.Errorf("native %s has unmodeled pipeline/property receiver %+v", role.name, p)
						}
						found = true
					}
				}
			}
			if !found {
				return fmt.Errorf("native %s lacks pipeline receiver %s", role.name, receiver)
			}
		}
	}
	// Check each actual combination against a single native parameter set, not a
	// union that accidentally accepts mutually exclusive parameters. Mandatory
	// inputs need an explicit binding or certified success-stream input through
	// this command's modeled receiver, never arbitrary native property binding.
	var visit func([]ProjectedPipeline) (Source, error)
	visit = func(pipelines []ProjectedPipeline) (Source, error) {
		output := None
		for _, pipeline := range pipelines {
			input := None
			for index, command := range pipeline.Commands {
				name := strings.ToLower(command.Name)
				if canonical, ok := aliases[name]; ok {
					name = canonical
				}
				info, ok := metadata[name]
				model, modeled := models[name]
				if !ok || !modeled {
					return Unknown, fmt.Errorf("unresolved command %s", name)
				}
				var binding *ProjectedBinding
				for i := range native.Bindings {
					if native.Bindings[i].Span == command.Span {
						binding = &native.Bindings[i]
						break
					}
				}
				if binding == nil {
					return Unknown, errors.New("missing native binding")
				}
				boundNames := map[string]bool{}
				for _, bound := range binding.Parameters {
					boundNames[bound.Name] = true
				}
				piped := false
				for _, edge := range pipeline.Edges {
					if index > 0 && edge == (Edge{index - 1, index}) {
						piped = true
					}
				}
				pipelineInput := piped && certified(input)
				compatible := false
				for _, set := range info.Sets {
					parameters := map[string]ParameterMetadata{}
					fits := true
					for _, p := range set.Parameters {
						parameters[p.Name] = p
						if p.Mandatory && !boundNames[p.Name] && !(pipelineInput && p.Name == receivers[name] && p.FromPipeline) {
							fits = false
						}
					}
					for name := range boundNames {
						if _, ok := parameters[name]; !ok {
							fits = false
						}
					}
					if fits {
						compatible = true
					}
				}
				if !compatible {
					return Unknown, fmt.Errorf("no native parameter set for %s", name)
				}
				blockOutput := None
				for _, element := range command.Elements {
					nested, err := visit(element.Statements)
					if err != nil {
						return Unknown, err
					}
					blockOutput = combine(blockOutput, nested)
				}
				input = model.output
				if model.name == "ForEach-Object" {
					input = Unknown
					if pipelineInput {
						input = blockOutput
					}
				}
				for _, redirect := range command.Redirects {
					if redirect.Merge == 0 && (redirect.Stream == 1 || redirect.Stream == -1) {
						input = None
					}
				}
			}
			output = combine(output, input)
		}
		return output, nil
	}
	_, err := visit(native.Statements)
	return err
}

// Expected native metadata is independently checked, not copied out of the
// projection. Native property binding does not grant the Go policy permission
// to omit explicit filenames. These attributes come from the fixed cmdlets;
// both editions must independently confirm them.
func nativeParameterInput(command string, p parameter) (pipeline, property bool) {
	switch p.name {
	case "InputObject":
		return true, false
	case "Value":
		return true, true
	case "Path":
		return command == "Get-ChildItem" || command == "Copy-Item", true
	case "LiteralPath", "Destination":
		return false, true
	default:
		return false, false
	}
}

// Run the test executable as a deliberately broken oracle, never a shell or
// candidate-controlled executable. Exercise the same bounded runner as CI.
func TestOracleRunnerFaults(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mode, want string }{
		{"missing", "process failed"},
		{"nonzero", "process failed"},
		{"malformed", "invalid JSON"},
		{"duplicate-key", "invalid JSON"},
		{"invalid-utf8", "invalid JSON"},
		{"unpaired-surrogate", "invalid JSON"},
		{"empty", "incomplete projection"},
		{"oversized", "output limit"},
		{"timeout", "timeout"},
		{"count", "count mismatch"},
		{"order", "order mismatch"},
		{"source-error", "source failed index=0 id=OracleSyntheticFailure line=42"},
		{"trailing", "trailing JSON"},
		{"stderr", "unexpected stderr"},
		{"missing-index", "incomplete projection"},
		{"missing-error", "incomplete projection"},
		{"missing-requirements", "incomplete projection"},
		{"missing-binding-flag", "incomplete projection"},
		{"null-binding-flag", "incomplete projection"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			mode := tc.mode
			runner := oracleRunner{executable: executable, script: "unused", directory: t.TempDir(), environment: []string{"SECRET_PS_FAULT_HELPER=" + mode}, prefix: []string{"-test.run=^TestOracleFaultHelper$", "--"}, timeout: 2 * time.Second, outputLimit: oracleOutputLimit}
			if mode == "missing" {
				runner.executable = filepath.Join(runner.directory, "missing-oracle.exe")
			}
			if mode == "timeout" {
				runner.timeout = 100 * time.Millisecond
			}
			source := "Write-Output synthetic"
			if mode == "invalid-utf8" || mode == "unpaired-surrogate" {
				source = "Write-Output '�'"
			}
			err := compareOracle(runner, source)
			var infrastructure *oracleInfrastructureError
			if !errors.As(err, &infrastructure) {
				t.Fatalf("broken oracle did not fail as infrastructure: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("fault was not exercised: got %v, want %s", err, tc.want)
			}
		})
	}
}
func TestOracleFaultHelper(t *testing.T) {
	mode := os.Getenv("SECRET_PS_FAULT_HELPER")
	if mode == "" {
		return
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, oracleInputLimit+1))
	var sources []string
	if err != nil || len(input) > oracleInputLimit || json.Unmarshal(input, &sources) != nil {
		os.Exit(12)
	}
	results := make([]oracleResult, len(sources))
	for i, source := range sources {
		// Fabricated runner unit data, never native oracle evidence.
		native := syntheticNativeMetadata(t)
		projected, err := Project([]byte(source), context.Background())
		if err != nil {
			os.Exit(13)
		}
		metadata := native.Metadata
		native.Projection = *projected
		native.Metadata = metadata
		results[i] = oracleResult{Index: i, Projection: native}
	}
	switch mode {
	case "nonzero":
		os.Exit(9)
	case "nonzero-diagnostic":
		fmt.Fprintln(os.Stderr, "powershell oracle failed id=PropertyNotFoundStrict line=42")
		os.Exit(9)
	case "nonzero-control", "nonzero-long", "nonzero-nonascii":
		text := map[string]string{"nonzero-control": "suppressed\x1b", "nonzero-long": strings.Repeat("suppressed", 100), "nonzero-nonascii": "suppressedé"}[mode]
		fmt.Fprint(os.Stderr, text)
		os.Exit(9)
	case "malformed":
		fmt.Print("not JSON")
		os.Exit(0)
	case "empty":
		fmt.Print("[{\"index\":0,\"projection\":{},\"error\":null}]")
		os.Exit(0)
	case "count":
		fmt.Print("[]")
		os.Exit(0)
	case "oversized":
		fmt.Print(strings.Repeat("x", oracleOutputLimit+1))
		os.Exit(0)
	case "timeout":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "order":
		results[0].Index++
	case "source-error", "mixed":
		index := 0
		if mode == "mixed" {
			index = 1
		}
		results[index].Projection = nil
		results[index].Error = &oracleSourceError{ID: "OracleSyntheticFailure", Line: 42}
	case "valid", "trailing", "stderr", "missing-index", "missing-error", "missing-requirements", "missing-binding-flag", "null-binding-flag", "duplicate-key", "invalid-utf8", "unpaired-surrogate":
	default:
		os.Exit(10)
	}
	data, err := json.Marshal(results)
	if err != nil {
		os.Exit(11)
	}
	switch mode {
	case "duplicate-key":
		data = bytes.Replace(data, []byte(`"unsupported":[]`), []byte(`"unsupported":["UnexpectedNode"],"unsupported":[]`), 1)
	case "invalid-utf8":
		data = bytes.Replace(data, []byte("�"), []byte{0xff}, 1)
	case "unpaired-surrogate":
		data = bytes.Replace(data, []byte("�"), []byte(`\ud800`), 1)
	case "missing-index":
		data = bytes.Replace(data, []byte(`"index":0,`), nil, 1)
	case "missing-error":
		data = bytes.Replace(data, []byte(`,"error":null`), nil, 1)
	case "missing-requirements":
		data = bytes.Replace(data, []byte(`"scriptRequirements":null,`), nil, 1)
	case "missing-binding-flag":
		data = bytes.Replace(data, []byte(`"positional":true,`), nil, 1)
	case "null-binding-flag":
		data = bytes.Replace(data, []byte(`"positional":true`), []byte(`"positional":null`), 1)
	case "stderr":
		fmt.Fprint(os.Stderr, "unexpected synthetic stderr")
	}
	_, _ = os.Stdout.Write(data)
	if mode == "trailing" {
		fmt.Print("[]")
	}
	os.Exit(0)
}

func TestOracleMetadataPolicyControls(t *testing.T) {
	// Independently exercise the safe pipeline/property contract. Native metadata
	// may allow implicit path binding, but these shapes must never be accepted.
	for _, role := range roleTable {
		if role.input == "none" {
			if Classify([]byte("Write-Output public.txt | "+role.name+" public.txt"), fakeContext()).Allow {
				t.Fatalf("implicit filename binding into %s", role.name)
			}
		}
	}
	for _, source := range []string{`Write-Output public | Set-Content`, `Write-Output public | Add-Content`, `Write-Output public | Out-File`, `Write-Output public | Select-String public`, `Write-Output public | Get-Content -LiteralPath public`, `Write-Output public | ForEach-Object -Parallel { Out-Null }`} {
		if Classify([]byte(source), fakeContext()).Allow {
			t.Fatalf("unmodeled property/pipeline binding accepted: %q", source)
		}
	}
}

func TestOracleClassifierPerformance(t *testing.T) {
	if os.Getenv("SECRET_PS_ORACLE_REQUIRED") != "1" {
		t.Skip("performance evidence is recorded by the required native oracle job")
	}
	_ = configuredOracle(t)
	sources := corpusSources(t)
	var samples []time.Duration
	for repeat := 0; repeat < 20; repeat++ {
		for _, source := range sources {
			start := time.Now()
			ctx := fakeContext()
			ctx.Deadline = start.Add(2 * time.Second)
			decision := Classify([]byte(source), ctx)
			samples = append(samples, time.Since(start))
			if decision.Reason == ReasonDeadline {
				t.Fatal("corpus exhausted the unchanged analysis deadline")
			}
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	worst := time.Duration(0)
	for _, workload := range []struct{ name, source string }{
		{"literal", "Write-Output '" + strings.Repeat("x", MaxSource-len("Write-Output ''")) + "'"},
		{"node-cap", strings.Repeat("Out-Null;", 679) + "Write-Output x;Write-Output y"},
		{"token-cap", strings.Repeat("#\n", MaxTokens/2)},
		{"nested-cap", strings.Repeat("Write-Output x | % { ", MaxDepth) + "Write-Output y" + strings.Repeat(" }", MaxDepth)},
	} {
		source := workload.source + strings.Repeat(" ", MaxSource-len(workload.source))
		maximum := time.Duration(0)
		for repeat := 0; repeat < 100; repeat++ {
			start := time.Now()
			ctx := fakeContext()
			ctx.Deadline = start.Add(2 * time.Second)
			decision := Classify([]byte(source), ctx)
			elapsed := time.Since(start)
			if !decision.Allow {
				t.Fatalf("40 KiB %s control rejected: %+v", workload.name, decision)
			}
			if elapsed > maximum {
				maximum = elapsed
			}
		}
		if maximum > worst {
			worst = maximum
		}
		t.Logf("classifier 40 KiB workload=%s n=100 max=%s", workload.name, maximum)
	}
	p99 := samples[(len(samples)-1)*99/100]
	t.Logf("classifier corpus n=%d p99=%s max=%s; 40 KiB worst=%s (analysis budget remains 2s)", len(samples), p99, samples[len(samples)-1], worst)
	if p99 >= 2*time.Second || worst >= 2*time.Second {
		t.Fatal("classifier exceeded existing analysis budget")
	}
}
