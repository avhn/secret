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
	"os/exec"
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
	environment := []string{"HOME=" + directory, "USERPROFILE=" + directory, "TEMP=" + directory, "TMP=" + directory, "TMPDIR=" + directory, "PSModulePath=" + filepath.Join(filepath.Dir(executable), "Modules"), "POWERSHELL_TELEMETRY_OPTOUT=1", "POWERSHELL_UPDATECHECK=Off"}
	// Windows process startup requires these OS-owned directories, not user state.
	for _, key := range []string{"SystemRoot", "WINDIR"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	return oracleRunner{executable: executable, script: script, directory: directory, environment: environment, timeout: 15 * time.Second, outputLimit: oracleOutputLimit}
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

func (r oracleRunner) run(source string) (*nativeProjection, error) {
	if len(source) > MaxSource {
		return nil, errors.New("oracle source limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	args := append(append([]string{}, r.prefix...), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", r.script)
	cmd := exec.CommandContext(ctx, r.executable, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = r.directory, r.environment, strings.NewReader(source)
	cmd.WaitDelay = time.Second
	configureOracleProcess(cmd)
	stdout, stderr := &boundedCapture{limit: r.outputLimit}, &boundedCapture{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("oracle timeout: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("oracle process failed: %w", err)
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("oracle output limit")
	}
	if stderr.data.Len() != 0 {
		return nil, errors.New("oracle unexpected stderr")
	}
	var result nativeProjection
	decoder := json.NewDecoder(&stdout.data)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("oracle invalid JSON: %w", err)
	}
	var tail any
	if err := decoder.Decode(&tail); err != io.EOF {
		return nil, errors.New("oracle trailing JSON")
	}
	// An empty object is broken evidence, not an empty successfully parsed script.
	if result.Tokens == nil || result.ParseErrors == nil || result.Statements == nil || result.Bindings == nil || result.Metadata == nil || result.Unsupported == nil || result.Aliases == nil {
		return nil, errors.New("oracle incomplete projection")
	}
	return &result, nil
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
	accepted := 0
	for i, source := range corpusSources(t) {
		if !Classify([]byte(source), fakeContext()).Allow {
			continue
		}
		accepted++
		t.Run(fmt.Sprintf("case-%04d", i), func(t *testing.T) {
			if err := compareOracle(runner, source); err != nil {
				t.Fatalf("synthetic source %q: %v", source, err)
			}
		})
	}
	if accepted == 0 {
		t.Fatal("no Go-accepted oracle cases")
	}
	t.Logf("native oracle %s: %d Go-accepted corpus/replay cases", runner.executable, accepted)
}

func compareOracle(runner oracleRunner, source string) error {
	goSide, err := Project([]byte(source), context.Background())
	if err != nil {
		return err
	}
	native, err := runner.run(source)
	if err != nil {
		return &oracleInfrastructureError{err}
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
	// union that accidentally accepts mutually exclusive parameters.
	var visit func([]ProjectedPipeline) error
	visit = func(pipelines []ProjectedPipeline) error {
		for _, pipeline := range pipelines {
			for _, command := range pipeline.Commands {
				name := strings.ToLower(command.Name)
				if canonical, ok := aliases[name]; ok {
					name = canonical
				}
				info, ok := metadata[name]
				if !ok {
					return fmt.Errorf("unresolved command %s", name)
				}
				var binding *ProjectedBinding
				for i := range native.Bindings {
					if native.Bindings[i].Span == command.Span {
						binding = &native.Bindings[i]
						break
					}
				}
				if binding == nil {
					return errors.New("missing native binding")
				}
				compatible := false
				for _, set := range info.Sets {
					parameters := map[string]ParameterMetadata{}
					for _, p := range set.Parameters {
						parameters[p.Name] = p
					}
					fits := true
					for _, bound := range binding.Parameters {
						if _, ok := parameters[bound.Name]; !ok {
							fits = false
						}
					}
					if fits {
						compatible = true
					}
				}
				if !compatible {
					return fmt.Errorf("no native parameter set for %s", name)
				}
				for _, element := range command.Elements {
					if err := visit(element.Statements); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	return visit(native.Statements)
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
	for _, mode := range []string{"missing", "nonzero", "malformed", "empty", "oversized", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			runner := oracleRunner{executable: executable, script: "unused", directory: t.TempDir(), environment: []string{"SECRET_PS_FAULT_HELPER=" + mode}, prefix: []string{"-test.run=^TestOracleFaultHelper$", "--"}, timeout: 2 * time.Second, outputLimit: 1024}
			if mode == "missing" {
				runner.executable = filepath.Join(runner.directory, "missing-oracle.exe")
			}
			if mode == "timeout" {
				runner.timeout = 100 * time.Millisecond
			}
			got, err := runner.run("Write-Output synthetic")
			if err == nil || got != nil {
				t.Fatalf("broken oracle passed: %+v %v", got, err)
			}
			want := map[string]string{"missing": "process failed", "nonzero": "process failed", "malformed": "invalid JSON", "empty": "incomplete projection", "oversized": "output limit", "timeout": "timeout"}[mode]
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("fault was not exercised: got %v, want %s", err, want)
			}
		})
	}
}
func TestOracleFaultHelper(t *testing.T) {
	switch os.Getenv("SECRET_PS_FAULT_HELPER") {
	case "":
		return
	case "valid":
		// Fabricated runner unit data, never native oracle evidence.
		data, err := json.Marshal(syntheticNativeMetadata(t))
		if err != nil {
			os.Exit(11)
		}
		_, _ = os.Stdout.Write(data)
	case "nonzero":
		os.Exit(9)
	case "malformed":
		fmt.Print("not JSON")
	case "empty":
		fmt.Print("{}")
	case "oversized":
		fmt.Print(strings.Repeat("x", 8192))
	case "timeout":
		time.Sleep(time.Minute)
	default:
		os.Exit(10)
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
