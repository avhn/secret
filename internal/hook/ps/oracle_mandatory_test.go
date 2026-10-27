package ps

import (
	"context"
	"strings"
	"testing"
)

func syntheticOracleProjection(t *testing.T, source string) *nativeProjection {
	t.Helper()
	native := syntheticNativeMetadata(t)
	projected, err := Project([]byte(source), context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metadata := native.Metadata
	native.Projection = *projected
	native.Metadata = metadata
	return native
}

func TestOracleMandatoryParameters(t *testing.T) {
	for _, tc := range []struct {
		name, source, command string
		pipeline, property    bool
	}{
		{"no pipeline", `Write-Output literal`, "Write-Output", false, false},
		{"pipeline", `Write-Output literal | Out-File public.txt`, "Out-File", false, false},
		{"arbitrary by-value receiver", `Write-Output literal | Out-File public.txt`, "Out-File", true, false},
		{"arbitrary property receiver", `Write-Output literal | Set-Content public.txt`, "Set-Content", false, true},
		{"arbitrary combined receiver", `Write-Output literal | Set-Content public.txt`, "Set-Content", true, true},
		{"nested command", `Write-Output literal | ForEach-Object { Write-Output nested }`, "Write-Output", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if decision := Classify([]byte(tc.source), fakeContext()); !decision.Allow {
				t.Fatalf("control rejected: %+v", decision)
			}
			native := syntheticOracleProjection(t, tc.source)
			if err := compareOracleProjection(tc.source, native); err != nil {
				t.Fatalf("unmodified control: %v", err)
			}
			for i := range native.Metadata {
				command := &native.Metadata[i]
				if command.Name == tc.command {
					for j := range command.Sets {
						set := &command.Sets[j]
						set.Parameters = append(set.Parameters, ParameterMetadata{Name: "UnexpectedRequired", Mandatory: true, Position: -1, Kind: "word", FromPipeline: tc.pipeline, FromProperty: tc.property})
					}
				}
			}
			if err := compareOracleProjection(tc.source, native); err == nil || !strings.Contains(err.Error(), "no native parameter set") {
				t.Fatalf("unsatisfied mandatory parameter did not invalidate every set: %v", err)
			}
		})
	}
}

func TestOracleMandatoryParameterControls(t *testing.T) {
	for _, source := range []string{
		`Write-Output literal`,
		`Write-Output -InputObject:literal`,
		`Set-Content public.txt literal`,
		`Set-Content -LiteralPath public.txt -Value literal`,
		`Write-Output literal | Set-Content public.txt`,
		`Get-Content public.txt | Set-Content -LiteralPath other.txt`,
		`Write-Output literal | Add-Content public.txt`,
		`Write-Output literal | ForEach-Object -Process { Write-Output nested }`,
		`Write-Output literal | ForEach-Object { Write-Output nested } | Set-Content public.txt`,
		`Write-Output literal | Out-File public.txt`,
		`Get-ChildItem -Path public -Name`,
		`Get-ChildItem -LiteralPath public -Name`,
		`Copy-Item public.txt other.txt`,
		`Copy-Item -LiteralPath public.txt -Destination other.txt`,
	} {
		t.Run(source, func(t *testing.T) {
			if decision := Classify([]byte(source), fakeContext()); !decision.Allow {
				t.Fatalf("control rejected: %+v", decision)
			}
			if err := compareOracleProjection(source, syntheticOracleProjection(t, source)); err != nil {
				t.Fatal(err)
			}
		})
	}
	// InputObject is optional natively for these cmdlets. Making it mandatory
	// must still allow an actual certified upstream object through that receiver.
	for _, command := range []string{"Out-File public.txt", "Out-Null", "ForEach-Object -Process { Write-Output nested }"} {
		t.Run("mandatory receiver "+command, func(t *testing.T) {
			source := "Write-Output literal | " + command
			native := syntheticOracleProjection(t, source)
			for i := range native.Metadata {
				if native.Metadata[i].Name != strings.Fields(command)[0] {
					continue
				}
				for j := range native.Metadata[i].Sets {
					for k := range native.Metadata[i].Sets[j].Parameters {
						parameter := &native.Metadata[i].Sets[j].Parameters[k]
						if parameter.Name == "InputObject" {
							parameter.Mandatory = true
						}
					}
				}
			}
			if err := compareOracleProjection(source, native); err != nil {
				t.Fatalf("certified modeled receiver rejected: %v", err)
			}
		})
	}
}

func TestOracleMandatoryPipelineProof(t *testing.T) {
	// These projections are syntactically bindable but have no certified input
	// for Value. A pipe character alone, prior statement output, an outer block's
	// input, and redirected or discarded output are not upstream object proofs.
	for _, source := range []string{
		`Set-Content public.txt`,
		`Write-Output literal; Set-Content public.txt`,
		`Out-Null | Set-Content public.txt`,
		`Write-Output literal > other.txt | Set-Content public.txt`,
		`Write-Output literal *> other.txt | Set-Content public.txt`,
		`Write-Output literal | Out-Null | Set-Content public.txt`,
		`Write-Output literal | ForEach-Object { Out-Null } | Set-Content public.txt`,
		`Write-Output literal | ForEach-Object { Set-Content public.txt }`,
	} {
		t.Run(source, func(t *testing.T) {
			native := syntheticOracleProjection(t, source)
			if err := compareOracleProjection(source, native); err == nil || !strings.Contains(err.Error(), "no native parameter set") {
				t.Fatalf("uncertified input satisfied mandatory Value: %v", err)
			}
		})
	}
	t.Run("missing edge", func(t *testing.T) {
		native := syntheticOracleProjection(t, `Write-Output literal | Set-Content public.txt`)
		native.Statements[0].Edges = nil
		// Directly exercise metadata: the normal comparison also rejects the
		// mutated structure before it reaches the binding-contract check.
		if err := compareNativeRoles(native); err == nil || !strings.Contains(err.Error(), "no native parameter set") {
			t.Fatalf("missing edge satisfied mandatory Value: %v", err)
		}
	})
}

func TestOracleMandatoryCorpusControls(t *testing.T) {
	accepted := 0
	for index, source := range corpusSources(t) {
		if !Classify([]byte(source), fakeContext()).Allow {
			continue
		}
		accepted++
		if err := compareOracleProjection(source, syntheticOracleProjection(t, source)); err != nil {
			t.Fatalf("accepted corpus index=%d incompatible with synthetic mandatory contracts: %v", index, err)
		}
	}
	if accepted == 0 {
		t.Fatal("no accepted corpus controls")
	}
	t.Logf("synthetic mandatory-contract controls: %d accepted corpus/replay cases (not native evidence)", accepted)
}
