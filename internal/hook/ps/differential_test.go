package ps

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const differentialDefaultBudget = 2000

// A fixed seed and an explicit input budget make every edition see the same
// grammar-directed cases. Mutations include deliberately rejected syntax, not
// only whitespace around known-good text. There is no candidate execution.
func generatedSources(seeds []string, budget int) []string {
	random := rand.New(rand.NewSource(0x50534f5241434c45))
	out := make([]string, 0, budget)
	punctuation := []string{",", "'adjacent'", "\"adjacent\"", "`", "`\n", "# boundary\n", "<# boundary #>", "2>", "2>&1", "{ Write-Output nested }", "\u2013", "\u2014", "‘", "’", "“", "”", "*", "?", "[a]"}
	for i := 0; i < budget; i++ {
		source := seeds[random.Intn(len(seeds))]
		switch i % 8 {
		case 0:
			source = "<# generated " + strconv.Itoa(i) + " #>\n" + source
		case 1:
			point := random.Intn(len(source) + 1)
			for point < len(source) && !utf8.RuneStart(source[point]) {
				point++
			}
			source = source[:point] + punctuation[(i/8)%len(punctuation)] + source[point:]
		case 2:
			source = strings.ReplaceAll(source, " ", ", ")
		case 3:
			source = "Write-Output literal | % { " + source + " }"
		case 4:
			source = source + " " + []string{"2> errors", "2 > errors", "3>> errors", "4>&1", "5>&1", "6> messages", "*> all"}[(i/8)%7]
		case 5:
			source = strings.ReplaceAll(source, " ", []string{"\t", " <# comment #> ", "`\r\n", "# comment\r\n", "'adjacent'", "\"adjacent\""}[(i/8)%6])
		case 6:
			source = source + "; Write-Output '" + []string{"*", "?", "[a]", "\u2013dash", "‘quote", "literal", "`tick"}[(i/8)%7] + "'"
		case 7:
			source = strings.ReplaceAll(source, "-", []string{"\u2013", "\u2014", "−", "`-"}[(i/8)%4])
		}
		// Keep the budget in distinct inputs even when a rejected seed is
		// unchanged by a particular grammar mutation.
		source = "# mutation " + strconv.Itoa(i) + "\n" + source
		if len(source) > MaxSource {
			source = source[:MaxSource]
		}
		out = append(out, source)
	}
	return out
}

func TestDifferentialReplayControls(t *testing.T) {
	file, err := os.Open("../../../testdata/hook/powershell/replay.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), MaxSource*6+4096)
	count := 0
	for scanner.Scan() {
		var row struct {
			Source   string `json:"source"`
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		if row.Decision != "allow" && row.Decision != "deny" {
			t.Fatal("replay row needs an explicit reviewed allow/deny expectation")
		}
		decision := Classify([]byte(row.Source), fakeContext())
		if decision.Allow != (row.Decision == "allow") {
			t.Fatalf("mandatory replay %q: %+v, want %s", row.Source, decision, row.Decision)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("empty mandatory replay")
	}
}

func TestDifferentialGenerationDeterministic(t *testing.T) {
	seeds := corpusSources(t)
	first, second := generatedSources(seeds, differentialDefaultBudget), generatedSources(seeds, differentialDefaultBudget)
	accepted := 0
	seen := map[string]bool{}
	for i, source := range first {
		if source != second[i] || len(source) > MaxSource || seen[source] {
			t.Fatalf("invalid or duplicate generation at %d", i)
		}
		seen[source] = true
		if Classify([]byte(source), fakeContext()).Allow {
			accepted++
		}
	}
	if accepted == 0 || len(first) != differentialDefaultBudget {
		t.Fatal("empty accepted generation or incorrect budget")
	}
	t.Logf("fixed-seed generated=%d Go-accepted=%d (native comparison is separately gated)", len(first), accepted)
}

func TestOracleDifferentialGeneration(t *testing.T) {
	runner := configuredOracle(t)
	budget := differentialDefaultBudget
	if raw := os.Getenv("SECRET_PS_ORACLE_BUDGET"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 20000 {
			t.Fatal("SECRET_PS_ORACLE_BUDGET must be 1..20000")
		}
		budget = value
	}
	accepted := 0
	for i, source := range generatedSources(corpusSources(t), budget) {
		if !Classify([]byte(source), fakeContext()).Allow {
			continue
		}
		accepted++
		if err := compareOracle(runner, source); err != nil {
			var infrastructure *oracleInfrastructureError
			if errors.As(err, &infrastructure) {
				t.Fatalf("oracle infrastructure failure at generated index=%d: %v", i, err)
			}
			// Bound minimization itself as well as every native invocation. It retains
			// only Go-accepted, UTF-8 complete inputs that reproduce a discrepancy,
			// never a missing or failed oracle. The printed row must be valid JSON.
			minimized := minimizeSynthetic(source, 32, func(candidate string) bool {
				if !Classify([]byte(candidate), fakeContext()).Allow {
					return false
				}
				err := compareOracle(runner, candidate)
				return err != nil && !errors.As(err, &infrastructure)
			})
			row, marshalErr := json.Marshal(struct {
				Source   string `json:"source"`
				Decision string `json:"decision"`
			}{minimized, "allow"})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			t.Fatalf("edition executable=%s generated index=%d: %v\noriginal synthetic source=%q\nminimized synthetic replay=%s\nPersist this case in testdata/hook/powershell/replay.jsonl before fixing the discrepancy.", runner.executable, i, err, source, row)
		}
	}
	if accepted == 0 {
		t.Fatal("no generated Go-accepted native comparisons")
	}
	t.Logf("native generation %s: fixed seed=0x50534f5241434c45 generated=%d accepted/compared=%d", runner.executable, budget, accepted)
}

func minimizeSynthetic(source string, budget int, fails func(string) bool) string {
	for width := len(source) / 2; width > 0 && budget > 0; width /= 2 {
		for start := 0; start+width <= len(source) && budget > 0; {
			candidate := source[:start] + source[start+width:]
			if !utf8.ValidString(candidate) {
				start++
				continue
			}
			budget--
			if fails(candidate) {
				source = candidate
			} else {
				start += width
			}
		}
	}
	return source
}
func TestDifferentialMinimizer(t *testing.T) {
	calls := 0
	got := minimizeSynthetic("synthetic discrepancy", 32, func(source string) bool { calls++; return strings.Contains(source, "discrepancy") })
	if !strings.Contains(got, "discrepancy") || len(got) >= len("synthetic discrepancy") || calls > 32 {
		t.Fatal(fmt.Sprintf("invalid minimization %q calls=%d", got, calls))
	}
}
