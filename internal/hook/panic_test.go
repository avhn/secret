package hook

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type panicInput struct{}

func (panicInput) Read([]byte) (int, error) { panic("synthetic internal failure") }

type failedOutput struct{}

var errSyntheticOutput = errors.New("synthetic output failure")

func (failedOutput) Write([]byte) (int, error) { return 0, errSyntheticOutput }

func TestPanicDenies(t *testing.T) {
	for _, host := range []string{"claude", "codex"} {
		t.Run(host, func(t *testing.T) {
			var output bytes.Buffer
			if err := Decide(host, panicInput{}, &output); err != nil {
				t.Fatal(err)
			}
			if strings.Count(output.String(), `"permissionDecision":"deny"`) != 1 {
				t.Fatalf("panic did not produce one denial: %s", output.String())
			}
			if strings.Contains(output.String(), "synthetic internal failure") {
				t.Fatal("panic payload escaped into host output")
			}
			if err := Decide(host, panicInput{}, failedOutput{}); !errors.Is(err, errSyntheticOutput) {
				t.Fatalf("output error lost: %v", err)
			}
		})
	}
}
