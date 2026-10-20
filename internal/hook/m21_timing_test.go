package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestM21DelayedStdin(t *testing.T) {
	if DecisionTimeout != 4*time.Second {
		t.Fatal("update the documented four-second decision bound and its tests together")
	}
	root := t.TempDir()
	data, err := json.Marshal(map[string]any{"tool_name": "Read", "cwd": root, "tool_input": map[string]string{"file_path": "public.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			name      string
			delay     time.Duration
			eof, deny bool
		}{
			{"delayed complete", 50 * time.Millisecond, true, false},
			{"no first byte", 3 * time.Second, true, true},
			{"delayed held eof", 1500 * time.Millisecond, false, true},
		} {
			t.Run(host+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				r, w := io.Pipe()
				defer r.Close()
				defer w.Close()
				stop := make(chan struct{})
				defer close(stop)
				go func() {
					timer := time.NewTimer(tc.delay)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-stop:
						return
					}
					_, _ = w.Write(data)
					if tc.eof {
						_ = w.Close()
					}
				}()
				start := time.Now()
				var output bytes.Buffer
				if err := Decide(host, r, &output); err != nil {
					t.Fatal(err)
				}
				if elapsed := time.Since(start); elapsed > DecisionTimeout+time.Second {
					t.Fatalf("decision exceeded documented total bound: %s", elapsed)
				}
				if denied := strings.Contains(output.String(), `"permissionDecision":"deny"`); denied != tc.deny {
					t.Fatalf("denied=%v want %v", denied, tc.deny)
				}
			})
		}
	}
}

func TestM21SharedDecisionDeadline(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		readDelay, analysisDelay time.Duration
	}{
		{"input stalls", 250 * time.Millisecond, 0},
		{"analysis stalls", 0, 250 * time.Millisecond},
		{"combined phases", 80 * time.Millisecond, 170 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			finished := make(chan struct{})
			start := time.Now()
			err := decideWithin(&output, 150*time.Millisecond, func(out io.Writer) error {
				defer close(finished)
				time.Sleep(tc.readDelay)
				time.Sleep(tc.analysisDelay)
				_, err := io.WriteString(out, "synthetic late decision")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			// Allow scheduler headroom on race-enabled and native CI runners.
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("phase delays extended total deadline: %s", elapsed)
			}
			before := output.String()
			if strings.Count(before, `"permissionDecision":"deny"`) != 1 {
				t.Fatalf("expected one fixed denial: %s", before)
			}
			<-finished
			if output.String() != before {
				t.Fatal("late analysis wrote to host output")
			}
		})
	}
}
