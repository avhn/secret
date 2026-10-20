package input

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestM21RawPathLimits(t *testing.T) {
	root := t.TempDir()
	for _, field := range []string{"cwd", "workdir", "file_path", "notebook_path", "path"} {
		for _, tc := range []struct {
			name, value string
			invalid     bool
		}{
			{"component at cap", strings.Repeat("a", 255), false},
			{"component over cap", strings.Repeat("a", 256), true},
			{"unicode at cap", strings.Repeat("界", 85), false},
			{"unicode over cap", strings.Repeat("界", 86), true},
			{"path at cap", strings.Repeat("a/", 2047) + "ab", false},
			{"path over cap", strings.Repeat("a/", 2048) + "a", true},
			{"redundant components", strings.Repeat("./", 2049) + "public", true},
			{"oversized before dotdot", strings.Repeat("a", 256) + "/../public", true},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				fields := map[string]any{"command": "true", field: tc.value}
				envelope := map[string]any{"tool_name": "Bash", "cwd": root, "tool_input": fields}
				if field == "cwd" {
					value := tc.value
					if strings.HasPrefix(tc.name, "path ") {
						value = value[1:] // Include the native root in the raw byte cap.
					}
					envelope["cwd"] = filepath.VolumeName(root) + string(filepath.Separator) + value
					// Account for a Windows volume without touching component cases.
					if volume := filepath.VolumeName(root); volume != "" && strings.HasPrefix(tc.name, "path ") {
						envelope["cwd"] = volume + string(filepath.Separator) + value[len(volume):]
					}
					delete(fields, field)
				}
				data, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Decode(bytes.NewReader(data))
				if (err != nil) != tc.invalid {
					t.Fatalf("invalid=%v want %v", err != nil, tc.invalid)
				}
			})
		}
	}
}
