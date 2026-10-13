package cli

import (
	"strings"
	"testing"

	"github.com/avhn/secret/internal/store"
)

func TestChildEnvironment(t *testing.T) {
	selection := store.Selection{Keys: []string{"A", "B", "C"}, Matched: map[string]store.Record{"A": {Value: []byte("last")}, "B": {Value: []byte("selected")}}, AllValues: [][]byte{[]byte("old"), []byte("last")}}
	ambient := []string{"HOME=/tmp", "A=ambient", "B=ambient", "C=ambient", "OPT=ambient", "KEEP=ambient", "SECRET_CHILD_DATA=ambient"}
	for _, tc := range []struct {
		name               string
		required, optional []string
		want               string
		failed             bool
	}{
		{"default", nil, nil, "HOME=/tmp,A=last,B=selected,KEEP=ambient", false},
		{"required", []string{"A"}, nil, "HOME=/tmp,A=last,KEEP=ambient,OPT=ambient", false},
		{"optional", nil, []string{"B", "OPT"}, "HOME=/tmp,B=selected,KEEP=ambient", false},
		{"absent", []string{"C"}, nil, "", true},
		{"invalid", nil, []string{"2BAD"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := childEnvironment(ambient, selection, tc.required, tc.optional, "/tmp/fallback.store")
			if (e != nil) != tc.failed {
				t.Fatalf("error: %v", e)
			}
			if !tc.failed {
				// Ambient surviving keys retain order; selected keys append in store order.
				want := strings.Split(tc.want, ",")
				if tc.name == "required" {
					want = []string{"HOME=/tmp", "OPT=ambient", "KEEP=ambient", "A=last"}
				}
				if tc.name == "default" {
					want = []string{"HOME=/tmp", "OPT=ambient", "KEEP=ambient", "A=last", "B=selected"}
				}
				if tc.name == "optional" {
					want = []string{"HOME=/tmp", "KEEP=ambient", "B=selected"}
				}
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Fatalf("got %q want %q", got, want)
				}
			}
		})
	}
}

func TestChildEnvironmentFilePrecedence(t *testing.T) {
	first, _ := store.Select([]store.Record{{Key: "A", Value: []byte("earlier")}, {Key: "B", Value: []byte("first-only")}}, store.Selectors{})
	later, _ := store.Select([]store.Record{{Key: "A", Value: []byte("later"), Labels: map[string]string{"env": "dev"}}, {Key: "A", Value: []byte("unselected"), Labels: map[string]string{"env": "prod"}}}, store.Selectors{"env": "dev"})
	missing, _ := store.Select([]store.Record{{Key: "A", Value: []byte("unselected"), Labels: map[string]string{"env": "prod"}}}, store.Selectors{"env": "dev"})
	for _, tc := range []struct {
		name       string
		selections []store.Selection
		want       string
	}{
		{"later selected", []store.Selection{first, later}, "A=later,B=first-only"},
		{"later unselected", []store.Selection{first, missing}, "A=earlier,B=first-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := childEnvironment(nil, store.Merge(tc.selections...), nil, nil, "fallback")
			if e != nil {
				t.Fatal(e)
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
