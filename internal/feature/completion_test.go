package feature

import (
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/avhn/secret/internal/store"
)

func TestCompleteNamesOnly(t *testing.T) {
	metadata := []store.Metadata{syntheticMetadata([]byte("Z=synthetic-secret-value\nA=synthetic-second\nA=synthetic-duplicate\n[env=prod]\nPROD=synthetic-private\n[env=dev]\nDEV=synthetic-private\n")), {
		Version: store.MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret", Records: []store.MetadataRecord{{Key: "PROVIDER", Account: "0123456789abcdef0123456789abcdef"}},
	}}
	for _, tt := range []struct {
		name    string
		request CompletionRequest
		want    []string
	}{
		{"commands", CompletionRequest{Prefix: "ro"}, []string{"rotate"}},
		{"flags", CompletionRequest{Command: "show", Prefix: "--f"}, []string{"--format=json"}},
		{"keys", CompletionRequest{Command: "run", Flag: "--key"}, []string{"A", "DEV", "PROD", "PROVIDER", "Z"}},
		{"selected keys", CompletionRequest{Command: "run", Flag: "--key", Selectors: store.Selectors{"env": "prod"}}, []string{"A", "PROD", "PROVIDER", "Z"}},
		{"optional keys", CompletionRequest{Flag: "--optional-key", Prefix: "PR"}, []string{"PROD", "PROVIDER"}},
		{"labels", CompletionRequest{Flag: "--label"}, []string{"env=dev", "env=prod"}},
		{"references", CompletionRequest{Flag: "reference", Prefix: "lib"}, []string{"libsecret:synthetic"}},
		{"provider targets only", CompletionRequest{Flag: "--to"}, []string{"libsecret:synthetic"}},
		{"empty", CompletionRequest{Flag: "--key", Prefix: "not-present"}, []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Complete(tt.request, metadata)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("candidates %q, error %v, want %q", got, err, tt.want)
			}
		})
	}
	changed := syntheticMetadata([]byte("Z=changed\nA=changed-to-a-longer-synthetic-value\nA=\n[env=prod]\nPROD=changed\n[env=dev]\nDEV=\xff\n"))
	for _, flag := range []string{"reference", "--key", "--label"} {
		request := CompletionRequest{Flag: flag}
		before, _ := Complete(request, metadata[:1])
		after, err := Complete(request, []store.Metadata{changed})
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("changing only values changed completion")
		}
	}
}

func TestCompleteImportSources(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "synthetic.secret")
	resolvedPath := filepath.Join(directory, "resolved.secret")
	metadata := []store.Metadata{
		{Version: store.MetadataVersion, Reference: "file:" + path, Backend: "file"},
		{Version: store.MetadataVersion, Reference: resolvedPath, Backend: "file"},
		{Version: store.MetadataVersion, Reference: "keychain:synthetic", Backend: "keychain"},
		{Version: store.MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret"},
	}
	imports := []string{"dotenv:" + path, "dotenv:" + resolvedPath}
	exports := []string{"file:" + path, resolvedPath, "keychain:synthetic", "libsecret:synthetic"}
	sort.Strings(imports)
	sort.Strings(exports)
	for _, tt := range []struct {
		name    string
		request CompletionRequest
		want    []string
	}{
		{"import sources", CompletionRequest{Command: "import", Flag: "--from"}, imports},
		{"import source prefix", CompletionRequest{Command: "import", Flag: "--from", Prefix: "dotenv:" + path}, []string{"dotenv:" + path}},
		{"unsupported import provider", CompletionRequest{Command: "import", Flag: "--from", Prefix: "keychain:"}, []string{}},
		{"export sources unchanged", CompletionRequest{Command: "export", Flag: "--from"}, exports},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Complete(tt.request, metadata)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("candidates %q, error %v, want %q", got, err, tt.want)
			}
			if tt.request.Command == "import" {
				for _, source := range got {
					if _, _, err := validateImportRequest(ImportRequest{Source: source, Target: "file:" + filepath.Join(directory, "target.secret")}); err != nil {
						t.Fatal("suggested import source rejected by validation")
					}
				}
			}
		})
	}
	for _, reference := range []string{"relative.secret", "file:relative.secret", "file:" + filepath.VolumeName(directory) + string(filepath.Separator)} {
		got, err := Complete(CompletionRequest{Command: "import", Flag: "--from"}, []store.Metadata{{Version: store.MetadataVersion, Reference: reference, Backend: "file"}})
		if err != nil || len(got) != 0 {
			t.Fatal("ineligible file suggested as import source")
		}
	}
}

func TestCompleteValidationAndIsolation(t *testing.T) {
	for _, request := range []CompletionRequest{
		{Command: "get-synthetic-secret"}, {Flag: "--value"}, {Prefix: "\x1b[31m"}, {Prefix: "\xff"},
		{Flag: "--key", Selectors: store.Selectors{"bad-name": "prod"}},
	} {
		if _, err := Complete(request, nil); !errors.Is(err, ErrCompletion) {
			t.Fatal("invalid completion request accepted")
		}
	}
	invalid := syntheticMetadata([]byte("A=synthetic\n"))
	invalid.Reference = "file:/synthetic/unsafe\nname"
	if _, err := Complete(CompletionRequest{Flag: "reference"}, []store.Metadata{invalid}); !errors.Is(err, ErrCompletion) {
		t.Fatal("unsafe reference emitted as shell completion")
	}
	metadata := syntheticMetadata([]byte("A=synthetic\n"))
	first, err := Complete(CompletionRequest{Flag: "--key"}, []store.Metadata{metadata})
	if err != nil {
		t.Fatal(err)
	}
	first[0] = "changed"
	second, err := Complete(CompletionRequest{Flag: "--key"}, []store.Metadata{metadata})
	if err != nil || !reflect.DeepEqual(second, []string{"A"}) {
		t.Fatal("candidates retain caller mutations")
	}
	ambiguous := syntheticMetadata([]byte("[env=prod]\nA=one\n[region=west]\nA=two\n"))
	if _, err := Complete(CompletionRequest{Flag: "--key", Selectors: store.Selectors{"env": "prod", "region": "west"}}, []store.Metadata{ambiguous}); !errors.Is(err, ErrCompletion) {
		t.Fatal("completion hid ambiguous metadata")
	}
}
