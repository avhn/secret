package policy

import (
	"github.com/avhn/secret/internal/hook/paths"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestFifthAuditReproducers pins the Go and shared findings without reading host configuration.
func TestFifthAuditReproducers(t *testing.T) {
	_, _, root := isolatedGitFixture(t)
	plain := filepath.Join(root, "plain")
	for _, dir := range []string{"sub", ".secrets"} {
		if err := os.MkdirAll(filepath.Join(plain, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join("sub", "app.env"), filepath.Join(".secrets", "store")} {
		if err := os.WriteFile(filepath.Join(plain, file), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	linkFallback := false
	for _, alias := range []string{"link", "link;p"} {
		if err := os.Symlink("app.env", filepath.Join(plain, "sub", alias)); err != nil {
			if runtime.GOOS != "windows" {
				t.Fatal(err)
			}
			linkFallback = true // Windows runners can lack symlink creation privileges.
		}
	}
	// Each alias case supplies its own synthetic config; the policy must not read it.
	for _, tc := range []struct{ name, command, config string }{
		{"GO5-1 uppercase alias", "git ZZ", "[alias]\n ZZ = !cat .env\n"},
		{"GO5-1 mixed alias", "git Zz", "[alias]\n Zz = !cat .env\n"},
		{"GO5-2 linked worktree alias", "git z", "[alias]\n z = !cat .env\n"},
		{"GO5-3 comment continuation", "git z", "[alias]\n # comment \\\n z = !cat .env\n"},
		{"GO5-3 semicolon continuation", "git z", "[alias]\n ; comment \\\n z = !cat .env\n"},
		{"GO5-3 BOM", "git z", "\xef\xbb\xbf[alias]\n z = !cat .env\n"},
		{"GO5-3 empty subsection", "git z", "[alias]\n z = !cat .env\n[alias \"\"]\n z = log\n"},
		{"GO5-3 dot subsection", "git z", "[alias]\n z = !cat .env\n[alias.]\n z = log\n"},
		{"GO5-3 continuation key", "git nz", "[alias]\n y = log \\\n nz = !cat .env\n"},
		{"GO5-4 relative git dir", "git --git-dir=rel/.git z", "[alias]\n z = !cat .env\n"},
		{"GO5-4 environment git dir", "GIT_DIR=rel/.git git z", "[alias]\n z = !cat .env\n"},
		{"GO5-6 autocorrect alias", "git zx", "[help]\n autocorrect = immediate\n[alias]\n zq = !cat .env\n"},
		{"B5-1 HOME alias", "HOME=other git z", "[alias]\n z = !cat .env\n"},
		{"B5-1 GIT_CONFIG_GLOBAL", "GIT_CONFIG_GLOBAL=other git z", "[alias]\n z = !cat .env\n"},
		{"P1a inline safe alias", "git -c alias.z=log z", "[alias]\n z = log\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caseRepo, gitDir, caseRoot := isolatedGitFixture(t)
			config := filepath.Join(gitDir, "config")
			if strings.HasPrefix(tc.name, "GO5-4") {
				config = filepath.Join(caseRepo, "rel", ".git", "config")
				if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(tc.name, "B5-1") {
				other := filepath.Join(caseRoot, "other")
				if err := os.MkdirAll(other, 0700); err != nil {
					t.Fatal(err)
				}
				config = filepath.Join(other, ".gitconfig")
				if tc.name == "B5-1 HOME alias" {
					tc.command = "HOME='" + filepath.ToSlash(other) + "' git z"
				} else {
					tc.command = "GIT_CONFIG_GLOBAL='" + filepath.ToSlash(config) + "' git z"
				}
			}
			if tc.name == "GO5-2 linked worktree alias" {
				common := filepath.Join(caseRoot, "common", ".git")
				if err := os.MkdirAll(filepath.Join(common, "worktrees", "linked"), 0700); err != nil {
					t.Fatal(err)
				}
				config = filepath.Join(common, "config")
				caseRepo = filepath.Join(caseRoot, "linked")
				if err := os.MkdirAll(caseRepo, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(caseRepo, ".git"), []byte("gitdir: "+filepath.ToSlash(filepath.Join(common, "worktrees", "linked"))+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(config, []byte(tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			check := func(name, dir string) bool { return paths.Protected(name, dir, "", caseRoot) }
			if reason := Analyze(tc.command, caseRepo, caseRoot, check); reason == "" {
				t.Fatal("alias allowed")
			}
		})
	}
	for _, tc := range []struct{ name, command string }{
		{"B5-2 busybox ash", "busybox ash -c 'paste sub/link'"},
		{"B5-2 dash", "dash -c 'paste sub/link'"},
		{"P9 busybox sh", "busybox sh -c 'paste sub/link'"},
		{"P9 toybox sh", "toybox sh -c 'paste sub/link'"},
		{"P9 env yash", "env yash -c 'paste sub/link'"},
		{"P9 posh", "posh -c 'paste sub/link'"},
		{"P9 mksh", "mksh -c 'paste sub/link'"},
		{"P9 applet", "busybox paste sub/link"},
		{"B5-3 I address", "sed -n '/x/Irsub/link' in.txt"},
		{"B5-3 M address", "sed -n '/x/Mrsub/link' in.txt"},
		{"B5-3 custom address", `sed -n '\%x%Irsub/link' in.txt`},
		{"P10 semicolon in filename", `sed -n 'r sub/link;p' in.txt`},
		{"P10 range", "sed -n '1,/x/MI!{r sub/link\n}' in.txt"},
		{"P10 substitution write", "sed -n 's|x|y|w sub/link' in.txt"},
		{"P10 substitution exec", "sed -n 's|x|paste sub/link|e' in.txt"},
		{"P10 malformed", "sed -n 's|x|y' in.txt"},
		{"B5-4 bash option", `bash -O cdable_vars -c 'paste sub/link'`},
		{"B5-4 quoted bash option", `bash -O cdable_""vars -c 'paste sub/link'`},
		{"B5-4 quoted shopt", `shopt -s cdable_'vars'; paste sub/link`},
		{"B5-4 variable cd", `bash -O cdable_vars -c 's=.secrets; cd s; paste store'`},
		{"P11 plus option", `bash +O autocd -c 'paste sub/link'`},
		{"P9 toybox ash", `toybox ash -c 'paste sub/link'`},
		{"P11 set option", `set -o extglob; paste sub/link`},
		{"P12 printf", `printf -v GIT_EDITOR safe; git status`},
		{"P12 reference", `declare -n ref=GIT_EDITOR; git status`},
		{"P12 read", `read -r GIT_EDITOR < in.txt; git status`},
		{"P12 mapfile", `mapfile -t GIT_EDITOR < in.txt; git status`},
		{"P12 dynamic export", `export "$NAME=literal"; git status`},
		{"P12 eval", `eval 'GIT_EDITOR=safe'; git status`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(name, dir string) bool {
				if linkFallback && (name == "sub/link" || name == "sub/link;p") {
					return true
				}
				return paths.Protected(name, dir, "", root)
			}
			if reason := Analyze(tc.command, plain, root, check); reason == "" {
				t.Fatal("protected or indeterminate command allowed")
			}
		})
	}
}

// TestFifthAuditSafeForms preserves safe built-ins and fully parsed sed scripts.
func TestFifthAuditSafeForms(t *testing.T) {
	repo, _, root := isolatedGitFixture(t)
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, source := range []string{
		"git status", "git -c color.ui=always status",
		"bash -O nullglob -c 'git status'", "busybox sh -c 'git status'",
		"sed -n '1,/x/M!{s|x|y|gp; p}' safe.txt",
		"sed -n '\\%x%Ip' safe.txt", "sed -n 'y|abc|def|' safe.txt",
		"printf -v ORDINARY safe; git status",
	} {
		t.Run(source, func(t *testing.T) {
			if reason := Analyze(source, repo, root, check); reason != "" {
				t.Fatalf("safe form denied: %s", reason)
			}
		})
	}
	for _, source := range []string{"ash -c", "dash -c 'garbled (('", "sed -n 's|x|y|z' safe.txt", "git UNKNOWN"} {
		t.Run(source, func(t *testing.T) {
			if reason := Analyze(source, repo, root, check); reason == "" {
				t.Fatal("indeterminate form allowed")
			}
		})
	}
}
