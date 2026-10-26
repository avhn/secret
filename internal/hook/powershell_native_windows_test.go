//go:build windows

package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/ps"
	"golang.org/x/sys/windows"
)

func TestPowerShellProductionClassifierNil(t *testing.T) {
	if powershellClassifier != nil {
		t.Fatal("production PowerShell classifier must remain nil")
	}
	_, work := windowsHookFixture(t)
	windowsHookCheck(t, "PowerShell", work, map[string]any{"command": "Write-Output public"}, powershellReason)
}

// This adapter exists only in the Windows test binary. No environment variable
// enables the production seam. Tests are serial and restore nil before cleanup.
func powerShellNativeAdapter(t *testing.T) {
	t.Helper()
	if powershellClassifier != nil {
		t.Fatal("PowerShell seam already installed")
	}
	powershellClassifier = func(e input.Envelope, cwd, home string) string {
		decision := ps.Classify([]byte(e.String("command")), ps.Context{
			Cwd: cwd, Home: home, Deadline: time.Now().Add(2 * time.Second),
			ProtectedRead: func(name string) bool { return paths.FileProtected(name, cwd, "", home) },
			ProtectedWrite: func(name string) bool {
				return paths.FileProtected(name, cwd, "", home) || paths.FileConfigWriteProtected(name, cwd, "", home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("GIT_CONFIG_GLOBAL"))
			},
			CertifyPath: powerShellCertifyPath,
		})
		return decision.Reason
	}
	t.Cleanup(func() { powershellClassifier = nil })
}

func powerShellCertifyPath(name string, kind ps.FileKind) bool {
	info, err := os.Lstat(name)
	if os.IsNotExist(err) && kind == ps.NonDirectory {
		// Missing destinations need a real, non-reparse directory parent.
		return powerShellCertifyPath(filepath.Dir(name), ps.Directory)
	}
	if err != nil {
		return false
	}
	if kind == ps.Directory && !info.IsDir() || kind != ps.Directory && !info.Mode().IsRegular() {
		return false
	}
	// Lstat of a child follows parent junctions. Inspect all ancestor attributes
	// as well so a regular leaf under a reparse cannot supply a kind proof.
	for current := name; ; {
		pointer, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return false
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return true
}

func powerShellNativeCheck(t *testing.T, cwd, source string, allow bool) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"tool_name": "PowerShell", "cwd": cwd, "tool_input": map[string]any{"command": source}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Decide("claude", bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	if (out.Len() == 0) != allow {
		t.Fatalf("synthetic source %q: decision=%s want allow=%v", source, out.Bytes(), allow)
	}
	if !allow {
		var denial any
		if err := json.Unmarshal(out.Bytes(), &denial); err != nil {
			t.Fatalf("invalid denial: %v", err)
		}
	}
}

func powerShellFixtureFile(t *testing.T, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("synthetic public bytes"), 0600); err != nil {
		t.Fatal(err)
	}
}
func psQuote(name string) string { return "'" + strings.ReplaceAll(name, "'", "''") + "'" }

func TestPowerShellNativeCommandRoles(t *testing.T) {
	home, work := windowsHookFixture(t)
	profile := filepath.Join(work, "different-userprofile")
	if err := os.Mkdir(profile, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", profile)
	public, protected := filepath.Join(work, "public.txt"), filepath.Join(home, ".secrets", "data.txt")
	for _, name := range []string{public, protected, filepath.Join(home, ".yarnrc.yml"), filepath.Join(profile, ".yarnrc.yml")} {
		powerShellFixtureFile(t, name)
	}
	powerShellNativeAdapter(t)
	for _, tc := range []struct {
		name, format string
		directory    bool
	}{
		{"Write-Output", `Write-Output 'literal' > %s`, false},
		{"Out-Null", `Get-Content -LiteralPath %s | Out-Null`, false},
		{"Get-Content", `Get-Content -LiteralPath %s`, false},
		{"Select-String", `Select-String -Pattern 'literal' -LiteralPath %s`, false},
		{"Get-ChildItem", `Get-ChildItem -Name -LiteralPath %s`, true},
		{"Copy-Item source", `Copy-Item -LiteralPath %s -Destination destination.txt`, false},
		{"Copy-Item destination", `Copy-Item public.txt -Destination %s`, false},
		{"Set-Content", `Set-Content -LiteralPath %s -Value 'literal'`, false},
		{"Add-Content", `Write-Output 'literal' | Add-Content -LiteralPath %s`, false},
		{"Out-File", `Write-Output 'literal' | Out-File -FilePath %s`, false},
		{"ForEach-Object", `Write-Output 'literal' | ForEach-Object { Get-Content -LiteralPath %s }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := public, protected
			if tc.directory {
				a, b = work, filepath.Dir(protected)
			}
			powerShellNativeCheck(t, work, fmt.Sprintf(tc.format, psQuote(a)), true)
			powerShellNativeCheck(t, work, fmt.Sprintf(tc.format, psQuote(b)), false)
		})
	}
	for _, alias := range []string{"gc", "cat", "type", "GC", "sls", "gci", "ls", "dir", "cp", "copy", "cpi", "%", "foreach"} {
		for _, private := range []bool{false, true} {
			name := public
			if private {
				name = protected
			}
			source := alias + " -LiteralPath " + psQuote(name)
			switch strings.ToLower(alias) {
			case "sls":
				source += " -Pattern literal"
			case "gci", "ls", "dir":
				source = alias + " -Name -LiteralPath " + psQuote(filepath.Dir(name))
			case "cp", "copy", "cpi":
				source += " -Destination destination.txt"
			case "%", "foreach":
				source = "Write-Output literal | " + alias + " { Get-Content " + psQuote(name) + " }"
			}
			powerShellNativeCheck(t, work, source, !private)
		}
	}
	// Literal data is never promoted to a path, including a protected-looking name.
	powerShellNativeCheck(t, work, "Write-Output "+psQuote(protected), true)
	powerShellNativeCheck(t, work, "Get-Content "+psQuote(filepath.Join(home, ".yarnrc.yml")), false)
	powerShellNativeCheck(t, work, "Get-Content "+psQuote(filepath.Join(profile, ".yarnrc.yml")), true)
	// The literal dollar directory is anchored first and never expanded as HOME.
	dollar := filepath.Join(work, "$HOME")
	powerShellFixtureFile(t, filepath.Join(dollar, "public.txt"))
	powerShellFixtureFile(t, filepath.Join(dollar, ".secrets", "data.txt"))
	powerShellNativeCheck(t, work, `Get-Content '.\$HOME\public.txt'`, true)
	powerShellNativeCheck(t, work, `Set-Content '.\$HOME\public.txt' -Value literal`, true)
	powerShellNativeCheck(t, work, `Get-Content '.\$HOME\.secrets\data.txt'`, false)
	powerShellNativeCheck(t, work, `Set-Content '.\$HOME\.secrets\data.txt' -Value literal`, false)
	powerShellNativeCheck(t, filepath.Dir(protected), `Get-Content data.txt`, false)
	powerShellNativeCheck(t, filepath.Dir(protected), `Set-Content data.txt -Value literal`, false)
	powerShellNativeCheck(t, filepath.Dir(protected), "Get-Content "+psQuote(public), true)
	powerShellNativeCheck(t, filepath.Dir(protected), "Set-Content "+psQuote(public)+" -Value literal", true)
	// Both configured global and XDG writes use the file tools' stricter proof.
	global, xdg := filepath.Join(work, "ordinary-global"), filepath.Join(work, "xdg")
	powerShellFixtureFile(t, global)
	powerShellFixtureFile(t, filepath.Join(xdg, "git", "config"))
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	for _, name := range []string{global, filepath.Join(xdg, "git", "config")} {
		powerShellNativeCheck(t, work, "Get-Content "+psQuote(name), true)
		powerShellNativeCheck(t, work, "Set-Content "+psQuote(name)+" -Value literal", false)
	}
}

func TestPowerShellNativePathAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	publicDir, privateDir := filepath.Join(home, "public"), filepath.Join(home, ".secrets")
	for _, dir := range []string{publicDir, privateDir} {
		powerShellFixtureFile(t, filepath.Join(dir, "data.txt"))
	}
	powerShellNativeAdapter(t)
	checkPair := func(t *testing.T, public, private string) {
		t.Helper()
		for _, format := range []string{"Get-Content %s", "Set-Content %s -Value literal", "Write-Output literal > %s", "Write-Output literal | %% { Get-Content %s }"} {
			powerShellNativeCheck(t, work, fmt.Sprintf(format, psQuote(public)), true)
			powerShellNativeCheck(t, work, fmt.Sprintf(format, psQuote(private)), false)
		}
	}
	t.Run("junction", func(t *testing.T) {
		system, err := windows.GetSystemDirectory()
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]string{{"public-junction", publicDir}, {"private-junction", privateDir}} {
			if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", filepath.Join(work, pair[0]), pair[1]).CombinedOutput(); err != nil {
				t.Fatalf("required junction: %v (%s)", err, output)
			}
		}
		checkPair(t, filepath.Join(work, "public-junction", "data.txt"), filepath.Join(work, "private-junction", "data.txt"))
		// Even a public reparse cannot certify a copy source or directory enumeration.
		powerShellNativeCheck(t, work, `Copy-Item public-junction\data.txt -Destination destination.txt`, false)
		powerShellNativeCheck(t, work, `Get-ChildItem -Name public-junction`, false)
	})
	t.Run("symlink", func(t *testing.T) {
		public, private := filepath.Join(work, "public-link"), filepath.Join(work, "private-link")
		if err := os.Symlink(filepath.Join(publicDir, "data.txt"), public); err != nil {
			t.Skipf("symlink creation unavailable on this image: %v", err)
		}
		if err := os.Symlink(filepath.Join(privateDir, "data.txt"), private); err != nil {
			t.Fatal(err)
		}
		checkPair(t, public, private)
		powerShellNativeCheck(t, work, `Copy-Item public-link -Destination destination.txt`, false)
	})
	t.Run("subst", func(t *testing.T) {
		public, private := windowsHookSubst(t, publicDir), windowsHookSubst(t, privateDir)
		checkPair(t, public+"data.txt", private+"data.txt")
	})
	t.Run("UNC-admin-C$", func(t *testing.T) {
		root, err := os.MkdirTemp(`C:\Windows\Temp`, "secret-ps-admin-")
		if err != nil {
			t.Fatalf("required C$ fixture: %v", err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(root); err != nil {
				t.Errorf("C$ fixture cleanup: %v", err)
			}
		})
		public, private := filepath.Join(root, "public.txt"), filepath.Join(root, ".secrets", "data.txt")
		powerShellFixtureFile(t, public)
		powerShellFixtureFile(t, private)
		toUNC := func(name string) string {
			return `\\localhost\C$` + strings.TrimPrefix(name, filepath.VolumeName(name))
		}
		if _, err := os.Stat(toUNC(public)); err != nil {
			t.Fatalf("required C$ public witness: %v", err)
		}
		checkPair(t, toUNC(public), toUNC(private))
		// The ordinary basename has no lexical credential cue. Native identity
		// must retain the configured local target across the C$ spelling.
		t.Setenv("AWS_CONFIG_FILE", public)
		powerShellNativeCheck(t, work, "Get-Content "+psQuote(toUNC(public)), false)
		powerShellNativeCheck(t, work, "Set-Content "+psQuote(toUNC(public))+" -Value literal", false)
	})
	t.Run("8.3", func(t *testing.T) {
		long := filepath.Join(home, "long-synthetic-powershell-name.txt")
		powerShellFixtureFile(t, long)
		pointer, err := windows.UTF16PtrFromString(long)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]uint16, 32768)
		n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 || n >= uint32(len(buffer)) {
			t.Fatalf("8.3 query failed: %v", err)
		}
		short := windows.UTF16ToString(buffer[:n])
		if strings.EqualFold(filepath.Base(short), filepath.Base(long)) {
			t.Logf("8.3 basename support absent on fixture volume %s; no short-alias evidence claimed", filepath.VolumeName(long))
		} else {
			t.Logf("8.3 basename support present on fixture volume %s; native identity witness tested", filepath.VolumeName(long))
		}
		powerShellNativeCheck(t, work, "Get-Content "+psQuote(short), true)
		t.Setenv("AWS_CONFIG_FILE", long)
		powerShellNativeCheck(t, work, "Get-Content "+psQuote(short), false)
	})
}
