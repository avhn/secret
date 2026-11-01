# Pinned standalone installer. HTTPS script execution is the bootstrap trust root.
# Keep state local for irm URL | iex. No source build or host activation occurs.
& {
    $ErrorActionPreference = 'Stop'
    $version = '0.3.5'
    if (Test-Path Env:SECRET_VERSION) { $version = $env:SECRET_VERSION }
    $commit = $env:SECRET_RELEASE_COMMIT
    $directory = $env:INSTALL_DIR
    $seen = @{}; $showHelp = $false
    for ($i = 0; $i -lt $args.Count; $i++) {
        $option = [string]$args[$i]
        if ($option -in @('--help', '-h')) { $showHelp = $true; continue }
        if ($option -notin @('--version', '--commit', '--dir') -or $seen.ContainsKey($option) -or $i + 1 -ge $args.Count) {
            throw 'secret: invalid arguments (use --help)'
        }
        $i++; $value = [string]$args[$i]
        if (-not $value -or $value.StartsWith('--')) { throw 'secret: invalid arguments (use --help)' }
        switch -Exact ($option) {
            '--version' {
                if ((Test-Path Env:SECRET_VERSION) -and $version.TrimStart('v') -cne $value.TrimStart('v')) { throw 'secret: conflicting version pins' }
                $version = $value
            }
            '--commit' {
                if ($commit -and $commit -cne $value) { throw 'secret: conflicting commit pins' }
                $commit = $value
            }
            '--dir' { $directory = $value }
        }
        $seen[$option] = $true
    }
    if ($showHelp) {
        Write-Output 'Usage: install.ps1 [--version V] [--commit C] [--dir DIR] [--help]'
        Write-Output 'SECRET_VERSION defaults to 0.3.5; SECRET_RELEASE_COMMIT optionally pins a full SHA.'
        Write-Output 'INSTALL_DIR defaults to $HOME\.local\bin (native user profile fallback). gh and curl.exe are required.'
        Write-Output 'Adds only its directory to user PATH. No source build, stores, profiles or client edits.'
        return
    }
    $version = $version -creplace '^v', ''
    if ($version -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z' -or
        ($commit -and $commit -cnotmatch '\A[0-9a-f]{40}\z')) { throw 'secret: invalid release pin' }
    if ($env:OS -ne 'Windows_NT') { throw 'secret: unsupported platform' }
    $gh = Get-Command gh -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue
    $curl = Get-Command curl.exe -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue
    if (-not $gh -or -not $curl) { throw 'secret: gh and curl.exe are required from a trusted package channel' }
    # Bounded native process output, detached stdin and strict duplicate-key JSON.
    if (-not ('SecretInstallerV032.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace SecretInstallerV032 {
 public static class Native {
  [DllImport("kernel32.dll", ExactSpelling=true)]
  static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
  public static ushort NativeMachine() {
   try {
    ushort processMachine, nativeMachine;
    if (!IsWow64Process2(GetCurrentProcess(), out processMachine, out nativeMachine)) {
     if (Marshal.GetLastWin32Error() == 120) return 0; // ERROR_CALL_NOT_IMPLEMENTED
     throw new Exception();
    }
    if (nativeMachine == 0) throw new Exception();
    return nativeMachine;
   } catch (EntryPointNotFoundException) { return 0; }
  }
  [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW", ExactSpelling=true, CharSet=CharSet.Unicode)]
  static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr parameter, string data,
                                        uint flags, uint milliseconds, out UIntPtr result);
  public static void BroadcastEnvironment() {
   UIntPtr result;
   // HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG. A timeout is not failure.
   SendMessageTimeout(new IntPtr(0xffff), 0x001a, UIntPtr.Zero, "Environment", 0x0002, 5000, out result);
  }
  [StructLayout(LayoutKind.Sequential)] struct HandleInfo {
   public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle handle, out HandleInfo info);
  public static void SingleLink(string path) {
   using (var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
    HandleInfo info;
    if (!GetFileInformationByHandle(stream.SafeFileHandle, out info) || info.Links != 1) throw new Exception();
   }
  }
  static string Quote(string s) {
   var b = new StringBuilder("\""); int n = 0;
   foreach (char c in s) {
    if (c == '\\') { n++; continue; }
    if (c == '"') b.Append('\\', n * 2 + 1); else b.Append('\\', n);
    n = 0; b.Append(c);
   }
   return b.Append('\\', n * 2).Append('"').ToString();
  }
  static byte[] Read(Stream s, int limit, Process p) {
   using (var m = new MemoryStream()) {
    var b = new byte[8192]; int n;
    while ((n = s.Read(b, 0, b.Length)) > 0) {
     if (m.Length + n > limit) { try { p.Kill(); } catch {} throw new Exception(); }
     m.Write(b, 0, n);
    }
    return m.ToArray();
   }
  }
  public static string Run(string exe, string[] args, int limit, int seconds, string watched, long maximum, string headers) {
   var a = new List<string>(); foreach (string s in args) a.Add(Quote(s));
   using (var p = new Process()) {
    p.StartInfo = new ProcessStartInfo(exe, String.Join(" ", a.ToArray()));
    p.StartInfo.UseShellExecute = false; p.StartInfo.CreateNoWindow = true;
    p.StartInfo.RedirectStandardInput = true; p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError = true;
    p.StartInfo.EnvironmentVariables["GH_PROMPT_DISABLED"] = "1";
    p.StartInfo.EnvironmentVariables["GH_NO_UPDATE_NOTIFIER"] = "1";
    p.Start(); p.StandardInput.Close();
    var output = Task.Run(() => Read(p.StandardOutput.BaseStream, limit, p));
    var error = Task.Run(() => Read(p.StandardError.BaseStream, 1048576, p));
    var timer = Stopwatch.StartNew();
    try {
     while (!p.WaitForExit(20)) {
      if (timer.Elapsed.TotalSeconds > seconds ||
          (watched != null && File.Exists(watched) && new FileInfo(watched).Length > maximum) ||
          (headers != null && File.Exists(headers) && new FileInfo(headers).Length > 65536)) throw new Exception();
     }
     if (!Task.WaitAll(new Task[] { output, error }, 2000) || p.ExitCode != 0) throw new Exception();
     return new UTF8Encoding(false, true).GetString(output.Result);
    } finally { if (!p.HasExited) { p.Kill(); p.WaitForExit(); } }
   }
  }
  public static void Json(string value) { var j = new StrictJson(value); j.Value(0); j.End(); }
 }
 sealed class StrictJson {
  readonly string s; int p;
  public StrictJson(string value) { s = value; }
  void Space() { while (p < s.Length && " \r\n\t".IndexOf(s[p]) >= 0) p++; }
  char Take() { if (p == s.Length) throw new Exception(); return s[p++]; }
  void Need(char c) { Space(); if (Take() != c) throw new Exception(); }
  string Text() {
   Need('"'); var b = new StringBuilder();
   while (true) {
    char c = Take(); if (c == '"') return b.ToString(); if (c < 32) throw new Exception();
    if (c == '\\') {
     c = Take(); int i = "\"\\/bfnrt".IndexOf(c);
     if (c == 'u') { if (p + 4 > s.Length) throw new Exception(); b.Append((char)Convert.ToInt32(s.Substring(p,4),16)); p += 4; }
     else { if (i < 0) throw new Exception(); b.Append("\"\\/\b\f\n\r\t"[i]); }
    } else b.Append(c);
   }
  }
  public void Value(int depth) {
   if (depth > 64) throw new Exception(); Space(); if (p == s.Length) throw new Exception();
   char c = s[p];
   if (c == '"') { Text(); return; }
   if (c == '{' || c == '[') {
    p++; Space(); char close = c == '{' ? '}' : ']';
    var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (p < s.Length && s[p] == close) { p++; return; }
    while (true) {
     if (c == '{') { if (!keys.Add(Text())) throw new Exception(); Need(':'); }
     Value(depth + 1); Space(); char next = Take(); if (next == close) return;
     if (next != ',') throw new Exception();
    }
   }
   int start = p; while (p < s.Length && ",]} \r\n\t".IndexOf(s[p]) < 0) p++;
   string atom = s.Substring(start, p - start);
   if (atom != "true" && atom != "false" && atom != "null" &&
       !System.Text.RegularExpressions.Regex.IsMatch(atom, @"\A-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?\z")) throw new Exception();
  }
  public void End() { Space(); if (p != s.Length) throw new Exception(); }
 }
}
'@
    }
    # Resolve wrappers from the caller when shadowed by the native test harness.
    if (-not (Get-Command Get-SecretNativeMachine -CommandType Function -TotalCount 1 -ErrorAction SilentlyContinue)) {
        function Get-SecretNativeMachine { [SecretInstallerV032.Native]::NativeMachine() }
    }
    if (-not (Get-Command Send-SecretEnvironmentChange -CommandType Function -TotalCount 1 -ErrorAction SilentlyContinue)) {
        function Send-SecretEnvironmentChange { [SecretInstallerV032.Native]::BroadcastEnvironment() }
    }
    if (-not (Get-Command Report-SecretInstallFailure -CommandType Function -TotalCount 1 -ErrorAction SilentlyContinue)) {
        function Report-SecretInstallFailure([string]$category, [string]$types, [string]$hresults) { }
    }
    try { $nativeMachine = Get-SecretNativeMachine } catch { throw 'secret: unsupported platform' }
    if ($nativeMachine -eq 0xaa64) { $arch = 'arm64' }
    elseif ($nativeMachine -eq 0x8664) { $arch = 'amd64' }
    elseif ($nativeMachine -eq 0) {
        # Older kernels lack IsWow64Process2. Preserve the previous fallback only
        # for that unavailable API, never instead of a supported native result.
        $architecture = $env:PROCESSOR_ARCHITECTURE
        if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
        switch ($architecture) {
            'AMD64' { $arch = 'amd64' }
            'ARM64' { $arch = 'arm64' }
            default { throw 'secret: unsupported platform' }
        }
    } else { throw 'secret: unsupported platform' }
    $scratch = $null; $owned = $false; $lock = $null
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    # Write only the owner section, naming this user; the DACL is untouched.
    function Set-CurrentOwner([string]$path) {
        $ownerOnly = New-Object Security.AccessControl.FileSecurity
        $ownerOnly.SetOwner($identity)
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($path), $ownerOnly)
        } else { (New-Object IO.FileInfo($path)).SetAccessControl($ownerOnly) }
    }
    function Assert-SafePath([string]$path, [bool]$private = $false, [bool]$installDirectory = $false) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'unsafe path' }
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        if ($owner -notin @($identity.Value, 'S-1-5-18', 'S-1-5-32-544', $trustedInstaller)) { throw 'unsafe owner' }
        if ($private -and ($owner -ne $identity.Value -or -not $acl.AreAccessRulesProtected)) { throw 'non-private destination' }
        if ($installDirectory -and (-not $item.PSIsContainer -or $owner -ne $identity.Value)) { throw 'unsafe destination' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor
                     [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                     [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
            # System roots may let users create their own subdirectories. That
            # does not grant replacement of an existing protected child directory.
            if ($item.PSIsContainer -and -not $private -and -not $installDirectory) { $write = $write -band (-bnot 4) }
            if (($installDirectory -or -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) -and
                $rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -and
                $sid -notin @($identity.Value, 'S-1-5-18', 'S-1-5-32-544', $trustedInstaller)) { throw 'unsafe DACL' }
        }
        if (-not $item.PSIsContainer) {
            [SecretInstallerV032.Native]::SingleLink($path)
            if ($item.Length -gt 67108864) { throw 'oversized destination' }
        }
    }
    function Assert-Chain([string]$path) {
        while ($path) {
            Assert-SafePath $path
            $parent = [IO.Directory]::GetParent($path)
            if (-not $parent) { break }; $path = $parent.FullName
        }
    }
    function New-PrivateDirectory([string]$path) {
        if (Test-Path -LiteralPath $path) { Assert-Chain $path; return }
        $parent = [IO.Directory]::GetParent($path).FullName
        New-PrivateDirectory $parent
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetOwner($identity); $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544')) {
            $principal = New-Object Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        # .NET Framework supports atomic ACL creation; .NET 7 uses the extension method.
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $acl)
        } else { [IO.Directory]::CreateDirectory($path, $acl) | Out-Null }
        Assert-SafePath $path $true
    }
    function Invoke-Bounded([string]$exe, [string[]]$arguments, [int]$limit = 1048576, [int]$seconds = 90, [string]$watched = $null, [long]$maximum = 0, [string]$headers = $null) {
        [SecretInstallerV032.Native]::Run($exe, $arguments, $limit, $seconds, $watched, $maximum, $headers)
    }
    $failureCategory = 'destination-safety'
    try {
        if (-not $directory) {
            # HOME is optional for native Windows callers. Never use LOCALAPPDATA.
            $profileRoot = $env:HOME
            if (-not $profileRoot) { $profileRoot = [Environment]::GetFolderPath('UserProfile') }
            if (-not $profileRoot) { throw 'missing user profile' }
            $directory = Join-Path $profileRoot '.local\bin'
        }
        if ($directory -match '[\x00-\x1f\x7f;~]' -or $directory -match '(^|[\\/])\.{1,2}([\\/]|$)' -or $directory.StartsWith('\\') -or
            $directory -match '(^|[\\/])[^\\/]*[. ]([\\/]|$)' -or $directory -match '(^|[\\/])(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])([.]|[\\/]|$)') { throw 'unsafe directory' }
        if (($directory -replace '^[A-Za-z]:', '') -match ':') { throw 'unsafe directory' }
        $directory = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($directory))
        if ($directory.Contains('%')) { throw 'secret: install directory must not contain %' }
        # Verify authentication before creating directories or downloading inputs.
        # Status output is discarded; credentials are never inspected or in argv.
        $failureCategory = 'github-auth'
        try { $null = Invoke-Bounded $gh.Source @('auth', 'status', '--hostname', 'github.com') 1048576 60 }
        catch { throw 'secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry' }
        $failureCategory = 'destination-safety'
        New-PrivateDirectory $directory; Assert-SafePath $directory $false $true
        $target = Join-Path $directory 'secret.exe'
        if (Test-Path -LiteralPath $target) { Assert-SafePath $target }
        $scratch = Join-Path $directory ('.secret-install-' + [Guid]::NewGuid().ToString('N'))
        New-PrivateDirectory $scratch
        $lock = Join-Path $directory '.secret.install-lock'
        $token = "pid=$PID`ntoken=" + [Guid]::NewGuid().ToString('N') + "`n"
        for ($attempt = 0; $attempt -lt 4; $attempt++) {
            try {
                # CreateNew is the atomic lock claim, not New-Item -Force.
                $handle = [IO.File]::Open($lock, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                $bytes = [Text.Encoding]::ASCII.GetBytes($token); $handle.Write($bytes, 0, $bytes.Length); $handle.Dispose()
                $owned = $true; break
            } catch [IO.IOException] {
                Assert-SafePath $lock
                if ($attempt -eq 3) { throw 'installation lock timeout; verify and remove stale lock manually' }
                Start-Sleep -Seconds 1
            }
        }
        $failureCategory = 'download-verification'
        $tag = "v$version"; $asset = "secret-$tag-windows-$arch.exe"; $manifestName = "checksums-$tag.txt"
        function Save-ReleaseFile([string]$name, [long]$limit) {
            $url = "https://github.com/avhn/secret/releases/download/$tag/$name"
            for ($redirect = 0; $redirect -lt 4; $redirect++) {
                $bodyDir = Join-Path $scratch ([Guid]::NewGuid().ToString('N'))
                $headerDir = Join-Path $scratch ([Guid]::NewGuid().ToString('N'))
                New-PrivateDirectory $bodyDir; New-PrivateDirectory $headerDir
                $body = Join-Path $bodyDir $name; $headers = Join-Path $headerDir 'response'
                $code = Invoke-Bounded $curl.Source @('--silent', '--proto', '=https', '--proto-redir', '=https', '--max-redirs', '0',
                    '--connect-timeout', '10', '--max-time', '60', '--max-filesize', [string]$limit, '--dump-header', $headers,
                    '--output', $body, '--write-out', '%{http_code}', $url) 1024 90 $body $limit $headers
                if ((Get-Item -LiteralPath $body).Length -gt $limit -or (Get-Item -LiteralPath $headers).Length -gt 65536) { throw 'oversized response' }
                if ($code -ceq '200') { return $body }
                if ($code -notin @('301', '302', '303', '307', '308') -or $redirect -eq 3) { throw 'HTTP failure' }
                $locations = [regex]::Matches([IO.File]::ReadAllText($headers), '(?im)^location:[ \t]*([^\r\n]+)\r?$')
                if ($locations.Count -ne 1) { throw 'invalid redirect' }
                $url = $locations[0].Groups[1].Value; $uri = [uri]$url
                if ($uri.Scheme -cne 'https' -or $uri.Authority -cne 'release-assets.githubusercontent.com' -or $url -match '[\x00-\x20\\]') { throw 'unsafe redirect' }
            }
            throw 'redirect limit'
        }
        function Get-Digest([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
        function Confirm-Attestation([string]$path, [string]$name, [string]$expected) {
            $sha = Get-Digest $path
            $bundle = Save-ReleaseFile "sha256-$sha.jsonl" 1048576
            $arguments = @('attestation', 'verify', $path, '--repo', 'avhn/secret', '--source-ref', "refs/tags/$tag",
                '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--cert-identity',
                "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/$tag", '--deny-self-hosted-runners',
                '--bundle', $bundle, '--format', 'json')
            if ($expected) { $arguments += @('--source-digest', $expected, '--signer-digest', $expected) }
            $json = Invoke-Bounded $gh.Source $arguments
            [SecretInstallerV032.Native]::Json($json)
            if (-not $json.TrimStart().StartsWith('[')) { throw 'invalid verification results' }
            $results = @($json | ConvertFrom-Json)
            if ($results.Count -eq 0) { throw 'empty verification results' }
            $sourceCommit = $null
            foreach ($result in $results) {
                $statement = $result.verificationResult.statement
                $subjects = @($statement.subject)
                if ($statement.predicateType -cne 'https://slsa.dev/provenance/v1' -or $subjects.Count -eq 0) { throw 'wrong subject' }
                foreach ($subject in $subjects) {
                    if (-not ($subject -is [pscustomobject])) { throw 'invalid subject' }
                }
                $matchingSubjects = @($subjects | Where-Object { $_.name -ceq $name })
                if ($matchingSubjects.Count -ne 1) { throw 'ambiguous subject' }
                $digestNames = @($matchingSubjects[0].digest.PSObject.Properties.Name)
                if ($digestNames.Count -ne 1 -or $digestNames[0] -cne 'sha256' -or
                    $matchingSubjects[0].digest.sha256 -cne $sha) { throw 'wrong subject digest' }
                $definition = $statement.predicate.buildDefinition; $workflow = $definition.externalParameters.workflow
                if ($workflow.repository -cne 'https://github.com/avhn/secret' -or $workflow.ref -cne "refs/tags/$tag" -or
                    $workflow.path -cne '.github/workflows/release.yml') { throw 'wrong source workflow' }
                $dependencies = @($definition.resolvedDependencies | Where-Object {
                    $_.uri -cin @("git+https://github.com/avhn/secret@refs/tags/$tag", "https://github.com/avhn/secret@refs/tags/$tag")
                })
                if ($dependencies.Count -ne 1) { throw 'ambiguous source' }
                $value = $dependencies[0].digest.gitCommit
                if ($value -cnotmatch '\A[0-9a-f]{40}\z' -or ($expected -and $value -cne $expected) -or
                    ($sourceCommit -and $value -cne $sourceCommit)) { throw 'wrong source commit' }
                $sourceCommit = $value
            }
            return $sourceCommit
        }
        function Invoke-ReleaseAPI([string]$endpoint, [int]$limit = 16384) {
            $json = Invoke-Bounded $gh.Source @('api', '--hostname', 'github.com', '--method', 'GET', "repos/avhn/secret/$endpoint") $limit
            [SecretInstallerV032.Native]::Json($json)
            if (-not $json.TrimStart().StartsWith('{')) { throw 'invalid API object' }
            $json | ConvertFrom-Json
        }
        function Confirm-SourceBoundary([string]$authenticated, [string]$manifest) {
            $reference = Invoke-ReleaseAPI "git/ref/tags/$tag"
            if ($reference.ref -cne "refs/tags/$tag" -or $reference.object.type -cne 'tag') { throw 'not an annotated tag' }
            $target = $reference.object; $visited = @{}; $peeled = $false
            for ($depth = 0; $depth -lt 8; $depth++) {
                $sha = $target.sha
                if ($sha -cnotmatch '\A[0-9a-f]{40}\z' -or $visited.ContainsKey($sha)) { throw 'invalid tag object' }
                $visited[$sha] = $true
                $annotated = Invoke-ReleaseAPI "git/tags/$sha"
                if ($annotated.sha -cne $sha -or ($depth -eq 0 -and $annotated.tag -cne $tag)) { throw 'wrong tag object' }
                $target = $annotated.object
                if ($target.type -ceq 'commit') {
                    if ($target.sha -cne $authenticated) { throw 'tag does not peel to C' }
                    $peeled = $true; break
                }
                if ($target.type -cne 'tag') { throw 'invalid tag target' }
            }
            if (-not $peeled) { throw 'tag depth exceeded' }
            # This endpoint diffs C against its sole parent. A result with more
            # than one file fails; never paginate into an apparent one-file C.
            $final = Invoke-ReleaseAPI "commits/${authenticated}?per_page=100" 1048576
            $parents = @($final.parents); $files = @($final.files)
            if ($final.sha -cne $authenticated -or $parents.Count -ne 1 -or
                $parents[0].sha -cnotmatch '\A[0-9a-f]{40}\z' -or $parents[0].sha -ceq $authenticated) { throw 'invalid C parent' }
            $checksumPath = "dist/$manifestName"
            if ($files.Count -ne 1 -or $files[0].filename -cne $checksumPath -or $files[0].status -cne 'added' -or
                @($files[0].PSObject.Properties.Name) -ccontains 'previous_filename') { throw 'not checksum-only C' }
            $blob = $files[0].sha
            if ($blob -cnotmatch '\A[0-9a-f]{40}\z') { throw 'invalid checksum blob' }
            $contents = Invoke-ReleaseAPI "contents/${checksumPath}?ref=$authenticated"
            if ($contents.type -cne 'file' -or $contents.path -cne $checksumPath -or $contents.sha -cne $blob -or
                $contents.encoding -cne 'base64') { throw 'wrong committed checksum file' }
            if ((-not ($contents.size -is [int]) -and -not ($contents.size -is [long])) -or
                $contents.size -lt 0 -or $contents.size -gt 4096 -or -not ($contents.content -is [string]) -or
                $contents.content.Length -gt 8192 -or $contents.content -cnotmatch '\A[A-Za-z0-9+/=\r\n]*\z') { throw 'invalid committed checksum bytes' }
            $committed = [Convert]::FromBase64String($contents.content)
            $downloaded = [IO.File]::ReadAllBytes($manifest)
            if ($committed.Length -ne $contents.size -or $committed.Length -ne $downloaded.Length) { throw 'committed checksum mismatch' }
            for ($index = 0; $index -lt $committed.Length; $index++) {
                if ($committed[$index] -ne $downloaded[$index]) { throw 'committed checksum mismatch' }
            }
        }
        $manifest = Save-ReleaseFile $manifestName 4096
        $authenticated = Confirm-Attestation $manifest $manifestName $commit
        $again = Confirm-Attestation $manifest $manifestName $authenticated
        if ($again -cne $authenticated) { throw 'inconsistent commit' }
        Confirm-SourceBoundary $authenticated $manifest
        $names = @('server.json', "secret-$tag-desktop.mcpb")
        foreach ($system in @('darwin', 'linux', 'windows')) {
            foreach ($cpu in @('amd64', 'arm64')) {
                $suffix = ''; if ($system -eq 'windows') { $suffix = '.exe' }
                $names += "secret-$tag-$system-$cpu$suffix"
            }
        }
        [Array]::Sort($names, [StringComparer]::Ordinal)
        $text = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($manifest))
        $lines = $text.Split([char]10)
        if ($lines.Count -ne 9 -or $lines[8] -cne '') { throw 'invalid checksum manifest' }
        $entries = @{}
        for ($i = 0; $i -lt 8; $i++) {
            if ($lines[$i] -cnotmatch ('\A[0-9a-f]{64}  ' + [regex]::Escape($names[$i]) + '\z')) { throw 'invalid checksum record' }
            $entries[$names[$i]] = $lines[$i].Substring(0,64)
        }
        $binary = Save-ReleaseFile $asset 67108864; $sha = $entries[$asset]
        if ((Get-Digest $binary) -cne $sha) { throw 'checksum mismatch' }
        $binaryCommit = Confirm-Attestation $binary $asset $authenticated
        if ($binaryCommit -cne $authenticated) { throw 'inconsistent commit' }
        $stream = [IO.File]::OpenRead($binary)
        try {
            $reader = New-Object IO.BinaryReader($stream)
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'not PE' }
            $stream.Position = 0x3c; $offset = $reader.ReadUInt32()
            if ($offset -gt $stream.Length - 6) { throw 'truncated PE' }
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550) { throw 'not PE' }
            $machine = $reader.ReadUInt16(); $expectedMachine = 0x8664
            if ($arch -eq 'arm64') { $expectedMachine = 0xaa64 }
            if ($machine -ne $expectedMachine) { throw 'wrong architecture' }
        } finally { $stream.Dispose() }
        $line = Invoke-Bounded $binary @('version') 256 10
        if ($line -cne "secret $version (go)`n" -or (Get-Digest $binary) -cne $sha) { throw 'wrong version or modified binary' }
        # An elevated token defaults new owners to Administrators, and Replace
        # publishes the scratch file's owner. Own the private scratch first, where
        # this user holds full control, so a Modify-only destination needs no write.
        $failureCategory = 'publication-owner'
        Set-CurrentOwner $binary
        $failureCategory = 'publication-safety'
        Assert-Chain $directory; Assert-SafePath $directory $false $true
        if (Test-Path -LiteralPath $target) {
            Assert-SafePath $target
            $failureCategory = 'atomic-replacement'
            # PowerShell converts $null to an empty string for .NET string
            # parameters. File.Replace needs a real CLR null to omit the backup.
            # Open-image failures preserve the old file. Never delete-first/copy.
            [IO.File]::Replace($binary, $target, [System.Management.Automation.Language.NullString]::Value)
        } else {
            $failureCategory = 'atomic-create'
            [IO.File]::Move($binary, $target)
        }
        # Should Replace keep the old owner instead, correct it here. Skip the write
        # when already owned: ownership grants no WRITE_OWNER under a Modify-only DACL.
        $failureCategory = 'publication-owner'
        if ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value) {
            Set-CurrentOwner $target
        }
        if ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value) { throw 'unsafe owner' }
        $failureCategory = 'user-path'
        # Read/update only the user registry PATH, not the merged process PATH.
        $key = Get-Item -LiteralPath 'HKCU:\Environment'
        $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $present = @($userPath -split ';' | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ieq $directory.TrimEnd('\') }).Count -gt 0
        if (-not $present) {
            $newPath = $directory
            if ($userPath) { $newPath = $userPath.TrimEnd(';') + ';' + $directory }
            New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name Path -Value $newPath -PropertyType ExpandString -Force | Out-Null
            Send-SecretEnvironmentChange
        }
        $quoted = "'" + ($target -replace "['\u2018\u2019\u201A\u201B]", '$0$0') + "'"
        Write-Output "Installed $target"
        Write-Output "claude mcp add --scope user --transport stdio secret -- $quoted mcp --store 'file:C:\ABSOLUTE\STORE'"
        Write-Output 'Raw executable only: no per-exec checkout rehash, MCP registration or hook activation. Open a new terminal for user PATH.'
    } catch {
        # Tests may record fixed stages, CLR type names and numeric HRESULTs.
        # Never forward exception messages, stack traces, paths or tool output.
        $types = @(); $hresults = @(); $cause = $_.Exception
        for ($depth = 0; $depth -lt 8 -and $null -ne $cause; $depth++) {
            $types += $cause.GetType().FullName
            $hresults += $cause.HResult.ToString('X8')
            $cause = $cause.InnerException
        }
        Report-SecretInstallFailure $failureCategory ($types -join ',') ($hresults -join ',')
        if ($_.Exception.Message -in @(
            'secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry',
            'secret: install directory must not contain %')) { throw $_.Exception.Message }
        if ($_.Exception.Message -eq 'installation lock timeout; verify and remove stale lock manually') {
            throw 'secret: installation lock timeout; verify and remove stale lock manually'
        }
        throw 'secret: release installation failed; no source build or verification fallback'
    } finally {
        if ($owned -and (Test-Path -LiteralPath $lock)) {
            try {
                Assert-SafePath $lock
                if ((Get-Item -LiteralPath $lock).Length -le 128 -and [IO.File]::ReadAllText($lock) -ceq $token) { [IO.File]::Delete($lock) }
            } catch { } # Changed owner/alias requires manual recovery, never stealing.
        }
        if ($scratch -and (Test-Path -LiteralPath $scratch)) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
} @args
