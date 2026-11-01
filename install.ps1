# Latest-release standalone installer. HTTPS script execution is the bootstrap trust root.
# Keep state local for irm URL | iex. No source build or host activation occurs.
& {
    $ErrorActionPreference = 'Stop'
    # A PowerShell 7 parent leaks its PSModulePath into Windows PowerShell 5.1, which then
    # cannot autoload Get-Acl or Get-Item. Load the core modules from this host's own folder.
    foreach ($module in @('Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')) {
        Import-Module (Join-Path $PSHOME "Modules\$module") -ErrorAction Stop
    }
    $version = ''
    if (Test-Path Env:SECRET_VERSION) { $version = $env:SECRET_VERSION }
    if (Test-Path Env:SECRET_RELEASE_COMMIT) { throw 'secret: commit pinning was removed; see docs/install.md for checkout verification' }
    $directory = $env:INSTALL_DIR
    $seen = @{}; $showHelp = $false
    for ($i = 0; $i -lt $args.Count; $i++) {
        $option = [string]$args[$i]
        if ($option -eq '--commit') { throw 'secret: commit pinning was removed; see docs/install.md for checkout verification' }
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
            '--dir' { $directory = $value }
        }
        $seen[$option] = $true
    }
    if ($showHelp) {
        Write-Output 'Usage: install.ps1 [--version V] [--dir DIR] [--help]'
        Write-Output 'SECRET_VERSION defaults to the latest release; explicit versions allow rollback.'
        Write-Output 'INSTALL_DIR defaults to $HOME\.local\bin (native user profile fallback). curl.exe is required.'
        Write-Output 'Adds only its directory to user PATH. No source build, stores, profiles or client edits.'
        return
    }
    $pinned = (Test-Path Env:SECRET_VERSION) -or $seen.ContainsKey('--version')
    $version = $version -creplace '^v', ''
    if ($pinned -and $version -cnotmatch '\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z') { throw 'secret: invalid release pin' }
    if ($env:OS -ne 'Windows_NT') { throw 'secret: unsupported platform' }
    $curl = Get-Command curl.exe -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue
    if (-not $curl) { throw 'secret: curl.exe is required from a trusted package channel' }
    # Bounded native process output, detached stdin.
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
                $url = $locations[0].Groups[1].Value
                if ($url -cnotmatch '\Ahttps://(github\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com)/' -or
                    $url -match '[\x00-\x20\x7f\\]') { throw 'unsafe redirect' }
            }
            throw 'redirect limit'
        }
        function Get-Digest([string]$path) {
            # .NET directly: Get-FileHash needs module autoload, which a PowerShell 7 PSModulePath breaks in 5.1.
            $stream = [IO.File]::OpenRead($path)
            try { $sha = [Security.Cryptography.SHA256]::Create(); try { -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() } }
            finally { $stream.Dispose() }
        }
        if (-not $version) {
            $latestBody = Join-Path $scratch 'latest-body'; $latestHeaders = Join-Path $scratch 'latest-headers'
            New-PrivateDirectory $latestBody; New-PrivateDirectory $latestHeaders
            $body = Join-Path $latestBody 'response'; $headers = Join-Path $latestHeaders 'response'
            $code = Invoke-Bounded $curl.Source @('--silent', '--proto', '=https', '--proto-redir', '=https', '--max-redirs', '0',
                '--connect-timeout', '10', '--max-time', '60', '--max-filesize', '4096', '--dump-header', $headers,
                '--output', $body, '--write-out', '%{http_code}', 'https://github.com/avhn/secret/releases/latest') 1024 90 $body 4096 $headers
            if ($code -notin @('301', '302', '303', '307', '308') -or
                (Get-Item -LiteralPath $body).Length -gt 4096 -or (Get-Item -LiteralPath $headers).Length -gt 65536) { throw 'invalid latest response' }
            $locations = [regex]::Matches([IO.File]::ReadAllText($headers), '(?im)^location:[ \t]*([^\r\n]+)\r?$')
            if ($locations.Count -ne 1 -or $locations[0].Groups[1].Value -cnotmatch
                '\Ahttps://github.com/avhn/secret/releases/tag/v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))\z') { throw 'invalid latest redirect' }
            $version = $Matches[1]
        }
        $tag = "v$version"; $asset = "secret-$tag-windows-$arch.exe"; $manifestName = "checksums-$tag.txt"
        $manifest = Save-ReleaseFile $manifestName 4096
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
        $sha = $entries[$asset]
        Assert-Chain $directory; Assert-SafePath $directory $false $true
        if (Test-Path -LiteralPath $target) {
            Assert-SafePath $target
            if ((Get-Digest $target) -ceq $sha) {
                Write-Output "secret $version is already installed at $target"
                return
            }
        }
        $binary = Save-ReleaseFile $asset 67108864
        if ((Get-Digest $binary) -cne $sha) { throw 'checksum mismatch' }
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
        # Older releases have no --version alias. Never execute the installed file.
        $versionArgument = '--version'
        if ($version -cmatch '\A0\.[0-4]\.') { $versionArgument = 'version' }
        $line = Invoke-Bounded $binary @($versionArgument) 256 10
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
        Write-Output "Installed secret $version at $target"
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
