#Requires -Version 7.0
<#
Hosted Windows integration only. CI builds both inputs before invoking this script.
All values are synthetic and travel on stdin, never argv, diagnostics or CI output.
Changing HOME does not isolate CredMan: only the exact journaled namespace is used.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $SecretExe,
    [Parameter(Mandatory)][string] $ConsoleFixture,
    [switch] $CleanupOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Assert-True([bool] $Condition, [string] $Name) {
    if (-not $Condition) { throw "Windows integration assertion failed: $Name" }
}

Assert-True ($IsWindows -and $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_OS -eq 'Windows') 'hosted Windows required'
foreach ($path in @($SecretExe, $ConsoleFixture, $env:RUNNER_TEMP)) {
    Assert-True ([IO.Path]::IsPathFullyQualified($path) -and (Test-Path -LiteralPath $path)) 'absolute existing input required'
}
$script:Utf8 = [Text.UTF8Encoding]::new($false)
$script:Values = @()
$script:Work = $env:RUNNER_TEMP

# Capture bytes, not PowerShell's native text pipeline (which transcodes output).
# Never include an exception's process arguments or captured output in a failure.
function Invoke-Captured([string] $Image, [string[]] $Arguments, [byte[]] $InputBytes = @(),
        [int] $TimeoutMilliseconds = 60000) {
    foreach ($arg in $Arguments) {
        foreach ($value in $script:Values) {
            Assert-True (-not $arg.Contains($value)) 'synthetic value absent from argv'
        }
    }
    $start = [Diagnostics.ProcessStartInfo]::new($Image)
    $start.UseShellExecute = $false
    $start.WorkingDirectory = $script:Work
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($arg in $Arguments) { $start.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdout = [IO.MemoryStream]::new()
    $stderr = [IO.MemoryStream]::new()
    $started = $false
    try {
        $started = $process.Start()
        Assert-True $started 'process starts'
        $copyOut = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $copyErr = $process.StandardError.BaseStream.CopyToAsync($stderr)
        $process.StandardInput.BaseStream.Write($InputBytes, 0, $InputBytes.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Kill($true)
            throw 'Windows integration process timeout'
        }
        Assert-True ([Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($copyOut, $copyErr), 10000)) 'output drains'
        Assert-True ($stdout.Length -le 1MB -and $stderr.Length -le 1MB) 'bounded captured output'
        $got = [pscustomobject]@{ Code = $process.ExitCode; Out = $stdout.ToArray(); Err = $stderr.ToArray() }
        Assert-NoValues $got.Out
        Assert-NoValues $got.Err
        return $got
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

function Assert-NoValues([byte[]] $Bytes) {
    foreach ($encoding in @($script:Utf8, [Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode)) {
        $text = $encoding.GetString($Bytes)
        foreach ($value in $script:Values) {
            Assert-True (-not $text.Contains($value)) 'no synthetic values in captured output'
        }
    }
}

function Invoke-Fixture($Request) {
    $bytes = $script:Utf8.GetBytes(($Request | ConvertTo-Json -Depth 8 -Compress))
    # Launcher mode includes a required 20 s idle exchange and detached waits.
    $timeoutMilliseconds = if ($Request.Mode -eq 'launcher') { 180000 } else { 60000 }
    $got = Invoke-Captured $ConsoleFixture @() $bytes -TimeoutMilliseconds $timeoutMilliseconds
    if ($got.Code -ne 0 -or $got.Err.Length -ne 0) {
        # Fixture diagnostics are fixed strings; still prove no synthetic value
        # is present before printing a bounded excerpt for CI triage.
        Assert-NoValues $got.Err
        $detail = $script:Utf8.GetString($got.Err)
        if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) }
        Write-Host ('fixture mode ' + $Request.Mode + ' exited ' + $got.Code + ': ' + $detail.Trim())
    }
    Assert-True ($got.Code -eq 0 -and $got.Err.Length -eq 0) 'native fixture succeeds'
    $reply = $script:Utf8.GetString($got.Out) | ConvertFrom-Json
    if ($null -ne $reply.Output) { Assert-NoValues ([Convert]::FromBase64String($reply.Output)) }
    return $reply
}

if ($CleanupOnly) {
    $null = Invoke-Fixture @{ Mode = 'cleanup' }
    Write-Output 'PASS independent exact CredMan cleanup and absence verification'
    exit 0
}

Assert-True ($env:SECRET_REQUIRE_WINCRED -eq '1') 'required CredMan gate enabled'
$journal = Join-Path $env:RUNNER_TEMP 'secret-windows-cli-targets.jsonl'
Assert-True (-not (Test-Path -LiteralPath $journal)) 'fresh exact-target journal'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:Sid = $identity.User
$identity.Dispose()
$root = Join-Path $env:RUNNER_TEMP ('secret native cli ' + [Guid]::NewGuid().ToString('N'))
$shareName = 'secret-m5a-' + [Guid]::NewGuid().ToString('N')
$shareCreated = $false
$drive = $null
$junction = $null
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$subst = Join-Path $env:SystemRoot 'System32\subst.exe'
$pwsh = (Get-Command pwsh -CommandType Application | Select-Object -First 1).Source

function New-PrivateDirectory([string] $Path) {
    $null = [IO.Directory]::CreateDirectory($Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($script:Sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($script:Sid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-PrivateAcl $Path
}

function Assert-PrivateAcl([string] $Path) {
    $acl = Get-Acl -LiteralPath $Path
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $script:Sid.Value) 'private owner SID'
    Assert-True ($acl.AreAccessRulesProtected) 'private protected DACL'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-True ($rules.Count -gt 0) 'nonempty private DACL'
    foreach ($rule in $rules) {
        Assert-True ($rule.IdentityReference.Value -eq $script:Sid.Value -and -not $rule.IsInherited -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
                [Security.AccessControl.FileSystemRights]::FullControl) 'owner-only explicit full control'
    }
    $check = Invoke-Captured (Join-Path $env:SystemRoot 'System32\icacls.exe') @($Path, '/verify')
    Assert-True ($check.Code -eq 0) 'icacls verifies private object'
}

function Quote-Pwsh([string] $Text) { return "'" + $Text.Replace("'", "''") + "'" }
function Quote-Cmd([string] $Text) {
    Assert-True ($Text -notmatch '["%\r\n]') 'literal cmd fixture argument'
    return '"' + $Text + '"'
}

# Generate value-free launch scripts. The same CLI matrix is exercised via both
# shells, with binary, wrappers and working directory all containing spaces.
function New-ShellInvocation([string] $Shell, [string] $Image, [string[]] $Arguments) {
    $stem = Join-Path $script:Work ([Guid]::NewGuid().ToString('N'))
    if ($Shell -eq 'cmd') {
        $path = $stem + '.cmd'
        $line = (@($Image) + $Arguments | ForEach-Object { Quote-Cmd $_ }) -join ' '
        [IO.File]::WriteAllText($path, "@echo off`r`n$line`r`nexit /b %errorlevel%`r`n", $script:Utf8)
        # Use a value-free basename in the space-containing cwd, avoiding CRT
        # argv quoting rules on cmd's /c command tail. The batch quotes secret.exe.
        return @{ Executable = $cmd; Args = @('/d', '/c', [IO.Path]::GetFileName($path)) }
    }
    $path = $stem + '.ps1'
    $line = (@($Image) + $Arguments | ForEach-Object { Quote-Pwsh $_ }) -join ' '
    [IO.File]::WriteAllText($path, "`$ErrorActionPreference = 'Continue'`n& $line`nexit `$LASTEXITCODE`n", $script:Utf8)
    return @{ Executable = $pwsh; Args = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $path) }
}

function Invoke-Shell([string] $Shell, [string] $Image, [string[]] $Arguments, [byte[]] $InputBytes = @()) {
    $launch = New-ShellInvocation $Shell $Image $Arguments
    return Invoke-Captured $launch.Executable $launch.Args $InputBytes
}

function Assert-Deny($Got, [string] $Reason, [switch] $Unavailable) {
    if ($Unavailable) {
        Assert-True ($Got.Code -eq 2 -and $script:Utf8.GetString($Got.Err).Trim() -ceq
            'secret: development binary unavailable') 'missing sibling blocks with status 2'
    } else {
        Assert-True ($Got.Code -eq 0 -and $Got.Err.Length -eq 0) 'shim exits successfully with decision'
    }
    $decision = ($script:Utf8.GetString($Got.Out) | ConvertFrom-Json).hookSpecificOutput
    $expected = $Reason
    if (-not $Reason.StartsWith('secret:')) {
        $expected += '; use secret show FILE for masked names, or secret run -f FILE -- CMD; never disguise a denied command'
    }
    Assert-True ($decision.hookEventName -ceq 'PreToolUse' -and $decision.permissionDecision -ceq 'deny' -and
        $decision.permissionDecisionReason -ceq $expected) 'fixed shim denial'
}

function Test-HookPath([string] $Shell, [string] $Path, [bool] $Denied) {
    $body = @{ tool_name = 'Read'; cwd = $script:Work; tool_input = @{ file_path = $Path } } | ConvertTo-Json -Compress
    $got = Invoke-Shell $Shell $script:Shim @() $script:Utf8.GetBytes($body)
    if ($Denied) { Assert-Deny $got 'file access targets a protected store' }
    else { Assert-True ($got.Code -eq 0 -and $got.Out.Length -eq 0 -and $got.Err.Length -eq 0) 'public shim control allowed' }
}

$script:Primary = $null
try {
    Write-Output ('Runner OS build: ' + [Environment]::OSVersion.VersionString)
    Write-Output ('Runner image: ' + $env:ImageOS + ' ' + $env:ImageVersion + '; architecture: ' + [Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    Write-Output ('PowerShell: ' + $PSVersionTable.PSVersion.ToString())
    $version = Invoke-Captured (Get-Command go -CommandType Application | Select-Object -First 1).Source @('version')
    Assert-True ($version.Code -eq 0 -and $script:Utf8.GetString($version.Out).Contains('go1.27.3')) 'pinned Go version'
    Write-Output ($script:Utf8.GetString($version.Out).Trim())
    New-PrivateDirectory $root
    $homeRoot = Join-Path $root 'home space'
    $storeRoot = Join-Path $root 'store space'
    $tempRoot = Join-Path $root 'temp space'
    $workRoot = Join-Path $root 'work space'
    # ACL verification launches icacls. Keep its cwd at RUNNER_TEMP until every
    # directory exists, including when setup fails before the work root is made.
    foreach ($dir in @($homeRoot, $storeRoot, $tempRoot, $workRoot)) { New-PrivateDirectory $dir }
    $script:Work = $workRoot
    $env:USERPROFILE = $homeRoot
    $env:HOME = $homeRoot
    $env:SECRETS_DIR = $storeRoot
    $env:SECRETS_ENV = Join-Path $homeRoot 'absent.env'
    $env:TEMP = $tempRoot
    $env:TMP = $tempRoot
    $env:TMPDIR = $tempRoot
    foreach ($name in @('SECRET_AUDIT_DIR', 'SECRET_AGE_IDENTITY', 'SECRET_BACKEND_STUB_DIR',
            'KUBECONFIG', 'AWS_CONFIG_FILE', 'AWS_SHARED_CREDENTIALS_FILE', 'GH_CONFIG_DIR',
            'XDG_CONFIG_HOME', 'GIT_CONFIG_GLOBAL', 'GIT_DIR', 'GIT_COMMON_DIR')) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    $binary = Join-Path $script:Work 'secret.exe'
    Copy-Item -LiteralPath $SecretExe -Destination $binary
    $script:Shim = Join-Path $script:Work 'guard-go.cmd'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\hooks\guard-go.cmd') -Destination $script:Shim
    $value = 'synthetic-native-' + [Guid]::NewGuid().ToString('N') + '-é'
    $credValue = 'synthetic-credman-' + [Guid]::NewGuid().ToString('N')
    $script:Values = @($value, $credValue)
    $file = Join-Path $storeRoot 'native.secret'
    $reference = 'file:' + $file
    [IO.File]::WriteAllText((Join-Path $script:Work 'public.txt'), 'public control', $script:Utf8)
    $child = Join-Path $script:Work 'child output.ps1'
    [IO.File]::WriteAllText($child, @'
param([string] $Mode)
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'exec') {
    [Console]::Out.WriteLine('exec-ok')
    [Console]::Error.WriteLine('exec-err')
    exit 23
}
if ([string]::Join(' ', [Environment]::GetCommandLineArgs()).Contains($env:TOKEN)) { exit 91 }
$encoding = switch ($Mode) {
    'utf8' { [Text.UTF8Encoding]::new($false) }
    'utf16le' { [Text.Encoding]::Unicode }
    'utf16be' { [Text.Encoding]::BigEndianUnicode }
    default { exit 92 }
}
$bytes = $encoding.GetBytes('out:' + $env:TOKEN + ':done')
[Console]::OpenStandardOutput().Write($bytes, 0, $bytes.Length)
$bytes = $encoding.GetBytes('err:' + $env:TOKEN + ':done')
[Console]::OpenStandardError().Write($bytes, 0, $bytes.Length)
'@, $script:Utf8)
    # Production exec uses real inherited pipes/files, not cli.Main buffers.
    # This lifecycle mode never activates or accesses a credential provider.
    $lifecycleRoot = Join-Path $root 'launcher lifecycle'
    New-PrivateDirectory $lifecycleRoot
    $lifecycle = Invoke-Fixture @{ Mode = 'launcher'; Executable = $binary; Path = $lifecycleRoot }
    Assert-True ($lifecycle.Code -eq 0 -and $null -eq $lifecycle.Output) 'long-lived detached exec and checked containment'
    Write-Output 'PASS synthetic configured-launcher lifecycle (not real-host compatibility)'

    $credRef = 'wincred:m5a-cli-' + $env:GITHUB_RUN_ID + '-' + $env:GITHUB_RUN_ATTEMPT + '-' + $env:GITHUB_JOB + '-' + [Guid]::NewGuid().ToString('N')
    $null = Invoke-Fixture @{ Mode = 'seed'; Reference = $credRef; Value = [Convert]::ToBase64String($script:Utf8.GetBytes($credValue)) }
    $manifest = Join-Path $storeRoot ($credRef.Substring(8) + '.wincred-keys')
    Assert-PrivateAcl $manifest

    foreach ($shell in @('cmd', 'pwsh')) {
        # Stash's console gate is real. A separate prebuilt fixture supplies only
        # hidden input through a required ConPTY after observing the final prompt.
        $launch = New-ShellInvocation $shell $binary @('stash', $reference, 'TOKEN')
        $terminal = Invoke-Fixture @{ Mode = 'console'; Executable = $launch.Executable; Args = $launch.Args;
            Prompt = 'TOKEN: '; Value = [Convert]::ToBase64String($script:Utf8.GetBytes($value)) }
        Assert-True ($terminal.Code -eq 0) 'console stash succeeds'
        Assert-PrivateAcl $file
        foreach ($ref in @($reference, $credRef)) {
            $got = Invoke-Shell $shell $binary @('show', $ref)
            Assert-True ($got.Code -eq 0 -and $script:Utf8.GetString($got.Out).Contains('TOKEN')) 'names-only show'
            $expected = if ($ref -eq $reference) { $value } else { $credValue }
            $launch = New-ShellInvocation $shell $binary @('get', $ref, 'TOKEN')
            $terminal = Invoke-Fixture @{ Mode = 'get'; Executable = $launch.Executable; Args = $launch.Args;
                Value = [Convert]::ToBase64String($script:Utf8.GetBytes($expected)) }
            Assert-True ($terminal.Code -eq 0 -and $null -eq $terminal.Output) 'terminal get checked privately using stdin expectation'
            foreach ($mode in @('utf8', 'utf16le', 'utf16be')) {
                $got = Invoke-Shell $shell $binary @('run', '-f', $ref, '--key', 'TOKEN', '--',
                    $pwsh, '-NoLogo', '-NoProfile', '-File', $child, $mode)
                Assert-True ($got.Code -eq 0) 'filtered run succeeds'
                Assert-True ($script:Utf8.GetString($got.Out).Contains('<redacted>') -and
                    $script:Utf8.GetString($got.Err).Contains('<redacted>')) 'both streams redact raw and UTF-16 values'
            }
        }
        $got = Invoke-Shell $shell $binary @('list')
        $text = $script:Utf8.GetString($got.Out)
        Assert-True ($got.Code -eq 0 -and $text.Contains('native.secret') -and $text.Contains($credRef)) 'file and wincred list'
        $got = Invoke-Shell $shell $binary @('exec', '-f', $reference, '--', $pwsh, '-NoProfile', '-File', $child, 'exec')
        Assert-True ($got.Code -eq 23 -and $script:Utf8.GetString($got.Out).Contains('exec-ok') -and
            $script:Utf8.GetString($got.Err).Contains('exec-err')) 'supervised exec preserves streams and exit'

        # Submit the get command itself on stdin, not a value or a terminal.
        # Redirected stdout must reject before exposing any bytes, even via shells.
        if ($shell -eq 'cmd') {
            $line = '@' + (Quote-Cmd $binary) + ' get ' + (Quote-Cmd $reference) + " TOKEN`r`n@exit %errorlevel%`r`n"
            $got = Invoke-Captured $cmd @('/d', '/q') $script:Utf8.GetBytes($line)
        } else {
            $line = '& ' + (Quote-Pwsh $binary) + ' get ' + (Quote-Pwsh $reference) + " TOKEN`nexit `$LASTEXITCODE`n"
            $got = Invoke-Captured $pwsh @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '-') $script:Utf8.GetBytes($line)
        }
        Assert-True ($got.Code -eq 1 -and $script:Utf8.GetString($got.Err).Contains('get is human-terminal-only')) 'get-by-stdin cannot reveal values'

        $absent = Join-Path $root 'consent must not create'
        foreach ($action in @('import', 'export', 'rename', 'rotate', 'delete', 'stash')) {
            $got = Invoke-Shell $shell $binary @($action, ('file:' + (Join-Path $absent 'store')), 'TOKEN') $script:Utf8.GetBytes("yes`n")
            Assert-True ($got.Code -eq 1 -and $script:Utf8.GetString($got.Err).Contains('terminal')) 'nonconsole input rejected'
            Assert-True (-not (Test-Path -LiteralPath $absent)) 'consent rejection before persistence'
        }
        foreach ($bad in @((Join-Path $storeRoot 'NUL.txt'), ($file + ':stream'), 'C:relative.secret')) {
            $got = Invoke-Shell $shell $binary @('show', ('file:' + $bad))
            Assert-True ($got.Code -eq 1 -and $script:Utf8.GetString($got.Err).Contains('invalid')) 'ambiguous store rejected'
            Test-HookPath $shell $bad $true
        }
        $body = @{ tool_name = 'Bash'; cwd = $script:Work; tool_input = @{ command = 'echo public' } } | ConvertTo-Json -Compress
        Assert-Deny (Invoke-Shell $shell $script:Shim @() $script:Utf8.GetBytes($body)) 'shell requests are unsupported on Windows'
        Test-HookPath $shell $file $true
        Test-HookPath $shell (Join-Path $script:Work 'public.txt') $false
        Write-Output "PASS $shell CLI, stdin, redaction, ACL and shim matrix"
    }

    # Native home discovery must work without HOME, with no ambient real profile.
    [Environment]::SetEnvironmentVariable('HOME', $null, 'Process')
    $got = Invoke-Captured $binary @('show', $reference)
    Assert-True ($got.Code -eq 0) 'USERPROFILE fallback'
    $env:HOME = $homeRoot

    # Required alias fixtures. No privilege or filesystem failure becomes a skip.
    $aliasRoot = Join-Path $root 'alias target'
    New-PrivateDirectory $aliasRoot
    $protected = Join-Path $aliasRoot 'synthetic credentials.secret'
    $public = Join-Path $aliasRoot 'public.txt'
    [IO.File]::WriteAllText($protected, '# synthetic names-only fixture', $script:Utf8)
    [IO.File]::WriteAllText($public, 'public', $script:Utf8)
    $junction = Join-Path $script:Work 'junction space'
    $null = New-Item -ItemType Junction -Path $junction -Target $aliasRoot
    Test-HookPath 'cmd' (Join-Path $junction 'synthetic credentials.secret') $true
    Test-HookPath 'pwsh' (Join-Path $junction 'public.txt') $false
    $account = $script:Sid.Translate([Security.Principal.NTAccount]).Value
    $null = New-SmbShare -Name $shareName -Path $aliasRoot -FullAccess $account -ErrorAction Stop
    $shareCreated = $true
    $unc = '\\localhost\' + $shareName
    Assert-True (Test-Path -LiteralPath (Join-Path $unc 'public.txt')) 'required UNC loopback share reachable'
    Test-HookPath 'cmd' (Join-Path $unc 'synthetic credentials.secret') $true
    Test-HookPath 'pwsh' (Join-Path $unc 'public.txt') $false
    $usedDrives = @([IO.Directory]::GetLogicalDrives())
    foreach ($letter in @('Z', 'Y', 'X', 'W', 'V', 'U', 'T')) {
        if ($usedDrives -notcontains ($letter + ':\')) {
            $candidate = $letter + ':'
            $got = Invoke-Captured $subst @($candidate, $aliasRoot)
            Assert-True ($got.Code -eq 0) 'required subst creation'
            $drive = $candidate
            break
        }
    }
    Assert-True ($null -ne $drive) 'required unused subst drive'
    Test-HookPath 'cmd' ($drive + '\synthetic credentials.secret') $true
    Test-HookPath 'pwsh' ($drive + '\public.txt') $false
    $short = Invoke-Fixture @{ Mode = 'shortpath'; Path = $protected }
    if ($short.Alias) {
        Test-HookPath 'cmd' $short.Path $true
        Write-Output 'PASS 8.3 alias available and protected'
    } else {
        Write-Output '8.3 basename alias unavailable on fixture volume; no short-alias coverage claimed'
    }
    Write-Output 'PASS required UNC loopback, junction and subst fixtures'

    $missing = Join-Path $script:Work 'missing binary space'
    New-PrivateDirectory $missing
    $missingShim = Join-Path $missing 'guard-go.cmd'
    Copy-Item -LiteralPath $script:Shim -Destination $missingShim
    foreach ($shell in @('cmd', 'pwsh')) {
        Assert-Deny (Invoke-Shell $shell $missingShim @() $script:Utf8.GetBytes('{}')) 'secret: development binary unavailable; build hooks/secret.exe' -Unavailable
    }
    Write-Output 'PASS fixed missing-binary shim denial (not host fail-closed evidence)'
} catch {
    # Report the first failure before cleanup so a later cleanup error cannot hide it.
    $script:Primary = $_
    Write-Output ('FAIL primary: ' + $_.Exception.Message + ' (' + $_.InvocationInfo.ScriptName + ':' + $_.InvocationInfo.ScriptLineNumber + ')')
} finally {
    # Attempt every cleanup even after assertion failure. Leave the journal for the
    # independent always() process, which must verify absence again.
    $cleanupFailed = $false
    try { $null = Invoke-Fixture @{ Mode = 'cleanup' } }
    catch { $cleanupFailed = $true; Write-Output 'FAIL exact CredMan cleanup or absence verification' }
    if ($null -ne $drive) {
        try {
            $got = Invoke-Captured $subst @($drive, '/D')
            Assert-True ($got.Code -eq 0 -and -not (Test-Path -LiteralPath ($drive + '\'))) 'subst cleanup and absence'
        } catch { $cleanupFailed = $true; Write-Output 'FAIL subst cleanup' }
    }
    if ($shareCreated) {
        try {
            Remove-SmbShare -Name $shareName -Force -Confirm:$false -ErrorAction Stop
            Assert-True ($null -eq (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) 'share absence'
        } catch { $cleanupFailed = $true; Write-Output 'FAIL exact share cleanup' }
    }
    try {
        if ($null -ne $junction -and (Test-Path -LiteralPath $junction)) { [IO.Directory]::Delete($junction) }
        $script:Work = $env:RUNNER_TEMP
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
        Assert-True (-not (Test-Path -LiteralPath $root)) 'disposable root removed'
    } catch { $cleanupFailed = $true; Write-Output 'FAIL disposable filesystem cleanup' }
    if ($cleanupFailed) { throw 'Windows integration cleanup could not prove absence' }
    if ($null -ne $script:Primary) { throw $script:Primary }
}
Write-Output 'PASS isolated native Windows CLI matrix; hosted host protection is not established'
exit 0
