# Native Windows PS 5.1/7 synthetic transports. Never reads/writes real user PATH.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'test-install.ps1 requires native Windows' }
$root = Split-Path -Parent $PSScriptRoot
$installer = [IO.File]::ReadAllText((Join-Path $root 'install.ps1'))
$work = Join-Path ([IO.Path]::GetTempPath()) ('secret-installer-tests-' + [Guid]::NewGuid().ToString('N'))
# setup-go can leave several go.exe on PATH; use the first, as the shell would.
$go = (Get-Command go -CommandType Application -TotalCount 1).Source
$names = @('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PATH', 'TEMP', 'TMP', 'SECRET_VERSION',
    'SECRET_RELEASE_COMMIT', 'INSTALL_DIR', 'SECRET_INSTALL_MODE', 'SECRET_INSTALL_FIXTURES', 'SECRET_INSTALL_LOG',
    'SECRET_INSTALL_ASSET', 'SECRET_INSTALL_READY', 'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOENV', 'GOWORK', 'CGO_ENABLED')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$script:fakeUserPath = '%USERPROFILE%\synthetic-existing'
$script:pathWrites = 0
$script:environmentChanges = 0
$script:nativeMachine = [uint16]0 # Exercise the existing environment fallback by default.
$originalProcessPath = $env:PATH
# Registry access is shadowed only in this test process. File access stays native.
function Get-Item {
    [CmdletBinding()] param([string]$LiteralPath, [switch]$Force)
    if ($LiteralPath -eq 'HKCU:\Environment') {
        $key = New-Object PSObject
        $key | Add-Member ScriptMethod GetValue {
            param($name, $default, $options)
            if ($name -ne 'Path' -or $options -ne [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) { throw 'unexpected registry read' }
            return $script:fakeUserPath
        }
        return $key
    }
    if ($LiteralPath.StartsWith('HKCU:')) { throw 'unexpected registry read' }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
}
function New-ItemProperty {
    [CmdletBinding()] param($LiteralPath, $Name, $Value, $PropertyType, [switch]$Force)
    if ($LiteralPath -ne 'HKCU:\Environment' -or $Name -ne 'Path' -or $PropertyType -ne 'ExpandString') { throw 'unexpected registry write' }
    $script:fakeUserPath = $Value; $script:pathWrites++
}
function Assert-True($condition, $message) { if (-not $condition) { throw "FAIL: $message" } }
# Shadow native detection and broadcasting, just as registry access is shadowed.
function Get-SecretNativeMachine { return $script:nativeMachine }
function Send-SecretEnvironmentChange {
    Assert-True ($script:environmentChanges -eq ($script:pathWrites - 1)) 'broadcast without a new user PATH write'
    $script:environmentChanges++
}
function Report-SecretInstallFailure([string]$category, [string]$types, [string]$hresults) {
    Assert-True ($category -cmatch '\A[a-z-]+\z') 'unsafe installer diagnostic category'
    Assert-True ($types -cmatch '\A[A-Za-z0-9_.+,]+\z') 'unsafe installer diagnostic type'
    Assert-True ($hresults -cmatch '\A[0-9A-F,]+\z') 'unsafe installer diagnostic HRESULT'
    $script:lastInstallFailure = "stage=$category; types=$types; hresults=$hresults"
}
function New-TestPrivateDirectory([string]$path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($identity); $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $principal = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($path), $acl)
    } else { [IO.Directory]::CreateDirectory($path, $acl) | Out-Null }
}
function Get-TestAclState([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    # Compare explicit ACE sets, not Windows SDDL spelling/order or re-inherited
    # entries. Numeric rights/flags also avoid FA versus hexadecimal formatting.
    $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        $key = '{0}|{1}|{2}|{3}|{4}' -f $rule.IdentityReference.Value, [long]$rule.FileSystemRights, [int]$rule.AccessControlType, [int]$rule.InheritanceFlags, [int]$rule.PropagationFlags
        [void]$keys.Add($key)
    }
    [string[]]$rules = @(foreach ($key in $keys) { $key })
    [Array]::Sort($rules, [StringComparer]::Ordinal)
    [pscustomobject]@{
        Owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        Group = $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
        Protected = $acl.AreAccessRulesProtected
        Rules = $rules
    }
}
function Assert-TestAclState([string]$path, $expected, [string]$message) {
    $actual = Get-TestAclState $path
    Assert-True ($actual.Owner -ceq $expected.Owner) "$message (owner)"
    Assert-True ($actual.Group -ceq $expected.Group) "$message (group)"
    Assert-True ($actual.Protected -eq $expected.Protected) "$message (protection)"
    Assert-True ($actual.Rules.Count -eq $expected.Rules.Count) "$message (explicit ACE count)"
    for ($index = 0; $index -lt $actual.Rules.Count; $index++) {
        Assert-True ($actual.Rules[$index] -ceq $expected.Rules[$index]) "$message (explicit ACE)"
    }
}
function Invoke-TestInstaller([string[]]$Arguments = @(), [switch]$ExpectedSuccess) {
    $script:lastInstallFailure = $null
    try { & ([scriptblock]::Create($installer)) @Arguments | Out-String } catch {
        if ($ExpectedSuccess) {
            if ($script:lastInstallFailure) { Write-Host "secret installer diagnostic: $script:lastInstallFailure" }
            else { Write-Host 'secret installer diagnostic: stage=bootstrap' }
        }
        throw
    }
}
function Expect-Failure([string]$label, [string[]]$Arguments = @(), [string]$ExpectedMessage = '') {
    $before = $script:pathWrites; $beforeBroadcasts = $script:environmentChanges; $failed = $false
    try { Invoke-TestInstaller $Arguments | Out-Null } catch {
        $failed = $true
        if ($ExpectedMessage) { Assert-True ($_.Exception.Message -ceq $ExpectedMessage) "$label had the wrong diagnostic" }
    }
    Assert-True $failed "$label accepted"
    Assert-True ($script:pathWrites -eq $before) "$label changed user PATH"
    Assert-True ($script:environmentChanges -eq $beforeBroadcasts) "$label broadcast an environment change"
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $env:INSTALL_DIR 'secret.exe'))) "$label published binary"
    if (Test-Path -LiteralPath $env:INSTALL_DIR) {
        Assert-True (@(Get-ChildItem -LiteralPath $env:INSTALL_DIR -Force).Count -eq 0) "$label left scratch/lock"
    }
    Write-Output "PASS $label"
}
try {
    New-TestPrivateDirectory $work
    foreach ($name in @('home', 'source', 'fixtures', 'tools', 'temp', 'modules', 'build-cache')) { New-TestPrivateDirectory (Join-Path $work $name) }
    $source = Join-Path $work 'source\transport.go'
    # Native fake gh/curl share one executable. No Go subprocess is available to the installer.
    [IO.File]::WriteAllText($source, @'
package main
import (
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"
)
func die() { os.Exit(9) }
func val(args []string, flag string) string { for i,v := range args { if v == flag && i+1<len(args) { return args[i+1] } }; return "" }
func hash(b []byte) string { x:=sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func main() {
 args:=os.Args[1:]; mode:=os.Getenv("SECRET_INSTALL_MODE")
 if len(args)==1 && args[0]=="version" { if mode=="version" { fmt.Println("secret 9.9.9 (go)") } else { fmt.Println("secret 0.3.5 (go)") }; return }
 log,_:=os.OpenFile(os.Getenv("SECRET_INSTALL_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600)
 if log!=nil { b,_:=json.Marshal(args); log.Write(append(b,'\n')); log.Close() }
 if len(args)>=2 && args[0]=="auth" && args[1]=="status" {
  if len(args)!=4 || val(args,"--hostname")!="github.com" { die() }
  if mode=="unauthenticated" { fmt.Fprintln(os.Stderr,"synthetic authentication diagnostic must not escape"); os.Exit(4) }
  if mode=="slow-auth" { time.Sleep(11*time.Second) }
  fmt.Println("synthetic authenticated status"); return
 }
 if strings.HasPrefix(filepath.Base(os.Args[0]),"curl") {
  if val(args,"--proto")!="=https" || val(args,"--proto-redir")!="=https" || val(args,"--max-redirs")!="0" || val(args,"--connect-timeout")!="10" || val(args,"--max-time")!="60" { die() }
  body:=val(args,"--output"); header:=val(args,"--dump-header"); url:=args[len(args)-1]
  if !strings.Contains(url,"/v0.3.5/") && !strings.Contains(url,"release-assets.githubusercontent.com/") { die() }
  os.WriteFile(body,nil,0600); os.WriteFile(header,[]byte("HTTP/1.1 200 OK\r\n\r\n"),0600)
  if mode=="network" || mode=="interrupted" { os.WriteFile(body,[]byte("partial"),0600); die() }
  if mode=="oversize" { os.WriteFile(body,make([]byte,4097),0600); fmt.Print("200"); return }
  if mode=="redirect" || mode=="redirect-loop" {
   url="https://attacker.invalid/asset"; if mode=="redirect-loop" { url="https://release-assets.githubusercontent.com/asset" }
   os.WriteFile(header,[]byte("Location: "+url+"\r\n"),0600); fmt.Print("302"); return
  }
  if mode=="stall" { os.WriteFile(os.Getenv("SECRET_INSTALL_READY"),nil,0600); time.Sleep(120*time.Second) }
  name:=url[strings.LastIndex(url,"/")+1:]; b:=[]byte("synthetic bundle")
  if !strings.HasPrefix(name,"sha256-") { var err error; b,err=os.ReadFile(filepath.Join(os.Getenv("SECRET_INSTALL_FIXTURES"),name)); if err!=nil { die() } }
  if mode=="corrupt" && name==os.Getenv("SECRET_INSTALL_ASSET") { b=[]byte("corruption") }
  os.WriteFile(body,b,0600); fmt.Print("200"); return
 }
 if len(args)>0 && args[0]=="api" {
  if val(args,"--hostname")!="github.com" || val(args,"--method")!="GET" { die() }
  if mode=="api-error" { die() }
  if mode=="api-size" { fmt.Print("{\"padding\":\""+strings.Repeat("x",16384)+"\"}"); return }
  endpoint:=args[len(args)-1]; prefix:="repos/avhn/secret/"
  if !strings.HasPrefix(endpoint,prefix) { die() }; endpoint=strings.TrimPrefix(endpoint,prefix)
  commit:=strings.Repeat("a",40); tagSHA:=strings.Repeat("d",40); blob:=strings.Repeat("e",40)
  result:=map[string]interface{}{}
  switch endpoint {
  case "git/ref/tags/v0.3.5":
   kind:="tag"; sha:=tagSHA; if mode=="lightweight-tag" { kind="commit"; sha=commit }
   result=map[string]interface{}{"ref":"refs/tags/v0.3.5","object":map[string]interface{}{"type":kind,"sha":sha}}
  case "git/tags/"+tagSHA:
   sha:=commit; if mode=="wrong-tag-commit" { sha=strings.Repeat("b",40) }
   result=map[string]interface{}{"sha":tagSHA,"tag":"v0.3.5","object":map[string]interface{}{"type":"commit","sha":sha}}
  case "commits/"+commit+"?per_page=100":
   parents:=[]interface{}{map[string]interface{}{"sha":strings.Repeat("c",40)}}
   if mode=="two-parents" { parents=append(parents,map[string]interface{}{"sha":strings.Repeat("b",40)}) }
   status:="added"; if mode=="modified-checksums" { status="modified" }
   files:=[]interface{}{map[string]interface{}{"filename":"dist/checksums-v0.3.5.txt","status":status,"sha":blob}}
   if mode=="extra-file" { files=append(files,map[string]interface{}{"filename":"README.md","status":"modified","sha":strings.Repeat("f",40)}) }
   result=map[string]interface{}{"sha":commit,"parents":parents,"files":files}
  case "contents/dist/checksums-v0.3.5.txt?ref="+commit:
   data,err:=os.ReadFile(filepath.Join(os.Getenv("SECRET_INSTALL_FIXTURES"),"checksums-v0.3.5.txt")); if err!=nil { die() }
   if mode=="committed-mismatch" { data=append(data,[]byte("committed bytes differ\n")...) }
   result=map[string]interface{}{"type":"file","path":"dist/checksums-v0.3.5.txt","sha":blob,"encoding":"base64",
    "size":len(data),"content":base64.StdEncoding.EncodeToString(data)}
  default: die()
  }
  encoded,_:=json.Marshal(result); text:=string(encoded)
  if mode=="api-duplicate" { text=strings.Replace(text,"\"ref\":","\"ref\":\"wrong\",\"ref\":",1) }
  fmt.Print(text); return
 }
 if len(args)<3 || args[0]!="attestation" || args[1]!="verify" { die() }
 if val(args,"--repo")!="avhn/secret" || val(args,"--source-ref")!="refs/tags/v0.3.5" ||
    val(args,"--cert-oidc-issuer")!="https://token.actions.githubusercontent.com" ||
    val(args,"--cert-identity")!="https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.3.5" ||
    !strings.Contains(strings.Join(args," "),"--deny-self-hosted-runners") || val(args,"--format")!="json" { die() }
 if mode=="attestation" { fmt.Fprintln(os.Stderr,"synthetic diagnostic must not escape"); die() }
 b,err:=os.ReadFile(args[2]); if err!=nil { die() }; name:=filepath.Base(args[2]); commit:=strings.Repeat("a",40)
 if mode=="inconsistent" && name==os.Getenv("SECRET_INSTALL_ASSET") { commit=strings.Repeat("b",40) }
 if pin:=val(args,"--source-digest"); pin!="" && (pin!=commit || val(args,"--signer-digest")!=commit) { die() }
 // One release-workflow statement contains all eight payloads and checksums.
 entries,err:=os.ReadDir(os.Getenv("SECRET_INSTALL_FIXTURES")); if err!=nil || len(entries)!=9 { die() }
 subjects:=[]interface{}{}; var matching map[string]interface{}
 for _,entry:=range entries {
  payload,err:=os.ReadFile(filepath.Join(os.Getenv("SECRET_INSTALL_FIXTURES"),entry.Name())); if err!=nil { die() }
  sha:=hash(payload); if entry.Name()==name { sha=hash(b) }
  subject:=map[string]interface{}{"name":entry.Name(),"digest":map[string]interface{}{"sha256":sha}}
  subjects=append(subjects,subject); if entry.Name()==name { matching=subject }
 }
 if matching==nil { die() }
 if mode=="subject" { matching["name"]="wrong-name" }
 if mode=="subject-duplicate" || (mode=="binary-subject-duplicate" && name==os.Getenv("SECRET_INSTALL_ASSET")) { subjects=append(subjects,matching) }
 if mode=="subject-digest" || (mode=="binary-subject-digest" && name==os.Getenv("SECRET_INSTALL_ASSET")) { matching["digest"]=map[string]interface{}{"sha256":strings.Repeat("0",64)} }
 workflow:=map[string]interface{}{"repository":"https://github.com/avhn/secret","ref":"refs/tags/v0.3.5","path":".github/workflows/release.yml"}
 if mode=="workflow" { workflow["path"]="wrong.yml" }
 statement:=map[string]interface{}{"predicateType":"https://slsa.dev/provenance/v1",
  "subject":subjects,
  "predicate":map[string]interface{}{"buildDefinition":map[string]interface{}{"externalParameters":map[string]interface{}{"workflow":workflow},
   "resolvedDependencies":[]interface{}{map[string]interface{}{"uri":"git+https://github.com/avhn/secret@refs/tags/v0.3.5","digest":map[string]interface{}{"gitCommit":commit}}}}}}
 result,_:=json.Marshal([]interface{}{map[string]interface{}{"verificationResult":map[string]interface{}{"statement":statement}}})
 text:=string(result); if mode=="duplicate" { text=strings.Replace(text,"\"predicateType\":","\"predicateType\":\"wrong\",\"predicateType\":",1) }; fmt.Print(text)
}
'@)
    $env:HOME = Join-Path $work 'home'; $env:USERPROFILE = $env:HOME
    $env:LOCALAPPDATA = $env:HOME; $env:APPDATA = $env:HOME
    $env:TEMP = Join-Path $work 'temp'; $env:TMP = $env:TEMP
    $env:GOMODCACHE = Join-Path $work 'modules'; $env:GOCACHE = Join-Path $work 'build-cache'
    $env:GOTOOLCHAIN = 'local'; $env:GOENV = 'off'; $env:GOWORK = 'off'; $env:CGO_ENABLED = '0'
    $transport = Join-Path $work 'tools\gh.exe'
    & $go build -trimpath -buildvcs=false -o $transport $source
    if ($LASTEXITCODE -ne 0) { throw 'synthetic helper build failed' }
    Copy-Item -LiteralPath $transport -Destination (Join-Path $work 'tools\curl.exe')
    $env:PATH = Join-Path $work 'tools'
    $env:SECRET_VERSION = '0.3.5'; $env:SECRET_RELEASE_COMMIT = $null
    $env:SECRET_INSTALL_FIXTURES = Join-Path $work 'fixtures'
    $env:SECRET_INSTALL_LOG = Join-Path $work 'transport.log'
    $env:SECRET_INSTALL_READY = Join-Path $work 'ready'
    $architecture = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
    $cpu = 'amd64'; if ($architecture -eq 'ARM64') { $cpu = 'arm64' }
    $env:SECRET_INSTALL_ASSET = "secret-v0.3.5-windows-$cpu.exe"
    $env:INSTALL_DIR = Join-Path $work "bin with 'quote and space"
    foreach ($system in @('darwin', 'linux', 'windows')) {
        foreach ($arch in @('amd64', 'arm64')) {
            $suffix = ''; if ($system -eq 'windows') { $suffix = '.exe' }
            Copy-Item -LiteralPath $transport -Destination (Join-Path $env:SECRET_INSTALL_FIXTURES "secret-v0.3.5-$system-$arch$suffix")
        }
    }
    [IO.File]::WriteAllText((Join-Path $env:SECRET_INSTALL_FIXTURES 'secret-v0.3.5-desktop.mcpb'), 'synthetic bundle')
    [IO.File]::WriteAllText((Join-Path $env:SECRET_INSTALL_FIXTURES 'server.json'), '{}')
    $manifest = Join-Path $env:SECRET_INSTALL_FIXTURES 'checksums-v0.3.5.txt'
    $files = @(Get-ChildItem -LiteralPath $env:SECRET_INSTALL_FIXTURES | Sort-Object Name)
    $records = @($files | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name })
    [IO.File]::WriteAllText($manifest, ($records -join "`n") + "`n", [Text.Encoding]::ASCII)
    $output = Invoke-TestInstaller -Arguments @('--help')
    Assert-True ($output.Contains('0.3.5') -and -not (Test-Path -LiteralPath $env:SECRET_INSTALL_LOG)) 'help had side effects'
    Expect-Failure 'unknown argument' -Arguments @('--unknown')
    Expect-Failure 'unknown argument after help' -Arguments @('--help', '--unknown')
    foreach ($pin in @('latest', '0.03.0', '1.2.3-rc1', '../0.3.5', 'vv0.3.5')) {
        $env:SECRET_VERSION = $pin; Expect-Failure "version pin $pin"
    }
    $env:SECRET_VERSION = '0.3.5'
    foreach ($pin in @('bad', ('A' * 40), ('a' * 39))) {
        $env:SECRET_RELEASE_COMMIT = $pin; Expect-Failure 'invalid commit pin'
    }
    $env:SECRET_RELEASE_COMMIT = $null
    $env:SECRET_INSTALL_MODE = 'unauthenticated'
    Expect-Failure 'unauthenticated gh' -ExpectedMessage 'secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry'
    Assert-True ($script:lastInstallFailure -clike 'stage=github-auth;*') 'authentication failure used the wrong category'
    Assert-True ($installer.Contains("@('auth', 'status', '--hostname', 'github.com') 1048576 60")) 'gh auth status must have a sixty-second bound'
    Assert-True (-not (Test-Path -LiteralPath $env:INSTALL_DIR)) 'authentication failure created destination'
    $authCalls = @([IO.File]::ReadAllLines($env:SECRET_INSTALL_LOG))
    Assert-True ($authCalls.Count -eq 1 -and $authCalls[0] -ceq '["auth","status","--hostname","github.com"]') 'authentication failure called curl or another command'
    [IO.File]::Delete($env:SECRET_INSTALL_LOG)
    $env:SECRET_INSTALL_MODE = $null
    $safeInstallDir = $env:INSTALL_DIR
    try {
        $env:INSTALL_DIR = Join-Path $work '%LOCALAPPDATA%\secret'
        Expect-Failure 'percent in resolved directory' -ExpectedMessage 'secret: install directory must not contain %'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $work '%LOCALAPPDATA%'))) 'percent rejection created a directory'
        Assert-True (-not (Test-Path -LiteralPath $env:SECRET_INSTALL_LOG)) 'percent rejection called a transport'
        Assert-True ($script:pathWrites -eq 0 -and $env:PATH -ceq (Join-Path $work 'tools')) 'percent rejection changed PATH'
    } finally { $env:INSTALL_DIR = $safeInstallDir }
    $env:SECRET_RELEASE_COMMIT = 'b' * 40; Expect-Failure 'wrong commit pin'
    Expect-Failure 'conflicting commit pins' -Arguments @('--commit', ('a' * 40))
    $env:SECRET_RELEASE_COMMIT = $null
    Rename-Item -LiteralPath $transport -NewName 'missing-gh.exe'
    Expect-Failure 'missing gh'
    Rename-Item -LiteralPath (Join-Path $work 'tools\missing-gh.exe') -NewName 'gh.exe'
    $emulatedProcess = @{
        Architecture = $env:PROCESSOR_ARCHITECTURE; Wow = $env:PROCESSOR_ARCHITEW6432
        Asset = $env:SECRET_INSTALL_ASSET; Mode = $env:SECRET_INSTALL_MODE; Machine = $script:nativeMachine
    }
    try {
        $env:PROCESSOR_ARCHITECTURE = 'AMD64'; $env:PROCESSOR_ARCHITEW6432 = 'AMD64'
        $script:nativeMachine = [uint16]0xaa64
        $env:SECRET_INSTALL_ASSET = 'secret-v0.3.5-windows-arm64.exe'
        # Stop at checksum validation: an x64 runner cannot execute Arm64 code,
        # but the transport log must prove native, not process, asset selection.
        $env:SECRET_INSTALL_MODE = 'corrupt'
        [IO.File]::Delete($env:SECRET_INSTALL_LOG)
        Expect-Failure 'native Arm64 with an AMD64 PowerShell process'
        $selectionLog = [IO.File]::ReadAllText($env:SECRET_INSTALL_LOG)
        Assert-True ($selectionLog.Contains('https://github.com/avhn/secret/releases/download/v0.3.5/secret-v0.3.5-windows-arm64.exe')) 'emulated AMD64 process did not select Arm64 asset'
        Assert-True (-not $selectionLog.Contains('https://github.com/avhn/secret/releases/download/v0.3.5/secret-v0.3.5-windows-amd64.exe')) 'emulated AMD64 process selected process architecture'
        Write-Output 'PASS native Arm64 overrides AMD64 process architecture'
    } finally {
        $env:PROCESSOR_ARCHITECTURE = $emulatedProcess.Architecture
        $env:PROCESSOR_ARCHITEW6432 = $emulatedProcess.Wow
        $env:SECRET_INSTALL_ASSET = $emulatedProcess.Asset; $env:SECRET_INSTALL_MODE = $emulatedProcess.Mode
        $script:nativeMachine = $emulatedProcess.Machine
    }
    foreach ($mode in @('attestation', 'subject', 'subject-duplicate', 'subject-digest', 'binary-subject-duplicate', 'binary-subject-digest',
        'workflow', 'duplicate', 'inconsistent', 'corrupt', 'network', 'interrupted', 'oversize', 'redirect', 'redirect-loop', 'version',
        'lightweight-tag', 'wrong-tag-commit', 'two-parents', 'extra-file', 'modified-checksums', 'committed-mismatch',
        'api-error', 'api-duplicate', 'api-size')) {
        $env:SECRET_INSTALL_MODE = $mode; Expect-Failure $mode
    }
    $env:SECRET_INSTALL_MODE = $null
    # Authenticate a deliberately wrong PE machine to prove pre-execution inspection.
    $nativeAsset = Join-Path $env:SECRET_INSTALL_FIXTURES $env:SECRET_INSTALL_ASSET
    $nativeBytes = [IO.File]::ReadAllBytes($nativeAsset)
    $wrongBytes = [byte[]]$nativeBytes.Clone()
    $peOffset = [BitConverter]::ToUInt32($wrongBytes, 0x3c)
    $wrongMachine = [uint16]0xaa64; if ($cpu -eq 'arm64') { $wrongMachine = [uint16]0x8664 }
    [BitConverter]::GetBytes($wrongMachine).CopyTo($wrongBytes, $peOffset + 4)
    [IO.File]::WriteAllBytes($nativeAsset, $wrongBytes)
    $wrongRecords = @($files | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name })
    [IO.File]::WriteAllText($manifest, ($wrongRecords -join "`n") + "`n", [Text.Encoding]::ASCII)
    Expect-Failure 'wrong PE architecture'
    [IO.File]::WriteAllBytes($nativeAsset, $nativeBytes)
    [IO.File]::WriteAllText($manifest, ($records -join "`n") + "`n", [Text.Encoding]::ASCII)
    $oldArchitecture = $env:PROCESSOR_ARCHITECTURE; $oldWow = $env:PROCESSOR_ARCHITEW6432
    try {
        $env:PROCESSOR_ARCHITECTURE = 'unsupported'; $env:PROCESSOR_ARCHITEW6432 = $null
        Expect-Failure 'unsupported platform'
    } finally { $env:PROCESSOR_ARCHITECTURE = $oldArchitecture; $env:PROCESSOR_ARCHITEW6432 = $oldWow }
    $originalManifest = [IO.File]::ReadAllBytes($manifest)
    [IO.File]::WriteAllText($manifest, ([IO.File]::ReadAllText($manifest).TrimEnd("`n")), [Text.Encoding]::ASCII)
    Expect-Failure 'missing final newline'; [IO.File]::WriteAllBytes($manifest, $originalManifest)
    # Each fault owns a fresh directory. Never restore serialized ACLs or mutate
    # the primary installation's permissions between otherwise independent cases.
    $primaryInstallDir = $env:INSTALL_DIR
    foreach ($sid in @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11',
            'S-1-5-21-111111111-222222222-333333333-4242')) {
        foreach ($rights in @('Modify', 'AppendData', 'DeleteSubdirectoriesAndFiles')) {
            $caseDirectory = Join-Path $work ('dacl-deny-' + [Guid]::NewGuid().ToString('N'))
            New-TestPrivateDirectory $caseDirectory
            try {
                $env:INSTALL_DIR = $caseDirectory
                $unsafeAcl = Get-Acl -LiteralPath $caseDirectory
                $principal = New-Object Security.Principal.SecurityIdentifier($sid)
                $unsafeRule = New-Object Security.AccessControl.FileSystemAccessRule($principal, $rights, 'Allow')
                $unsafeAcl.AddAccessRule($unsafeRule); Set-Acl -LiteralPath $caseDirectory -AclObject $unsafeAcl
                $unsafeState = Get-TestAclState $caseDirectory
                Expect-Failure "unsafe destination DACL $sid $rights"
                Assert-TestAclState $caseDirectory $unsafeState 'DACL rejection rewrote existing permissions'
            } finally {
                $env:INSTALL_DIR = $primaryInstallDir
                Remove-Item -LiteralPath $caseDirectory -Recurse -Force
            }
        }
    }
    # Existing destinations are never repaired, aliases are refused, stale locks stay.
    if (-not (Test-Path -LiteralPath $env:INSTALL_DIR)) { New-TestPrivateDirectory $env:INSTALL_DIR }
    $lock = Join-Path $env:INSTALL_DIR '.secret.install-lock'
    [IO.File]::WriteAllText($lock, 'stale token')
    $failed = $false; try { Invoke-TestInstaller | Out-Null } catch { $failed = $true }
    Assert-True ($failed -and [IO.File]::ReadAllText($lock) -ceq 'stale token') 'stale lock stolen'
    [IO.File]::Delete($lock)
    $aliasTarget = Join-Path $work 'aliased destination'
    New-TestPrivateDirectory $aliasTarget
    [IO.Directory]::Delete($env:INSTALL_DIR)
    New-Item -ItemType Junction -Path $env:INSTALL_DIR -Target $aliasTarget | Out-Null
    Expect-Failure 'reparse destination'
    # Remove the junction only, never its target.
    [IO.Directory]::Delete($env:INSTALL_DIR)
    New-TestPrivateDirectory $env:INSTALL_DIR
    # A normal existing user-owned directory may inherit safe ACEs from its parent.
    # Accept that DACL without protecting or otherwise rewriting it.
    $inheritedAcl = Get-Acl -LiteralPath $env:INSTALL_DIR
    $inheritedAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $env:INSTALL_DIR -AclObject $inheritedAcl
    $inheritedAcl = Get-Acl -LiteralPath $env:INSTALL_DIR
    Assert-True (-not $inheritedAcl.AreAccessRulesProtected) 'test destination unexpectedly protected'
    $originalAclState = Get-TestAclState $env:INSTALL_DIR
    $env:SECRET_RELEASE_COMMIT = 'a' * 40
    $env:SECRET_INSTALL_MODE = 'slow-auth'
    $output = Invoke-TestInstaller -Arguments @('--version', '0.3.5', '--commit', ('a' * 40)) -ExpectedSuccess
    $env:SECRET_INSTALL_MODE = $null
    $target = Join-Path $env:INSTALL_DIR 'secret.exe'
    Assert-True (Test-Path -LiteralPath $target) 'valid install absent'
    $currentUserSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert-True ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $currentUserSID) 'first install owner is not the current user'
    Write-Output 'PASS first install current-user owner'
    Assert-True (-not $output.Contains('synthetic authenticated status')) 'installer printed authentication status output'
    Assert-TestAclState $env:INSTALL_DIR $originalAclState 'installer rewrote safe inherited DACL'
    Assert-True ($output.Contains($target) -and $output.Contains("--store 'file:C:\ABSOLUTE\STORE'")) 'missing absolute registration'
    $registration = ($output -split "`r?`n" | Where-Object { $_.StartsWith('claude mcp add ') })
    $tokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($registration, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'quoted registration parse failure'
    $command = $ast.EndBlock.Statements[0].PipelineElements[0]
    Assert-True ($command.CommandElements[9].Value -ceq $target) 'quoted registration changed binary argv'
    Assert-True ($script:pathWrites -eq 1 -and $script:fakeUserPath -ceq ('%USERPROFILE%\synthetic-existing;' + $env:INSTALL_DIR)) 'user PATH changed beyond destination'
    Assert-True ($script:environmentChanges -eq 1) 'changed user PATH did not broadcast exactly once'
    $before = (Get-FileHash -LiteralPath $target).Hash
    $env:SECRET_INSTALL_MODE = 'corrupt'
    $failed = $false; try { Invoke-TestInstaller | Out-Null } catch { $failed = $true }
    Assert-True ($failed -and (Get-FileHash -LiteralPath $target).Hash -ceq $before) 'failure damaged existing destination'
    Assert-True ($script:lastInstallFailure -clike 'stage=download-verification; types=*; hresults=*') 'missing path-free failure diagnostic'
    $env:SECRET_INSTALL_MODE = $null
    # Where the token permits it, seed an elevated install's Administrators owner;
    # replacement must still publish the current user as owner.
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $administratorsOwnerApplied = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($administratorsOwnerApplied) {
        $ownerOnly = New-Object Security.AccessControl.FileSecurity
        $ownerOnly.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($target), $ownerOnly)
        } else { (New-Object IO.FileInfo($target)).SetAccessControl($ownerOnly) }
        Assert-True ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq 'S-1-5-32-544') 'replacement fixture is not Administrators-owned'
    } else {
        Write-Output 'SKIP Administrators-owned replacement fixture: token is not an elevated Administrator'
    }
    # Exercise File.Replace before later DACL faults. Passing $null instead of
    # NullString.Value used to pass an empty backup path to .NET.
    Invoke-TestInstaller -ExpectedSuccess | Out-Null
    Assert-True ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $currentUserSID) 'replacement owner is not the current user'
    if ($administratorsOwnerApplied) { Write-Output 'PASS replacement corrects Administrators owner to current user' }
    Assert-True ((Get-FileHash -LiteralPath $target).Hash -ceq $before) 'atomic replacement changed verified bytes'
    Assert-True ($script:pathWrites -eq 1 -and $script:environmentChanges -eq 1) 'atomic replacement changed PATH or broadcast again'
    Assert-TestAclState $env:INSTALL_DIR $originalAclState 'atomic replacement changed destination DACL'
    Assert-True (@(Get-ChildItem -LiteralPath $env:INSTALL_DIR -Force).Count -eq 1) 'atomic replacement left backup, lock or scratch'
    Write-Output 'PASS atomic replacement before DACL fault injection'
    # FILE_DELETE_CHILD (0x40) must deny for the destination and every ancestor,
    # even when that is the broad principal's only granted write-like right.
    # Each case gets an isolated parent/destination and an existing synthetic
    # binary. Never restore ACLs or alter the shared work/primary directories.
    # The unregistered synthetic local-group SID models a sandbox user group
    # such as CodexSandboxUsers, without reading or changing real group membership.
    foreach ($location in @('destination', 'ancestor')) {
        foreach ($case in @(@('S-1-1-0', 'DeleteSubdirectoriesAndFiles'),
            @('S-1-5-32-545', 'DeleteSubdirectoriesAndFiles'),
            @('S-1-5-11', 'DeleteSubdirectoriesAndFiles'),
            @('S-1-5-21-111111111-222222222-333333333-4242', 'Modify'))) {
            $sid, $rights = $case
            $caseRoot = Join-Path $work ('dacl-preserve-' + [Guid]::NewGuid().ToString('N'))
            New-TestPrivateDirectory $caseRoot
            $caseDirectory = Join-Path $caseRoot 'bin'
            New-TestPrivateDirectory $caseDirectory
            $caseBinary = Join-Path $caseDirectory 'secret.exe'
            Copy-Item -LiteralPath $target -Destination $caseBinary
            try {
                $env:INSTALL_DIR = $caseDirectory
                $unsafeDirectory = $caseDirectory
                if ($location -eq 'ancestor') { $unsafeDirectory = $caseRoot }
                $unsafeAcl = Get-Acl -LiteralPath $unsafeDirectory
                $principal = New-Object Security.Principal.SecurityIdentifier($sid)
                $deleteChild = New-Object Security.AccessControl.FileSystemAccessRule($principal, $rights, 'Allow')
                $unsafeAcl.AddAccessRule($deleteChild)
                Set-Acl -LiteralPath $unsafeDirectory -AclObject $unsafeAcl
                $unsafeState = Get-TestAclState $unsafeDirectory
                $failed = $false; try { Invoke-TestInstaller | Out-Null } catch { $failed = $true }
                Assert-True $failed "$rights accepted for $sid"
                Assert-True ((Get-FileHash -LiteralPath $caseBinary).Hash -ceq $before) 'DACL rejection damaged installed binary'
                Assert-TestAclState $unsafeDirectory $unsafeState 'DACL rejection rewrote existing permissions'
                Assert-True ($script:pathWrites -eq 1 -and $script:environmentChanges -eq 1) 'DACL rejection changed user PATH or broadcast'
                Assert-True (@(Get-ChildItem -LiteralPath $caseDirectory -Force).Count -eq 1) 'DACL rejection left scratch or lock'
                Write-Output "PASS $rights rejection preserves DACL and binary ($sid, $location)"
            } finally {
                $env:INSTALL_DIR = $primaryInstallDir
                Remove-Item -LiteralPath $caseRoot -Recurse -Force
            }
        }
    }
    # Owning a file grants no WRITE_OWNER. Replacing a current-user-owned binary
    # whose protected DACL allows only Modify must skip the no-op owner write.
    $savedPathState = $null
    $caseRoot = Join-Path $work ('owner-modify-' + [Guid]::NewGuid().ToString('N'))
    New-TestPrivateDirectory $caseRoot
    $caseDirectory = Join-Path $caseRoot 'bin'
    New-TestPrivateDirectory $caseDirectory
    $caseBinary = Join-Path $caseDirectory 'secret.exe'
    Copy-Item -LiteralPath $target -Destination $caseBinary
    try {
        $currentUser = New-Object Security.Principal.SecurityIdentifier($currentUserSID)
        $ownerOnly = New-Object Security.AccessControl.FileSecurity
        $ownerOnly.SetOwner($currentUser)
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($caseBinary), $ownerOnly)
        } else { (New-Object IO.FileInfo($caseBinary)).SetAccessControl($ownerOnly) }
        $modifyOnly = Get-Acl -LiteralPath $caseBinary
        $modifyOnly.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($modifyOnly.Access)) { [void]$modifyOnly.RemoveAccessRuleSpecific($rule) }
        $modifyOnly.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($currentUser, 'Modify', 'Allow')))
        Set-Acl -LiteralPath $caseBinary -AclObject $modifyOnly
        Assert-True ((Get-Acl -LiteralPath $caseBinary).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $currentUserSID) 'modify-only fixture is not current-user owned'
        $modifyState = Get-TestAclState $caseBinary
        # A new destination appends to the synthetic PATH; restore the counters.
        $savedPathState = @($script:fakeUserPath, $script:pathWrites, $script:environmentChanges)
        $env:INSTALL_DIR = $caseDirectory
        Invoke-TestInstaller -ExpectedSuccess | Out-Null
        Assert-True ((Get-Acl -LiteralPath $caseBinary).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $currentUserSID) 'modify-only replacement owner is not the current user'
        Assert-TestAclState $caseBinary $modifyState 'modify-only replacement changed binary DACL'
        Assert-True ((Get-FileHash -LiteralPath $caseBinary).Hash -ceq $before) 'modify-only replacement changed verified bytes'
        Assert-True (@(Get-ChildItem -LiteralPath $caseDirectory -Force).Count -eq 1) 'modify-only replacement left backup, lock or scratch'
        Write-Output 'PASS current-user-owned Modify-only replacement skips owner write'
    } finally {
        $env:INSTALL_DIR = $primaryInstallDir
        if ($savedPathState) { $script:fakeUserPath, $script:pathWrites, $script:environmentChanges = $savedPathState }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
    Assert-True (@(Get-ChildItem -LiteralPath $env:INSTALL_DIR -Force).Count -eq 1) 'DACL fault injection left install scratch or lock'
    Invoke-TestInstaller -ExpectedSuccess | Out-Null
    Assert-True ((Get-Acl -LiteralPath $target).GetOwner([Security.Principal.SecurityIdentifier]).Value -ceq $currentUserSID) 'repeated replacement owner is not the current user'
    Assert-True ($script:pathWrites -eq 1) 'replacement duplicated PATH'
    Assert-True ($script:environmentChanges -eq 1) 'unchanged user PATH broadcast an environment change'
    Assert-True ($env:PATH -ceq (Join-Path $work 'tools')) 'installer edited process PATH'
    # The final name intentionally replaces the old standalone Bash-name contract.
    Assert-True (Test-Path -LiteralPath (Join-Path $env:INSTALL_DIR 'secret.exe')) 'final CLI absent'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $env:INSTALL_DIR 'compat'))) 'standalone installer published Bash fallback'
    Assert-True (@(Get-ChildItem -LiteralPath $env:INSTALL_DIR -Force).Count -eq 1) 'successful install left scratch/lock'
    # Exercise default HOME publication in a disposable directory, including spaces.
    $env:HOME = Join-Path $work 'default home with spaces'
    New-TestPrivateDirectory $env:HOME
    $env:INSTALL_DIR = $null
    $defaultOutput = Invoke-TestInstaller -ExpectedSuccess
    $defaultTarget = Join-Path $env:HOME '.local\bin\secret.exe'
    Assert-True ((Test-Path -LiteralPath $defaultTarget) -and $defaultOutput.Contains($defaultTarget)) 'HOME default destination differs'
    Assert-True ((Get-FileHash -LiteralPath $defaultTarget).Hash -ceq $before) 'HOME default payload differs'
    # Evaluate only the path-selection AST when HOME is absent. No native profile
    # file is touched and no host installer/registry action can execute here.
    $env:HOME = $null
    $tokens = $null; $parseErrors = $null
    $installerAst = [Management.Automation.Language.Parser]::ParseInput($installer, [ref]$tokens, [ref]$parseErrors)
    $defaultSelection = @($installerAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text.StartsWith('if (-not $directory) {')
    }, $true))
    Assert-True ($parseErrors.Count -eq 0 -and $defaultSelection.Count -eq 1) 'default path selection is ambiguous'
    $fallbackDirectory = & {
        $directory = $null
        . ([scriptblock]::Create($defaultSelection[0].Extent.Text))
        $directory
    }
    Assert-True ($fallbackDirectory -ceq (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local\bin')) 'native profile fallback differs'
    Write-Output 'PASS HOME default destination and side-effect-free native profile fallback'
    Write-Output 'PASS nine-subject install, authenticated source boundary, quoted registration, safe ACL, replacement and synthetic user PATH'
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    Assert-True ($env:PATH -ceq $originalProcessPath) 'test did not restore process PATH'
}
