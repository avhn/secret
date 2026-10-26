# Test-only parse/binding oracle. Run a fixed absolute script with a fixed
# powershell.exe/pwsh.exe -NoProfile -NonInteractive -File path, isolated cwd and
# environment, bounded output capture and an external process-tree watchdog.
# Candidate texts are a bounded UTF-8 JSON array on stdin, never arguments
# and never executed. Each indexed result contains a projection or a fixed error.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-Span($Extent) {
    return [ordered]@{ start = [int]$Extent.StartOffset; end = [int]$Extent.EndOffset }
}
function Add-Unsupported($Node) {
    $name = $Node.GetType().Name
    if (-not $script:unsupported.Contains($name)) { $script:unsupported.Add($name) }
}
function Get-Element($Node) {
    $kind = 'literal'; $value = ''; $quote = ''; $colon = $false
    $statements = @()
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
        $value = $Node.Value
        switch ($Node.StringConstantType.ToString()) {
            'BareWord' { $quote = 'bare' }
            'SingleQuoted' { $quote = 'single' }
            'DoubleQuoted' { $quote = 'double' }
            default { Add-Unsupported $Node }
        }
    } elseif ($Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
        $value = $Node.Value; $quote = 'double'
        if ($null -ne $Node.NestedExpressions -and $Node.NestedExpressions.Count -ne 0) { Add-Unsupported $Node }
    } elseif ($Node -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
        $kind = 'block'
        $statements = @(Get-Statements $Node.ScriptBlock)
    } else {
        $kind = 'unsupported'; Add-Unsupported $Node
    }
    return [ordered]@{ kind = $kind; value = $value; quote = $quote; colon = $colon;
        span = (Get-Span $Node.Extent); statements = @($statements) }
}
function Get-ParameterToken($Node) {
    foreach ($token in $script:tokens) {
        if ($token.Extent.StartOffset -eq $Node.Extent.StartOffset -and $token.Kind.ToString() -eq 'Parameter') {
            return $token
        }
    }
    throw 'oracle parameter token unavailable'
}
function Get-Redirect($Node) {
    $stream = [int]$Node.FromStream
    if ($stream -eq 0) { $stream = -1 }
    $append = $false; $merge = 0; $target = $null
    if ($Node -is [System.Management.Automation.Language.FileRedirectionAst]) {
        $append = [bool]$Node.Append; $target = Get-Element $Node.Location
    } elseif ($Node -is [System.Management.Automation.Language.MergingRedirectionAst]) {
        $merge = [int]$Node.ToStream
    } else { Add-Unsupported $Node }
    return [ordered]@{ stream = $stream; append = $append; merge = $merge;
        target = $target; span = (Get-Span $Node.Extent) }
}
function Get-CommandProjection($Node) {
    $elements = @(); $redirects = @()
    foreach ($element in $Node.CommandElements) {
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $token = Get-ParameterToken $element
            $elements += [ordered]@{ kind = 'parameter'; value = $element.ParameterName;
                quote = ''; colon = $token.Text.EndsWith(':'); span = (Get-Span $token.Extent); statements = @() }
            if ($null -ne $element.Argument) { $elements += Get-Element $element.Argument }
        } else { $elements += Get-Element $element }
    }
    foreach ($redirect in $Node.Redirections) { $redirects += Get-Redirect $redirect }
    $operator = $Node.InvocationOperator.ToString()
    if ($operator -eq 'Unknown') { $operator = 'none' }
    return [ordered]@{ name = $Node.GetCommandName(); invocationOperator = $operator;
        span = (Get-Span $Node.Extent); elements = @($elements); redirects = @($redirects) }
}
function Get-Statements($Block) {
    if ($script:projectionDepth -gt 4) { throw 'oracle nesting limit' }
    $script:projectionDepth++
    try {
    if ($null -ne $Block.ParamBlock -or $null -ne $Block.BeginBlock -or $null -ne $Block.ProcessBlock -or
        $null -ne $Block.DynamicParamBlock -or
        ($null -ne $Block.UsingStatements -and $Block.UsingStatements.Count -ne 0)) { Add-Unsupported $Block }
    $clean = $Block.PSObject.Properties['CleanBlock']
    if ($null -ne $clean -and $null -ne $clean.Value) { Add-Unsupported $Block }
    if ($null -eq $Block.EndBlock) { return }
    if ($null -ne $Block.EndBlock.Traps -and $Block.EndBlock.Traps.Count -ne 0) { Add-Unsupported $Block.EndBlock }
    foreach ($statement in $Block.EndBlock.Statements) {
        if ($statement -isnot [System.Management.Automation.Language.PipelineAst]) {
            Add-Unsupported $statement; continue
        }
        $commands = @(); $edges = @(); $index = 0
        foreach ($command in $statement.PipelineElements) {
            if ($command -isnot [System.Management.Automation.Language.CommandAst]) {
                Add-Unsupported $command; continue
            }
            $commands += Get-CommandProjection $command
            if ($index -gt 0) { $edges += [ordered]@{ from = $index - 1; to = $index } }
            $index++
        }
        [ordered]@{ span = (Get-Span $statement.Extent); commands = @($commands); edges = @($edges) }
    }
    } finally { $script:projectionDepth-- }
}
function Get-Binding($Command) {
    $parameters = @(); $exceptions = @()
    try {
        $bound = [System.Management.Automation.Language.StaticParameterBinder]::BindCommand($Command)
        foreach ($key in @($bound.BoundParameters.Keys | Sort-Object)) {
            $binding = $bound.BoundParameters[$key]
            $name = $binding.Parameter.Name
            $named = $null
            foreach ($element in $Command.CommandElements) {
                if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and
                    ($element.ParameterName -ieq $name -or $binding.Parameter.Aliases -icontains $element.ParameterName)) {
                    $named = $element; break
                }
            }
            $extent = $Command.Extent
            if ($null -ne $binding.Value) { $extent = $binding.Value.Extent }
            elseif ($null -ne $named) { $extent = (Get-ParameterToken $named).Extent }
            $parameters += [ordered]@{ name = $name; positional = ($null -eq $named); span = (Get-Span $extent) }
        }
        foreach ($key in @($bound.BindingExceptions.Keys | Sort-Object)) {
            # Error identifiers only. Never emit exception messages or source.
            $exceptions += [string]$bound.BindingExceptions[$key].BindingException.ErrorRecord.FullyQualifiedErrorId
        }
    } catch { $exceptions += 'oracle static binding failed' }
    return [ordered]@{ span = (Get-Span $Command.Extent); parameters = @($parameters); exceptions = @($exceptions) }
}
function Get-Metadata {
    $names = @('Write-Output', 'Out-Null', 'Get-Content', 'Select-String', 'Get-ChildItem',
        'Copy-Item', 'Set-Content', 'Add-Content', 'Out-File', 'ForEach-Object')
    foreach ($name in @($names | Sort-Object)) {
        # Only fixed built-in names, never candidate-controlled command discovery.
        $command = Get-Command -Name $name -CommandType Cmdlet -ErrorAction Stop
        if ($null -eq $command -or $command -isnot [System.Management.Automation.CmdletInfo]) {
            throw 'oracle cmdlet unavailable'
        }
        $parameterSets = $command.ParameterSets
        if ($null -eq $parameterSets -or $parameterSets.Count -eq 0) { throw 'oracle parameter sets unavailable' }
        $sets = @()
        foreach ($set in @($parameterSets | Sort-Object Name)) {
            $parameters = @()
            foreach ($parameter in @($set.Parameters | Sort-Object Name)) {
                $position = [int]$parameter.Position
                if ($position -lt 0) { $position = -1 }
                $kind = 'word'
                if ($parameter.ParameterType -eq [System.Management.Automation.SwitchParameter]) { $kind = 'switch' }
                if ($parameter.ParameterType -eq [scriptblock] -or $parameter.ParameterType -eq [scriptblock[]]) { $kind = 'block' }
                $parameters += [ordered]@{ name = $parameter.Name; position = $position;
                    mandatory = [bool]$parameter.IsMandatory; fromPipeline = [bool]$parameter.ValueFromPipeline;
                    fromProperty = [bool]$parameter.ValueFromPipelineByPropertyName; kind = $kind }
            }
            $sets += [ordered]@{ name = $set.Name; default = [bool]$set.IsDefault; parameters = @($parameters) }
        }
        [ordered]@{ name = $command.Name; sets = @($sets) }
    }
}

# ErrorRecord identifiers only, never Exception.Message, source or environment.
# Restrict even identifiers to a short value-free spelling before emitting them.
function Get-OracleError($Record) {
    $id = [string]$Record.FullyQualifiedErrorId
    if ($id.Length -eq 0 -or $id.Length -gt 160 -or $id -cnotmatch '^[A-Za-z0-9_.:,+-]+$') { $id = 'unavailable' }
    $line = 0
    if ($null -ne $Record.InvocationInfo) { $line = [int]$Record.InvocationInfo.ScriptLineNumber }
    return [ordered]@{ id = $id; line = $line }
}
function Get-Projection([string]$Source) {
    if ($script:utf8.GetByteCount($Source) -gt 40960) { throw 'oracle source limit' }
    $script:tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$script:tokens, [ref]$errors)
    if ($script:tokens.Count -gt 4097) { throw 'oracle token limit' }
    $script:unsupported = New-Object 'System.Collections.Generic.List[string]'
    $script:projectionDepth = 0
    # Argument-mode native token kinds vary (for example %). Normalize only
    # tokens independently proven to be a complete literal AST extent.
    $literalSpans = @{}
    foreach ($literal in $ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $node -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
    }, $true)) {
        $key = '{0}:{1}' -f $literal.Extent.StartOffset, $literal.Extent.EndOffset
        $literalSpans[$key] = $true
    }
    $tokenProjection = @()
    foreach ($token in $script:tokens) {
        $kind = $token.Kind.ToString()
        switch ($kind) {
            'EndOfInput' { continue }
            'Comment' { $kind = 'comment' }
            'NewLine' { $kind = 'separator' }
            'Semi' { $kind = 'separator' }
            'Pipe' { $kind = 'pipe' }
            'LCurly' { $kind = 'block_start' }
            'RCurly' { $kind = 'block_end' }
            'Parameter' { $kind = 'parameter' }
            'Redirection' { $kind = 'redirect' }
            'Generic' { $kind = 'word' }
            'Identifier' { $kind = 'word' }
            'StringLiteral' { $kind = 'word' }
            'StringExpandable' { $kind = 'word' }
            default { }
        }
        if ($token.Kind.ToString() -eq 'EndOfInput') { continue }
        $key = '{0}:{1}' -f $token.Extent.StartOffset, $token.Extent.EndOffset
        if ($literalSpans.ContainsKey($key)) { $kind = 'word' }
        $tokenProjection += [ordered]@{ kind = $kind; text = $token.Text; span = (Get-Span $token.Extent) }
    }
    $parseErrors = @()
    foreach ($errorItem in $errors) { $parseErrors += [ordered]@{ id = $errorItem.ErrorId; span = (Get-Span $errorItem.Extent) } }
    $requirements = $null
    if ($null -ne $ast.ScriptRequirements) { $requirements = [ordered]@{ present = $true } }
    $statements = @(Get-Statements $ast)
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | Sort-Object { $_.Extent.StartOffset })
    if ($commands.Count -gt 2048) { throw 'oracle node limit' }
    $bindings = @()
    foreach ($command in $commands) { $bindings += Get-Binding $command }
    return [ordered]@{ aliases = $script:aliases; tokens = @($tokenProjection); parseErrors = @($parseErrors);
        scriptRequirements = $requirements; statements = @($statements); bindings = @($bindings);
        metadata = @($script:metadata); unsupported = @($script:unsupported | Sort-Object) }
}

try {
    # Bound bytes before UTF-8/JSON decoding. The external watchdog bounds a
    # writer that never closes stdin. No candidate text is sent to stderr.
    $inputStream = [Console]::OpenStandardInput()
    $buffer = New-Object byte[] 4096
    $bytes = New-Object System.IO.MemoryStream
    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        if ($bytes.Length + $count -gt 8388608) { throw 'oracle input limit' }
        $bytes.Write($buffer, 0, $count)
    }
    $script:utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false, $true)
    [Console]::OutputEncoding = $script:utf8
    $document = $script:utf8.GetString($bytes.ToArray())
    if (-not $document.TrimStart().StartsWith('[')) { throw 'oracle input array required' }
    # 5.1 emits the root array as one object; 7.x enumerates it by default.
    # Preserve the actual root array, including singleton/empty strings and
    # invalid nested arrays, without relying on pipeline collection flattening.
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $sources = ConvertFrom-Json -InputObject $document -NoEnumerate -ErrorAction Stop
    } else {
        $sources = ConvertFrom-Json -InputObject $document -ErrorAction Stop
    }
    if ($sources -isnot [array]) { throw 'oracle input array required' }
    if ($sources.Count -lt 1 -or $sources.Count -gt 250) { throw 'oracle batch count limit' }

    # Capture aliases before any binder or metadata lookup can autoload their
    # target modules. AliasInfo.Definition is the static target name on 5.1/7.x;
    # ResolvedCommand can be null when that module has not been loaded.
    $script:aliases = @{}
    foreach ($name in @('gc', 'cat', 'type', 'sls', 'gci', 'ls', 'dir', 'cp', 'copy', 'cpi', '%', 'foreach')) {
        $alias = Get-Alias -Name $name -ErrorAction Stop
        $script:aliases[$name] = [string]$alias.Definition
    }
    # Fixed built-ins only. Candidate text cannot mutate this fresh no-profile
    # session, so immutable metadata can be shared by every source in the batch.
    $script:metadata = @(Get-Metadata)
    [Console]::Out.Write('[')
    for ($index = 0; $index -lt $sources.Count; $index++) {
        if ($index -gt 0) { [Console]::Out.Write(',') }
        try {
            if ($sources[$index] -isnot [string]) { throw 'oracle source string required' }
            $projection = Get-Projection $sources[$index]
            $result = [ordered]@{ index = $index; projection = $projection; error = $null }
            $json = ConvertTo-Json -InputObject $result -Depth 100 -Compress
        } catch {
            $result = [ordered]@{ index = $index; projection = $null; error = (Get-OracleError $_) }
            $json = ConvertTo-Json -InputObject $result -Depth 100 -Compress
        }
        [Console]::Out.Write($json)
    }
    [Console]::Out.WriteLine(']')
} catch {
    $failure = Get-OracleError $_
    [Console]::Error.WriteLine(('powershell oracle failed id={0} line={1}' -f $failure.id, $failure.line))
    exit 2
}
