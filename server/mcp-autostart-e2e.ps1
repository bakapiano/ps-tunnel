[CmdletBinding()]
param(
    [switch]$CodexMcp,
    [string]$CodexPath = 'codex',
    [string]$ClientPowerShellPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Get-FreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw ('MCP auto-start E2E assertion failed: {0}' -f $Message)
    }
}

function Wait-Until {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][string]$Description,
        [int]$TimeoutSeconds = 30
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $value = & $Condition
            if ($null -ne $value -and $value -ne $false) { return $value }
        }
        catch {
            # Startup and reconnect polling naturally encounter short gaps.
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw ('Timed out waiting for {0}.' -f $Description)
}

function Join-NativeArguments {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
    return (($ArgumentList | ForEach-Object {
        $value = [string]$_
        if ($value -notmatch '[\s"]') { return $value }
        return '"{0}"' -f $value
    }) -join ' ')
}

function New-SshKeyPair {
    param(
        [Parameter(Mandatory = $true)][string]$SshKeygenPath,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $arguments = '-q -t ed25519 -N "" -f "{0}"' -f $Path
    $process = Start-Process -FilePath $SshKeygenPath -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    try {
        if ($process.ExitCode -ne 0) {
            throw ('ssh-keygen exited with code {0}.' -f $process.ExitCode)
        }
    }
    finally {
        $process.Dispose()
    }
}

function Protect-PrivateKey {
    param([Parameter(Mandatory = $true)][string]$Path)
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $Path /inheritance:r /grant:r ('*{0}:(F)' -f $sid) '*S-1-5-18:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw ('Could not protect private key {0}.' -f $Path)
    }
}

$serverDirectory = $PSScriptRoot
$rootDirectory = Split-Path -Parent $serverDirectory
$mcpServerPath = Join-Path $serverDirectory 'mcp-server.mjs'
$mcpSmokePath = Join-Path $serverDirectory 'mcp-smoke.mjs'
$mcpConcurrencySmokePath = Join-Path $serverDirectory 'mcp-concurrency-smoke.mjs'
$clientPath = Join-Path $rootDirectory 'client\client.ps1'
$nodePath = (Get-Command node.exe -ErrorAction Stop).Source
$powerShellPath = (Get-Command powershell.exe -ErrorAction Stop).Source
$sshPath = (Get-Command ssh.exe -ErrorAction Stop).Source
$sshKeygenPath = (Get-Command ssh-keygen.exe -ErrorAction Stop).Source

if ([string]::IsNullOrWhiteSpace($ClientPowerShellPath)) {
    $clientPowerShellExecutable = (Get-Command pwsh.exe -ErrorAction Stop).Source
}
elseif (Test-Path -LiteralPath $ClientPowerShellPath -PathType Leaf) {
    $clientPowerShellExecutable = (Resolve-Path -LiteralPath $ClientPowerShellPath).Path
}
else {
    $clientPowerShellExecutable = (Get-Command $ClientPowerShellPath -ErrorAction Stop).Source
}

$codexExecutable = $null
if ($CodexMcp) {
    if (Test-Path -LiteralPath $CodexPath -PathType Leaf) {
        $codexExecutable = (Resolve-Path -LiteralPath $CodexPath).Path
    }
    else {
        $codexExecutable = (Get-Command $CodexPath -ErrorAction Stop).Source
    }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempDirectory = [IO.Path]::GetFullPath((Join-Path $tempBase ('ps-tunnel-mcp-autostart-{0}' -f [guid]::NewGuid().ToString('N'))))
if (-not $tempDirectory.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary test path escaped the system temporary directory.'
}
[void](New-Item -ItemType Directory -Path $tempDirectory)

$mcpWorkspace = Join-Path $tempDirectory 'mcp-workspace'
$codexWorkspace = Join-Path $tempDirectory 'codex-workspace'
$codexHome = Join-Path $tempDirectory 'codex-home'
[void](New-Item -ItemType Directory -Path $mcpWorkspace)
[void](New-Item -ItemType Directory -Path $codexWorkspace)
[void](New-Item -ItemType Directory -Path $codexHome)

$ports = New-Object System.Collections.Generic.List[int]
while ($ports.Count -lt 3) {
    $candidate = Get-FreeTcpPort
    if (-not $ports.Contains($candidate)) { [void]$ports.Add($candidate) }
}
$agentPort = $ports[0]
$controlPort = $ports[1]
$sshPort = $ports[2]

$agentSecret = New-RandomSecret
$controlToken = New-RandomSecret
$configPath = Join-Path $tempDirectory 'config.json'
$statePath = Join-Path $tempDirectory 'state.json'
$hostKeyPath = Join-Path $tempDirectory 'ssh-host-ed25519'
$agentKeyPath = Join-Path $tempDirectory 'agent-a-ed25519'
$knownHostsPath = Join-Path $tempDirectory 'known_hosts'
$clientStdout = Join-Path $tempDirectory 'client.stdout.log'
$clientStderr = Join-Path $tempDirectory 'client.stderr.log'
$clientLog = Join-Path $tempDirectory 'client.audit.log'
$codexStdout = Join-Path $tempDirectory 'codex.stdout.jsonl'
$codexStderr = Join-Path $tempDirectory 'codex.stderr.log'
$codexLastMessage = Join-Path $tempDirectory 'codex.last-message.txt'
$codexPromptInput = Join-Path $tempDirectory 'codex.prompt.txt'
$baseUri = 'http://127.0.0.1:{0}' -f $controlPort
$headers = @{ Authorization = 'Bearer {0}' -f $controlToken }

function Invoke-TestApi {
    param([string]$Method, [string]$Path, $Body)
    $parameters = @{
        Method = $Method
        Uri = $baseUri + $Path
        Headers = $headers
        TimeoutSec = 5
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json; charset=utf-8'
        $parameters.Body = $Body | ConvertTo-Json -Compress -Depth 12
    }
    return Invoke-RestMethod @parameters
}

function Get-TestServerProcessIds {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort @($agentPort, $controlPort, $sshPort) -ErrorAction SilentlyContinue)
    return @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
}

function Stop-TestServers {
    foreach ($processId in @(Get-TestServerProcessIds)) {
        $process = Get-CimInstance Win32_Process -Filter ('ProcessId = {0}' -f $processId) -ErrorAction SilentlyContinue
        if ($null -eq $process) { continue }
        $commandLine = [string]$process.CommandLine
        $isExpected = ($commandLine -match 'broker\.js' -or $commandLine -match 'ssh-server\.js') -and
            $commandLine.IndexOf($configPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
        if (-not $isExpected) {
            throw ('Port owner {0} is outside the isolated test deployment.' -f $processId)
        }
        Stop-Process -Id $processId -Force
    }
    [void](Wait-Until -Description 'isolated server ports to close' -TimeoutSeconds 15 -Condition {
        if (@(Get-NetTCPConnection -State Listen -LocalPort @($agentPort, $controlPort, $sshPort) -ErrorAction SilentlyContinue).Count -eq 0) {
            return $true
        }
        return $false
    })
}

$clientProcess = $null
$testSucceeded = $false
$originalAgentSecret = $env:PS_TUNNEL_AGENT_SECRET
$originalControlToken = $env:PS_TUNNEL_CONTROL_TOKEN
$originalControlBaseUri = $env:PS_TUNNEL_CONTROL_BASE_URI
$originalServerConfigPath = $env:PS_TUNNEL_SERVER_CONFIG_PATH
$originalAutoStart = $env:PS_TUNNEL_AUTO_START
$originalPowerShellPath = $env:PS_TUNNEL_POWERSHELL_PATH
$originalCodexHome = $env:CODEX_HOME

try {
    New-SshKeyPair -SshKeygenPath $sshKeygenPath -Path $hostKeyPath
    New-SshKeyPair -SshKeygenPath $sshKeygenPath -Path $agentKeyPath
    Protect-PrivateKey -Path $agentKeyPath

    $hostPublicKey = ((Get-Content -LiteralPath ($hostKeyPath + '.pub') -Raw).Trim() -split '\s+')
    ('[{0}]:{1} {2} {3}' -f '127.0.0.1', $sshPort, $hostPublicKey[0], $hostPublicKey[1]) |
        Set-Content -LiteralPath $knownHostsPath -Encoding ASCII

    $config = [ordered]@{
        agentListen = [ordered]@{ host = '127.0.0.1'; port = $agentPort }
        controlListen = [ordered]@{ host = '127.0.0.1'; port = $controlPort }
        controlToken = $controlToken
        agents = [ordered]@{ 'agent-a' = $agentSecret }
        ssh = [ordered]@{
            host = '127.0.0.1'
            port = $sshPort
            user = 'agent-a'
            hostKeyFile = $hostKeyPath
            authorizedKeyFile = $agentKeyPath + '.pub'
            brokerHost = '127.0.0.1'
            brokerPort = $agentPort
        }
        stateFile = $statePath
        heartbeatSeconds = 1
        sessionTimeoutSeconds = 5
        maxMessageBytes = 262144
        maxTaskTimeoutSeconds = 30
        maxConcurrentTasksPerAgent = 4
        enableTestHooks = $true
    }
    $config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8

    Assert-True (@(Get-TestServerProcessIds).Count -eq 0) 'isolated ports should be unused before MCP startup'

    $env:PS_TUNNEL_AGENT_SECRET = $agentSecret
    $clientArguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $clientPath,
        '-AgentId', 'agent-a',
        '-Transport', 'Ssh',
        '-SshHost', '127.0.0.1',
        '-SshPort', [string]$sshPort,
        '-SshUser', 'agent-a',
        '-SshPath', $sshPath,
        '-IdentityFile', $agentKeyPath,
        '-KnownHostsFile', $knownHostsPath,
        '-TaskTimeoutSeconds', '10',
        '-MaxConcurrentTasks', '4',
        '-SessionReadTimeoutSeconds', '10',
        '-ReconnectInitialSeconds', '1',
        '-ReconnectMaxSeconds', '2',
        '-LauncherMode', 'Never',
        '-LogPath', $clientLog
    )
    $clientProcess = Start-Process -FilePath $clientPowerShellExecutable `
        -ArgumentList (Join-NativeArguments -ArgumentList $clientArguments) `
        -RedirectStandardOutput $clientStdout -RedirectStandardError $clientStderr `
        -NoNewWindow -PassThru

    Remove-Item Env:PS_TUNNEL_CONTROL_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:PS_TUNNEL_CONTROL_BASE_URI -ErrorAction SilentlyContinue
    $env:PS_TUNNEL_SERVER_CONFIG_PATH = $configPath
    $env:PS_TUNNEL_AUTO_START = 'true'
    $env:PS_TUNNEL_POWERSHELL_PATH = $powerShellPath

    $mcpMarker = 'autostart-sdk-{0}' -f [guid]::NewGuid().ToString('N')
    $mcpOutput = @(& $nodePath $mcpSmokePath `
        --server $mcpServerPath `
        --agent 'agent-a' `
        --marker $mcpMarker `
        --cwd $mcpWorkspace)
    if ($LASTEXITCODE -ne 0) {
        throw ('MCP auto-start smoke process exited with code {0}.' -f $LASTEXITCODE)
    }
    $mcpResult = ($mcpOutput -join "`n") | ConvertFrom-Json
    Assert-True ($mcpResult.ok -eq $true) 'MCP SDK auto-start smoke should succeed'
    Assert-True ($mcpResult.marker -eq $mcpMarker) 'MCP SDK marker should round-trip through the agent'
    Assert-True (@(Get-TestServerProcessIds).Count -eq 2) 'MCP should start one broker and one SSH server process'

    $status = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
    $agent = @($status.agents | Where-Object agentId -eq 'agent-a')[0]
    Assert-True ($agent.connected -eq $true) 'agent-a should connect through the MCP-started SSH server'
    Write-Host ('MCP AUTO-START SDK PASS: session {0}, marker {1}.' -f $agent.sessionId, $mcpMarker)

    $mcpConcurrencyMarker = 'autostart-parallel-{0}' -f [guid]::NewGuid().ToString('N')
    $mcpConcurrencyOutput = @(& $nodePath $mcpConcurrencySmokePath `
        --server $mcpServerPath `
        --agent 'agent-a' `
        --marker $mcpConcurrencyMarker `
        --cwd $mcpWorkspace)
    if ($LASTEXITCODE -ne 0) {
        throw ('MCP auto-start concurrency process exited with code {0}.' -f $LASTEXITCODE)
    }
    $mcpConcurrencyResult = ($mcpConcurrencyOutput -join "`n") | ConvertFrom-Json
    Assert-True ($mcpConcurrencyResult.ok -eq $true) 'two MCP instances should share the auto-started services'
    Assert-True ([int]$mcpConcurrencyResult.elapsedMs -lt 12000) 'two MCP calls should execute concurrently over SSH'
    Assert-True (@(Get-TestServerProcessIds).Count -eq 2) 'parallel MCP instances should reuse one broker and one SSH server'
    Write-Host ('MCP AUTO-START CONCURRENCY PASS: {0} ms, tasks {1}.' -f `
        $mcpConcurrencyResult.elapsedMs, (@($mcpConcurrencyResult.taskIds) -join ', '))

    if ($CodexMcp) {
        Stop-TestServers

        $sourceCodexHome = if ([string]::IsNullOrWhiteSpace($originalCodexHome)) {
            Join-Path $HOME '.codex'
        }
        else {
            $originalCodexHome
        }
        $sourceCodexConfigPath = Join-Path $sourceCodexHome 'config.toml'
        $isolatedCodexConfigPath = Join-Path $codexHome 'config.toml'
        if (Test-Path -LiteralPath $sourceCodexConfigPath -PathType Leaf) {
            $skipMcpSection = $false
            $isolatedConfigLines = foreach ($line in Get-Content -LiteralPath $sourceCodexConfigPath) {
                if ($line -match '^\s*\[\[?\s*([^\]]+)\]\]?\s*(?:#.*)?$') {
                    $skipMcpSection = $Matches[1].Trim() -match '^mcp_servers(?:\.|$)'
                }
                if (-not $skipMcpSection) { $line }
            }
            $isolatedConfigLines | Set-Content -LiteralPath $isolatedCodexConfigPath -Encoding UTF8
        }
        foreach ($fileName in @('gc-provider-models.json', 'cap_sid', 'installation_id')) {
            $sourcePath = Join-Path $sourceCodexHome $fileName
            if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
                Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $codexHome $fileName)
            }
        }
        $env:CODEX_HOME = $codexHome

        $codexMarker = 'autostart-codex-{0}' -f [guid]::NewGuid().ToString('N')
        $codexExpectedValue = 4991
        $codexScript = "[pscustomobject]@{ marker = '$codexMarker'; value = (499 * 10 + 1); source = 'mcp-autostart-codex' }"
        $codexMcpServerName = 'ps_tunnel_autostart_e2e'
        $codexPrompt = @"
Use the $codexMcpServerName MCP server. Call list_agents until agent-a reports connected. Then call run_powershell once with agentId agent-a, timeoutSeconds 10, waitTimeoutSeconds 20, and this exact script:
$codexScript

The MCP server must perform the execution. Reply with one compact JSON object containing marker, value, source, and taskId from the MCP result.
"@
        $nodeToml = ConvertTo-Json -InputObject $nodePath -Compress
        $mcpToml = ConvertTo-Json -InputObject $mcpServerPath -Compress
        $workspaceToml = ConvertTo-Json -InputObject $codexWorkspace -Compress
        $codexConfigPath = Join-Path $codexHome 'config.toml'
        @(
            ''
            ('[mcp_servers.{0}]' -f $codexMcpServerName)
            ('command = {0}' -f $nodeToml)
            ('args = [{0}]' -f $mcpToml)
            ('cwd = {0}' -f $workspaceToml)
            'env_vars = ["PS_TUNNEL_SERVER_CONFIG_PATH", "PS_TUNNEL_AUTO_START", "PS_TUNNEL_POWERSHELL_PATH"]'
            'startup_timeout_sec = 60'
            'tool_timeout_sec = 120'
            'default_tools_approval_mode = "approve"'
            'required = true'
        ) | Add-Content -LiteralPath $codexConfigPath -Encoding UTF8
        $codexPrompt | Set-Content -LiteralPath $codexPromptInput -Encoding UTF8 -NoNewline
        $codexArguments = @(
            'exec', '--json', '--ephemeral', '--skip-git-repo-check',
            '--color', 'never', '--sandbox', 'read-only',
            '--output-last-message', $codexLastMessage,
            '-C', $codexWorkspace,
            '-'
        )
        $codexProcess = Start-Process -FilePath $codexExecutable `
            -ArgumentList (Join-NativeArguments -ArgumentList $codexArguments) `
            -WorkingDirectory $codexWorkspace `
            -RedirectStandardInput $codexPromptInput `
            -RedirectStandardOutput $codexStdout `
            -RedirectStandardError $codexStderr `
            -NoNewWindow -PassThru
        $codexTimedOut = $false
        try {
            if (-not $codexProcess.WaitForExit(240000)) {
                $codexTimedOut = $true
                $codexProcess.Kill($true)
                [void]$codexProcess.WaitForExit(5000)
            }
            $codexExitCode = if ($codexTimedOut) { -1 } else { $codexProcess.ExitCode }
        }
        finally {
            $codexProcess.Dispose()
        }
        if ($codexTimedOut) {
            throw 'Isolated Codex MCP invocation exceeded 240 seconds.'
        }
        $codexStdoutText = Get-Content -LiteralPath $codexStdout -Raw
        $codexOutput = @($codexStdoutText -split '\r?\n')
        $events = @($codexOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
        $completedTurns = @($events | Where-Object { $_.type -eq 'turn.completed' })
        Assert-True ($completedTurns.Count -gt 0) 'isolated Codex should complete its model turn'
        if ($codexExitCode -ne 0) {
            Write-Warning ('Codex exited with code {0} after emitting a completed turn; validating MCP events and persisted task.' -f $codexExitCode)
        }
        $toolCalls = @($events | Where-Object {
            $_.type -eq 'item.completed' -and $null -ne $_.item -and $_.item.type -eq 'mcp_tool_call'
        })
        $listCalls = @($toolCalls | Where-Object { ($_.item | ConvertTo-Json -Compress -Depth 20) -match 'list_agents' })
        $runCalls = @($toolCalls | Where-Object { ($_.item | ConvertTo-Json -Compress -Depth 20) -match 'run_powershell' })
        Assert-True ($listCalls.Count -gt 0) 'isolated Codex should call list_agents through MCP'
        Assert-True ($runCalls.Count -gt 0) 'isolated Codex should call run_powershell through MCP'

        $savedState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $matchingTasks = @($savedState.tasks.PSObject.Properties | ForEach-Object { $_.Value } | Where-Object {
            $_.status -eq 'succeeded' -and [string]$_.args.script -match [regex]::Escape($codexMarker)
        })
        $codexTask = $matchingTasks | Select-Object -Last 1
        Assert-True ($null -ne $codexTask) 'isolated Codex marker task should be persisted by the broker'
        Assert-True ([int]$codexTask.result.output.value -eq $codexExpectedValue) 'isolated Codex task should return the expected value'
        Assert-True ($codexTask.result.output.source -eq 'mcp-autostart-codex') 'isolated Codex task should return its source'

        $codexFinal = Get-Content -LiteralPath $codexLastMessage -Raw
        Assert-True ($codexFinal -match [regex]::Escape($codexMarker)) 'isolated Codex final response should contain the marker'
        Assert-True ($codexFinal -match [string]$codexExpectedValue) 'isolated Codex final response should contain the expected value'
        Assert-True (@(Get-TestServerProcessIds).Count -eq 2) 'Codex-started MCP should restart broker and SSH server'
        Write-Host ('MCP AUTO-START CODEX PASS: model task {0}, marker {1}, CODEX_HOME {2}.' -f $codexTask.id, $codexMarker, $codexHome)
    }

    $testSucceeded = $true
    Write-Host ('MCP AUTO-START E2E PASS: isolated config, ports, SSH keys, state, MCP workspace, and Codex home at {0}.' -f $tempDirectory)
}
finally {
    if ($null -ne $clientProcess) {
        try {
            if (-not $clientProcess.HasExited) {
                Stop-Process -Id $clientProcess.Id -Force
                $clientProcess.WaitForExit(5000) | Out-Null
            }
        }
        catch { Write-Warning ('Client cleanup failed: {0}' -f $_.Exception.Message) }
        $clientProcess.Dispose()
    }
    try { Stop-TestServers }
    catch { Write-Warning ('Server cleanup failed: {0}' -f $_.Exception.Message) }

    $environmentValues = @{
        PS_TUNNEL_AGENT_SECRET = $originalAgentSecret
        PS_TUNNEL_CONTROL_TOKEN = $originalControlToken
        PS_TUNNEL_CONTROL_BASE_URI = $originalControlBaseUri
        PS_TUNNEL_SERVER_CONFIG_PATH = $originalServerConfigPath
        PS_TUNNEL_AUTO_START = $originalAutoStart
        PS_TUNNEL_POWERSHELL_PATH = $originalPowerShellPath
        CODEX_HOME = $originalCodexHome
    }
    foreach ($entry in $environmentValues.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            Remove-Item ('Env:{0}' -f $entry.Key) -ErrorAction SilentlyContinue
        }
        else {
            Set-Item ('Env:{0}' -f $entry.Key) -Value $entry.Value
        }
    }

    if ($testSucceeded) {
        if ($tempDirectory.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
    else {
        Remove-Item -LiteralPath $codexHome -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $configPath,$hostKeyPath,$agentKeyPath -Force -ErrorAction SilentlyContinue
        Write-Host ('MCP auto-start E2E logs retained at {0}' -f $tempDirectory)
        foreach ($logFile in @($clientStdout, $clientStderr, $clientLog, $codexStdout, $codexStderr, $codexLastMessage)) {
            if (Test-Path -LiteralPath $logFile) {
                Write-Host ('--- {0} ---' -f $logFile)
                Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue
            }
        }
    }
}
