[CmdletBinding()]
param(
    [string]$ClientPowerShellPath,
    [switch]$CodexMcp,
    [string]$CodexPath = 'codex'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Get-FreeTcpPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw ('E2E assertion failed: {0}' -f $Message)
    }
}

$serverDirectory = $PSScriptRoot
$rootDirectory = Split-Path -Parent $serverDirectory
$clientPath = Join-Path $rootDirectory 'client\client.ps1'
$brokerPath = Join-Path $serverDirectory 'broker.js'
$sessionPath = Join-Path $serverDirectory 'session.js'
$controlPath = Join-Path $serverDirectory 'ctl.ps1'
$mcpServerPath = Join-Path $serverDirectory 'mcp-server.mjs'
$mcpSmokePath = Join-Path $serverDirectory 'mcp-smoke.mjs'
$mcpConcurrencySmokePath = Join-Path $serverDirectory 'mcp-concurrency-smoke.mjs'
$nodePath = (Get-Command node -ErrorAction Stop).Source
$codexExecutable = $null
if ($CodexMcp) {
    if (Test-Path -LiteralPath $CodexPath -PathType Leaf) {
        $codexExecutable = (Resolve-Path -LiteralPath $CodexPath).Path
    }
    else {
        $codexExecutable = (Get-Command $CodexPath -ErrorAction Stop).Source
    }
}
if ([string]::IsNullOrWhiteSpace($ClientPowerShellPath)) {
    $clientPowerShellExecutable = (Get-Command pwsh -ErrorAction Stop).Source
}
elseif (Test-Path -LiteralPath $ClientPowerShellPath) {
    $clientPowerShellExecutable = (Resolve-Path -LiteralPath $ClientPowerShellPath).Path
}
else {
    $clientPowerShellExecutable = (Get-Command $ClientPowerShellPath -ErrorAction Stop).Source
}

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$tempDirectory = [System.IO.Path]::GetFullPath((Join-Path $tempBase ('ps-tunnel-e2e-{0}' -f [Guid]::NewGuid().ToString('N'))))
if (-not $tempDirectory.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary test path escaped the system temporary directory.'
}
[void](New-Item -ItemType Directory -Path $tempDirectory)
$mcpWorkspace = Join-Path $tempDirectory 'mcp-workspace'
$codexWorkspace = Join-Path $tempDirectory 'codex-workspace'
[void](New-Item -ItemType Directory -Path $mcpWorkspace)
[void](New-Item -ItemType Directory -Path $codexWorkspace)

$agentPort = Get-FreeTcpPort
do {
    $controlPort = Get-FreeTcpPort
} while ($controlPort -eq $agentPort)
$agentSecret = New-RandomSecret
$controlToken = New-RandomSecret
$configPath = Join-Path $tempDirectory 'config.json'
$statePath = Join-Path $tempDirectory 'state.json'
$brokerStdout = Join-Path $tempDirectory 'broker.stdout.log'
$brokerStderr = Join-Path $tempDirectory 'broker.stderr.log'
$clientStdout = Join-Path $tempDirectory 'client.stdout.log'
$clientStderr = Join-Path $tempDirectory 'client.stderr.log'
$clientLog = Join-Path $tempDirectory 'client.audit.log'
$launcherPath = Join-Path $tempDirectory 'start-client.ps1'
$launcherStdout = Join-Path $tempDirectory 'launcher.stdout.log'
$launcherStderr = Join-Path $tempDirectory 'launcher.stderr.log'
$codexStdout = Join-Path $tempDirectory 'codex.stdout.jsonl'
$codexStderr = Join-Path $tempDirectory 'codex.stderr.log'
$codexLastMessage = Join-Path $tempDirectory 'codex.last-message.txt'
$baseUri = 'http://127.0.0.1:{0}' -f $controlPort
$headers = @{ Authorization = 'Bearer {0}' -f $controlToken }

$config = [ordered]@{
    agentListen = [ordered]@{ host = '127.0.0.1'; port = $agentPort }
    controlListen = [ordered]@{ host = '127.0.0.1'; port = $controlPort }
    controlToken = $controlToken
    agents = [ordered]@{ 'agent-a' = $agentSecret }
    stateFile = $statePath
    heartbeatSeconds = 1
    sessionTimeoutSeconds = 5
    maxMessageBytes = 262144
    maxTaskTimeoutSeconds = 30
    maxConcurrentTasksPerAgent = 4
    enableTestHooks = $true
}
$config | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configPath -Encoding UTF8

function Invoke-TestApi {
    param([string]$Method, [string]$Path, $Body)

    $parameters = @{
        Method = $Method
        Uri = $baseUri + $Path
        Headers = $headers
        TimeoutSec = 3
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json; charset=utf-8'
        $parameters.Body = $Body | ConvertTo-Json -Compress -Depth 10
    }
    return Invoke-RestMethod @parameters
}

function Wait-Until {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][string]$Description,
        [int]$TimeoutSeconds = 15
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $value = & $Condition
            if ($null -ne $value -and $value -ne $false) {
                return $value
            }
        }
        catch {
            # Startup and reconnect polling naturally encounter short connection gaps.
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw ('Timed out waiting for {0}.' -f $Description)
}

function Wait-Task {
    param([string]$TaskId)
    return Wait-Until -Description ('task {0}' -f $TaskId) -TimeoutSeconds 15 -Condition {
        $task = Invoke-TestApi -Method GET -Path ('/v1/tasks/{0}' -f $TaskId) -Body $null
        if ([string]$task.status -in @('succeeded', 'failed')) {
            return $task
        }
        return $false
    }
}

$brokerProcess = $null
$clientProcess = $null
$launcherProcess = $null
$originalAgentSecret = $env:PS_TUNNEL_AGENT_SECRET
$originalControlToken = $env:PS_TUNNEL_CONTROL_TOKEN
$originalControlBaseUri = $env:PS_TUNNEL_CONTROL_BASE_URI
$testSucceeded = $false
try {
    $brokerProcess = Start-Process -FilePath $nodePath -ArgumentList @($brokerPath, '--config', $configPath) `
        -RedirectStandardOutput $brokerStdout -RedirectStandardError $brokerStderr -PassThru -NoNewWindow

    [void](Wait-Until -Description 'broker health endpoint' -Condition {
        $health = Invoke-TestApi -Method GET -Path '/health' -Body $null
        if ($health.ok) { return $health }
        return $false
    })

    $transportArguments = @($sessionPath, '--host', '127.0.0.1', '--port', [string]$agentPort)
    $transportJson = ConvertTo-Json -InputObject ([string[]]$transportArguments) -Compress
    $transportBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($transportJson))
    $env:PS_TUNNEL_AGENT_SECRET = $agentSecret
    $clientArguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $clientPath,
        '-AgentId', 'agent-a',
        '-Transport', 'Process',
        '-ProcessFilePath', 'node',
        '-ProcessArgumentsBase64', $transportBase64,
        '-ReconnectInitialSeconds', '1',
        '-ReconnectMaxSeconds', '2',
        '-SessionReadTimeoutSeconds', '10',
        '-TaskTimeoutSeconds', '10',
        '-MaxConcurrentTasks', '4',
        '-LauncherMode', 'Always',
        '-LauncherPath', $launcherPath,
        '-LogPath', $clientLog
    )
    $clientProcess = Start-Process -FilePath $clientPowerShellExecutable -ArgumentList $clientArguments `
        -RedirectStandardOutput $clientStdout -RedirectStandardError $clientStderr -PassThru -NoNewWindow

    $firstStatus = Wait-Until -Description 'initial agent session' -Condition {
        $status = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
        $agent = @($status.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
        if ($agent.connected) { return $agent }
        return $false
    }
    $firstSessionId = [string]$firstStatus.sessionId
    Assert-True ($firstSessionId.Length -gt 0) 'initial session id should be populated'
    Assert-True ([int]$firstStatus.maxConcurrentTasks -eq 4) 'client and broker should negotiate four concurrent tasks'

    [void](Wait-Until -Description 'one-click launcher creation' -Condition {
        if (Test-Path -LiteralPath $launcherPath -PathType Leaf) { return $true }
        return $false
    })
    $launcherContent = Get-Content -LiteralPath $launcherPath -Raw
    Assert-True ($launcherContent -notmatch [regex]::Escape($agentSecret)) 'launcher must not contain the plaintext agent secret'
    Assert-True ($launcherContent -match 'ProtectedData.*Unprotect') 'launcher should restore a DPAPI-protected secret'
    $launcherTokens = $null
    $launcherErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $launcherPath,
        [ref]$launcherTokens,
        [ref]$launcherErrors
    )
    Assert-True ($launcherErrors.Count -eq 0) 'generated launcher should parse successfully'

    $controlStatusJson = & $controlPath status -BaseUri $baseUri -ControlToken $controlToken
    $controlStatus = $controlStatusJson | ConvertFrom-Json
    Assert-True ($controlStatus.ok -eq $true) 'ctl.ps1 should reach the authenticated control API'

    $marker = 'e2e-{0}' -f [Guid]::NewGuid().ToString('N')
    $echoTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'; action = 'echo'; args = @{ text = $marker }; timeoutSeconds = 10
    }
    $echoResult = Wait-Task -TaskId $echoTask.id
    Assert-True ($echoResult.status -eq 'succeeded') 'echo task should succeed'
    Assert-True ($echoResult.result.output.text -eq $marker) 'echo task should preserve its payload'

    $hostTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'; action = 'get_host_info'; args = @{}; timeoutSeconds = 10
    }
    $hostResult = Wait-Task -TaskId $hostTask.id
    Assert-True ($hostResult.status -eq 'succeeded') 'get_host_info task should succeed'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$hostResult.result.output.powerShellVersion)) 'host info should include PowerShell version'

    $powerShellMarker = 'powershell-{0}' -f [Guid]::NewGuid().ToString('N')
    $powerShellScript = @"
`$numbers = 1..4
[pscustomobject]@{
    marker = '$powerShellMarker'
    total = (`$numbers | Measure-Object -Sum).Sum
    runtime = `$PSVersionTable.PSVersion.ToString()
}
"@
    $powerShellResultJson = & $controlPath submit `
        -BaseUri $baseUri `
        -ControlToken $controlToken `
        -AgentId 'agent-a' `
        -TaskAction powershell `
        -PowerShellScript $powerShellScript `
        -TaskTimeoutSeconds 10 `
        -Wait `
        -WaitTimeoutSeconds 15
    $powerShellResult = $powerShellResultJson | ConvertFrom-Json
    Assert-True ($powerShellResult.status -eq 'succeeded') 'powershell task should succeed'
    Assert-True ($powerShellResult.result.output.marker -eq $powerShellMarker) 'powershell task should return arbitrary script output'
    Assert-True ([int]$powerShellResult.result.output.total -eq 10) 'powershell task should execute variables and pipelines'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$powerShellResult.result.output.runtime)) 'powershell task should expose its runtime version'

    $heartbeatSessionBefore = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
    $heartbeatSessionId = [string](@($heartbeatSessionBefore.agents | Where-Object { $_.agentId -eq 'agent-a' })[0].sessionId)
    $parallelMarkerA = 'parallel-a-{0}' -f [Guid]::NewGuid().ToString('N')
    $parallelMarkerB = 'parallel-b-{0}' -f [Guid]::NewGuid().ToString('N')
    $parallelStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $parallelTaskA = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'
        action = 'powershell'
        args = @{ script = "Start-Sleep -Seconds 7; [pscustomobject]@{ marker = '$parallelMarkerA' }" }
        timeoutSeconds = 10
    }
    $parallelTaskB = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'
        action = 'powershell'
        args = @{ script = "Start-Sleep -Seconds 7; [pscustomobject]@{ marker = '$parallelMarkerB' }" }
        timeoutSeconds = 10
    }
    [void](Wait-Until -Description 'two tasks running concurrently' -Condition {
        $taskA = Invoke-TestApi -Method GET -Path ('/v1/tasks/{0}' -f $parallelTaskA.id) -Body $null
        $taskB = Invoke-TestApi -Method GET -Path ('/v1/tasks/{0}' -f $parallelTaskB.id) -Body $null
        return ($taskA.status -eq 'running' -and $taskB.status -eq 'running')
    })
    $parallelStatus = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
    $parallelAgent = @($parallelStatus.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
    Assert-True ([int]$parallelAgent.activeTasks -eq 2) 'status should report both active tasks'
    $parallelResultA = Wait-Task -TaskId $parallelTaskA.id
    $parallelResultB = Wait-Task -TaskId $parallelTaskB.id
    $parallelStopwatch.Stop()
    Assert-True ($parallelResultA.status -eq 'succeeded') 'first parallel task should succeed'
    Assert-True ($parallelResultB.status -eq 'succeeded') 'second parallel task should succeed'
    Assert-True ($parallelResultA.result.output.marker -eq $parallelMarkerA) 'first parallel task should preserve its output'
    Assert-True ($parallelResultB.result.output.marker -eq $parallelMarkerB) 'second parallel task should preserve its output'
    Assert-True ($parallelStopwatch.Elapsed.TotalSeconds -lt 12) 'two seven-second tasks should complete in parallel'
    $heartbeatSessionAfter = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
    $heartbeatAgentAfter = @($heartbeatSessionAfter.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
    Assert-True ($heartbeatAgentAfter.connected -eq $true) 'agent should remain connected during parallel long-running tasks'
    Assert-True ([string]$heartbeatAgentAfter.sessionId -eq $heartbeatSessionId) 'parallel tasks should preserve the authenticated session'

    $timeoutTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'
        action = 'powershell'
        args = @{ script = 'Start-Sleep -Seconds 30' }
        timeoutSeconds = 2
    }
    $timeoutResult = Wait-Task -TaskId $timeoutTask.id
    Assert-True ($timeoutResult.status -eq 'failed') 'timed-out worker task should fail'
    Assert-True ($timeoutResult.result.error.code -eq 'TASK_TIMEOUT') 'timed-out worker should return TASK_TIMEOUT'
    $postTimeoutTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'; action = 'ping'; args = @{}; timeoutSeconds = 10
    }
    $postTimeoutResult = Wait-Task -TaskId $postTimeoutTask.id
    Assert-True ($postTimeoutResult.status -eq 'succeeded') 'task after a worker timeout should succeed'
    $postTimeoutStatus = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
    $postTimeoutAgent = @($postTimeoutStatus.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
    Assert-True ([string]$postTimeoutAgent.sessionId -eq $heartbeatSessionId) 'worker timeout should preserve the authenticated session'

    $env:PS_TUNNEL_CONTROL_TOKEN = $controlToken
    $env:PS_TUNNEL_CONTROL_BASE_URI = $baseUri
    $mcpMarker = 'mcp-{0}' -f [Guid]::NewGuid().ToString('N')
    $mcpOutput = @(& $nodePath $mcpSmokePath `
        --server $mcpServerPath `
        --agent 'agent-a' `
        --marker $mcpMarker `
        --cwd $mcpWorkspace)
    if ($LASTEXITCODE -ne 0) {
        throw ('MCP smoke process exited with code {0}.' -f $LASTEXITCODE)
    }
    $mcpResult = ($mcpOutput -join "`n") | ConvertFrom-Json
    Assert-True ($mcpResult.ok -eq $true) 'MCP SDK client smoke test should succeed'
    Assert-True ($mcpResult.marker -eq $mcpMarker) 'MCP run_powershell should preserve its marker'
    Assert-True (@($mcpResult.tools).Count -eq 4) 'MCP tools/list should return all four tools'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$mcpResult.runTaskId)) 'MCP run_powershell should return a task id'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$mcpResult.submittedTaskId)) 'MCP submit_powershell should return a task id'

    $mcpConcurrencyMarker = 'mcp-parallel-{0}' -f [Guid]::NewGuid().ToString('N')
    $mcpConcurrencyOutput = @(& $nodePath $mcpConcurrencySmokePath `
        --server $mcpServerPath `
        --agent 'agent-a' `
        --marker $mcpConcurrencyMarker `
        --cwd $mcpWorkspace)
    if ($LASTEXITCODE -ne 0) {
        throw ('MCP concurrency smoke process exited with code {0}.' -f $LASTEXITCODE)
    }
    $mcpConcurrencyResult = ($mcpConcurrencyOutput -join "`n") | ConvertFrom-Json
    Assert-True ($mcpConcurrencyResult.ok -eq $true) 'two MCP instances should complete concurrent calls'
    Assert-True ([int]$mcpConcurrencyResult.elapsedMs -lt 12000) 'two MCP PowerShell calls should execute in parallel'
    Assert-True (@($mcpConcurrencyResult.taskIds).Count -eq 2) 'MCP concurrency test should return two task ids'

    if ($CodexMcp) {
        $codexMarker = 'codex-{0}' -f [Guid]::NewGuid().ToString('N')
        $codexExpectedValue = 3973
        $codexPowerShell = "[pscustomobject]@{ marker = '$codexMarker'; value = (137 * 29); source = 'codex-mcp' }"
        $codexPrompt = @"
Use the ps_tunnel MCP server for this task. Call list_agents first and select agent-a. Then call run_powershell with agentId agent-a, timeoutSeconds 10, waitTimeoutSeconds 20, and this exact script:
$codexPowerShell

Use the MCP tools for execution. After the tool succeeds, reply with one compact JSON object containing marker, value, source, and taskId from the MCP result.
"@
        $nodeTomlString = ConvertTo-Json -InputObject $nodePath -Compress
        $mcpServerTomlString = ConvertTo-Json -InputObject $mcpServerPath -Compress
        $codexWorkspaceTomlString = ConvertTo-Json -InputObject $codexWorkspace -Compress
        $codexArguments = @(
            'exec',
            '--json',
            '--ephemeral',
            '--skip-git-repo-check',
            '--color', 'never',
            '--sandbox', 'read-only',
            '--output-last-message', $codexLastMessage,
            '-C', $codexWorkspace,
            '-c', ('mcp_servers.ps_tunnel.command={0}' -f $nodeTomlString),
            '-c', ('mcp_servers.ps_tunnel.args=[{0}]' -f $mcpServerTomlString),
            '-c', ('mcp_servers.ps_tunnel.cwd={0}' -f $codexWorkspaceTomlString),
            '-c', 'mcp_servers.ps_tunnel.env_vars=["PS_TUNNEL_CONTROL_TOKEN","PS_TUNNEL_CONTROL_BASE_URI"]',
            '-c', 'mcp_servers.ps_tunnel.startup_timeout_sec=10',
            '-c', 'mcp_servers.ps_tunnel.tool_timeout_sec=120',
            '-c', 'mcp_servers.ps_tunnel.default_tools_approval_mode="approve"',
            '-c', 'mcp_servers.ps_tunnel.required=true',
            $codexPrompt
        )
        $codexOutput = @(& $codexExecutable @codexArguments 2> $codexStderr)
        $codexExitCode = $LASTEXITCODE
        $codexOutput | Set-Content -LiteralPath $codexStdout -Encoding UTF8
        if ($codexExitCode -ne 0) {
            throw ('Codex MCP invocation exited with code {0}.' -f $codexExitCode)
        }

        $codexEvents = @($codexOutput | ForEach-Object { $_ | ConvertFrom-Json })
        $codexMcpCalls = @($codexEvents | Where-Object {
            $_.type -eq 'item.completed' -and
            $null -ne $_.item -and
            $_.item.type -eq 'mcp_tool_call'
        })
        $codexListAgentsCalls = @($codexMcpCalls | Where-Object {
            (($_.item | ConvertTo-Json -Compress -Depth 20) -match 'ps_tunnel') -and
            (($_.item | ConvertTo-Json -Compress -Depth 20) -match 'list_agents')
        })
        $codexRunPowerShellCalls = @($codexMcpCalls | Where-Object {
            (($_.item | ConvertTo-Json -Compress -Depth 20) -match 'ps_tunnel') -and
            (($_.item | ConvertTo-Json -Compress -Depth 20) -match 'run_powershell')
        })
        Assert-True ($codexListAgentsCalls.Count -gt 0) 'Codex JSON events should contain a completed ps_tunnel list_agents MCP tool call'
        Assert-True ($codexRunPowerShellCalls.Count -gt 0) 'Codex JSON events should contain a completed ps_tunnel run_powershell MCP tool call'

        $codexTask = Wait-Until -Description 'Codex-created MCP task' -TimeoutSeconds 20 -Condition {
            $savedState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            $matchingTasks = @($savedState.tasks.PSObject.Properties | ForEach-Object { $_.Value } | Where-Object {
                $_.action -eq 'powershell' -and [string]$_.args.script -match [regex]::Escape($codexMarker)
            })
            $completedTask = @($matchingTasks | Where-Object { $_.status -eq 'succeeded' }) | Select-Object -Last 1
            if ($null -ne $completedTask) { return $completedTask }
            return $false
        }
        Assert-True ($codexTask.result.output.marker -eq $codexMarker) 'Codex MCP task should return its unique marker'
        Assert-True ([int]$codexTask.result.output.value -eq $codexExpectedValue) 'Codex MCP task should execute the requested arithmetic'
        Assert-True ($codexTask.result.output.source -eq 'codex-mcp') 'Codex MCP task should return its source label'

        $codexFinal = Get-Content -LiteralPath $codexLastMessage -Raw
        Assert-True ($codexFinal -match [regex]::Escape($codexMarker)) 'Codex final response should include the MCP result marker'
        Assert-True ($codexFinal -match [string]$codexExpectedValue) 'Codex final response should include the MCP result value'
        Write-Host ('CODEX MCP PASS: model called run_powershell, task {0}, marker {1}.' -f $codexTask.id, $codexMarker)
    }

    [void](Invoke-TestApi -Method POST -Path '/v1/test/disconnect' -Body @{ agentId = 'agent-a' })
    $secondStatus = Wait-Until -Description 'reconnected agent session' -TimeoutSeconds 20 -Condition {
        $status = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
        $agent = @($status.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
        if ($agent.connected -and [string]$agent.sessionId -ne $firstSessionId) { return $agent }
        return $false
    }
    Assert-True ([string]$secondStatus.sessionId -ne $firstSessionId) 'reconnect should create a new session id'

    $postReconnectTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'; action = 'ping'; args = @{}; timeoutSeconds = 10
    }
    $postReconnectResult = Wait-Task -TaskId $postReconnectTask.id
    Assert-True ($postReconnectResult.status -eq 'succeeded') 'task after reconnect should succeed'
    Assert-True ($postReconnectResult.result.output.message -eq 'pong') 'ping should return pong'

    Stop-Process -Id $clientProcess.Id -Force
    $clientProcess.WaitForExit(5000) | Out-Null
    [void](Wait-Until -Description 'original client disconnect' -Condition {
        $status = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
        $agent = @($status.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
        if (-not $agent.connected) { return $true }
        return $false
    })

    $launcherArguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $launcherPath
    )
    $launcherProcess = Start-Process -FilePath $clientPowerShellExecutable -ArgumentList $launcherArguments `
        -RedirectStandardOutput $launcherStdout -RedirectStandardError $launcherStderr -PassThru -NoNewWindow
    $launcherStatus = Wait-Until -Description 'generated launcher session' -Condition {
        $status = Invoke-TestApi -Method GET -Path '/v1/status' -Body $null
        $agent = @($status.agents | Where-Object { $_.agentId -eq 'agent-a' })[0]
        if ($agent.connected -and [string]$agent.sessionId -ne [string]$secondStatus.sessionId) { return $agent }
        return $false
    }

    $launcherTask = Invoke-TestApi -Method POST -Path '/v1/tasks' -Body @{
        agentId = 'agent-a'; action = 'ping'; args = @{}; timeoutSeconds = 10
    }
    $launcherResult = Wait-Task -TaskId $launcherTask.id
    Assert-True ($launcherResult.status -eq 'succeeded') 'task through generated launcher should succeed'
    Assert-True ($launcherResult.result.output.message -eq 'pong') 'generated launcher should return pong'

    $testSucceeded = $true
    $codexCoverage = if ($CodexMcp) { ', Codex model MCP invocation' } else { '' }
    Write-Host ('E2E PASS: auth, protected launcher, parallel workers, dual MCP instances, timeout recovery{0}, forced disconnect, and reconnect. Session {1} -> {2} -> {3}' -f $codexCoverage, $firstSessionId, $secondStatus.sessionId, $launcherStatus.sessionId)
}
finally {
    $env:PS_TUNNEL_AGENT_SECRET = $originalAgentSecret
    if ($null -eq $originalControlToken) {
        Remove-Item Env:PS_TUNNEL_CONTROL_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:PS_TUNNEL_CONTROL_TOKEN = $originalControlToken
    }
    if ($null -eq $originalControlBaseUri) {
        Remove-Item Env:PS_TUNNEL_CONTROL_BASE_URI -ErrorAction SilentlyContinue
    }
    else {
        $env:PS_TUNNEL_CONTROL_BASE_URI = $originalControlBaseUri
    }
    foreach ($process in @($launcherProcess, $clientProcess, $brokerProcess)) {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    Stop-Process -Id $process.Id -Force
                    $process.WaitForExit(5000) | Out-Null
                }
            }
            catch {
                Write-Warning ('Process cleanup failed for pid {0}: {1}' -f $process.Id, $_.Exception.Message)
            }
            $process.Dispose()
        }
    }

    if (-not $testSucceeded) {
        Write-Host ('E2E artifacts retained at {0}' -f $tempDirectory)
        foreach ($logFile in @($brokerStderr, $clientStdout, $clientStderr, $launcherStdout, $launcherStderr, $clientLog, $codexStdout, $codexStderr, $codexLastMessage)) {
            if (Test-Path -LiteralPath $logFile) {
                Write-Host ('--- {0} ---' -f $logFile)
                Get-Content -LiteralPath $logFile -ErrorAction SilentlyContinue
            }
        }
    }
    elseif ($tempDirectory.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force
    }
}
