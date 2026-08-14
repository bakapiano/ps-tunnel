[CmdletBinding()]
param(
    [string]$ClientPowerShellPath
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
$nodePath = (Get-Command node -ErrorAction Stop).Source
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
    Write-Host ('E2E PASS: auth, protected launcher execution, echo, host info, forced disconnect, and reconnect. Session {0} -> {1} -> {2}' -f $firstSessionId, $secondStatus.sessionId, $launcherStatus.sessionId)
}
finally {
    $env:PS_TUNNEL_AGENT_SECRET = $originalAgentSecret
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
        foreach ($logFile in @($brokerStderr, $clientStdout, $clientStderr, $launcherStdout, $launcherStderr, $clientLog)) {
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
