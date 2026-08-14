[CmdletBinding()]
param(
    [string]$ConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot 'config.json'
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$serverDirectory = Split-Path -Parent $ConfigPath
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$nodePath = (Get-Command node.exe -ErrorAction Stop).Source
$brokerPath = Join-Path $serverDirectory 'broker.js'
$sshServerPath = Join-Path $serverDirectory 'ssh-server.js'
$sshModulePath = Join-Path $serverDirectory 'node_modules\ssh2'

foreach ($requiredPath in @($brokerPath, $sshServerPath, $sshModulePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required server component was not found: $requiredPath"
    }
}

function Join-NativeArguments {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)

    return (($ArgumentList | ForEach-Object {
        $value = [string]$_
        if ($value -notmatch '[\s"]') {
            return $value
        }
        # Windows paths cannot contain a quote. Quoting the complete value is
        # sufficient for the Node script and config paths passed here.
        return '"{0}"' -f $value
    }) -join ' ')
}

$agentPort = [int]$config.agentListen.port
$controlPort = [int]$config.controlListen.port
$sshPort = [int]$config.ssh.port

function Get-Listener {
    param([Parameter(Mandatory = $true)][int]$Port)
    return @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -First 1)[0]
}

function Test-ExpectedProcess {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$ScriptName
    )
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $ProcessId) -ErrorAction SilentlyContinue
    return ($null -ne $process -and [string]$process.CommandLine -match [regex]::Escape($ScriptName))
}

function Wait-ForListener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $listener = Get-Listener -Port $Port
        if ($null -ne $listener) {
            return $listener
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "TCP listener $Port did not become ready."
}

$agentListener = Get-Listener -Port $agentPort
$controlListener = Get-Listener -Port $controlPort
if (($null -eq $agentListener) -xor ($null -eq $controlListener)) {
    throw 'Broker listeners are in a partial state. Stop the owning process and run start.ps1 again.'
}

$brokerStarted = $false
if ($null -eq $agentListener) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $brokerArguments = Join-NativeArguments -ArgumentList @($brokerPath, '--config', $ConfigPath)
    $brokerProcess = Start-Process -FilePath $nodePath `
        -ArgumentList $brokerArguments `
        -WorkingDirectory $serverDirectory -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $serverDirectory "broker-$stamp.stdout.log") `
        -RedirectStandardError (Join-Path $serverDirectory "broker-$stamp.stderr.log") `
        -PassThru
    $agentListener = Wait-ForListener -Port $agentPort
    $controlListener = Wait-ForListener -Port $controlPort
    $brokerStarted = $true
}
elseif ($agentListener.OwningProcess -ne $controlListener.OwningProcess -or
        -not (Test-ExpectedProcess -ProcessId $agentListener.OwningProcess -ScriptName 'broker.js')) {
    throw 'Broker ports are occupied by an unexpected process.'
}

$sshListener = Get-Listener -Port $sshPort
$sshStarted = $false
if ($null -eq $sshListener) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $sshArguments = Join-NativeArguments -ArgumentList @($sshServerPath, '--config', $ConfigPath)
    $sshProcess = Start-Process -FilePath $nodePath `
        -ArgumentList $sshArguments `
        -WorkingDirectory $serverDirectory -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $serverDirectory "ssh-server-$stamp.stdout.log") `
        -RedirectStandardError (Join-Path $serverDirectory "ssh-server-$stamp.stderr.log") `
        -PassThru
    $sshListener = Wait-ForListener -Port $sshPort
    $sshStarted = $true
}
elseif (-not (Test-ExpectedProcess -ProcessId $sshListener.OwningProcess -ScriptName 'ssh-server.js')) {
    throw "SSH port $sshPort is occupied by an unexpected process."
}

$headers = @{ Authorization = 'Bearer {0}' -f [string]$config.controlToken }
$status = Invoke-RestMethod -Method Get `
    -Uri ("http://{0}:{1}/v1/status" -f $config.controlListen.host, $controlPort) `
    -Headers $headers -TimeoutSec 5

[ordered]@{
    ok = $true
    broker = [ordered]@{
        started = $brokerStarted
        processId = [int]$agentListener.OwningProcess
        agentEndpoint = '{0}:{1}' -f $config.agentListen.host, $agentPort
        controlEndpoint = '{0}:{1}' -f $config.controlListen.host, $controlPort
    }
    ssh = [ordered]@{
        started = $sshStarted
        processId = [int]$sshListener.OwningProcess
        endpoint = '{0}:{1}' -f $config.ssh.host, $sshPort
        user = [string]$config.ssh.user
    }
    agents = $status.agents
} | ConvertTo-Json -Depth 10
