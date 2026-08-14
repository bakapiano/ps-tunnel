[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'submit', 'get', 'disconnect')]
    [string]$Command = 'status',

    [string]$AgentId,
    [ValidateSet('ping', 'echo', 'get_host_info')]
    [string]$TaskAction,
    [string]$ArgumentsJson = '{}',
    [ValidateRange(1, 3600)]
    [int]$TaskTimeoutSeconds = 30,
    [string]$TaskId,
    [string]$BaseUri = 'http://127.0.0.1:8766',
    [string]$ControlToken = $env:PS_TUNNEL_CONTROL_TOKEN,
    [switch]$Wait,
    [ValidateRange(1, 3600)]
    [int]$WaitTimeoutSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ControlToken) -or $ControlToken.Length -lt 16) {
    throw 'PS_TUNNEL_CONTROL_TOKEN (or ControlToken) must contain at least 16 characters.'
}
$headers = @{ Authorization = 'Bearer {0}' -f $ControlToken }
$BaseUri = $BaseUri.TrimEnd('/')

function Invoke-ControlRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        $Body
    )

    $parameters = @{
        Method = $Method
        Uri = $BaseUri + $Path
        Headers = $headers
        TimeoutSec = 10
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json; charset=utf-8'
        $parameters.Body = $Body | ConvertTo-Json -Compress -Depth 16
    }
    return Invoke-RestMethod @parameters
}
function Write-Result {
    param($Value)
    $Value | ConvertTo-Json -Depth 20
}

switch ($Command) {
    'status' {
        Write-Result (Invoke-ControlRequest -Method GET -Path '/v1/status' -Body $null)
    }
    'submit' {
        if ([string]::IsNullOrWhiteSpace($AgentId) -or [string]::IsNullOrWhiteSpace($TaskAction)) {
            throw 'submit requires AgentId and TaskAction.'
        }
        try {
            $taskArguments = $ArgumentsJson | ConvertFrom-Json
        }
        catch {
            throw ('ArgumentsJson is invalid: {0}' -f $_.Exception.Message)
        }
        $created = Invoke-ControlRequest -Method POST -Path '/v1/tasks' -Body ([ordered]@{
            agentId = $AgentId
            action = $TaskAction
            args = $taskArguments
            timeoutSeconds = $TaskTimeoutSeconds
        })
        if (-not $Wait) {
            Write-Result $created
            break
        }

        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitTimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 250
            $current = Invoke-ControlRequest -Method GET -Path ('/v1/tasks/{0}' -f $created.id) -Body $null
            if ([string]$current.status -in @('succeeded', 'failed')) {
                Write-Result $current
                break
            }
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if ([string]$current.status -notin @('succeeded', 'failed')) {
            throw ('Task {0} did not finish within {1} seconds.' -f $created.id, $WaitTimeoutSeconds)
        }
    }
    'get' {
        if ([string]::IsNullOrWhiteSpace($TaskId)) {
            throw 'get requires TaskId.'
        }
        Write-Result (Invoke-ControlRequest -Method GET -Path ('/v1/tasks/{0}' -f $TaskId) -Body $null)
    }
    'disconnect' {
        if ([string]::IsNullOrWhiteSpace($AgentId)) {
            throw 'disconnect requires AgentId.'
        }
        Write-Result (Invoke-ControlRequest -Method POST -Path '/v1/test/disconnect' -Body @{ agentId = $AgentId })
    }
}
