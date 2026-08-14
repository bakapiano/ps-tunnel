[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$AgentId,

    [ValidateSet('Ssh', 'Process')]
    [string]$Transport = 'Ssh',

    [string]$SshHost,
    [ValidateRange(1, 65535)]
    [int]$SshPort = 22,
    [string]$SshUser,
    [string]$IdentityFile,
    [string]$KnownHostsFile = (Join-Path -Path $HOME -ChildPath '.ssh\known_hosts'),
    [string]$RemoteCommand,
    [string]$SshPath = 'ssh.exe',

    # Process transport exists for the local E2E test. Production uses Ssh.
    [string]$ProcessFilePath,
    [string]$ProcessArgumentsBase64,

    [string]$AgentSecret = $env:PS_TUNNEL_AGENT_SECRET,
    [ValidateRange(1, 300)]
    [int]$TaskTimeoutSeconds = 30,
    [ValidateRange(1024, 1048576)]
    [int]$MaxMessageBytes = 262144,
    [ValidateRange(1, 3600)]
    [int]$SessionReadTimeoutSeconds = 90,
    [ValidateRange(1, 300)]
    [int]$ReconnectInitialSeconds = 1,
    [ValidateRange(1, 3600)]
    [int]$ReconnectMaxSeconds = 30,
    [ValidateRange(0, 1000000)]
    [int]$MaxReconnectAttempts = 0,
    [ValidateSet('Prompt', 'Always', 'Never')]
    [string]$LauncherMode = 'Prompt',
    [string]$LauncherPath,
    [string]$LogPath,
    [switch]$Once
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ProtocolVersion = 1
$ClientScriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
$script:LauncherOfferHandled = $false

function Write-AgentLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f [DateTimeOffset]::UtcNow.ToString('o'), $Level, $Message
    Write-Host $line
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    }
}

function Test-InteractiveInput {
    if (-not [Environment]::UserInteractive) {
        return $false
    }
    try {
        return (-not [Console]::IsInputRedirected)
    }
    catch {
        return $false
    }
}

function Get-LauncherParameters {
    $parameters = [ordered]@{
        AgentId = $AgentId
        Transport = $Transport
        TaskTimeoutSeconds = $TaskTimeoutSeconds
        MaxMessageBytes = $MaxMessageBytes
        SessionReadTimeoutSeconds = $SessionReadTimeoutSeconds
        ReconnectInitialSeconds = $ReconnectInitialSeconds
        ReconnectMaxSeconds = $ReconnectMaxSeconds
        MaxReconnectAttempts = $MaxReconnectAttempts
        LauncherMode = 'Never'
    }

    if ($Transport -eq 'Ssh') {
        $parameters.SshHost = $SshHost
        $parameters.SshPort = $SshPort
        $parameters.SshUser = $SshUser
        $parameters.SshPath = $SshPath
        $parameters.IdentityFile = $IdentityFile
        $parameters.KnownHostsFile = $KnownHostsFile
        if (-not [string]::IsNullOrWhiteSpace($RemoteCommand)) {
            $parameters.RemoteCommand = $RemoteCommand
        }
    }
    else {
        $parameters.ProcessFilePath = $ProcessFilePath
        $parameters.ProcessArgumentsBase64 = $ProcessArgumentsBase64
    }

    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        $parameters.LogPath = $LogPath
    }
    if ($Once.IsPresent) {
        $parameters.Once = $true
    }
    return $parameters
}

function Protect-LauncherFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls.exe $Path /inheritance:r /grant:r `
            (('*{0}:(F)' -f $currentSid)) '*S-1-5-18:(F)' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw ('icacls exited with code {0}.' -f $LASTEXITCODE)
        }
    }
    catch {
        Write-AgentLog -Level 'WARN' -Message ('Launcher ACL hardening failed: {0}' -f $_.Exception.Message)
    }
}

function New-OneClickLauncher {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'One-click launcher protection requires Windows DPAPI.'
    }

    $outputPath = $LauncherPath
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
        $outputPath = Join-Path (Split-Path -Parent $ClientScriptPath) 'start-client.ps1'
    }
    $outputPath = [System.IO.Path]::GetFullPath($outputPath)
    if ([System.IO.Path]::GetExtension($outputPath) -ne '.ps1') {
        throw 'LauncherPath must use the .ps1 extension.'
    }
    $outputDirectory = Split-Path -Parent $outputPath
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        throw ('Launcher directory was not found: {0}' -f $outputDirectory)
    }
    if (Test-Path -LiteralPath $outputPath) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($outputPath)
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $outputPath = Join-Path $outputDirectory ('{0}-{1}.ps1' -f $name, $stamp)
    }

    $parameterJson = (Get-LauncherParameters) | ConvertTo-Json -Compress -Depth 10
    $parameterData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($parameterJson))
    $clientPathData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ClientScriptPath))

    Add-Type -AssemblyName System.Security -ErrorAction Stop
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($AgentSecret)
    $entropy = [System.Text.Encoding]::UTF8.GetBytes('ps-tunnel-launcher-v1')
    try {
        $protectedSecretBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $secretBytes,
            $entropy,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $protectedSecret = [Convert]::ToBase64String($protectedSecretBytes)
    }
    finally {
        [Array]::Clear($secretBytes, 0, $secretBytes.Length)
    }

    $template = @'
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The Agent Secret below is protected by Windows DPAPI. This launcher works
# only for the Windows user and computer that created it.
$parameterData = '__PARAMETER_DATA__'
$clientPathData = '__CLIENT_PATH_DATA__'
$protectedAgentSecret = '__PROTECTED_SECRET__'

$parameterJson = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($parameterData)
)
$parameterObject = $parameterJson | ConvertFrom-Json
$clientParameters = @{}
foreach ($property in $parameterObject.PSObject.Properties) {
    $clientParameters[[string]$property.Name] = $property.Value
}
$clientPath = [System.Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($clientPathData)
)
if (-not (Test-Path -LiteralPath $clientPath -PathType Leaf)) {
    throw ('client.ps1 was not found: {0}' -f $clientPath)
}

$null = Add-Type -AssemblyName System.Security -ErrorAction Stop
$entropy = [System.Text.Encoding]::UTF8.GetBytes('ps-tunnel-launcher-v1')
$protectedSecretBytes = [Convert]::FromBase64String($protectedAgentSecret)
$plainSecretBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $protectedSecretBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$plainAgentSecret = $null
try {
    $plainAgentSecret = [System.Text.Encoding]::UTF8.GetString($plainSecretBytes)
    & $clientPath @clientParameters -AgentSecret $plainAgentSecret
}
finally {
    [Array]::Clear($plainSecretBytes, 0, $plainSecretBytes.Length)
    $plainAgentSecret = $null
}
'@

    $content = $template.Replace('__PARAMETER_DATA__', $parameterData).
        Replace('__CLIENT_PATH_DATA__', $clientPathData).
        Replace('__PROTECTED_SECRET__', $protectedSecret)
    [System.IO.File]::WriteAllText(
        $outputPath,
        $content,
        (New-Object System.Text.UTF8Encoding($false))
    )
    Protect-LauncherFile -Path $outputPath
    return $outputPath
}

function Invoke-LauncherOffer {
    if ($script:LauncherOfferHandled) {
        return
    }
    $script:LauncherOfferHandled = $true

    if ($LauncherMode -eq 'Never') {
        return
    }

    $createLauncher = ($LauncherMode -eq 'Always')
    if ($LauncherMode -eq 'Prompt') {
        if (-not (Test-InteractiveInput)) {
            return
        }
        $answer = Read-Host 'Connection authenticated. Create a one-click start-client.ps1 with these settings? [y/N]'
        $createLauncher = $answer -match '^(?i:y|yes|是)$'
    }

    if (-not $createLauncher) {
        return
    }
    try {
        $createdPath = New-OneClickLauncher
        Write-AgentLog -Message ('Created one-click launcher: {0}' -f $createdPath)
    }
    catch {
        Write-AgentLog -Level 'WARN' -Message ('One-click launcher creation failed: {0}' -f $_.Exception.Message)
    }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if (($Value.Length -gt 0) -and ($Value -notmatch '[\s"]')) {
        return $Value
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            if ($backslashes -gt 0) {
                [void]$builder.Append(('\' * ($backslashes * 2)))
            }
            [void]$builder.Append('\"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-NativeArguments {
    param([string[]]$ArgumentList)
    return (($ArgumentList | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' ')
}

function New-RandomHex {
    param([ValidateRange(8, 128)][int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-HmacHex {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $data = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $key)
    try {
        $digest = $hmac.ComputeHash($data)
    }
    finally {
        $hmac.Dispose()
    }
    return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-ConstantTimeString {
    param([string]$Left, [string]$Right)

    if (($null -eq $Left) -or ($null -eq $Right)) {
        return $false
    }
    $leftBytes = [System.Text.Encoding]::ASCII.GetBytes($Left)
    $rightBytes = [System.Text.Encoding]::ASCII.GetBytes($Right)
    $difference = $leftBytes.Length -bxor $rightBytes.Length
    $length = [Math]::Max($leftBytes.Length, $rightBytes.Length)
    for ($index = 0; $index -lt $length; $index++) {
        $leftValue = if ($index -lt $leftBytes.Length) { $leftBytes[$index] } else { 0 }
        $rightValue = if ($index -lt $rightBytes.Length) { $rightBytes[$index] } else { 0 }
        $difference = $difference -bor ($leftValue -bxor $rightValue)
    }
    return ($difference -eq 0)
}

function ConvertTo-StringKeyHashtable {
    param($Value)

    $result = @{}
    if ($null -eq $Value) {
        return $result
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            $result[[string]$key] = $Value[$key]
        }
        return $result
    }
    foreach ($property in $Value.PSObject.Properties) {
        $result[[string]$property.Name] = $property.Value
    }
    return $result
}

$AllowedTaskScript = {
    param(
        [string]$Action,
        [hashtable]$Arguments
    )

    switch ($Action) {
        'ping' {
            [ordered]@{
                message = 'pong'
                utc = [DateTimeOffset]::UtcNow.ToString('o')
            }
            break
        }
        'echo' {
            if (-not $Arguments.ContainsKey('text')) {
                throw 'echo requires the text argument.'
            }
            $text = [string]$Arguments['text']
            if ($text.Length -gt 4096) {
                throw 'echo text exceeds 4096 characters.'
            }
            [ordered]@{ text = $text }
            break
        }
        'get_host_info' {
            [ordered]@{
                computerName = [Environment]::MachineName
                userName = [Environment]::UserName
                powerShellVersion = $PSVersionTable.PSVersion.ToString()
                processId = [System.Diagnostics.Process]::GetCurrentProcess().Id
                workingDirectory = (Get-Location).Path
                utc = [DateTimeOffset]::UtcNow.ToString('o')
            }
            break
        }
        'powershell' {
            if (-not $Arguments.ContainsKey('script')) {
                throw 'powershell requires the script argument.'
            }
            if ($Arguments['script'] -isnot [string]) {
                throw 'powershell script must be a string.'
            }

            $scriptBlock = [scriptblock]::Create([string]$Arguments['script'])
            & $scriptBlock
            break
        }
        default {
            throw ('Action is outside the allowlist: {0}' -f $Action)
        }
    }
}

function Invoke-AllowedTask {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $runner = [System.Management.Automation.PowerShell]::Create()
    $asyncResult = $null
    try {
        [void]$runner.AddScript($AllowedTaskScript.ToString())
        [void]$runner.AddArgument($Action)
        [void]$runner.AddArgument($Arguments)
        $asyncResult = $runner.BeginInvoke()
        $completed = $asyncResult.AsyncWaitHandle.WaitOne($TaskTimeoutSeconds * 1000)
        if (-not $completed) {
            $runner.Stop()
            return [pscustomobject]@{
                ok = $false
                output = $null
                error = [ordered]@{ code = 'TASK_TIMEOUT'; message = 'Task execution exceeded the local timeout.' }
            }
        }

        $items = @($runner.EndInvoke($asyncResult))
        if ($runner.HadErrors) {
            $messages = @($runner.Streams.Error | ForEach-Object { $_.Exception.Message })
            return [pscustomobject]@{
                ok = $false
                output = $null
                error = [ordered]@{ code = 'TASK_FAILED'; message = ($messages -join '; ') }
            }
        }

        $output = $null
        if ($items.Count -eq 1) {
            $output = $items[0]
        }
        elseif ($items.Count -gt 1) {
            $output = $items
        }
        return [pscustomobject]@{ ok = $true; output = $output; error = $null }
    }
    catch {
        return [pscustomobject]@{
            ok = $false
            output = $null
            error = [ordered]@{ code = 'TASK_FAILED'; message = $_.Exception.Message }
        }
    }
    finally {
        if ($null -ne $asyncResult) {
            $asyncResult.AsyncWaitHandle.Dispose()
        }
        $runner.Dispose()
    }
}

function Send-ProtocolMessage {
    param(
        [Parameter(Mandatory = $true)][System.IO.StreamWriter]$Writer,
        [Parameter(Mandatory = $true)]$Message
    )

    $json = $Message | ConvertTo-Json -Compress -Depth 16
    $size = [System.Text.Encoding]::UTF8.GetByteCount($json)
    if ($size -gt $MaxMessageBytes) {
        throw ('Protocol message is {0} bytes; limit is {1}.' -f $size, $MaxMessageBytes)
    }
    $Writer.WriteLine($json)
    $Writer.Flush()
}

function Read-ProtocolMessage {
    param(
        [Parameter(Mandatory = $true)][System.IO.StreamReader]$Reader,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $readTask = $Reader.ReadLineAsync()
    if (-not $readTask.Wait($TimeoutSeconds * 1000)) {
        throw ('No protocol message arrived within {0} seconds.' -f $TimeoutSeconds)
    }
    $line = $readTask.Result
    if ($null -eq $line) {
        return $null
    }
    if ([System.Text.Encoding]::UTF8.GetByteCount($line) -gt $MaxMessageBytes) {
        throw 'Received protocol message exceeds the configured size limit.'
    }
    try {
        return ($line | ConvertFrom-Json)
    }
    catch {
        throw ('Received invalid protocol JSON: {0}' -f $_.Exception.Message)
    }
}

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw ('{0} path is required.' -f $Description)
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('{0} was not found: {1}' -f $Description, $Path)
    }
    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    catch {
        throw ('{0} could not be resolved: {1}' -f $Description, $_.Exception.Message)
    }
}

function Get-TransportStandardError {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process -or
        -not ($Process.PSObject.Properties.Name -contains 'StandardErrorReadTask')) {
        return $null
    }

    try {
        $task = $Process.StandardErrorReadTask
        if (-not $task.IsCompleted) {
            [void]$task.Wait(1000)
        }
        if (-not $task.IsCompleted -or $task.IsFaulted -or $task.IsCanceled) {
            return $null
        }
        $text = [string]$task.Result
        if ($text.Length -gt 4096) {
            $text = $text.Substring(0, 4096) + ' ...[truncated]'
        }
        return $text.Trim()
    }
    catch {
        return $null
    }
}

function Get-TransportSpec {
    if ($Transport -eq 'Ssh') {
        if ([string]::IsNullOrWhiteSpace($SshHost) -or [string]::IsNullOrWhiteSpace($SshUser)) {
            throw 'SshHost and SshUser are required for SSH transport.'
        }
        if ([string]::IsNullOrWhiteSpace($KnownHostsFile)) {
            throw 'KnownHostsFile is required so the B host key can be pinned.'
        }

        $sshCommand = Get-Command $SshPath -CommandType Application -ErrorAction SilentlyContinue
        if ($null -eq $sshCommand) {
            throw ('SSH executable was not found: {0}' -f $SshPath)
        }
        $resolvedKnownHostsFile = Resolve-RequiredFile -Path $KnownHostsFile -Description 'Known-hosts file'

        $arguments = @(
            '-T',
            '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', ('UserKnownHostsFile={0}' -f $resolvedKnownHostsFile),
            '-o', 'LogLevel=ERROR',
            '-p', [string]$SshPort
        )
        if (-not [string]::IsNullOrWhiteSpace($IdentityFile)) {
            $resolvedIdentityFile = Resolve-RequiredFile -Path $IdentityFile -Description 'SSH identity file'
            try {
                $identityStream = [System.IO.File]::Open(
                    $resolvedIdentityFile,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read
                )
                $identityStream.Dispose()
            }
            catch {
                throw ('SSH identity file is not readable: {0}' -f $_.Exception.Message)
            }
            $arguments += @('-i', $resolvedIdentityFile)
        }
        # Keep the login name separate from the destination so Windows domain
        # identities such as DOMAIN\user are passed to OpenSSH unchanged.
        $arguments += @('-l', $SshUser, $SshHost)
        if (-not [string]::IsNullOrWhiteSpace($RemoteCommand)) {
            $arguments += $RemoteCommand
        }
        return [pscustomobject]@{ FilePath = $sshCommand.Source; Arguments = [string[]]$arguments }
    }

    if ([string]::IsNullOrWhiteSpace($ProcessFilePath) -or [string]::IsNullOrWhiteSpace($ProcessArgumentsBase64)) {
        throw 'ProcessFilePath and ProcessArgumentsBase64 are required for Process transport.'
    }
    try {
        $jsonBytes = [Convert]::FromBase64String($ProcessArgumentsBase64)
        $json = [System.Text.Encoding]::UTF8.GetString($jsonBytes)
        $decodedValue = $json | ConvertFrom-Json
        $decoded = @()
        foreach ($item in $decodedValue) {
            $decoded += [string]$item
        }
    }
    catch {
        throw ('ProcessArgumentsBase64 is invalid: {0}' -f $_.Exception.Message)
    }
    return [pscustomobject]@{ FilePath = $ProcessFilePath; Arguments = [string[]]$decoded }
}

function Start-TransportProcess {
    $spec = Get-TransportSpec
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $spec.FilePath
    $startInfo.Arguments = Join-NativeArguments -ArgumentList $spec.Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    if ($startInfo.PSObject.Properties.Name -contains 'StandardInputEncoding') {
        $startInfo.StandardInputEncoding = New-Object System.Text.UTF8Encoding($false)
    }
    if ($startInfo.PSObject.Properties.Name -contains 'StandardOutputEncoding') {
        $startInfo.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw 'Transport process did not start.'
    }
    $standardErrorReadTask = $process.StandardError.ReadToEndAsync()
    $process | Add-Member -MemberType NoteProperty -Name StandardErrorReadTask -Value $standardErrorReadTask -Force
    $process.StandardInput.AutoFlush = $true
    return $process
}

function Invoke-AgentSession {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    $reader = $Process.StandardOutput
    $writer = $Process.StandardInput
    $challenge = Read-ProtocolMessage -Reader $reader -TimeoutSeconds 20
    if ($null -eq $challenge) {
        throw 'Transport closed before authentication challenge.'
    }
    if ([string]$challenge.type -ne 'challenge' -or [int]$challenge.protocol -ne $ProtocolVersion) {
        throw 'Unexpected authentication challenge.'
    }
    $serverNonce = [string]$challenge.nonce
    if ($serverNonce -notmatch '^[a-f0-9]{64}$') {
        throw 'Server challenge nonce is invalid.'
    }

    $clientNonce = New-RandomHex -ByteCount 32
    $authText = 'auth|{0}|{1}|{2}|{3}' -f $ProtocolVersion, $AgentId, $serverNonce, $clientNonce
    $authProof = Get-HmacHex -Secret $AgentSecret -Text $authText
    Send-ProtocolMessage -Writer $writer -Message ([ordered]@{
        type = 'authenticate'
        protocol = $ProtocolVersion
        agentId = $AgentId
        nonce = $clientNonce
        proof = $authProof
    })

    $ready = Read-ProtocolMessage -Reader $reader -TimeoutSeconds 20
    if ($null -eq $ready) {
        throw 'Transport closed during authentication.'
    }
    if ([string]$ready.type -eq 'error') {
        throw ('Server rejected authentication: {0}' -f [string]$ready.message)
    }
    if ([string]$ready.type -ne 'ready' -or [int]$ready.protocol -ne $ProtocolVersion) {
        throw 'Unexpected authentication response.'
    }
    $sessionId = [string]$ready.sessionId
    $readyText = 'ready|{0}|{1}|{2}|{3}|{4}' -f $ProtocolVersion, $AgentId, $serverNonce, $clientNonce, $sessionId
    $expectedReadyProof = Get-HmacHex -Secret $AgentSecret -Text $readyText
    if (-not (Test-ConstantTimeString -Left $expectedReadyProof -Right ([string]$ready.proof))) {
        throw 'Server authentication proof is invalid.'
    }

    Write-AgentLog -Message ('Authenticated session {0}.' -f $sessionId)
    Invoke-LauncherOffer
    while ($true) {
        $message = Read-ProtocolMessage -Reader $reader -TimeoutSeconds $SessionReadTimeoutSeconds
        if ($null -eq $message) {
            throw 'Transport reached end-of-stream.'
        }

        switch ([string]$message.type) {
            'ping' {
                Send-ProtocolMessage -Writer $writer -Message ([ordered]@{
                    type = 'pong'
                    protocol = $ProtocolVersion
                    at = [DateTimeOffset]::UtcNow.ToString('o')
                })
            }
            'task' {
                $taskId = [string]$message.id
                $action = [string]$message.action
                if ($taskId -notmatch '^[A-Za-z0-9-]{8,64}$') {
                    throw 'Task id is invalid.'
                }

                $started = [DateTimeOffset]::UtcNow
                $execution = $null
                if ($null -ne $message.deadline -and -not [string]::IsNullOrWhiteSpace([string]$message.deadline)) {
                    if ($message.deadline -is [DateTime]) {
                        $deadline = [DateTimeOffset]$message.deadline
                    }
                    elseif ($message.deadline -is [DateTimeOffset]) {
                        $deadline = $message.deadline
                    }
                    else {
                        $deadline = [DateTimeOffset]::Parse(
                            [string]$message.deadline,
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::RoundtripKind
                        )
                    }
                    if ($deadline -lt $started) {
                        $execution = [pscustomobject]@{
                            ok = $false
                            output = $null
                            error = [ordered]@{ code = 'TASK_EXPIRED'; message = 'Task deadline passed before execution.' }
                        }
                    }
                }
                if ($null -eq $execution) {
                    $arguments = ConvertTo-StringKeyHashtable -Value $message.args
                    Write-AgentLog -Message ('Executing task {0} ({1}).' -f $taskId, $action)
                    $execution = Invoke-AllowedTask -Action $action -Arguments $arguments
                }
                $completed = [DateTimeOffset]::UtcNow
                $resultMessage = [ordered]@{
                    type = 'result'
                    protocol = $ProtocolVersion
                    id = $taskId
                    ok = [bool]$execution.ok
                    output = $execution.output
                    error = $execution.error
                    startedAt = $started.ToString('o')
                    completedAt = $completed.ToString('o')
                    durationMs = [Math]::Round(($completed - $started).TotalMilliseconds)
                }
                try {
                    Send-ProtocolMessage -Writer $writer -Message $resultMessage
                }
                catch {
                    Send-ProtocolMessage -Writer $writer -Message ([ordered]@{
                        type = 'result'
                        protocol = $ProtocolVersion
                        id = $taskId
                        ok = $false
                        output = $null
                        error = [ordered]@{ code = 'RESULT_TOO_LARGE'; message = 'Task result exceeded the protocol size limit.' }
                        startedAt = $started.ToString('o')
                        completedAt = [DateTimeOffset]::UtcNow.ToString('o')
                        durationMs = [Math]::Round(([DateTimeOffset]::UtcNow - $started).TotalMilliseconds)
                    })
                }
                Write-AgentLog -Message ('Completed task {0}; ok={1}.' -f $taskId, [bool]$execution.ok)
            }
            'error' {
                throw ('Server protocol error: {0}' -f [string]$message.message)
            }
            default {
                throw ('Unexpected protocol message type: {0}' -f [string]$message.type)
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($AgentSecret) -or $AgentSecret.Length -lt 16) {
    throw 'PS_TUNNEL_AGENT_SECRET (or AgentSecret) must contain at least 16 characters.'
}
if ($ReconnectInitialSeconds -gt $ReconnectMaxSeconds) {
    throw 'ReconnectInitialSeconds must be less than or equal to ReconnectMaxSeconds.'
}

$reconnectCount = 0
$failureStreak = 0
while ($true) {
    $transportProcess = $null
    $sessionStarted = [DateTimeOffset]::UtcNow
    try {
        Write-AgentLog -Message ('Starting {0} transport.' -f $Transport)
        $transportProcess = Start-TransportProcess
        Invoke-AgentSession -Process $transportProcess
    }
    catch {
        Write-AgentLog -Level 'WARN' -Message $_.Exception.Message
    }
    finally {
        if ($null -ne $transportProcess) {
            try {
                if (-not $transportProcess.HasExited) {
                    $transportProcess.Kill()
                    $transportProcess.WaitForExit(5000) | Out-Null
                }
            }
            catch {
                Write-AgentLog -Level 'WARN' -Message ('Transport cleanup failed: {0}' -f $_.Exception.Message)
            }
            $transportError = Get-TransportStandardError -Process $transportProcess
            if (-not [string]::IsNullOrWhiteSpace($transportError)) {
                foreach ($transportErrorLine in @($transportError -split '\r?\n')) {
                    if (-not [string]::IsNullOrWhiteSpace($transportErrorLine)) {
                        Write-AgentLog -Level 'WARN' -Message ('Transport stderr: {0}' -f $transportErrorLine.Trim())
                    }
                }
            }
            $transportProcess.Dispose()
        }
    }

    if ($Once) {
        break
    }
    $reconnectCount++
    if (($MaxReconnectAttempts -gt 0) -and ($reconnectCount -gt $MaxReconnectAttempts)) {
        throw ('Reconnect limit reached after {0} retries.' -f $MaxReconnectAttempts)
    }

    $sessionDuration = ([DateTimeOffset]::UtcNow - $sessionStarted).TotalSeconds
    if ($sessionDuration -ge 60) {
        $failureStreak = 0
    }
    else {
        $failureStreak++
    }
    $exponent = [Math]::Min($failureStreak - 1, 10)
    $baseDelay = [Math]::Min($ReconnectMaxSeconds, $ReconnectInitialSeconds * [Math]::Pow(2, $exponent))
    $jitterMilliseconds = Get-Random -Minimum 0 -Maximum 1000
    $delayMilliseconds = ([int]($baseDelay * 1000)) + $jitterMilliseconds
    Write-AgentLog -Message ('Reconnecting in {0:N1} seconds.' -f ($delayMilliseconds / 1000.0))
    Start-Sleep -Milliseconds $delayMilliseconds
}
