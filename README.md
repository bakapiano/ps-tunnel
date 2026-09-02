**English** | [简体中文](README.zh-CN.md)

# PS Tunnel

PS Tunnel is an outbound task channel for **authorized administration of Windows devices**. Managed endpoint A needs only PowerShell 5.1+ and the Windows OpenSSH client (`ssh.exe`). Management endpoint B runs the Node.js services and listens for SSH connections.

A initiates the connection to B, so A runs only an outbound SSH client. SSH encrypts the transport; after SSH public-key authentication, the application protocol performs a separate mutual HMAC-SHA256 challenge-response using an Agent Secret.

```text
Codex / Claude Code / GitHub Copilot
                  -> MCP stdio -> mcp-server.mjs
                                      |
B: ctl.ps1 ---------------------------+-> 127.0.0.1:8766 -> broker.js
                                                               ^
                                                               | loopback only
A: client.ps1 -------------------------> SSH :2222 -> ssh-server.js
```

## Security model

- The SSH entry point accepts only the configured username and Ed25519 public key.
- Each SSH session can bridge only to the Broker on B's loopback interface.
- TTY, environment-variable, X11, and additional SSH session requests are rejected.
- Each Agent uses an independent secret for mutual HMAC-SHA256 authentication.
- The control API binds to `127.0.0.1` and requires a separate Bearer Token.
- AI clients start the MCP server over stdio; the MCP server uses the control token to access the loopback control API.
- A pins B's SSH host key with `StrictHostKeyChecking=yes`.
- The client reconnects automatically with jittered exponential backoff.
- A non-blocking client event loop keeps heartbeats flowing while every task runs and serializes its result in a separate PowerShell worker.
- One Agent executes four tasks concurrently by default. Multiple MCP/CLI instances share the Broker and can submit and await independent PowerShell commands at the same time.
- Task actions include `ping`, `echo`, `get_host_info`, and `powershell`, which can execute arbitrary PowerShell script content.

This design targets explicitly authorized devices. Store, distribute, and rotate keys according to your organization's security policy.

## Repository layout

```text
mcp-config/
  codex.config.toml             Codex user configuration example
  claude.mcp.json               Claude Code project configuration example
  github-copilot.mcp.json       GitHub Copilot / VS Code configuration example
client/
  client.ps1                    PowerShell 5.1/7 client that runs on A
server/
  broker.js                     Agent sessions, task queue, and local control API
  mcp-server.mjs                Standard stdio MCP server
  mcp-smoke.mjs                 Official MCP SDK end-to-end client test
  mcp-autostart-e2e.ps1         MCP auto-start and isolated Codex model test
  ssh-server.js                 Restricted SSH listener built on ssh2
  session.js                    Local process bridge used by protocol E2E tests
  start.ps1                     Starts or checks the B-side processes
  ctl.ps1                       Local B-side control command
  config.example.json           Configuration template
  e2e.ps1                       Authentication, MCP, task, and reconnect E2E test
```

Runtime configuration, private and public keys, `known_hosts`, state, logs, and `node_modules` are covered by `.gitignore`.

## Prerequisites

### A: managed Windows endpoint

- Windows PowerShell 5.1 or PowerShell 7
- Windows OpenSSH client

Check:

```powershell
Get-Command powershell.exe, ssh.exe, ssh-keygen.exe
```

### B: management Windows endpoint

- Node.js 20+
- Windows PowerShell 5.1 or PowerShell 7
- Windows OpenSSH client for key generation
- Administrator access only when creating the inbound firewall rule

Check:

```powershell
node --version
Get-Command node.exe, ssh.exe, ssh-keygen.exe
```

## Deploy B

Run the following commands from the repository root.

### 1. Install dependencies

```powershell
Set-Location .\server
npm ci --ignore-scripts --omit=dev --no-audit --no-fund
Copy-Item .\config.example.json .\config.json
```

`ssh2` has a pure-JavaScript fallback, so controlled environments can use `--ignore-scripts` to skip optional native-module compilation.

### 2. Generate independent secrets

```powershell
function New-RandomSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes)
}

$configPath = (Resolve-Path .\config.json).Path
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$config.controlToken = New-RandomSecret
$config.agents.'agent-a' = New-RandomSecret
$json = $config | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText(
    $configPath,
    $json,
    (New-Object System.Text.UTF8Encoding($false))
)
```

`controlToken` is used only by B's local control API. `agents.agent-a` is used only for application-layer authentication between A and the Broker. Keep them independent.

`maxConcurrentTasksPerAgent` controls how many tasks the Broker dispatches concurrently to each online Agent. The template defaults to `4`.

### 3. Generate the SSH host key and Agent key

Run both commands once during the initial deployment:

```powershell
ssh-keygen.exe -t ed25519 -C 'ps-tunnel-host' -f .\ssh-host-ed25519
ssh-keygen.exe -t ed25519 -C 'ps-tunnel-agent-a' -f .\agent-a-ed25519
```

Press Enter at both passphrase prompts. The B listener needs unattended access to its host private key, and the A client needs unattended reconnection. File ACLs and the independent Agent Secret provide additional protection.

Restrict the host private-key ACL on B:

```powershell
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$hostKey = (Resolve-Path .\ssh-host-ed25519).Path
icacls.exe $hostKey /inheritance:r
icacls.exe $hostKey /grant:r "${me}:(R)" 'SYSTEM:(R)'
```

### 4. Create A's pinned host-key file

Replace `<B_ADDRESS>` with the IPv4 address or DNS name that A actually uses to reach B:

```powershell
$BAddress = '<B_ADDRESS>'
$port = 2222
$hostPublicKey = ((Get-Content .\ssh-host-ed25519.pub -Raw).Trim() -split '\s+')
('[{0}]:{1} {2} {3}' -f $BAddress, $port, $hostPublicKey[0], $hostPublicKey[1]) |
    Set-Content -LiteralPath .\known_hosts-a -Encoding ascii

ssh-keygen.exe -lf .\known_hosts-a
```

For a custom port, the host field in `known_hosts` must use the `[host]:port` format.

### 5. Start B

```powershell
.\start.ps1
```

The script starts or checks these listeners:

- `127.0.0.1:8765`: Agent Broker
- `127.0.0.1:8766`: control API
- `0.0.0.0:2222`: restricted SSH entry point

Startup logs are written under `server` and ignored by Git. Running `start.ps1` again verifies that the expected processes own the ports.

This is also the entry point for running B independently. After MCP configuration, starting the stdio MCP server performs the same check and starts these services automatically.

### 6. Create B's firewall rule

Run this in an elevated PowerShell session on B:

```powershell
$ruleName = 'PS-Tunnel-SSH-In-TCP'
if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -Name $ruleName `
        -DisplayName 'PS Tunnel restricted SSH listener' `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 2222 `
        -RemoteAddress LocalSubnet `
        -Profile Domain,Private
}
```

Adjust `RemoteAddress` and the firewall profile for your network boundary. Ports 8765 and 8766 remain bound to the loopback interface.

## Deploy A

### 1. Copy three files

Create `C:\ps_tunnel` on A, then use an approved file-transfer method to copy:

```text
client/client.ps1        -> C:\ps_tunnel\client.ps1
server/agent-a-ed25519   -> C:\ps_tunnel\agent-a-ed25519
server/known_hosts-a     -> C:\ps_tunnel\known_hosts-a
```

Keep the Agent public key on B at `server/agent-a-ed25519.pub` and place the Agent private key on A.

### 2. Restrict the private-key ACL on A

```powershell
$key = 'C:\ps_tunnel\agent-a-ed25519'
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

icacls.exe $key /inheritance:r
icacls.exe $key /grant:r "${me}:(R)" 'SYSTEM:(R)'

# Verify that the current account can read the key and show its public-key fingerprint.
ssh-keygen.exe -y -f $key | ssh-keygen.exe -lf -
```

### 3. Start the client

Transfer the value of `agents.agent-a` from `config.json` to A over a secure channel, then run:

```powershell
Set-Location 'C:\ps_tunnel'
$env:PS_TUNNEL_AGENT_SECRET = '<AGENT_SECRET>'

& 'C:\ps_tunnel\client.ps1' `
    -AgentId 'agent-a' `
    -SshHost '<B_ADDRESS>' `
    -SshPort 2222 `
    -SshUser 'agent-a' `
    -SshPath "$env:WINDIR\System32\OpenSSH\ssh.exe" `
    -IdentityFile 'C:\ps_tunnel\agent-a-ed25519' `
    -KnownHostsFile 'C:\ps_tunnel\known_hosts-a' `
    -LogPath "$HOME\ps-tunnel-client.log" `
    -MaxConcurrentTasks 4 `
    -ReconnectInitialSeconds 1 `
    -ReconnectMaxSeconds 30
```

`Authenticated session ...` means that A is online. The client keeps reconnecting after network interruptions or a restart of B.

After the first successful authentication in an interactive terminal, the client asks:

```text
Connection authenticated. Create a one-click start-client.ps1 with these settings? [y/N]
```

Entering `y` generates `start-client.ps1` next to `client.ps1`. The generator stores all effective connection, timeout, and reconnect parameters. It protects the Agent Secret with the Windows DPAPI .NET API, so only the same Windows user on the same computer can decrypt the launcher. The file ACL is restricted to the current user and `SYSTEM`.

Future launches take one command:

```powershell
& 'C:\ps_tunnel\start-client.ps1'
```

The launcher passes `LauncherMode=Never` and therefore runs directly. Automation can also add `-LauncherMode Never` to the original command. Use `-LauncherMode Always -LauncherPath <path.ps1>` to generate a launcher immediately.

## Submit tasks on B

Load the control token from the local configuration:

```powershell
Set-Location '<REPOSITORY_ROOT>'
$env:PS_TUNNEL_CONTROL_TOKEN =
    (Get-Content .\server\config.json -Raw | ConvertFrom-Json).controlToken

.\server\ctl.ps1 status
.\server\ctl.ps1 submit -AgentId agent-a -TaskAction ping -Wait
.\server\ctl.ps1 submit -AgentId agent-a -TaskAction echo `
    -ArgumentsJson '{"text":"hello"}' -Wait
.\server\ctl.ps1 submit -AgentId agent-a -TaskAction get_host_info -Wait

$script = @'
$services = Get-Service | Where-Object Status -eq 'Running'
[pscustomobject]@{
    computerName = $env:COMPUTERNAME
    runningServiceCount = @($services).Count
    topFive = @($services | Select-Object -First 5 -ExpandProperty Name)
}
'@
.\server\ctl.ps1 submit -AgentId agent-a -TaskAction powershell `
    -PowerShellScript $script -TaskTimeoutSeconds 30 -Wait
```

`get_host_info` returns the computer name, current user, PowerShell version, process ID, working directory, and time.

`powershell` executes `args.script` in a separate PowerShell worker on the client and returns the pipeline output as the task result. You can also submit `-ArgumentsJson '{"script":"Get-Date"}'`. Worker execution, result conversion, and timeout termination remain isolated from the main protocol event loop. Before transport, the client normalizes bare `NaN` and `Infinity` tokens emitted by Windows PowerShell 5.1 into strict JSON.

During authentication, the client advertises `-MaxConcurrentTasks`. The Broker uses the lower value between that setting and `maxConcurrentTasksPerAgent`. Older clients automatically run as single-task sessions.

## Use through MCP

The project provides a standard stdio MCP server with four tools:

- `list_agents`: list Agents and connection state.
- `run_powershell`: submit PowerShell and wait for the complete result.
- `submit_powershell`: submit PowerShell and immediately return a task ID.
- `get_task`: retrieve task state and the complete result by task ID.

By default, the MCP server reads `config.json` from its own directory to obtain the control token and control API address. At stdio startup, it authenticates to and probes the control API. When the loopback services need startup, it silently runs `start.ps1`, waits for the Broker and SSH listener, and then starts the MCP protocol. Repeated launches reuse healthy processes.

Codex, Claude Code, GitHub Copilot CLI, and other clients each start an independent stdio MCP process. These processes connect to the same loopback control API and Broker. Tasks from multiple CLI/MCP sessions enter one queue and are dispatched concurrently according to the Agent configuration.

A standard deployment only needs the AI client to execute `server/mcp-server.mjs`. These environment variables customize the deployment:

- `PS_TUNNEL_SERVER_CONFIG_PATH`: use another server configuration file.
- `PS_TUNNEL_CONTROL_TOKEN`: override the control token from the configuration.
- `PS_TUNNEL_CONTROL_BASE_URI`: override the control API address derived from the configuration.
- `PS_TUNNEL_AUTO_START`: `true` or `false`; defaults to `true`.
- `PS_TUNNEL_POWERSHELL_PATH`: select the PowerShell executable for `start.ps1`.
- `PS_TUNNEL_SERVER_START_TIMEOUT_MS`: startup wait time in milliseconds; defaults to 45000.

For example, to use an isolated configuration:

```powershell
Set-Location '<REPOSITORY_ROOT>'
$env:PS_TUNNEL_SERVER_CONFIG_PATH = 'C:\ps-tunnel-test\config.json'
```

### Codex

Replace the paths in `mcp-config/codex.config.toml` with absolute repository paths, then merge the configuration into the user-level `$HOME/.codex/config.toml`:

```powershell
codex mcp list
codex
```

In a new session, you can ask the model:

```text
Use the ps_tunnel MCP. List the Agents first, then run Get-Date on agent-a.
```

Codex CLI, IDE extensions, and the desktop app share the MCP configuration. See [OpenAI Docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) for configuration details.

### Claude Code

Merge `mcp-config/claude.mcp.json` into the project-level `.mcp.json` for each project that should use the MCP server:

```powershell
claude mcp list
claude
```

### GitHub Copilot

Merge `mcp-config/github-copilot.mcp.json` into the workspace-level `.vscode/mcp.json`. Open that workspace and enable the `ps_tunnel` tools in the Copilot Chat tool list to call them from Agent mode.

The three files under `mcp-config` are examples and are not loaded automatically by this repository. After an AI client loads its configuration, it starts the stdio MCP process, and MCP ensures that the local PS Tunnel services are ready.

## Troubleshooting

### A has only `ssh.exe`

This is the expected deployment shape. A is the outbound SSH client, and the listener runs on B. The client operates independently of an `sshd` service on A.

### SSH does not offer the specified private key

The client always passes:

```text
-o BatchMode=yes
-o IdentitiesOnly=yes
-i <identity-file>
```

`IdentitiesOnly=yes` prevents SSH Agent, default keys, and SSH configuration from interfering with the explicitly selected key. Confirm that the private key is readable:

```powershell
ssh-keygen.exe -y -f C:\ps_tunnel\agent-a-ed25519 | ssh-keygen.exe -lf -
```

### Windows OpenSSH rejects the private-key permissions

Typical messages include `UNPROTECTED PRIVATE KEY FILE`, `Permissions ... are too open`, or a key that is skipped. Remove inherited ACLs, grant read access only to the client account and `SYSTEM`, and run `ssh-keygen -y` again.

### `known_hosts` looks correct but host verification fails

The line for port 2222 must start with `[B_ADDRESS]:2222`. Confirm that A uses exactly the address recorded in the file, then inspect the fingerprint:

```powershell
ssh-keygen.exe -lf C:\ps_tunnel\known_hosts-a
```

When the host key changes, verify B's new fingerprint through a trusted channel before replacing the pinned entry.

### Manual SSH authenticates and then reports a protocol error

A direct SSH session first receives a Broker `challenge`. Writing `{}` to the SSH pipeline closes standard input, and the Broker responds with `Expected authenticate message`. This confirms that SSH, the public key, and the Broker path are connected while the input remains outside the complete HMAC protocol. The production client keeps standard input open and completes the challenge-response.

### The client reports `Transport closed before authentication challenge`

The current client writes SSH standard error to `-LogPath`. Start with:

```powershell
Test-NetConnection '<B_ADDRESS>' -Port 2222
Get-Content "$HOME\ps-tunnel-client.log" -Tail 100
```

Then use verbose SSH logging to inspect the connection, public key, and host key:

```powershell
ssh.exe -vvv -T -p 2222 `
    -l agent-a `
    -i C:\ps_tunnel\agent-a-ed25519 `
    -o IdentitiesOnly=yes `
    -o BatchMode=yes `
    -o StrictHostKeyChecking=yes `
    -o 'UserKnownHostsFile=C:\ps_tunnel\known_hosts-a' `
    '<B_ADDRESS>'
```

A successful path shows `Connection established`, a matching host key, `Offering public key`, `Authenticated`, and the JSON challenge. Press Ctrl+C to end the manual diagnostic session.

### UTF-8 BOM in Windows PowerShell 5.1

`Set-Content -Encoding UTF8` in Windows PowerShell 5.1 writes a BOM. The configuration example uses `.NET UTF8Encoding(false)`, and the server also accepts configuration files with a BOM.

When PowerShell 7 starts Windows PowerShell 5.1, the inherited `PSModulePath` can affect built-in module auto-loading. The one-click launcher calls the Windows DPAPI .NET API directly and therefore has no dependency on the `Microsoft.PowerShell.Security` module.

### Paths contain spaces

The client and `start.ps1` quote arguments for native commands. A short fixed path such as `C:\ps_tunnel` remains convenient for manual diagnostics.

### A port is already in use

```powershell
Get-NetTCPConnection -State Listen -LocalPort 2222,8765,8766 |
    Select-Object LocalAddress,LocalPort,OwningProcess
```

`start.ps1` validates the command line of the process that owns each listening port so an unrelated listener is not mistaken for PS Tunnel.

## Extend task actions

Adding an action requires coordinated updates:

1. Update `$AllowedTaskScript` in `client/client.ps1`.
2. Update `ALLOWED_ACTIONS` in `server/broker.js`.
3. Update the `TaskAction` `ValidateSet` in `server/ctl.ps1`.
4. Add success, failure, and timeout coverage in `server/e2e.ps1`.

The `powershell` action already carries arbitrary PowerShell scripts. A dedicated action should use structured parameters and results, with explicit limits for input length, execution time, and output size.

## Tests

Tests require the complete dependency set. From the repository root:

```powershell
Set-Location .\server
npm ci --ignore-scripts --no-audit --no-fund
Set-Location ..

pwsh -NoProfile -File .\server\e2e.ps1 `
    -ClientPowerShellPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
```

This test uses the official MCP client SDK to complete `initialize`, `tools/list`, and calls to all four tools. It also starts two independent stdio MCP instances that concurrently execute two seven-second PowerShell tasks. The suite verifies heartbeats during task execution, timeout termination, recovery for subsequent tasks, session continuity, and strict JSON output for non-finite PowerShell numbers.

Add `-CodexMcp` to start an ephemeral local Codex session, make the model call `list_agents` and `run_powershell`, and verify a unique marker in both Broker state and the model's final response:

```powershell
pwsh -NoProfile -File .\server\e2e.ps1 -CodexMcp
```

E2E creates isolated Broker state, MCP workspace, and Codex workspace under `%TEMP%/ps-tunnel-e2e-*`. Codex uses `--ephemeral` and one-time `-c` settings. A successful test removes the entire temporary directory and keeps the current repository's Codex resume state independent.

The auto-start test first verifies that its temporary ports are free, then lets MCP start a temporary Broker and SSH server. With `-CodexMcp`, it stops the services used by the SDK phase, creates an isolated `CODEX_HOME` and working directory, and then lets a real Codex model start MCP, wait for the Agent to reconnect, and call `run_powershell`:

```powershell
pwsh -NoProfile -File .\server\mcp-autostart-e2e.ps1 -CodexMcp
```

Its configuration, state, SSH keys, logs, MCP workspace, and Codex state live under `%TEMP%/ps-tunnel-mcp-autostart-*` and are removed together after success. The current repository and existing Codex resume state are loaded read-only.

The complete suite covers HMAC authentication, DPAPI launcher generation and execution, secret checks, arbitrary PowerShell, parallel workers, dual MCP instances, Codex model calls, timeout recovery, `echo`, host information, forced disconnect, automatic reconnect, and post-reconnect tasks. Production deployment should also include one `Test-NetConnection` and verbose SSH handshake from A.

## Key rotation

- Rotate an Agent SSH key by updating the public key referenced by `authorizedKeyFile` on B and the matching private key on A.
- Rotate an Agent Secret by updating `agents.<agent-id>` on B, then updating A's environment variable and restarting the client.
- Rotate the control token by updating `controlToken` on B, then updating the environment of every process that runs `ctl.ps1`.
- Rotate B's host key by distributing the new fingerprint and `known_hosts` entry through a trusted channel before restarting the SSH listener.

Use a separate Agent ID, SSH key, and Agent Secret for each A endpoint so each device can be revoked and managed independently.
