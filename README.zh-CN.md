[English](README.md) | **简体中文**

# PS Tunnel

PS Tunnel 是一个用于**已授权 Windows 设备管理**的出站任务通道。受管端 A 只需要 PowerShell 5.1+ 和 Windows OpenSSH 客户端 `ssh.exe`；管理端 B 运行 Node.js 服务并监听 SSH 端口。

A 主动连接 B，因此 A 无需监听端口，也无需安装 `sshd`。传输由 SSH 加密，SSH 公钥认证后，协议层再用独立 Agent Secret 完成 HMAC-SHA256 双向挑战应答。

```text
Codex / Claude Code / GitHub Copilot
                  -> MCP stdio -> mcp-server.mjs
                                      |
B: ctl.ps1 ---------------------------+-> 127.0.0.1:8766 -> broker.js
                                                               ^
                                                               | loopback only
A: client.ps1 -------------------------> SSH :2222 -> ssh-server.js
```

## 安全模型

- SSH 入口只接受配置中的用户名和 Ed25519 公钥。
- SSH 会话只能桥接到 B 本机回环地址上的 Broker。
- TTY、环境变量、X11 和额外 SSH 会话请求会被拒绝。
- Agent 使用独立 Secret 做 HMAC-SHA256 双向认证。
- 控制 API 只绑定 `127.0.0.1`，并要求独立 Bearer Token。
- MCP server 由 AI 客户端通过 stdio 启动，并使用环境变量中的控制令牌访问回环控制 API。
- A 使用 `StrictHostKeyChecking=yes` 固定校验 B 的 SSH host key。
- 客户端采用带抖动的指数退避自动重连。
- 客户端通过非阻塞事件循环持续处理心跳，每条任务在独立 PowerShell worker 中运行并转换结果。
- 同一 Agent 默认并行执行 4 条任务；多个 MCP/CLI 实例共享 Broker，可同时提交并等待各自的 PowerShell 命令。
- 任务动作包括 `ping`、`echo`、`get_host_info` 和可执行任意脚本内容的 `powershell`。

该设计面向明确授权的设备。请按组织安全策略保存、分发和轮换密钥。

## 目录

```text
mcp-config/
  codex.config.toml             Codex 用户配置示例
  claude.mcp.json               Claude Code 项目配置示例
  github-copilot.mcp.json       GitHub Copilot / VS Code 配置示例
client/
  client.ps1          A 上运行的 PowerShell 5.1/7 客户端
server/
  broker.js           Agent 会话、任务队列和本地控制 API
  mcp-server.mjs      标准 stdio MCP server
  mcp-smoke.mjs       官方 MCP SDK client 全链路测试
  mcp-autostart-e2e.ps1 MCP 自动启动与隔离 Codex 模型测试
  ssh-server.js       基于 ssh2 的受限 SSH 监听器
  session.js          协议 E2E 使用的本地进程桥
  start.ps1           启动或检查 B 端进程
  ctl.ps1             B 本机控制命令
  config.example.json 配置模板
  e2e.ps1             认证、MCP、任务和断线重连 E2E
```

运行时配置、私钥、公钥、`known_hosts`、状态、日志和 `node_modules` 均已加入 `.gitignore`。

## 前置条件

### A：受管 Windows 设备

- Windows PowerShell 5.1 或 PowerShell 7
- Windows OpenSSH 客户端

检查：

```powershell
Get-Command powershell.exe, ssh.exe, ssh-keygen.exe
```

### B：管理端 Windows 设备

- Node.js 20+
- PowerShell 5.1 或 PowerShell 7
- Windows OpenSSH 客户端，用于生成密钥
- 管理员权限，仅用于创建入站防火墙规则

检查：

```powershell
node --version
Get-Command node.exe, ssh.exe, ssh-keygen.exe
```

## 部署 B

以下命令在仓库根目录执行。

### 1. 安装依赖

```powershell
Set-Location .\server
npm ci --ignore-scripts --omit=dev --no-audit --no-fund
Copy-Item .\config.example.json .\config.json
```

`ssh2` 可以使用纯 JavaScript 后备实现，因此受控环境中可使用 `--ignore-scripts` 跳过可选原生模块编译。

### 2. 生成独立 Secret

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

`controlToken` 只用于 B 本机控制 API；`agents.agent-a` 只用于 A 与 Broker 的应用层认证。两者应保持独立。
`maxConcurrentTasksPerAgent` 控制 Broker 向每个在线 Agent 同时派发的任务数，模板默认值为 `4`。

### 3. 生成 SSH host key 和 Agent key

首次部署分别执行下面两条命令：

```powershell
ssh-keygen.exe -t ed25519 -C 'ps-tunnel-host' -f .\ssh-host-ed25519
ssh-keygen.exe -t ed25519 -C 'ps-tunnel-agent-a' -f .\agent-a-ed25519
```

两次命令都在 passphrase 提示处直接按 Enter。B 的监听器需要无人值守读取 host 私钥，A 的客户端需要无人值守断线重连。文件 ACL 和独立 Agent Secret 提供额外保护。

收紧 B 上 host 私钥的 ACL：

```powershell
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$hostKey = (Resolve-Path .\ssh-host-ed25519).Path
icacls.exe $hostKey /inheritance:r
icacls.exe $hostKey /grant:r "${me}:(R)" 'SYSTEM:(R)'
```

### 4. 为 A 创建固定 host key 文件

把 `<B_ADDRESS>` 替换为 A 实际连接 B 时使用的 IPv4 地址或 DNS 名称：

```powershell
$BAddress = '<B_ADDRESS>'
$port = 2222
$hostPublicKey = ((Get-Content .\ssh-host-ed25519.pub -Raw).Trim() -split '\s+')
('[{0}]:{1} {2} {3}' -f $BAddress, $port, $hostPublicKey[0], $hostPublicKey[1]) |
    Set-Content -LiteralPath .\known_hosts-a -Encoding ascii

ssh-keygen.exe -lf .\known_hosts-a
```

自定义端口的 `known_hosts` 主机字段必须使用 `[host]:port` 格式。

### 5. 启动 B

```powershell
.\start.ps1
```

脚本会启动或检查以下监听器：

- `127.0.0.1:8765`：Agent Broker
- `127.0.0.1:8766`：控制 API
- `0.0.0.0:2222`：受限 SSH 入口

启动日志写入 `server` 目录并由 Git 忽略。再次运行 `start.ps1` 会检查端口是否由预期进程占用。

这也是独立运行 B 服务的入口。配置 MCP 后，AI 客户端启动 stdio MCP 时会自动执行同一检查和启动流程。

### 6. 创建 B 的防火墙规则

在 B 的管理员 PowerShell 中执行：

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

根据实际网络边界调整 `RemoteAddress` 和 Profile。Broker 的 8765、8766 继续只监听回环地址。

## 部署 A

### 1. 复制三个文件

在 A 创建固定目录 `C:\ps_tunnel`，然后通过获批的文件传输方式复制：

```text
client/client.ps1        -> C:\ps_tunnel\client.ps1
server/agent-a-ed25519   -> C:\ps_tunnel\agent-a-ed25519
server/known_hosts-a     -> C:\ps_tunnel\known_hosts-a
```

Agent 公钥留在 B 的 `server/agent-a-ed25519.pub`，Agent 私钥放在 A。

### 2. 收紧 A 上私钥 ACL

```powershell
$key = 'C:\ps_tunnel\agent-a-ed25519'
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

icacls.exe $key /inheritance:r
icacls.exe $key /grant:r "${me}:(R)" 'SYSTEM:(R)'

# 验证当前账户能够读取私钥，并显示它对应的公钥指纹
ssh-keygen.exe -y -f $key | ssh-keygen.exe -lf -
```

### 3. 启动客户端

通过安全渠道把 `config.json` 中 `agents.agent-a` 的值交给 A，然后执行：

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

看到 `Authenticated session ...` 表示 A 已在线。网络或 B 重启后，客户端会持续重连。

首次在交互终端认证成功后，客户端会询问：

```text
Connection authenticated. Create a one-click start-client.ps1 with these settings? [y/N]
```

输入 `y` 会在 `client.ps1` 旁生成 `start-client.ps1`。生成器会保存本次全部有效连接、超时和重连参数；Agent Secret 使用 Windows DPAPI 的 .NET API 加密，因此启动脚本只可由创建它的同一台计算机、同一 Windows 用户解密。文件 ACL 会收紧到当前用户和 `SYSTEM`。

以后可以一键运行：

```powershell
& 'C:\ps_tunnel\start-client.ps1'
```

启动脚本会传入 `LauncherMode=Never`，因此不会再次询问。自动化场景也可在原始命令中使用 `-LauncherMode Never`；需要直接生成时可使用 `-LauncherMode Always -LauncherPath <path.ps1>`。

## 在 B 上提交任务

从本机配置读取控制令牌：

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

`get_host_info` 返回计算机名、当前用户、PowerShell 版本、进程 ID、工作目录和时间。
`powershell` 在客户端的独立 PowerShell worker 进程中执行 `args.script`，并把管道输出作为任务结果返回；也可以通过 `-ArgumentsJson '{"script":"Get-Date"}'` 提交。worker 执行、结果转换和超时终止均与主协议事件循环隔离。client 在认证时声明 `-MaxConcurrentTasks`，Broker 使用它与 `maxConcurrentTasksPerAgent` 中的较小值；旧版 client 自动按单任务会话处理。

传输前，客户端会把 Windows PowerShell 5.1 产生的裸 `NaN` 和 `Infinity` 标记归一化为严格 JSON。

## 通过 MCP 使用

项目提供标准 stdio MCP server，并注册四个 tools：

- `list_agents`：列出 Agent 和连接状态。
- `run_powershell`：提交 PowerShell 并等待完整结果。
- `submit_powershell`：提交 PowerShell 并立即返回 task ID。
- `get_task`：按 task ID 查询状态和完整结果。

MCP server 默认读取自身同目录的 `config.json`，从中获取控制令牌和控制 API 地址。stdio MCP 启动时会先认证探测控制 API；本机回环服务尚未就绪时，它会静默执行 `start.ps1`，等 Broker 和 SSH 监听器就绪后再开始 MCP 协议通信。重复启动会复用已经就绪的进程。

Codex、Claude Code、GitHub Copilot CLI 等工具各自启动独立 stdio MCP 进程；这些进程连接同一个回环控制 API 和 Broker。来自多个 CLI/MCP 会话的任务会进入同一队列，并按 Agent 的并发配置同时派发。

标准部署只需让 AI 客户端执行 `server/mcp-server.mjs`。以下环境变量用于自定义部署：

- `PS_TUNNEL_SERVER_CONFIG_PATH`：指定另一份 server 配置文件。
- `PS_TUNNEL_CONTROL_TOKEN`：覆盖配置文件中的控制令牌。
- `PS_TUNNEL_CONTROL_BASE_URI`：覆盖配置文件推导出的控制 API 地址。
- `PS_TUNNEL_AUTO_START`：设置为 `true` 或 `false`，默认 `true`。
- `PS_TUNNEL_POWERSHELL_PATH`：指定执行 `start.ps1` 的 PowerShell。
- `PS_TUNNEL_SERVER_START_TIMEOUT_MS`：启动等待时间，默认 45000 毫秒。

例如，使用另一份隔离配置：

```powershell
Set-Location '<REPOSITORY_ROOT>'
$env:PS_TUNNEL_SERVER_CONFIG_PATH = 'C:\ps-tunnel-test\config.json'
```

### Codex

将 `mcp-config/codex.config.toml` 中的路径替换为仓库绝对路径，再把配置段合并到用户级 `$HOME/.codex/config.toml`：

```powershell
codex mcp list
codex
```

新会话中可以直接要求模型：

```text
使用 ps_tunnel MCP，先列出 Agent，再在 agent-a 执行：Get-Date
```

Codex CLI、IDE 扩展和桌面端共用 MCP 配置，具体配置项见 [OpenAI Docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)。

### Claude Code

把 `mcp-config/claude.mcp.json` 的内容合并到需要启用 MCP 的项目级 `.mcp.json`：

```powershell
claude mcp list
claude
```

### GitHub Copilot

把 `mcp-config/github-copilot.mcp.json` 的内容合并到需要启用 MCP 的工作区级 `.vscode/mcp.json`。打开该工作区后，在 Copilot Chat 的工具列表中启用 `ps_tunnel` tools，即可从 Agent 模式调用。

这三份文件位于纯示例目录，当前仓库不会自动加载 MCP 配置。AI 客户端加载配置后会负责启动 stdio MCP，MCP 再负责确保本地 PS Tunnel 服务就绪。

## 踩坑与诊断

### A 只有 `ssh.exe`

这是预期部署形态。A 是出站 SSH 客户端，监听器位于 B。`Get-Service sshd` 在 A 上没有结果不会影响客户端运行。

### 指定的私钥没有被 SSH 提交

客户端固定传入：

```text
-o BatchMode=yes
-o IdentitiesOnly=yes
-i <identity-file>
```

`IdentitiesOnly=yes` 可以避免 SSH Agent、默认密钥和配置文件干扰显式指定的密钥。用下面的命令确认私钥可读：

```powershell
ssh-keygen.exe -y -f C:\ps_tunnel\agent-a-ed25519 | ssh-keygen.exe -lf -
```

### Windows OpenSSH 拒绝私钥权限

典型现象是 `UNPROTECTED PRIVATE KEY FILE`、`Permissions ... are too open` 或私钥未被采用。移除继承 ACL，只授予运行客户端的账户和 `SYSTEM` 读取权限，然后再次执行 `ssh-keygen -y`。

### `known_hosts` 看起来正确，但主机校验仍失败

端口 2222 对应的行必须以 `[B_ADDRESS]:2222` 开头。确认 A 使用的地址与生成文件时完全一致，并检查指纹：

```powershell
ssh-keygen.exe -lf C:\ps_tunnel\known_hosts-a
```

主机密钥变化时，应先通过可信渠道核验 B 的新指纹，再替换固定记录。

### 手工 SSH 已认证，随后收到协议错误

直接运行 SSH 会先看到 Broker 发出的 `challenge`。向 SSH 管道写入 `{}` 会关闭标准输入，Broker 会返回 `Expected authenticate message`；这说明 SSH、公钥和 Broker 链路已经连通，但输入不是完整 HMAC 协议。正式客户端会保持标准输入开启并完成挑战应答。

### 客户端显示 `Transport closed before authentication challenge`

新版客户端会把 SSH 标准错误写入 `-LogPath`。常见检查顺序：

```powershell
Test-NetConnection '<B_ADDRESS>' -Port 2222
Get-Content "$HOME\ps-tunnel-client.log" -Tail 100
```

然后使用详细 SSH 日志确认连接、公钥和 host key：

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

成功链路会依次出现 `Connection established`、host key 匹配、`Offering public key`、`Authenticated` 和 JSON challenge。按 Ctrl+C 结束手工诊断。

### PowerShell 5.1 的 UTF-8 BOM

Windows PowerShell 5.1 的 `Set-Content -Encoding UTF8` 会写入 BOM。配置生成示例使用 `.NET UTF8Encoding(false)` 写入；服务端读取配置时也会兼容 BOM。

由 PowerShell 7 启动 Windows PowerShell 5.1 时，继承的 `PSModulePath` 可能影响内置模块自动加载。一键脚本生成直接调用 Windows DPAPI 的 .NET API，因此不依赖 `Microsoft.PowerShell.Security` 模块。

### 路径中包含空格

客户端和 `start.ps1` 都会为原生命令正确引用参数。固定部署到简短目录仍更便于人工排障，例如 `C:\ps_tunnel`。

### 端口已被占用

```powershell
Get-NetTCPConnection -State Listen -LocalPort 2222,8765,8766 |
    Select-Object LocalAddress,LocalPort,OwningProcess
```

`start.ps1` 会校验监听端口的进程命令行，避免把未知监听器误认为 PS Tunnel。

## 扩展任务动作

增加一个动作时，需要同步更新：

1. `client/client.ps1` 中的 `$AllowedTaskScript`。
2. `server/broker.js` 中的 `ALLOWED_ACTIONS`。
3. `server/ctl.ps1` 中 `TaskAction` 的 `ValidateSet`。
4. `server/e2e.ps1` 中相应的正常、异常和超时测试。

`powershell` 动作可直接承载任意 PowerShell 脚本。新增专用动作时，应使用结构化参数和结构化结果，并设置输入长度、执行时间和输出大小上限。

## 测试

测试需要完整依赖。在仓库根目录执行：

```powershell
Set-Location .\server
npm ci --ignore-scripts --no-audit --no-fund
Set-Location ..

pwsh -NoProfile -File .\server\e2e.ps1 `
    -ClientPowerShellPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
```

以上测试会通过官方 MCP client SDK 完成 `initialize`、`tools/list` 和四个 tools 的调用，并启动两个独立 MCP stdio 实例并发执行两条 7 秒 PowerShell 任务。测试同时验证任务运行期间心跳、超时 worker 终止、后续任务恢复和 session 连续性。加入 `-CodexMcp` 会再启动本机 Codex 临时会话，让模型实际调用 `list_agents` 和 `run_powershell`，并在 Broker 状态与模型最终回复中核对唯一 marker：

```powershell
pwsh -NoProfile -File .\server\e2e.ps1 -CodexMcp
```

E2E 会在 `%TEMP%/ps-tunnel-e2e-*` 下创建独立的 Broker 状态、MCP 工作区和 Codex 工作区。Codex 使用 `--ephemeral` 与一次性 `-c` 配置，测试成功后自动删除整个临时目录，当前仓库的 Codex resume 状态保持独立。

自动启动专项测试会先确认临时端口为空，再由 MCP 启动临时 Broker 和 SSH server。加入 `-CodexMcp` 后，测试会停止 SDK 阶段启动的服务，创建独立 `CODEX_HOME` 和工作目录，再由真实 Codex 模型启动 MCP、等待 Agent 回连并调用 `run_powershell`：

```powershell
pwsh -NoProfile -File .\server\mcp-autostart-e2e.ps1 -CodexMcp
```

专项测试的配置、状态、SSH 密钥、日志、MCP 工作区和 Codex 状态都位于 `%TEMP%/ps-tunnel-mcp-autostart-*`，成功后整体删除；当前仓库和现有 Codex resume 状态只参与只读加载。

完整测试覆盖 HMAC 认证、DPAPI 启动脚本生成与实际执行、Secret 检查、任意 PowerShell、并行 worker、双 MCP 实例、Codex 模型调用、任务超时恢复、`echo`、主机信息、强制断线、自动重连和重连后任务。生产部署还应从 A 执行一次 `Test-NetConnection` 和详细 SSH 握手检查。

## 密钥轮换

- 轮换 Agent SSH key：在 B 更新 `authorizedKeyFile` 指向的公钥，在 A 更新对应私钥。
- 轮换 Agent Secret：在 B 更新 `agents.<agent-id>`，随后更新 A 的环境变量并重启客户端。
- 轮换控制令牌：在 B 更新 `controlToken`，随后更新运行 `ctl.ps1` 的环境变量。
- 轮换 B host key：先通过可信渠道分发新指纹和 `known_hosts`，再重启 SSH 监听器。

每台 A 建议使用独立 Agent ID、SSH key 和 Agent Secret，以便单独撤销和审计。
