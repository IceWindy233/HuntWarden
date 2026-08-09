# HuntWarden

HuntWarden（猎卫）是面向安全分析师的 AI 主机安全调查与受控处置 Agent。首期 MVP 通过 SSH 调用目标端白名单辅助程序，完成 WebShell、Tomcat 9/JDK 17 内存马、Linux 后门账户和 Linux 持久化调查；文件隔离与账户禁用必须逐动作审批。项目同时保留全屏 TUI，供自动化、无桌面环境和故障回退使用。

桌面 GUI 的架构、安全边界与验收设计见 [`docs/GUI_MVP_IMPLEMENTATION_PLAN.md`](docs/GUI_MVP_IMPLEMENTATION_PLAN.md)。
处置闭环的范围、命令和安全验收见 [`docs/REMEDIATION_CLOSURE_SPRINT.md`](docs/REMEDIATION_CLOSURE_SPRINT.md)。
恢复、报告版本化与 Linux 持久化实现见 [`docs/RECOVERY_PERSISTENCE_SPRINT.md`](docs/RECOVERY_PERSISTENCE_SPRINT.md)。

## 已实现范围

- Pi 低层 `Agent` Tool Loop；支持 Pi 内置多供应商 Provider 与自定义兼容端点，默认仍为 OpenAI Responses `gpt-5.6-terra` / `medium`。
- Electron + React 全屏桌面 GUI：仪表盘、结构化配置中心、API Key 安全存储、模型检查、SSH 测试、新建任务、Agent 文本增量流式显示、任务归档与恢复、实时调查、Steering、审批、恢复、Evidence、审计和报告。
- 内置 DeepSeek 与 OpenAI Profile；可在 GUI 中切换 Pi 内置 Provider，或配置 OpenAI Responses/Completions、Anthropic Messages 兼容端点。
- Renderer 启用 Chromium 沙箱、Context Isolation、严格 CSP 和固定 IPC 白名单；不能直接访问 Node.js、文件系统、SQLite、SSH 或凭据明文。
- Ink 7 + React 19 全屏 TUI：新建、运行、Agent 文本增量流式显示、历史任务、Steering、审批、恢复、Finding、Evidence、审计和报告。
- SQLite WAL/FULL 事件存储、单实例写锁、完整消息持久化、人工触发的崩溃恢复、工具幂等与写操作回执恢复；重启前未消费审批一律过期。
- 严格 SSH 主机指纹校验；无密码配置、无自动接受未知 Host Key。
- 固定操作名的 Python 辅助程序；不接受任意命令，不使用 Shell 执行参数。
- WebShell 候选发现、YARA、脚本特征、日志关联、文件证据和受控隔离。
- Tomcat 运行时 Filter/Servlet/Listener 枚举、ClassLoader/CodeSource/ProtectionDomain、磁盘来源和只读 Class Dump；不清除、不重定义、不重启 JVM。
- 特权账户、账户状态、SSH Key 指纹、登录历史和受控账户禁用。
- Cron、systemd、SSH Authorized Keys、Shell 启动项，以及基于不透明引用的进程和网络关联调查；仅提供 READ/COLLECT 工具。
- 由分析师确认后手动生成的不可变版本化中文 Markdown 报告、ID 引用校验、一次模型修复和确定性回退模板；支持历史版本切换与 Finder 定位。
- 四套无害 Docker Lab 与 Pi Faux Provider 可重复 Agent 测试。

## 环境

- Node.js `>=22.19.0`
- npm
- Java 17+（构建 Tomcat 探针）
- Docker Compose（仅 Lab 集成测试需要）
- 实时模型运行需要所选供应商的 API 凭据，或本机无认证推理服务

目标 Linux 主机需要 Python 3、YARA、JDK Attach 权限，并安装本项目的 `huntwarden-helper`。Docker Lab 会自动提供这些依赖。

## 安装与验证

```bash
npm ci
npm run build
npm test
npm run probe:build
docker compose -f labs/docker-compose.yml config --quiet
```

`npm test` 不需要 OpenAI Key，也不连接真实主机；测试使用 Pi Faux Provider 和 FakeExecutor。

## 配置

默认配置在 `config/default.yaml`。复制并通过环境变量选择自定义配置：

```bash
cp config/default.yaml config/local.yaml
HUNTWARDEN_CONFIG=./config/local.yaml npm run dev
```

敏感值只通过环境或受权限保护的本地文件提供。不要把私钥、Token 或运行时 `data/` 提交到版本库。

### 模型供应商

模型配置分为两类：

- `source: builtin`：使用 Pi 0.84 内置适配器，可选 OpenAI、Anthropic、Google Gemini、Azure OpenAI、DeepSeek、OpenRouter、Moonshot、Z.AI、Bedrock 等。
- `source: custom`：连接企业网关、LiteLLM、Ollama、vLLM、LM Studio 或其他兼容端点。支持 `openai-responses`、`openai-completions` 和 `anthropic-messages` 三种协议。

查看当前依赖版本实际包含的供应商和模型 ID：

```bash
npm run model:list
npm run model:list -- anthropic
```

使用内置 Anthropic Provider 时，只需替换默认配置中的 `model` 段，并设置对应环境变量：

```yaml
model:
  source: builtin
  provider: anthropic
  model: claude-sonnet-4-5
  thinkingLevel: medium
```

```bash
export ANTHROPIC_API_KEY='...'
HUNTWARDEN_CONFIG=./config/local.yaml npm run model:check
```

自定义 OpenAI Chat Completions 兼容网关示例：

```yaml
model:
  source: custom
  provider: company-gateway
  model: security-model
  thinkingLevel: off
  protocol: openai-completions
  baseUrl: https://llm-gateway.example.com/v1
  authentication:
    type: api-key-env
    apiKeyEnv: HUNTWARDEN_LLM_API_KEY
  reasoning: false
  contextWindow: 131072
  maxTokens: 16384
  compatibility:
    supportsDeveloperRole: false
    supportsReasoningEffort: false
    supportsStrictMode: false
```

```bash
export HUNTWARDEN_LLM_API_KEY='...'
HUNTWARDEN_CONFIG=./config/local.yaml npm run model:check
```

本机 Ollama、vLLM 等可使用 `http://127.0.0.1`/`http://localhost` 与 `authentication.type: none`；远程端点强制 HTTPS 且必须认证。YAML 只保存环境变量名，禁止保存真实密钥。所选模型必须支持函数/工具调用，否则无法运行 Agent Tool Loop。`model:check` 只检查配置、模型目录和凭据解析，不发起网络请求或输出密钥。

### DeepSeek 配置档

项目提供可直接使用的 `config/deepseek.yaml`，默认选择 `deepseek-v4-flash` 与 `high` 推理等级。切换高能力版本时，将模型 ID 改为 `deepseek-v4-pro`；当前 Pi 0.84 模型目录对两款 V4 接受的推理等级为 `off | high | max`。

```bash
export DEEPSEEK_API_KEY='在 DeepSeek Platform 创建的密钥'

# 静态检查，不请求 API
HUNTWARDEN_CONFIG=./config/deepseek.yaml npm run model:check

# 发起一次小型真实请求，验证认证、流式响应和 Tool Call
HUNTWARDEN_CONFIG=./config/deepseek.yaml npm run model:smoke

# 启动完整 Agent
HUNTWARDEN_CONFIG=./config/deepseek.yaml npm run dev
```

`model:smoke` 仅要求模型调用本地虚拟 `connection_probe`，不连接 SSH 主机、不执行安全检测或写操作；但会产生少量 API Token 费用。

## 启动 TUI

先设置所选供应商的 API Key（以下为默认 OpenAI 配置）：

```bash
export OPENAI_API_KEY='...'
npm run dev
```

在 TUI 中按 `n` 新建任务。YAML 提供私钥与 `known_hosts` 路径；向导收集目标、端口、SSH 用户、主机 SHA-256 指纹、模式和调查请求。

也可以从命令行直接创建并启动：

```bash
npm run dev -- \
  --host 127.0.0.1 \
  --port 2222 \
  --user secagent \
  --fingerprint 'SHA256:...' \
  --mode SCAN \
  --request '排查四类主机安全风险并形成报告' \
  --auto-start
```

恢复已有任务：

```bash
npm run dev -- --resume TASK-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

主要按键：

- `n`：新建任务
- `a`：开始当前任务
- `i`：提交 Steering 输入
- `y` / `n`：批准或拒绝当前一次性写操作
- `r`：恢复中断任务
- `g`：生成报告
- `Tab`：切换任务、事件、发现和证据视图
- `q`：退出

## 启动桌面 GUI

开发模式（Vite 热更新 + Electron）：

```bash
npm run dev:gui
```

生产构建后直接启动：

```bash
npm run start:gui
```

生成本机 `.app` 应用包；生成 zip/dmg 安装介质使用第二条命令：

```bash
npm run package:gui
npm run make:gui
```

首次启动会在系统应用数据目录创建两个配置 Profile，并默认启用 DeepSeek。打开“配置中心”，输入 DeepSeek API Key 后可选择：

- “系统安全存储持久化”：通过 Electron `safeStorage` 使用 macOS Keychain 加密保存；GUI 不提供读取明文的能力。
- 取消持久化：密钥仅保存在当前桌面进程内存中，退出即丢失。

保存后先执行“静态检查”，再执行“真实 Tool Call 冒烟”。冒烟请求只调用本地虚拟探针，不连接 SSH 或执行处置，但会产生少量模型费用。

GUI 的活动 Profile、任务事件数据库、Evidence 和报告均位于 Electron `userData` 下；目录和文件分别限制为 `0700`、`0600`。SSH 私钥只保存绝对路径，不复制密钥内容。首次从旧版 SecHostAgent 启动 HuntWarden 时，应用会非破坏性复制旧配置与运行数据并保留原目录；由于 Electron `safeStorage` 密文绑定应用身份，API Key 不会跨品牌复制，需在 HuntWarden 中重新录入。已被早期迁移版本复制的旧密文会在重新保存同一 Provider 的 Key 时以 `0600` 权限备份并安全替换；`SECHOST_CONFIG` 仅作为旧脚本兼容变量继续读取。

## Docker Lab

启动脚本会临时生成登录 Key、容器 Host Key 和 `known_hosts`，构建 Java 探针并启动四套环境：

```bash
npm run lab:up
npm run test:docker
```

`npm run test:docker` 会先自动重置 Lab，再执行包含真实文件隔离和账户禁用的测试；若只想针对已经运行且状态已知的容器执行测试，可使用 `npm run test:docker:running`。

处置闭环的 Electron GUI 自动化会为每个用例重置 Lab，使用仅在测试环境启用的 Pi Faux 脚本模型，并真实点击拒绝、二次确认和审计回执界面：

```bash
npm run test:gui:remediation
npm run test:gui:investigation
npm run test:gui:recovery
```

写操作测试会改变容器内的文件或账户状态。重新执行处置场景前，用以下命令删除并重建四个 Lab 容器；本地测试身份 Key 会保留，`known_hosts` 会按当前容器重新生成：

```bash
npm run lab:reset
```

| 场景 | SSH | 应用 | 内容 |
| --- | --- | --- | --- |
| Lab-Web | `127.0.0.1:2222` | `http://127.0.0.1:8080` | 正常脚本、无害 WebShell 标记样本、关键词误报样本 |
| Lab-Tomcat | `127.0.0.1:2223` | `http://127.0.0.1:8081/lab/` | Tomcat 9/JDK 17、无害动态 Filter、磁盘类删除后的 Dump 场景 |
| Lab-Account | `127.0.0.1:2224` | — | 正常执行账户、测试 UID 0 账户、未知 SSH Key 指纹 |
| Lab-Persistence | `127.0.0.1:2225` | — | 正常项、无害 Cron/systemd/SSH/Shell 持久化模拟及回环监听进程 |

停止环境：

```bash
npm run lab:down
```

Lab 只允许在隔离开发环境使用。账户禁用与隔离测试会真实改变对应容器状态。

## 安全与恢复语义

- Agent 工具参数没有 host、任意路径、任意 PID 或命令字符串；后续调查使用任务内不透明引用。
- `SCAN` 模式在工具执行前硬阻断全部写操作。
- `REMEDIATE` 模式仍要求绑定 `taskId + targetFingerprint + tool + argsDigest + actionId` 的一次性票据。
- 文件隔离要求已有 Evidence，且远端当前哈希与审批时一致；仅同文件系统原子移动并设置 `000`。
- 账户禁用永久拒绝 `root` 和当前 SSH 执行用户，保存前态并验证锁定/过期结果。
- SAFE 工具按原 `toolCallId` 幂等恢复；NEVER 工具先查远端 `actionId` 回执。状态未知时必须重新审批，绝不自动重放。
- 启动时遗留活动任务会转为 `ABORTED + recoveryRequired`；GUI 仅在分析师点击后恢复。报告以 `v1/v2/...` 不可变保存，旧版单文件报告懒迁移为 LEGACY。
- 已结束任务可归档并恢复到当前列表；归档只改变列表可见性，Finding、Evidence、报告和审计记录不会被删除，活动或待恢复任务禁止归档。
- 流式半成品只存在于当前进程与界面内存，完整 Assistant 消息仅在 `message_end` 后写入 SQLite；Thinking 和未完成的 Tool Call 参数不会发送到 GUI/TUI。
- 模型只接收脱敏且最多 64 KiB 的文本；原始 Evidence、二进制和 Class Dump 不上传。
- 数据目录为 `0700`，数据库、Evidence 和报告为 `0600`。首期不提供应用层加密或自动过期删除。

## 目录

```text
src/                 Agent、桌面 GUI、TUI、领域模型、存储、SSH、工具和报告
assets/              桌面应用图标
host-helper/         目标端固定操作辅助程序
java/tomcat-probe/   Java 17 Attach/Agent 只读探针
rules/yara/          项目测试规则
labs/                Web、Tomcat、Account、Persistence Docker Lab
tests/               单元和集成测试
config/              YAML 配置
```

## 明确限制

首期只支持单台 Linux、SSH、Tomcat 9/JDK 17 和单活动任务。不支持 Windows、批量 Hunt、Velociraptor、多 Agent 或生产级密钥托管。
