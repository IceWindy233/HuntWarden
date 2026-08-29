# HuntWarden 模型分析能力修复计划

> 状态：**已完成并归档（2026-08-21）**。P1/P2/P3 全部条目已落地并进入 `v0.1.1` 之后的 `[Unreleased]`；本文只作历史记录，不再作为待办依据。
>
> 后继文档：本文第 1 节的实测基线已迁入 [`docs/TOOL_PROTOCOL_V2_DESIGN.md`](../TOOL_PROTOCOL_V2_DESIGN.md) 的 §0，第 12 节列出的模型能力边界正是该 v2 设计要消除的对象。需要了解当前架构方向请读 v2 设计，不要读本文。
>
> 目标（历史）：消除"确定性最低扫描已经命中真实后门，但模型看不到、也取不回"这一类架构性失明，同时不放松任何写门控与目标绑定不变量。
>
> 建立日期：2026-08-21
>
> 适用版本基线：`0.1.1`（`package.json`）、Helper `0.4.2`（`host-helper/huntwarden_helper.py:42`）、Helper 协议版本 `1`（`src/executor/operations.ts:7`）
>
> 本计划只处理**信息漏斗与降级语义**。检测规则召回率、新增检测类别、新平台适配继续留在 [`docs/TODO_PLAN_REAL_WORLD.md`](../TODO_PLAN_REAL_WORLD.md)，不由本计划阻塞。

## 0. 实施状态（2026-08-21）

P1、P2、P3 的全部条目已落地。同一场景（默认全选五类检测、STANDARD、8 个特权账户、12 个可疑进程、40 个 Web 候选、每类持久化源 120 项）实测前后对比：

| 指标 | 修复前 | 修复后 |
| --- | --- | --- |
| Planner 消耗 Tool Call | 50 / 100（无闸门；26 账户时 83%） | 50 / 100，闸门硬上限 = `maxToolCalls × 0.5` |
| 逐引用扇出配额 | 无上限（26 账户 → 78 次调用） | 按本次检测项从预算推导：全选五类 9、后门账户+分诊 11、只查后门账户 15、只查分诊 47 |
| 注入模型的扫描块 | 65 536 B，`JSON.parse` 失败 | 63 582 B，**可解析** |
| 确定性规则结论进入上下文 | 0 / 3 | **3 / 3** |
| 最低步骤在上下文可见 | 11 / 18（持久化 5 + 分诊 2 全缺） | **18 / 18** |
| 省略信号 | 无 | `itemsPerOutcome: 9`、`itemsOmitted: 1317`，显式可见且可 `read_tool_result` 回取 |

另有两条 Linux 侧修复在 Docker Lab 容器内直接验证：

- `/etc/ld.so.preload` 指向 `/usr/lib/huntwarden-fake-preload.so` 时，`entries` 现在包含该路径并给出"在固定采集根之外"的 warning + `partial: true`；修复前 `entries` 为空且无任何提示。
- 访问日志搜索命中 `access.log.1`、`access.log.2.gz` 与 `/var/log/nginx/site-a/access.log` 共 3 条，`scannedLogs` 列出 4 个文件；修复前裸 glob 只匹配 `access.log`，命中数为 0。

门禁全绿：`lint`（19 条既有 warning，退出码 0）、core/renderer 双 `typecheck`、`build`、`npm test`（145 通过 / 34 按环境跳过）、`npm run test:docker`（五套 Lab 10/10）、`npm run test:gui:investigation`（4/4）、`npm run test:gui:remediation`（3/3）、`npm run test:gui:recovery`（6/6）。

未纳入本轮的遗留项：从 `nginx -T` 的 `access_log` 指令推导日志路径（取代固定 glob）、`inspect_authorized_keys` 是否返回选项键名。

两处按用户决定放宽的边界：逐引用扇出配额改为从预算推导（而非写死 8 / 12 常量）；`enrich_task_file_iocs` 接受 `evidenceRefs`，允许模型把本任务已采集 Evidence 的 SHA-256 送检——仍然不能提交任意字符串。

## 1. 证据基线

用仓库自带的 `FakeExecutor` + 真实 `ScanPlanner` 实测（脚本为一次性探针，已删除）。

### 1.1 实验 A：默认全选 5 类检测，中等规模主机

场景：STANDARD 预设、8 个特权账户、12 个可疑进程、40 个 Web 候选文件、每类持久化源 120 项。

| 观测项 | 实测值 |
| --- | --- |
| Planner 在模型第一个 token 之前消耗的 Tool Call | 50 / 100 |
| 注入模型的 `<deterministic-minimum-scan>` | 65 536 字节，已截断，`JSON.parse` 失败 |
| `cron` / `systemd` / `extended-persistence` / `ssh-persistence` / `shell-startup` 事实进入模型上下文 | **0 / 5 个源** |
| `suspicious-processes` / `suspicious-connections` 进入模型上下文 | **0** |
| 8 个账户的 `login-history` 进入模型上下文 | 3 / 8 |
| 确定性规则结论进入模型上下文 | **0 / 3**（DB 中为 backdoor_account、linux_persistence、linux_intrusion_triage 各一条 `SUSPICIOUS/MEDIUM`） |
| 模型剩余可用工具中的持久化枚举工具 | **0 个**（5 个 list 工具全部被移除） |

### 1.2 实验 B：只查 `backdoor_account`，扫特权账户数

| 特权账户数 | 3 | 4 | 6 | 8 | 12 | 26 |
| --- | --- | --- | --- | --- | --- | --- |
| Planner 预算占用 | 14% | 17% | 23% | 29% | 41% | 83% |
| 上下文字节 | 48 762 | 62 799 | 65 536 | 65 536 | 65 536 | 65 536 |
| 是否截断 | 否 | 否 | **是** | 是 | 是 | 是 |
| JSON 可解析 | 是 | 是 | 否 | 否 | 否 | 否 |
| 规则结论可见 | 是 | 是 | **否** | 否 | 否 | 否 |
| 模型剩余工具 | `list_processes` + `record_finding` | 同 | 同 | 同 | 同 | 同 |

**截断临界点是 5 个特权账户。** 超过它，`HW-ACCOUNT-UID0-001` 命中的"非 root 的 UID 0 账户"永远不会进入模型视野，而 6 个账户工具（`src/tools/account/tools.ts:14,26,39,53,65,77`）恰好等于最低执行图的 6 步（`src/checks/check-definitions.ts:78-86`），全部被 `src/runtime/security-agent-runtime.ts:89` 移除。

### 1.3 脱敏正则的正确性缺陷（实测复现）

`src/agent/data-sanitizer.ts:2` 的 `(?<=…)[^\s,;]+` 作用在**已 `JSON.stringify` 的字符串**上：

| 输入（JSON 内） | 输出 | 后果 |
| --- | --- | --- |
| `"$secret=Ax9k2Lm\n@eval($_POST[$secret]);"` | `"$secret=[REDACTED];"` | JSON 里 `\n` 是 `\`+`n` 两个字符，`\s` 匹配不到，匹配跨行吃到下一个 `;`；**`@eval(...)` 被删除**，恶意文件在模型眼里变干净 |
| `{"excerpt":"api_key=AKIA0000EXAMPLE"},{"next":"keep"}` | `api_key=[REDACTED],{"next":"keep"}` | 吃掉 `"}`，**JSON 结构损坏** |
| `{"password":"Hunter2"}` | 原样 | lookbehind 被引号打断，**结构化字段的凭据不脱敏** |

## 2. 验收口径

以 1.1 的场景作为回归门禁，落地为 `tests/integration/model-context-budget.test.ts`。

- [ ] 注入模型的扫描块**始终** `JSON.parse` 成功。
- [ ] 确定性规则结论 **3 / 3** 出现在模型上下文。
- [ ] 5 个持久化源与 triage 两步的事实进入模型上下文（可为"摘要 + 可回取"形态，不要求全量 items）。
- [ ] 任何被省略的数据都带 `truncated: true` + `itemsOmitted: N` + `status: "partial"` + warning，且**可通过一次本地调用回取**，不重跑远程采集。
- [ ] Planner 消耗的 Tool Call 有上限，模型可用预算有下限保证。
- [ ] 脱敏后 `@eval(...)` 保留、`{"password": "..."}` 被脱敏、输出恒为合法 JSON。
- [ ] `npm run lint`、`npm run typecheck`、`npm run typecheck:renderer`、`npm test` 全绿；`npm run test:docker` 与三条 GUI E2E 在 P1、P3 结束后各跑一次。

## 3. 不动的不变量

修复不得触碰产品论点，每个阶段的测试必须复核：

- `SCAN` 模式不注册写工具（`src/tools/index.ts:31-36`）；一次性票据绑定 `taskId + targetFingerprint + tool + argsDigest + actionId`（`src/agent/approval-service.ts:17-27`）。
- 模型不能提交任意路径 / PID / 命令 / 目标主机；不透明引用仍是唯一寻址方式（`src/tools/reference-utils.ts:20-29`）。
- **模型永远拿不到原始 Evidence 字节。** 第 4.3 项新增的回取能力只覆盖 `tool_runs.result_json` 的结构化 `items`，并在返回模型前再次统一脱敏；不覆盖 `collect_file` / `dump_java_class` / `collect_process_executable` 落盘的 Evidence 文件。此边界必须写入 ADR 并由测试断言。
- `record_finding.category` 仍限于任务已选类别；`CONFIRMED` / `HIGHLY_SUSPICIOUS` 仍强制引用 `EV-`。
- 报告事实源仍是 DB；四层 coverage 兜底与 `coverage` 只升不降不变。
- `PARTIAL` / `ERROR` / `NOT_CHECKED` 绝不呈现为安全。

## 4. P1：让模型看得见（同一批提交，五项互相耦合）

### 4.1 脱敏移到序列化之前，按字符串叶子与键名处理

- **落点**：`src/agent/data-sanitizer.ts`；调用方 `src/tools/tool-factory.ts:60`、`src/checks/scan-planner.ts:185`、`src/report/report-service.ts:177`。
- **改动**：新增 `redactValue(value: unknown): unknown`，深拷贝时对每个 string 叶子跑现有 4 条正则，并对键名命中 `password|passwd|pwd|secret|token|api[_-]?key|cookie|authorization` 的字段整体置 `[REDACTED]`。保留 `sanitizeForLlm(text, maxBytes)` 只服务真正的纯文本，届时全仓仅剩 `src/runtime/security-agent-runtime.ts:340` 一个调用点。
- **为什么这样修**：在真实字符串上 `\n` 是换行，`\s` 命中，`[^\s,;]+` 自然停在行尾——跨行吞代码的缺陷随之消失；不再对序列化文本做替换——破坏 JSON 结构的缺陷也消失。两个 bug 同一个根因，一处修掉。
- **验收**：`tests/unit/data-sanitizer.test.ts` 新增三条用例，对应 1.3 表格三行。
- **风险**：深拷贝对大对象有额外分配。缓解——只在进入模型的路径上做，`details` 落库仍用原对象；对 string 叶子先 `indexOf` 粗筛关键字再跑正则，避免对无关字段编译匹配。

### 4.2 `deterministicFindings` 提到序列化最前

- **落点**：`src/checks/scan-planner.ts:185-194`。
- **改动**：把对象字段顺序调整为 `trust` → `instruction` → `deterministicFindings` → `outcomes`。
- **为什么这样修**：截断从尾部发生，规则结论是全场最高信息密度的内容，必须排在最先被保留的位置。
- **验收**：在 1.1 场景下断言 `promptContext` 含全部 `findingId`。
- **风险**：无。一次字段重排。

### 4.3 结构化截断 + 本地分页回取

**(a) 结构化截断**

- **落点**：`src/agent/data-sanitizer.ts` 新增 `serializeForLlm(details, maxBytes, options?)`。
- **契约**：
  1. 先 `redactValue`，再序列化。
  2. 超预算时按 `options.droppable`（默认 `["items"]`）从**数组尾部**逐轮丢弃元素并重新计量。
  3. 输出**恒为合法 JSON**，写入 `truncated: true`、`itemsOmitted: N`、`status: "partial"`，并向 `warnings` 追加"结果超出模型文本预算，已省略 N 项，可用 `read_tool_result` 回取"。
  4. `summary.count` 保持真实总数（`src/tools/triage/tools.ts:48-61` 的 `partialResult` 已写入 `count`），模型可用 `count` 对比 `items.length`。
- **`scan-planner` 专用顺序**：先丢 `outcomes` 内各 outcome 的 `details.items` 尾部，再丢整条 outcome，`deterministicFindings` 永不丢弃；`outcomes` 的投影必须新增 `toolCallId` 字段（当前 `scan-planner.ts:188` 未输出），否则模型无法回取 planner 采集的数据。
- **`report-service` 专用顺序**：`findings` / `approvals` / `actionReceipts` / `task` 为**强制字段**（`validate` 要求每个 action/approval 的 id 与 status 出现在正文，`src/report/report-service.ts:37-44`），只允许丢 `audit`、再丢 `evidence`。强制字段仍超预算时写入 `contextIncomplete: true`，`generate` 直接走 `fallback()`，不再浪费两次模型往返。

**(b) `read_tool_result` 工具**

- **落点**：新增 `src/tools/local/read-tool-result.ts`，在 `src/tools/index.ts` 中与 `record_finding` 同级恒定注册。
- **签名**：`{ toolCallId: string(1..128), offset: integer(>=0) }`，`risk: "LOCAL"`，`replayPolicy: "SAFE"`，`timeoutMs: 10_000`。
- **实现**：`RuntimeStore` 新增 `getToolRunForTask(taskId, toolCallId)`——现有 `getToolRun(toolCallId)`（`src/storage/runtime-store.ts:363-366`）**不按任务过滤**，直接复用会形成跨任务读取，必须先补作用域。取 `result.details.items` 从 `offset` 切片，用 `serializeForLlm` 输出 `{ status, summary: { toolCallId, total, offset, returned }, items, artifactRefs: [], warnings }`。
- **为什么选这个方案**：数据已经越过采集边界、已经脱敏、已经落库，回取不新增任何远程面、不新增 Helper 操作、不放宽任何参数白名单，却一次性修好全部 57 个工具的"数据在本地却拿不到"。相比给 15 个 list 工具逐个加 `offset`，它不破坏"工具入参只有空对象或不透明引用"这一设计。
- **安全约束（必须测试）**：只接受本任务的 `toolCallId`；只返回 `tool_runs.result_json` 中的结构化 items；**不得**接受 `EV-` 或返回任何 Evidence 文件内容。
- **风险**：模型可能滥用回取消耗预算。缓解——`LOCAL` 工具不走 SSH，成本只有上下文；把总回取次数纳入 `maxToolCalls` 即可自然收敛。

### 4.4 Planner 预算闸门 + 按预算推导的风险排序扇出配额

- **落点**：`src/checks/scan-planner.ts`（`fanOutPlan` / `skipsStep` / `executeStep`）、`src/checks/check-definitions.ts`（`ScanStepContext.fanOutLimit` / `MinimumScanStep.fansOut` / `referenceArguments`）、`src/config/schema.ts`、`config/*.yaml`。
- **改动**：
  1. 新增配置 `agent.plannerToolCallShare`（`0.1 – 0.9`，默认 `0.5`）。Planner 预算 = `floor(maxToolCalls × share)`，`executeStep` 在**每次 invocation 之前**检查；超限则该步及剩余 invocation 产出 `status: "error"`、`error: "最低扫描已达到 Tool Call 预算上限"`，经既有路径路由为类别 coverage `ERROR`。
  2. 扇出配额**从预算推导，不写死常量**。步骤用 `fansOut: true` 声明自己按引用逐条展开；`fanOutPlan()` 普查本次实际要跑的步骤（跳过配置关闭的），固定步骤各占 1 次、每个扇出步骤保底 1 次、余量在扇出步骤之间平分，再夹到 `FAN_OUT_CEILING = 200`。实测默认预算下：全选五类 9、后门账户 + 分诊 11、只查后门账户 15、只查分诊 47。
  3. `referenceArguments` 先按风险排序再截到配额：账户按 `uid === 0` → `sudo` → `accountSource !== "local"`，进程按 `signals.length` 降序。`Array.prototype.sort` 稳定，等风险项保持枚举顺序。
- **为什么这样修**：修复前 `toolCallCount += 1` 无条件自增且不做检查，而模型侧超限即被 `beforeToolCall` 硬阻断——预算是单向被抢占的。配额从预算推导而非写死，才能做到"只勾选一类检测时远宽于全选五类"，同时全选时也不让靠前的逐账户扇出吃光预算。排序截断把"看前 N 个"变成"看最可疑的 N 个"，同样预算下召回率不同。
- **验收**：26 账户场景下 planner 占用 ≤ 50%；`systemd-helper`（UID 0）在全选与单类别两种配额下都必须被深挖；单类别深挖的账户数严格多于全选。

### 4.5 不再移除 Planner 用过的工具

- **落点**：`src/runtime/security-agent-runtime.ts:86-92,129`。
- **改动**：删除 `agent.state.tools = originalTools.filter(...)`；改为在注入块的 `instruction` 中列出"已执行的步骤 + 其 `toolCallId` + items 总数"，并说明"需要完整列表用 `read_tool_result` 回取；仅在需要新鲜数据时重新调用该工具"。`minimumToolNames` 保留为审计与提示数据，不再用于裁剪。
- **为什么这样修**：实验 A 证明当前实现会让 `inspect_persistence_item` / `find_related_processes` / `collect_persistence_artifact` **注册了但结构上不可调用**——它们只接受 `PERSIST-` 引用，而产生引用的 5 个 list 工具被移除且输出被截断。`linux_persistence` 因此没有任何补救路径。
- **风险**：模型可能重复远程枚举、浪费预算。这是**预算浪费而非安全违规**，且 4.4 已为模型保留预算下限；相比"整个类别失明"是明显更好的权衡。
- **验收**：1.1 场景下模型工具表包含 5 个持久化 list 工具与 `list_suspicious_processes`、`list_process_connections`。

## 5. P2：修掉确定的检测盲区

### 5.1 `inspect_script_file` 预算解耦 + 尾部片段

- **落点**：`src/tools/webshell/tools.ts:150`、`src/config/schema.ts:63-71`、`host-helper/huntwarden_helper.py:1159-1170`。
- **问题**：工具把 `config.llmData.maxTextBytes` 当作 `maxBytes`，schema 允许到 262 144（`src/config/schema.ts:62`），而 Helper 硬夹 `[1024, 65536]` 且 `safe_int` **越界抛错不夹取**（`huntwarden_helper.py:168-171`）。把 `maxTextBytes` 调大来缓解截断，会让该工具恒定 `INVALID_ARGUMENT`（再经 `tool-factory.ts:75-77` 变成"环境不支持"）。同时 `excerpt` 只取文件**前** `maxBytes` 字节，大文件末尾追加的后门永不可见。
- **改动**：新增 `webshell.maxScriptExcerptBytes`（默认 `65536`，schema 上限 `65536` 与 Helper 对齐）替换该调用点；Helper 在文件超预算时返回 `excerptHead` + `excerptTail`（各占一半预算）与 `excerptGapBytes`，`features` 计数覆盖两段。工具保持零参数，不放宽模型的输入面。
- **协议**：Helper 响应新增字段，控制端必须容忍旧 Helper 缺字段；`REQUIRED_HELPER_PROTOCOL_VERSION` 保持 `1`，只提升 `HELPER_VERSION`。

### 5.2 `inspect_dynamic_loader` 不再静默丢弃条目

- **落点**：`host-helper/huntwarden_helper.py:2697-2701`。
- **问题**：`/etc/ld.so.preload` 的条目被 `TRIAGE_ROOTS` 白名单过滤，而该白名单（`:62-65`）**不含 `/lib`、`/usr/lib`**——正是 LD_PRELOAD 劫持最经典的落点。指向 `/usr/lib/evil.so` 的条目被丢弃且不产 warning，模型看到 `entries: []`。
- **改动**：`entries` 始终记录条目字符串；`TRIAGE_ROOTS` 判定只用于是否采集 `loaded_library` 文件事实，落在白名单外时追加显式 warning 并置 `partial`。路径白名单的安全属性（不读取白名单外文件）不变。
- **验收**：`tests/integration/host-helper.test.ts` 增加"preload 指向白名单外路径"用例，断言 `entries` 非空且 `partial === true`。

### 5.3 Web 访问日志覆盖轮转、gzip 与子目录

- **落点**：`host-helper/huntwarden_helper.py:1173-1194`（`search_web_access_log`）、`:1237-1273`（`correlate_web_requests`）。
- **问题**：两处都用裸 `glob.glob("/var/log/nginx/access*.log")`，不匹配 `access.log.1`、`access.log.2.gz`、`/var/log/nginx/<site>/access.log`。而 Helper 自己已有 rotation + gzip 感知的 `log_file_set`（`:540-554`）与 `bounded_log_lines`（`:501`）——认证/审计日志用了，Web 日志没用。WebShell 落地时的上传请求通常就在轮转文件里。
- **改动**：改用 `log_file_set` + `bounded_log_lines`，pattern 扩展为 `access*.log*`、`access_log*`、`*/access*.log*`；结果新增 `scannedLogs` 字段，让模型知道实际覆盖了哪些文件。
- **后续（P3 或下一版）**：从已解析的 `nginx -T` 有效配置推导 `access_log` 指令路径，取代固定 glob。

### 5.4 工具描述改为由实际生效值生成，并显式标注被删除的信号

- **落点**：`src/tools/triage/tools.ts:135,200,263,275`、`src/tools/shared/process-connections.ts:41`、`src/tools/account/tools.ts:66`、`src/tools/webshell/tools.ts:161`。
- **问题（逐条核对过）**：
  - `scaleForProfile` 对默认 STANDARD 乘 0.5（`shared/process-connections.ts:20-23`），任何描述都没提这个系数。
  - `list_recent_executables` 描述写"168 小时、500 结果、单文件 100 MiB"（`triage/tools.ts:200`），实际传入的是任务时间窗 / `maxFiles`（STANDARD 下 2500）/ `triage.maxArtifactBytes`（默认 10 MiB）。
  - `inspect_process_tree` 描述写"最多 12 层、1000 个节点"（`:135`），实际 `maxNodes` 是缩放值（QUICK 500 / STANDARD 1000 / DEEP 2000）。
  - `query_auth_events` / `query_exec_events` 描述写死"最近 168 小时"（`:263,275`），实际是任务时间窗。
  - `inspect_authorized_keys` 描述写"类型、SHA-256 指纹、注释和选项"（`account/tools.ts:66`），而 Helper 只返回 `hasOptions: boolean`（`huntwarden_helper.py:1528`）——`command=` 强制命令、`from=` 来源限制、`environment=` 的**内容从不返回**。这不只是文案问题：`command="..."` 型 SSH 后门在本架构下无法识别。
- **改动**：描述改为模板字符串插值真实生效值（工具构造期 `deps.task` 与 `deps.config` 均可用），使其无法再漂移；同时在描述中显式列出"本工具**不返回**"的字段，让模型知道信号是被有意删除而非环境缺失。`inspect_authorized_keys` 额外评估是否返回**选项键名**（不返回值），与"只回指纹不回完整 Key"的既有边界一致。
- **为什么值得做**：模型的覆盖度陈述直接建立在描述上。"我扫了 500 个可执行文件，覆盖充分"在 STANDARD 下是错的；"已检查 SSH Key 的选项"在当前实现下是无据的。

### 5.5 错误码语义纠正

- **落点**：`src/tools/tool-factory.ts:72-77`、`src/executor/ssh-executor.ts:302-310`。
- **问题**：(a) 所有非 `SecurityError` 异常被统一改写为 `UNSUPPORTED_ENVIRONMENT`——`record-finding.ts:38-40` 抛的裸 `Error`（"CONFIRMED 必须至少引用一个 Evidence"）也变成"环境不支持"，模型会放弃该方向而不是修正参数重试。(b) 控制端 2 MiB 超限被归类为 `UNSUPPORTED_ENVIRONMENT`，语义变成"目标没能力"，而实际是数据太多、应缩小时间窗或降低采集上限。
- **改动**：(a) `InvalidArgumentError` 与 `TypeError` 映射为 `INVALID_ARGUMENT` 并保留原始消息；其余保持。(b) 新增 `SecurityErrorCode` 成员（如 `OUTPUT_BUDGET_EXCEEDED`）或复用 `EVIDENCE_COLLECTION`，错误文案给出可执行动作。`record-finding.ts` 的 Evidence 强校验改抛 `InvalidArgumentError`。
- **注意**：`HELPER_ERROR_CODES`（`ssh-executor.ts:42-44`）是 Helper→控制端的协议白名单，新增控制端本地错误码不得加入该集合。

### 5.6 工具层上限比 Helper 更严且不可配

- **落点**：`src/tools/webshell/tools.ts:161`（`maxLines: 500` vs Helper 允许 5000，`huntwarden_helper.py:1178`）、`src/tools/account/tools.ts:83`（`maxEntries: 100` vs Helper 允许 500，`:1534`）、`src/tools/triage/tools.ts:140`（`maxDepth: 12` vs Helper 允许 32，`:2383`）。
- **问题**：目标端有能力返回更多，工具层写死砍掉，既非配置项也非参数——只能改源码。高流量站点的 WebShell 访问记录远超 500 条时，模型看到的可能全是上传后的探测流量，看不到真正的命令执行请求；`last` 只回 100 条时，长期低频登录的后门账户历史被近期正常登录挤出。
- **改动**：提为配置项（`webshell.maxAccessLogLines`、`account.maxLoginHistoryEntries`、`triage.maxProcessTreeDepth`），schema 上限与 Helper `safe_int` 区间对齐；默认值保持现状，避免改变既有验收基线。

## 6. P3：韧性与结论质量

### 6.1 上下文淘汰（取代不存在的 compaction）

- **落点**：`src/runtime/security-agent-runtime.ts:38-55`，使用 SDK 的 `prepareNextTurnWithContext`（`node_modules/@earendil-works/pi-agent-core/dist/agent.d.ts:17`，可返回 `AgentLoopTurnUpdate.context` 替换下一轮 messages，`dist/types.d.ts:107-114`）。
- **问题**：用的是低层 `Agent` 而非带 compaction 的 `AgentHarness`；`src/` 对 `compaction` / `shouldCompact` / `estimateContextTokens` 零引用，历史消息从 SQLite 全量无 LIMIT 回放（`src/storage/runtime-store.ts:339-343`）。单条满额工具结果约 16.4k tokens，`gpt-5.6-terra` 可用窗口约 268k → 约 16 条撑满，而预算允许 100 次调用。
- **改动**：实现 `prepareNextTurnWithContext`：把超过 N 轮（默认 3）的旧 toolResult 文本替换为 `{ toolCallId, summary, itemsOmitted, hint: "read_tool_result" }` 存根。因为 4.3(b) 已让模型可以按需回取，**淘汰是无损的**。
- **架构表述**：上下文是缓存，SQLite 是事实源，`read_tool_result` 是回取通道。这三句话进 ADR。
- **不选 `AgentHarness`**：迁移会引入 harness 自己的 session tree 持久化模型，与现有 `messages` 表、稳定 `CORE-` toolCallId 复用和 `recover()` 语义冲突，代价远大于收益。

### 6.2 Provider 韧性

- **落点**：`src/runtime/security-agent-runtime.ts:38-55`（`AgentOptions.maxRetryDelayMs`）与 `streamFn` 的重试策略。
- **问题**：调查循环不传重试策略，一次 429 / 网络抖动即 `stopReason === "error"` → 抛出（`:93-96`）→ 任务 FAILED 且所有未固化类别标 `ERROR`（`:108-121`）。
- **改动**：为调查循环设置有界重试与 `maxRetryDelayMs`，并把重试事件写审计；区分"Provider 不可用"与"目标环境受限"两类 coverage 原因文案。

### 6.3 威胁情报按风险选择并分页

- **落点**：`src/tools/threat-intel/tools.ts:49-58`、`:76-97`。
- **问题**：(a) `[...refsByIoc.keys()].sort()` 后 `slice(0, maxBatchSize)`——超过 100 个公网远端时被查的是**字典序**前 100 个，C2 若是 `203.x` 直接不查，warning 也不说明排序依据。(b) `enrich_task_file_iocs` 零参数、只查 `task.iocs.hash`（`:89`），模型从 `collect_file` 拿到的新样本 sha256 无法送检。
- **改动**：(a) 按风险代理排序（关联进程带可疑 `reasons` 优先、出现次数少的稀有外联优先），并支持多次调用分页覆盖全部候选，而不是丢弃；warning 明确写出排序与分页状态。(b) 新增 `evidenceRef`（`^EV-`）入参，只允许送检**本任务 Evidence 记录中已有的 sha256**——不接受模型自由输入哈希，保持"模型不能提交任意 IOC"不变量。

### 6.4 `severity × status` 交叉校验

- **落点**：`src/tools/local/record-finding.ts:20-42`。
- **问题**：两个 union 相互独立、无交叉校验，模型可提交 `severity: CRITICAL` + `status: NO_FINDING`；`report-service.ts:211-213` 会逐字打印，`validate` 只检查 coverage 状态串是否出现（`:32-36`），于是产生"严重度极高但结论是没发现"的自相矛盾报告。
- **改动**：run 内拒绝 `CRITICAL`/`HIGH` 配 `NO_FINDING`/`NOT_CHECKED`，拒绝 `INFO` 配 `CONFIRMED`/`HIGHLY_SUSPICIOUS`，抛 `InvalidArgumentError`（配合 5.5，模型会收到可修正的语义）。

### 6.5 `HW-PERSIST-CONTEXT-001` 覆盖 `extended-persistence`

- **落点**：`src/rules/registry.ts:11`。
- **问题**：`persistenceSteps` 是 `["cron","systemd","ssh-persistence","shell-startup"]`，缺 `extended-persistence`——而 `check-definitions.ts:95` 会执行该步。PAM / udev / modprobe / cloud-init / 包管理 Hook 的强特征不参与规则判定。
- **改动**：加入该 stepId，`ruleVersion` 升到 `1.1.0`（`toolCallId` 含 `ruleVersion`，旧任务的幂等键不受影响）。
- **待确认**：代码与注释均未说明这是有意收窄还是遗漏；若为有意，需在 `registry.ts` 写明理由，否则按遗漏处理。

## 7. 配置与协议变更汇总

| 键 | 默认值 | schema 约束 | 阶段 |
| --- | --- | --- | --- |
| `agent.plannerToolCallShare` | `0.5` | `0.1 – 0.9` | P1 |
| `webshell.maxScriptExcerptBytes` | `65536` | `1024 – 65536`（与 Helper `safe_int` 对齐） | P2 |
| `webshell.maxAccessLogLines` | `500` | `1 – 5000`（Helper 上限） | P2 |
| `account.maxLoginHistoryEntries` | `100` | `1 – 500`（Helper 上限） | P2 |
| `triage.maxProcessTreeDepth` | `12` | `1 – 32`（Helper 上限） | P2 |
| `agent.contextRetainTurns` | `3` | `1 – 20` | P3 |

Helper 侧：`HELPER_VERSION` 提升；`REQUIRED_HELPER_PROTOCOL_VERSION` 保持 `1`。新增响应字段（`excerpt`/`excerptTail`/`excerptGapBytes`/`scannedLogs`）必须向后兼容，控制端缺字段时降级而不报错。`config/deepseek.yaml` 与 `tests/helpers.ts:4-29` 的 `testConfig` 同步新增键。

## 8. 测试改动清单

### 需要同步的现有测试

| 文件 | 断言 | 原因 |
| --- | --- | --- |
| `tests/unit/data-sanitizer.test.ts:14-20` | `[TRUNCATED:` 标记 | 结构化截断改为 `itemsOmitted`；纯文本路径仍保留标记，需拆成两组用例 |
| `tests/unit/scan-planner.test.ts:72` | `toolCallCount === 4` | 新增预算闸门后复核小规模场景行为不变 |
| `tests/unit/scan-planner.test.ts:73` | `minimumToolNames` 集合 | 语义从"待裁剪工具名"变为"已执行工具名" |
| `tests/unit/scan-planner.test.ts:74-77,194` | `promptContext` 内容与 `[REDACTED]` | 字段顺序变化、脱敏时机变化 |
| `tests/unit/report-service.test.ts` | 报告上下文与 fallback 路径 | 新增 `contextIncomplete` 直接走 fallback 的分支 |
| `tests/unit/tool-scope.test.ts` | 工具装配范围 | 新增 `read_tool_result` 恒定注册 |
| `tests/acceptance/real-world.test.ts:170-184` | planner 结果 | 新增配置键与 outcome 投影字段 |

### 需要新增的测试

- [ ] `tests/integration/model-context-budget.test.ts`：1.1 场景的全部验收口径。
- [ ] `tests/unit/data-sanitizer.test.ts`：1.3 三行 + "输出恒为合法 JSON"。
- [ ] `tests/unit/read-tool-result.test.ts`：跨任务 `toolCallId` 必须被拒；`EV-` 不被接受；分页边界；**不得**返回 Evidence 文件内容。
- [ ] `tests/unit/scan-planner.test.ts`：预算闸门触发时该类别 coverage 为 `ERROR`；风险排序下 UID 0 账户必被深挖。
- [ ] `tests/integration/host-helper.test.ts`：preload 指向白名单外路径；轮转与 `.gz` 访问日志命中。
- [ ] `tests/unit/deterministic-rule-engine.test.ts`：`extended-persistence` 强特征触发 `SUSPICIOUS`。

## 9. 文档变更清单

- [ ] `docs/adr/0002-model-context-as-cache.md`：新建。记录"上下文是缓存、SQLite 是事实源、`read_tool_result` 是回取通道"，并**显式声明该通道不覆盖 Evidence 字节**、不放宽任何写门控与目标绑定。
- [ ] `README.md:17`：`| 读取脱敏且不超过 64 KiB 的文本事实 | 拿到原始 Evidence、二进制或 Class Dump |` 需改写为"每条工具结果不超过 64 KiB；超出部分只能按页回取已脱敏的结构化结果，永远拿不到原始 Evidence 字节"。
- [ ] `README.md:116-127` 已知限制：补充"检测覆盖范围受固定扫描根、投影式返回与采集上限约束"，并指向本计划。
- [ ] `docs/USAGE.md`：新增三个配置键说明与调参后果（尤其 `webshell.maxScriptExcerptBytes` 与 Helper 上限的对齐要求）。
- [ ] `docs/SUPPORT_MATRIX.md`：`inspect_dynamic_loader` 与 Web 日志覆盖范围的状态更新。
- [ ] `CHANGELOG.md` `[Unreleased]`：按 Keep a Changelog 的 `Fixed` / `Added` 分节，逐条描述"此前的错误行为"——与 `0.1.0` 条目的写法保持一致。

## 10. 执行顺序与门禁

| 阶段 | 内容 | 门禁 |
| --- | --- | --- |
| P1 | 4.1 → 4.2 → 4.3 → 4.4 → 4.5，单批提交 | `lint` + 双 `typecheck` + `npm test` + 新增回归测试 + `npm run test:docker` |
| P2 | 5.1 → 5.2 → 5.3 → 5.4 → 5.5 → 5.6 | 同上 + `tests/integration/host-helper.test.ts` + Helper `self-check-helper.sh` |
| P3 | 6.1 → 6.2 → 6.3 → 6.4 → 6.5 | 同上 + 三条 GUI E2E + 一次真实 VM 冒烟 |

P1 内部五项不可拆分：4.5 移除工具裁剪后，若没有 4.3 的回取通道，模型会被迫重复远程枚举；若没有 4.4 的预算闸门，重复枚举会耗尽预算。

顺序理由：P1 修的是"看不见"，P2 修的是"根本没采到"，P3 修的是"长跑与结论质量"。P2 的盲区在 P1 之前修没有意义——数据修好了也进不了模型上下文。

## 11. 与已知限制的关系

`README.md:120` 写明"检测质量尚未度量"。本计划处理的是**在度量之前就能确定会压低召回率的架构因素**：4.2、4.3、4.4、4.5 与 5.4 会让"规则已经命中真实后门"这件事对模型不可见。若不先修，后续度量出的低召回会被误归因到检测规则或验收语料，而不是信息漏斗。

## 12. 本轮复核后的模型能力边界

这些边界不能简单地靠继续增大 token 或删除参数校验解决；其中一部分是安全授权语义，另一部分才是后续应消除的信息漏斗。

本轮已经落实两个优先项：新增任务内脱敏字面量搜索 `search_tool_results`，以及来源绑定的 `promote_tool_result_reference`。后者只接受 `sourceToolCallId + itemIndex + jsonPointer + kind`，不接受引用内容，并按来源工具、任务检测范围和稳定身份字段硬校验。

| 边界 | 对模型的实际影响 | 建议方向 |
| --- | --- | --- |
| 工具包只按任务已选检测类别注册 | 调查中发现跨类别线索时，模型无法直接转向相邻工具包；这是当前授权范围而非预算问题 | 后续增加由分析师显式开启的“相邻只读扩展”，扩展事件写审计；不得自动带入写工具 |
| Linux 文件调查仍受固定采集根约束 | `/etc`、`/usr/lib`、`/var`、`/srv` 中的可疑路径可能只被报告路径，拿不到文件事实 | 从已解析配置、进程 maps/FD 与包完整性结果中生成有来源绑定的候选引用，再允许只读检查；不开放任意路径 |
| 报告阶段不注册调查工具 | 若调查阶段未固化关键 Finding，报告模型不能回查遗漏事实 | 报告上下文应优先由确定性引用图生成；上下文不完整时继续使用明确标记的本地 fallback，而不是让报告模型猜测 |

当前不建议通过“任意 Shell、任意路径/PID、自动跨类别扩权”来解决这些问题。那会提高表面上的自由度，但破坏任务授权、可审计性和 Prompt Injection 隔离；更合适的方向是扩大**有来源、只读、任务内**的语义操作面。
