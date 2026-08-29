# HuntWarden Ubuntu 24.04 ARM64 v2 GUI 只读验收记录

## 1. 结论

- 结果：`PASS_WITH_LIMITATIONS`（本目标 Release Gate 已闭环；Provider 高推理大上下文兼容性与跨平台矩阵仍有限）
- 执行时间：2026-08-26（Asia/Shanghai）
- 补充复验：2026-08-27（真实 journald 身份、generation 与跨页 `contains`）；2026-08-29（可复现 Git 基线、smoke 4/4、journald 1/1 与 Helper 摘要一致性）
- 执行方式：HuntWarden Electron GUI、真实 DeepSeek/SiliconFlow Provider、Multipass VM
- 可复现实现基线 commit：`7318233e1327111de12895867e09bbee965df5e2`（HuntWarden `0.2.0`；包含 v2 重构、默认处置 fail-close 与全部验收代码）
- 历史说明：2026-08-26 原始 GUI/Provider 验收运行在 `283a8d0` 加未提交 v2 工作树上；2026-08-29 已将相同实现固化到上述基线，并用当前目标端 Helper SHA-256 `bbd4463cb0a60fc7026d2cefaa3942c55b47266669bca1ff6d2780b9ac443753` 复验。
- 协议：Tool Protocol v2 / Manifest `2.0.0`
- 主要正式报告：STANDARD `RPT-d12f2c8c-451b-4451-8427-7dfe94c2f708`，SHA-256 `b1e577ee441882d55b8e8130b2b4bb778871b4dda7cee0fb45e404c6dbead832`

本轮已经证明 Ubuntu 24.04 ARM64 上的真实 GUI、Provider Tool Call、严格 SSH Host Key、root Helper v2、五类 QUICK、五类联合 STANDARD、小上下文 DEEP、SFTP Evidence、SQLite 持久化、报告确定性校验和 SCAN 零写入形成闭环。更换为 `siliconflow/deepseek-ai/DeepSeek-V4-Flash` 后，兼容 Profile（reasoning off、retainTurns 1、8 KiB 工具文本、4096 输出 token）完成五类 DEEP；冻结的 novel malicious + benign 模型统计评测七项门槛全部通过。原始高推理大上下文 Profile 曾出现 `terminated` 与长时间无响应，现由单轮 600 秒 Provider 超时 fail-close，但该 Profile 不列为本次兼容配置。

## 2. 目标身份

| 项目 | 实际值 |
| --- | --- |
| 官方镜像来源 | Canonical Multipass Ubuntu 24.04 LTS |
| Image hash | `4a281a921b8d` |
| 发行版 | Ubuntu 24.04.4 LTS |
| 架构 | AArch64 / ARM64 |
| 内核 | `6.8.0-137-generic` |
| init/systemd | `running` |
| LSM | AppArmor enabled；SELinux 不适用 |
| VM 规格 | 2 CPU / 4 GiB / 20 GiB |
| Helper | `huntwarden-helper-v2 2.0.0`，协议 2，Manifest `2.0.0` |
| Host Key 带外核验 | PASS；Multipass 控制台、专用 `known_hosts` 与 GUI 指纹一致 |
| SSH 凭据 | 本轮专用 Ed25519；密钥与真实地址未写入仓库或本记录 |

## 3. 能力与降级

| 能力 | 状态 | 原因/证据 |
| --- | --- | --- |
| root Helper | SUPPORTED | sudo 固定 argv；自检通过 |
| 八个取证原语 | SUPPORTED | `collect/enumerate/match/probe/project/read/relate/verify` |
| YARA | SUPPORTED | YARA `4.5.0`；Helper 声明版本化 matcher |
| journald | SUPPORTED | systemd 正常运行；2026-08-27 实机验证一等 `log_source`、追加写入 generation、event/source join、稳定事件身份及跨页 `contains` |
| auditd | SUPPORTED | `auditctl -s` 可查询；exec event 的 `pid/uid` 已验证为整数归一化 |
| JDK Attach | SUPPORTED | OpenJDK 17.0.20；Probe 已安装 |
| Tomcat Probe | SUPPORTED / NOT_APPLICABLE | `jvm.tomcat.inventory`、`jvm.class.inspect` 已声明；目标无运行 JVM/Tomcat |
| `/proc` 可见性 | SUPPORTED | root Helper 可见 |

完整依赖安装前的最低依赖自检也已执行：YARA/JVM 缺失时 Helper 以能力子集启动并明确降级；补齐发行版包后再次自检为完整能力。缺失运行 JVM 没有触发 Attach，也没有覆盖 Coverage 的 `NOT_APPLICABLE`。

## 4. 检测包与 Profile 结果

| 检测包 | QUICK 任务 | STANDARD | DEEP | 结构化结果 | 限制 |
| --- | --- | --- | --- | --- | --- |
| WebShell | `TASK-f83cf60b-3efd-4142-a20a-0e81a194ce70` | 联合任务覆盖 | `TASK-ce3050a2-2e88-4402-9374-de65935d1ba3` | Coverage `COMPLETE/APPLICABLE`；DEEP 写入类别 `INCONCLUSIVE` | novel 模型评测另由 `TASK-d77591cc-823c-424b-9e67-23869b422448` 独立检出 |
| Java 内存马 | `TASK-f73682b7-c81c-47d5-b069-bf7519d4ffbf` | 联合任务覆盖 | 同上 | Coverage `COMPLETE/NOT_APPLICABLE`；DEEP `INCONCLUSIVE` | 不代表 Tomcat/JVM 安全 |
| 后门账户 | `TASK-9a5d4f8e-b0b6-4b48-bb84-c8659671846e` | 联合任务覆盖 | 同上 | Coverage `PARTIAL/UNKNOWN`；DEEP `INCONCLUSIVE` | login history 为 `PARTIAL_SOURCE` |
| Linux 持久化 | `TASK-97940c23-a191-4559-b0b0-1350ef38b682` | 联合任务覆盖 | 同上 | Coverage `PARTIAL/UNKNOWN`；DEEP `INCONCLUSIVE` | systemd/SSH/shell-loader/extended 为 `PARTIAL_SOURCE` |
| Linux 入侵分诊 | `TASK-07d426c0-74b9-4dcb-a69e-12143b298ad1` | 联合任务覆盖 | 同上 | Coverage `PARTIAL/UNKNOWN`；DEEP `INCONCLUSIVE` | volatile/event/package sources 为 `PARTIAL_SOURCE` |

联合任务：

- STANDARD：`TASK-3401e0c5-62b9-46e3-a072-d693058dec5c`，`COMPLETED`，9 轮、44 次模型工具调用；五类均为 `MODEL: CONCLUDED`。1 次伪造 `QUERY-*` 引用被控制端拒绝后纠正。报告首版遗漏 5 个 Coverage ID，第二轮修复后通过同一 deterministic validator；历史校验错误保留在报告审计字段中。
- DEEP 兼容任务：`TASK-ce3050a2-2e88-4402-9374-de65935d1ba3`，`COMPLETED`，3 轮、10 次模型工具调用、0 失败；五个 Coverage QuerySnapshot 与五条 `MODEL OBSERVED_CATEGORY=INCONCLUSIVE` 均落盘。旧任务 `TASK-1456735b-0fc7-4cdd-beee-41f1ccc3cc6a` 的 402 失败保留为历史证据；高推理 Profile 的 `terminated`/长流任务也不计入通过样本。

正式模型能力统计：[`MODEL_EVAL_2026-08-26.md`](MODEL_EVAL_2026-08-26.md) / [`MODEL_EVAL_2026-08-26.json`](MODEL_EVAL_2026-08-26.json)。`factReachability=2/2`、`novelRecall=1/1`，truncation、model-not-concluded、preset-partial、invalid-tool-call、benign-false-positive 均为 0；冻结清单为 `acceptance/model-eval/manifest.release.json`。

## 5. 样本、对照与安全边界

| 场景 | 预期 | 实际 | 结果 |
| --- | --- | --- | --- |
| 固定无害阳性夹具 | 形成可追溯 Fact/Evidence/SUSPICIOUS | QUICK 形成 `SUSPICIOUS/MEDIUM` 与完整 Evidence；SHA-256 `a7b44c7e3516506251afd29c57a7bb56499065cf03c51dbaa4d4b536ecc075ab` | PASS |
| 良性关键词对照 | 不形成 HIGH/CRITICAL | QUICK 为 `BENIGN/LOW`；SHA-256 `bf387fbf1e7d5cb31c117269bcf93eceb955f09ba77fcf1dc517015dddd83b64` | PASS |
| novel 动态回调链 | 未写入 YARA/具体确定性规则，模型独立检出 | YARA 0 命中；MODEL SUBJECT `HIGHLY_SUSPICIOUS`，可达全文与 QuerySnapshot 完整 | PASS |
| benign 无 JVM + 控制 IOC | 不形成 RULE/MODEL 风险 | Coverage `COMPLETE/NOT_APPLICABLE`；MODEL `NO_OBSERVED_FINDING` | PASS |
| 夹具清理 | 两个固定文件均为 `ABSENT` | sentinel 脚本移除后逐路径复核均为 `ABSENT` | PASS |
| 未选择类别 | 单类 QUICK 仅运行所选 Preset/工具 | 五个单类 QUICK 均完成 | PASS |
| SCAN 写操作 | 成功次数为 0 | 正式任务成功 WRITE 0，Action Receipt 0 | PASS |
| 凭据保护 | Key 不进入仓库、报告或模型上下文 | Provider 来自系统安全凭据存储；SSH 文件位于本机临时状态目录 | PASS |

## 6. 性能、报告与自动化门禁

| 项目 | 实际值 |
| --- | ---: |
| 5 个 QUICK 合计耗时 | 约 388 秒 |
| STANDARD 耗时 | 约 211 秒（含报告修复） |
| DEEP 兼容任务耗时 | 约 436 秒 |
| 模型工具调用 | QUICK 64；STANDARD 44；DEEP 10；正式模型评测 22 |
| 正式任务 ToolRun（含 Preset） | 165；失败 1；成功 WRITE 0 |
| Evidence | 3 |

不依赖 Provider 的最终门禁：

- `npm test`：30 个文件通过、8 个环境项跳过；117 项通过、34 项跳过。
- core/Renderer typecheck、生产 build、零告警 lint、`npm audit --omit=dev --audit-level=high`、`git diff --check`：PASS。
- Docker 五套 Lab：3 个测试文件、11/11 PASS。
- GUI E2E：investigation 4/4、remediation 3/3、recovery 6/6 PASS。
- GUI E2E 补充复验：四套串行 16/16 PASS，包含 Grant 生命周期 3/3。
- 真实 VM v2 smoke：4/4 PASS（含跨目标/控制端时钟漂移的 collect/SFTP/SHA-256）。
- 真实 VM journald 专项：1/1 PASS；无害 marker 追加后 generation 推进，`log_event.sourceId` 与 journald `log_source.sourceId` 一致，同一事件重复查询 identity 稳定，`contains` 跨 500 条分页后可到达 marker 与 journald auth event。
- RE2：macOS ARM64 与 Linux ARM64 匹配路径 PASS；不支持语义回退被拒。

## 7. 本轮发现与处理

| ID | 严重度 | 现象 | 当前处理 |
| --- | --- | --- | --- |
| V2-VM-001 | HIGH | Ubuntu `/etc/os-release` 是符号链接，严格 file identity 拒绝读取 | Preset 优先使用规范文件 `/usr/lib/os-release`，并增加真实 VM 回归 |
| V2-VM-002 | HIGH | DeepSeek 拒绝 `adjudicate_assessment` 顶层 `allOf` Tool Schema | 扁平化为顶层 `type: object`；所有调查工具 Schema 增加回归断言 |
| V2-VM-003 | MEDIUM | `query_facts` 过宽 Schema 导致非法 select/predicate，并可能浪费查询预算 | 限定 select/orderBy 枚举、按 view 提供默认字段、参数校验先于预算消耗并增强提示 |
| V2-VM-004 | HIGH | 并行远程调用的最坏时间预留可制造虚假 QUICK 预算缺口 | Agent 工具执行改为 sequential；账户任务由 13 轮/31 调用/1 Gap 降至 6 轮/14 调用/0 Gap |
| V2-VM-005 | MEDIUM | audit log 的 `pid/uid` 为字符串，`exec_event` Manifest 要求整数 | Helper 归一化可选整数并修正 executable 映射；Docker 与 VM 分诊复测通过 |
| V2-VM-006 | MEDIUM | 模型把风险 verdict 写入 OBSERVED_CATEGORY，或遗漏 Query namespace/错误选择元数据字段 | Prompt 与 Tool Schema 明确类别/对象裁定及 Query 规则；最终 WebShell QUICK 为 0 失败 |
| V2-VM-007 | MEDIUM | STANDARD 幻觉一个不存在的 `QUERY-*`；并把惰性夹具升为 `CONFIRMED_MALICIOUS/HIGH` | 引用被控制端 fail-close；任务完成但作为模型无效调用与校准限制记账 |
| V2-VM-008 | RESOLVED | DEEP 首轮 Provider 返回 `402 Insufficient Balance` | 更换凭据后以 SiliconFlow 同模型兼容 Profile 完成 DEEP 与冻结模型评测；旧失败保留审计 |
| V2-VM-009 | HIGH | 高推理大上下文 Provider 流式响应可持续 10–34 分钟并返回 `terminated` | 新增 `agent.providerTimeoutSeconds=600`，每轮 fail-close；兼容 Profile 关闭显式 reasoning 并缩小上下文 |
| V2-VM-010 | HIGH | read 仅按原始 length 预留，Helper 按 Observation JSON 字节结算，小文件也会超预留 | 预留覆盖最坏 6 倍字符转义 + 16 KiB 元数据；单测与真实 466/467 字节读取通过 |
| V2-VM-011 | HIGH | 目标时钟落后控制端时，刚生成 Artifact 被本地绝对时间比较误判过期 | 不再跨主机比较绝对墙钟；随机 token、存在性、size/SHA-256 与释放仍 fail-close；真实 VM 跨时钟回归通过 |
| V2-VM-012 | HIGH | sudo 调用 Helper 本身会写 journald，导致刚枚举的 `(sourceId,generation)` 在下一次 `contains` 前必然变旧并永久 `STALE_REF` | `contains` 按稳定 `sourceId` 解析逻辑源、边仍绑定原 ObjectRef，并显式返回 `SOURCE_CHANGED` gap；真实 VM join 通过 |
| V2-VM-013 | HIGH | 活跃 journal 超过 500 条后，每次 sudo 调用都会推进 generation，日志枚举与 `contains` 的第二页 Cursor 永久不可用 | 日志类 Cursor 以 `CURSOR_BEST_EFFORT` 续页并逐页携带 `SOURCE_CHANGED`；非日志 Namespace 保持严格拒绝；真实 VM 跨页 marker 可达 |

修复前及失败任务均保留在本地审计库，不作为正式通过样本。

## 8. 支持矩阵与清理状态

- [x] 本轮结果已回填 `docs/SUPPORT_MATRIX.md` 与 `docs/V2_INVARIANT_VERIFICATION.md`。
- [x] `PASS/FAIL` 边界已按真实证据记录；没有用 QUICK/STANDARD 替代 DEEP。
- [x] 两个固定夹具和专用模型评测夹具均已移除并验证 `ABSENT/STOPPED`。
- [x] novel malicious + benign 冻结清单已执行，七项阈值全部 PASS。
- [ ] 临时 VM 与本轮 SSH 状态目录暂时保留，便于复核审计；它们不在仓库中，后续可人工销毁。
