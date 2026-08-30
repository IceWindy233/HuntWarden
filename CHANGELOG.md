# Changelog

本文件记录 HuntWarden 的重要用户可见变化，格式参考 Keep a Changelog，版本遵循语义化版本。

## [Unreleased]

### Added

- Tool Protocol v2 Manifest/Helper 升级为 `2.1.0`，新增通用 `delegation_rule` 与 `ssh_trust_config` Namespace；后门账户 Preset 现在采集 sudoers/doas/polkit 策略语句和 `sshd -T` 默认上下文有效信任配置。
- Linux 分诊 Preset 通过固定策略绑定 `/usr/bin`、`/tmp` file Scope，并执行 `package → owns_file → verify(package_db)` 有界基线链路；新增软件包不一致确定性规则。
- 新增 Ubuntu 24.04 ARM64 P1 增量实机验收记录；Helper `2.1.0` smoke 4/4 与 journald 回归 1/1 通过，限制与环境准备过程完整留档。
- 新增 Manifest `2.1.0` 真实 Provider P1 发布评测：重新冻结 novel malicious + benign 已完成任务，七项门槛全部通过；模型评测脚本新增可独立安装、loopback-only 的 effective-root 专项夹具。

### Changed

- WebShell Preset 恢复请求 `web_root.effective`；只有运行时有效配置来源能完成该字段，静态或兜底 root 继续以 `FIELD_UNAVAILABLE` 明示不确定性。
- 初始 Scope 的 `scope_resolve` 远程调用纳入 PRESET 持久预算，固定策略只存在于 `INITIAL_GRANT_POLICY`。

## [0.2.0] - 2026-08-29

### Changed

- 默认 REMEDIATE 白名单只开放 `quarantine_file`；`disable_account` 在补齐活动会话、SSH Key/CA 信任面与恢复验证前保持显式禁用，避免把仅锁定密码认证误报为“账户已禁用”。
- 生产调查链路切换到 Tool Protocol v2：新任务只创建 v2 Epoch，模型远程能力收敛为八个类型化取证原语，结果原子写入 Fact Store 后再通过本地 `query_facts` 暴露。
- 五类检测迁移为版本化 Preset、CoverageRun 与不可覆盖的 RULE/MODEL/HUMAN Assessment；GUI、TUI、报告、审批、处置与崩溃恢复统一读取 v2 投影。
- Helper 只接受 v2 静态动词白名单；控制端 v1 operation map、旧问题型工具、ScanPlanner 和旧规则运行时已删除，v1 历史任务仅可只读查看。
- Docker 五类 Lab、Linux IR、四套 GUI E2E、Debian 12 动态场景和 VM smoke 均已迁移到 v2；逐条安全不变量归属见 `docs/V2_INVARIANT_VERIFICATION.md`。

### Removed

- **破坏性变更：删除 v1 结构化结论平面。** `findings` 表、`Finding`/`FindingStatus` 类型、`TaskContext.coverage`、`putFinding`/`listFindings`/覆盖聚合、`finding_recorded` 事件与 GUI/TUI/报告的 v1 回退分支全部移除。v0.1.x 创建的历史任务在新版本中只保留任务元数据、Evidence 与已生成的报告文件，原 Finding 不再展示（数据库行不会被删除，只是不再读取）。
- 删除 Helper 中 43 个运行时不可达的 v1 collector（约 1263 行）与随之孤立的常量；`install-helper.sh` 不再引用已删除的 `yara_scan_files`。由此明确的能力缺口（sudoers/doas/polkit 委派配置与 sshd 有效信任配置在 v2 尚未采集）已记入 `docs/SUPPORT_MATRIX.md`。
- 删除只断言死代码源文本的 `helper-optional-paths.test.ts`；`collect`/目录穿越/枚举上限/进程环境四类边界测试改用 v2 verb 断言。

### Added

- 新增 `log_event`、版本化日志游标及系统日志凭据脱敏，并补齐进程、Socket、文件、账户、SSH Key、持久化、日志、Web、Package 和 Java Probe 关系边。
- 新增控制端版本化 `known_hash_set` Dataset Registry：GUI 可导入严格 JSON，目标 Helper 仅重观测文件哈希，哈希集合不离开控制端。
- 新增五类 `v1→v2` 冻结能力等价语料与 Docker 门禁，证明旧版能力子集可由 v2 通用 Namespace、Relation、Matcher、Verify 与 Probe 到达。
- 新增 macOS ARM64 + Ubuntu 22.04 ARM64 RE2 语义矩阵，验证实际匹配及不支持语法必须返回 `INVALID_ARGUMENT`，禁止回退 Python `re`。
- 新增真实模型能力统计评测入口与严格标签清单，基于 QuerySnapshot provenance 统计事实可达率、截断、模型结论、Preset 覆盖、新颖召回、良性误报、无效工具调用及 Token/延迟/远程成本。
- 新增 Ubuntu 24.04.4 ARM64 的 v2 真实 VM 只读验收记录与首个真实 Provider 模型能力统计结果（冻结 novel malicious + benign 清单，七项门槛全部通过）：见 `docs/acceptance/VM_UBUNTU_24.04_ARM64_V2_2026-08-26.md` 与 `docs/acceptance/MODEL_EVAL_2026-08-26.md`。
- 新增配置键 `agent.providerTimeoutSeconds`（默认 600 秒）：单轮 Provider 流式请求硬超时，覆盖首 token 与流中停滞，旧 Profile 迁移时自动注入。
- 新增 GUI Sensitive-read Grant 生命周期 E2E（`tests/e2e/gui-grant.test.ts`，门控 `HUNTWARDEN_GUI_GRANT_TESTS`）：批准后 Grant 绑定申请对象并 ACTIVE、拒绝后落 `InvestigationGap(GRANT_DENIED)` 且无 Grant、撤销后立即失效且理由进审计。INV-16/INV-17 的 GUI 层覆盖由此补齐。

### Fixed

- `query_facts` 与 `get_assessment_projection` 在 INVESTIGATE/REPORT 阶段均可用；SCAN 工具表不包含写工具。
- Query 字节预算二分试算不再落模型未见过的孤儿 QuerySnapshot/Cursor；默认排序下推 SQLite 并使用 keyset，自定义排序固化剩余事实顺序，分页不跳行。
- Helper 错误码收敛为 Wire 闭集，Predicate 在投影前严格校验字段和类型，Reservation、Cursor、FactBatch 与 Target/Epoch 绑定均 fail-close。
- RE2 编译和目标对象读取错误不再被吞成“零命中”；Probe 专属 Namespace/Relation 只在目标 Probe 实际可用时声明。
- 日志、Evidence、SECRET/SENSITIVE 字段和 Dataset 内容遵循双平面暴露策略，artifact token、storage path、凭据与 Provider 原始响应不进入模型。
- Helper 输出超预算改发 `OUTPUT_LIMIT_EXCEEDED`，探针执行失败改发 `PROBE_FAILED`，不再被折叠成“环境不支持”；控制端按错误码给出可执行类别（预算类提示收窄请求）。
- `enumerate`/`relate` 在分页期间源变化时保留已产出的一页并返回 `PARTIAL` + `SOURCE_CHANGED` gap + 可续游标，只有零结果时才整体失败；远程分页新增隐式稳定身份排序键，游标同时绑定 `epochId`。
- `match` 的 `includeContext` 已真正实现（此前先是静默忽略、后改为显式拒绝）：命中处返回固定数量的有界脱敏窗口，每个窗口以**字节偏移**标注可直接交给 `read` 复读，窗口内换行转义因此单个窗口不会被拆行；它复用 `read` 的内容分级与 Sensitive-read 授权链路，`DENIED_TEXT` 拒绝、批次内任一对象缺授权即整体失败，并计入内容出境预算。1 MiB 扫描窗口仍写成 `BYTE_LIMIT` gap，未命中不再被当成整文件真阴性。
- `match includeContext` 对非法 UTF-8 的窗口偏移改为映射原始字节，不再因 U+FFFD 重编码导致后续 offset 漂移；Helper 直连请求遇到 `DENIED_TEXT` 也会整体返回 `PERMISSION_DENIED`。
- 采集器未取到的字段不再填 `unknown` / `NOT_VERIFIED` / `effective=true` 等占位值，而是缺省并由 `unavailableFields` 与 `FIELD_UNAVAILABLE` gap 表达；`web_root.effective` 仅在来自运行时生效配置（`nginx -T`）时为真。
- Preset 已删除 Helper 不产出的 `web_stack.version`、`web_root.effective`、`jvm.version` 与 `package.integrity` 必选字段；`module.sha256` 也不再被能力清单宣称，不会把固定能力缺口伪装成每次调查的动态 PARTIAL。
- GUI 覆盖区显式渲染 `INCOMPLETE：…` 与 `MODEL: NOT_CONCLUDED：…`，不再只写在悬浮 title 里。
- 自定义 Provider 配置：Provider ID 与 API Key 环境变量名在输入期即按 Schema 字符集收敛（凭据按 Provider ID 存取，大小写不合法会先存下一个永远校验不过的 Provider）；配置校验通道改为返回结构化 issues 并只报告 `model.source` 选定分支的真实原因，不再抛出混杂 anyOf 分支的 IPC 异常。
- 修复日志事件与日志源之间的身份断链。`log_event`/`auth_event`/`exec_event` 的 `sourceId` 现在与 `log_source` 共用同一派生函数：此前 `auth_event`/`exec_event` 用硬编码的 `"auth"`/`"exec"` 字符串，事件无法与任何日志源关联；文件源两端一个用 resolve 后路径、一个用 glob 原始路径，符号链接日志目录会把同一文件拆成两个源。
- 修复事件游标不稳定。`auth_event`/`exec_event` 的 `cursor` 此前是页内数组下标，同一事件在不同时间窗口会得到不同 ObjectRef；现在由事件内容派生。
- journald 现在作为一等 `log_source` 对象出现（`kind: "journald"`，路径指向 journal 存储目录）。此前它是 `log_event`/`auth_event`/`exec_event` 的主要来源之一却不在源清单里，journald 事件因此无法通过 `relate log_source contains` 到达。generation 现在摘要 journal 文件的 inode、mtime 与 size，而不是只看父目录 mtime，追加已有 journal 文件也会如实触发 `SOURCE_CHANGED`。
- 日志事件游标与记录去重键改为绑定完整原始消息，不再只摘要前 512 字节，也不再用脱敏后的文本派生身份；共享前缀或不同凭据值的两条事件不会被错误合并。
- Helper 运行时会复核内置 YARA RuleSet 的固定 SHA-256，摘要不符时不声明/不执行该 matcher；控制端 Registry 同步记录摘要并由契约测试锁定实际规则文件。
- `relate log_source contains` 现在按源的 `kind` 覆盖它真正产生的事件类型（journald → log/auth/exec，auth → auth/log，audit → exec，system → log）。此前只查 `log_event`，认证与执行事件通过关系永远不可达；`web_access` 类源返回明确的 `CAPABILITY_UNAVAILABLE` gap 而不是空集。
- `relate log_source contains` 在 journald 因 Helper 的 sudo 调用自身产生日志、导致 generation 在两次请求间推进时，改为按稳定 `sourceId` 解析逻辑源并返回 `SOURCE_CHANGED` gap，关系边仍绑定调用方原引用；此前真实 systemd 主机上该关系会永久 `STALE_REF`。
- 活跃日志类 Namespace 的远程 Cursor 在两页之间发生 generation 漂移时允许以 `CURSOR_BEST_EFFORT` 继续，并在每页显式携带 `SOURCE_CHANGED` gap；非日志 Namespace 仍严格拒绝旧 Cursor。此前通过 sudo 调用 Helper 会自行写 journal，超过 500 条的 `log_event`/`contains` 永远无法翻到第二页。
- `log_source.firstEventAt`/`lastEventAt` 改为由 Helper 声明为不可用。它们在 Manifest 中可枚举但采集器从不产出，模型请求后只会拿到 PARTIAL + `FIELD_UNAVAILABLE`；现在能力集里不再宣称，请求直接得到 `INVALID_ARGUMENT`。
- `labs/lab-up.sh` 现在等待 Lab-Linux-IR 的可疑客户端与假 C2 建立 `ESTABLISHED` 连接才宣告就绪。此前检查只匹配端口号，会把假 C2 的 `LISTEN` socket 误当成客户端已连入，`relate process connects` 仍会偶发看不到 46666 连接。

### Planned

- Rocky Linux 9 x86_64/SELinux 兼容性验收、复杂 Web 配置路径推导及扩展平台矩阵。

## [0.1.1] - 2026-08-21

### Fixed

- 调查任务侧栏与任务详情内容区增加稳定滚动槽和可见滚动条，并约束侧栏 Grid/Flex 高度；修复任务较多时列表撑出窗口、无法形成滚动区域的问题。
- 发布脚本只收集当前版本的 ZIP/DMG，并在生成校验和前清理目标目录中的旧分发包；避免 `out/make` 历史产物混入新版本 Release。

## [0.1.0] - 2026-08-20

### Fixed

- 认证事件与时间线改为按目标主机时区解析 syslog 时间戳并推断年份，跨源事件按绝对时刻排序；此前非 UTC 主机的时间线整体偏移，跨年日志被丢弃。
- WebShell YARA 规则与 Tomcat 探针由 `install-helper.sh` 下发到目标端并复核 SHA-256，规则路径改由配置提供；此前规则只存在于 Docker Lab，真实主机上 YARA 扫描必然失败。
- 认证与执行事件新增 journald 采集，并覆盖 `auth.log`/`secure` 的轮转与 `.gz` 归档，多源并存时去重合并；此前 journald 主导的发行版返回空结果。
- Helper 新增输出字节预算与墙钟 deadline：超预算截断并置 `PARTIAL`，到期返回已采集部分；目录遍历统一施加深度、访问数与文件系统边界限制，递归搜索拒绝 `/` 与伪文件系统根。
- `list_process_connections` 合并为唯一强校验实现，工具装配增加名称唯一性不变量；此前默认全选五类检测会注册重名工具。
- `quarantine_file` 改为两阶段回执，同一 `actionId` 幂等；`disable_account` 在控制端永久拒绝 `root` 与当前 SSH 执行账户。
- 崩溃恢复在远端回执为 `STARTED`/`UNKNOWN` 时保留不确定性，不再无条件把任务归档为 `COMPLETED`。
- Helper 的静默 `OSError` 跳过改为累积告警并置 `PARTIAL`，聚合类操作改为逐子采集器隔离降级。
- Helper Artifact 状态根目录改为不可列举但可穿越的 `root:root 0711`，`actions/` 与 `quarantine/` 继续保持 `0700`；修复真实 SSH 用户无法通过 SFTP 下载已授权 Evidence 的问题。
- 权限委派检查区分“可选 doas/旧式 Polkit 配置不存在”与真实权限/I/O 失败；缺失未启用的设施不再把后门账户覆盖错误降级为 `ERROR`。
- Electron Forge 明确排除本地 `release/`，发布脚本同时检查 `app.asar`；修复重复构建时旧 ZIP/DMG 被递归打入应用、导致安装包持续膨胀的问题。

### Added

- 控制端校验 Helper 协议版本与 envelope 结构，不兼容即拒绝任务。
- 写操作与崩溃恢复不变量进入必跑 CI；新增 Lint 门禁与 core/renderer 双 typecheck 门禁。
- `self-check-helper.sh` 逐项报告 YARA、journald、auditd、JDK Attach、`/proc` 可见性与 SELinux/AppArmor 的能力状态及降级影响。
- `install-helper.sh` 校验 Python 3.8 下限并支持幂等升级，保留 Action Receipt。
- Ubuntu 24.04.4 ARM64 完成真实 Electron GUI、DeepSeek Provider、严格 SSH Host Key 与 root Helper 只读验收：5 个 QUICK、1 个 STANDARD、1 个 DEEP 均完成，正式报告引用校验通过；平台状态为 `PASS_WITH_LIMITATIONS`。
- Ubuntu 24.04.4 ARM64 完成最低依赖降级补测：缺少 YARA、auditd 与 JDK Attach 时分别保留 `NOT_CHECKED`、`PARTIAL/ERROR`，未把覆盖缺口误报为安全。
- WebShell、Tomcat 9/JDK 17 内存马、Linux 后门账户、Linux 持久化和 Linux 入侵分诊五类检测包。
- Electron GUI 与 Ink TUI，支持 Agent 流式输出、安全 GFM Markdown、Steering、任务归档和历史查看。
- 确定性最低扫描图、受控 Agent 工具循环、Finding、Evidence、审计与手动版本化 Markdown 报告。
- 严格 SSH Host Key 信任流程、白名单 Helper、不透明引用和 SFTP 分块 Evidence 采集。
- WebShell 隔离与账户禁用的逐动作审批、一次性授权、远端回执和崩溃恢复。
- 安恒威胁情报受控 IOC 富化及来源归因。
- 五套隔离 Docker Lab、动态 Debian 场景、Electron GUI E2E 与授权真实 VM 只读冒烟入口。

### Security

- `SCAN` 模式不暴露写工具，模型不能调用任意 Shell、自由路径、PID、目标地址或任意 IOC。
- 重启前未消费授权全部过期；远端写动作恢复时优先核对 Action Receipt，禁止盲目重放。
- `PARTIAL`、`ERROR` 与 `NOT_CHECKED` 不会被报告为安全，Prompt Injection 不得扩展工具范围。

[Unreleased]: https://github.com/IceWindy233/HuntWarden/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/IceWindy233/HuntWarden/releases/tag/v0.2.0
[0.1.1]: https://github.com/IceWindy233/HuntWarden/releases/tag/v0.1.1
[0.1.0]: https://github.com/IceWindy233/HuntWarden/releases/tag/v0.1.0
