# HuntWarden 实战可用版 TODO Plan

> 文档用途：冻结 HuntWarden 从 Docker Lab MVP 演进为真实主机专项检测与受控查杀 Agent 的功能路线，作为后续开发、上下文恢复和验收的唯一长期 TODO 基线。
>
> 最近更新：2026-08-20
>
> **分工声明（2026-08-25）**：本文只负责**检测能力、语料质量与平台覆盖**的长期路线。协议形态、工具面、事实存储、结论模型与运行时架构一律以 [`docs/TOOL_PROTOCOL_V2_DESIGN.md`](TOOL_PROTOCOL_V2_DESIGN.md) 为准。两者冲突时以 v2 设计为准，本文不再作为架构承诺来源。

## 0. 当前状态

已具备：

- Sprint 1～3 的检测能力、确定性执行图、Finding/Evidence/审计/报告闭环。
- 安全边界：固定 Helper 操作集、不透明引用、三层写门控、一次性审批票据；模型拿不到 Shell 或任意路径。（v1 是 52 个按检测问题枚举的操作；v2 收敛为 8 个类型化取证动词，边界性质不变，见 v2 设计 §11。）
- 数据正确性：主机时区感知的时间线、journald 与轮转日志采集、输出字节预算、Helper 墙钟 deadline 与遍历边界。
- 工程门禁：Lint、core/renderer 双 typecheck、写操作与崩溃恢复不变量进必跑 CI、Helper 协议版本与 envelope 结构校验。
- DBAPP 威胁情报受控富化，已用真实 Key 完成人工在线验收。

尚未具备：

- 已完成首个真实 Provider 的冻结 novel malicious + benign 发布评测；但语料仍为安全自造夹具，真实 WebShell、内存马、发行版输出快照与良性站点语料不足，因此当前召回率与精确率仍不能代表真实站点。
- v2 已有五类冻结能力等价语料、Helper 集成测试和 Docker Lab；仍需扩大 namespace collector 的跨发行版 golden fixture，特别是日志、NSS/SSSD、复杂 Web 配置与多版本 JVM。
- Ubuntu 24.04 ARM64 已完成真实 GUI/Provider/SSH VM 只读验收（`PASS_WITH_LIMITATIONS`）；其余发行版、架构与受限能力组合未验收。
- 处置不可逆，且 `disable_account` 不处理密钥信任面。

工作队列按优先级冻结为：

1. **真实语料与误报基线**：真实 WebShell/内存马语料、真实 CMS 良性对照，产出可复算的召回率/精确率报告。
2. **扩展 golden fixture 与 Helper 测试**：在现有五类 v2 等价语料、集成测试和 Docker Lab 上继续固化跨发行版 collector 输出，见 v2 设计 §15.1 的 MERGE 层。
3. **真实 Linux 兼容性门禁**：Ubuntu 22.04/24.04、Debian 12、Rocky/AlmaLinux 9、Amazon Linux 2023 的只读验收与降级记录。
4. **处置补强**：`disable_account` 的会话终止与密钥信任面处置、动作后定向复扫。
5. **Sprint 5 可逆处置**：`restore_quarantined_file` / `restore_account_state` 优先于其余处置动作。
6. **真实连接补强**：SSH Agent、加密私钥、ProxyJump，以及连接/操作/空闲/任务超时拆分。
7. **Sprint 4A LocalExecutor**：先建立统一 Transport 语义，再复用现有 HostOperation 和 Helper。
8. **Sprint 4B Collector/Offline Import**：一次性只读采集、完整性清单和安全离线导入。
9. **Sprint 4C Container**：Docker/containerd 宿主机与容器关联调查。
10. **Sprint 5 处置扩展**：持久化禁用与恢复、进程暂停/终止。

## 1. 目标定义

本路线中的“生产级”专指**实战可用能力**，暂不以企业平台化为目标。

实战可用版必须满足：

- 不要求目标必须是预先准备好的 HuntWarden Lab。
- 缺少 root、YARA、Python、JDK Attach 或部分系统命令时可以降级调查。
- 能完成通用 Linux 入侵分诊，而不只覆盖四个固定样本。
- 最低调查覆盖由确定性执行图保证，不完全依赖模型临场选择工具。
- 支持 SSH 之外的本机、一次性 Collector、离线采集、容器和后续 Windows 接入。
- 检测失败、权限不足和未检查项必须明确展示，不能被描述为安全。
- 处置必须逐动作审批、状态可验证、支持恢复，并在执行后自动复查。

当前暂不作为主线：

- 企业 SSO、RBAC、集中式多租户控制台。
- SIEM/SOC 平台集成和企业级报表治理。
- 大规模批量 Hunt、多 Agent 编排和持续实时 EDR。
- 自动网络隔离、内核 Rootkit 自动清除、Java 组件在线卸载。

## 2. 当前已实现基线

- [x] WebShell：Web Root → 近期脚本 → YARA/特征 → 日志关联 → Evidence → 受控隔离。
- [x] Tomcat 内存马：Java 进程 → Tomcat 识别 → Filter/Servlet/Listener → Class 来源 → Class Dump。
- [x] 后门账户：特权账户 → 账户详情 → SSH Key 指纹 → 登录历史 → 受控禁用。
- [x] Linux 持久化：Cron/systemd/SSH Key/Shell → 进程 → 网络连接 → Evidence。
- [x] 单任务 Agent Tool Loop、Steering、逐动作审批、回执恢复和崩溃恢复。
- [x] Finding、Evidence、审计日志、版本化 Markdown 报告。
- [x] GUI/TUI 流式输出、任务归档、报告手动确认生成。
- [x] Agent 消息与报告的安全 GFM Markdown 渲染，原始工具 JSON 保持等宽文本展示。
- [x] 安恒威胁情报受控富化：公网 IP/域名/文件哈希、缓存、Evidence、审计和 GUI 情报视图。
- [x] 五套 Docker Lab 与 Faux Provider 自动化验证。

## 3. 真实主机准入的 P0 项

### 3.1 SSH 目标身份与连接

- [x] 根据 `host + port` 探测服务器提供的 Host Key。
- [x] 返回并展示解析 IP、Host Key 算法、SHA-256 指纹和原始公钥摘要。
- [x] 正确解析标准 OpenSSH `known_hosts`，不依赖 Lab 额外添加的指纹注释。
- [x] 支持 hashed `known_hosts`、非 22 端口的 `[host]:port` 和多种 Host Key 算法。
- [x] 将指纹严格绑定到 host、port 和算法，禁止全文搜索任意匹配指纹。
- [x] 未知主机只标记为 `OBSERVED_UNTRUSTED`，必须由用户确认后才能原子写入 `known_hosts`。
- [x] Host Key 发生变化时红色阻断，不允许自动覆盖旧信任。
- [x] 指纹发现过程不携带 SSH 用户凭据或私钥。
- [x] 为发现、确认、写入、匹配和不匹配产生本地审计事件。
- [ ] 支持 SSH Agent。
- [ ] 支持加密私钥及从系统安全存储读取 passphrase。
- [ ] 支持 Bastion/ProxyJump。
- [ ] 支持 IPv6、Keepalive、连接重试和连接超时。

安全不变量：自动功能只负责“发现指纹”，绝不能把第一次在线获得的指纹自动转为可信。

### 3.2 Helper 能力协商与降级

- [x] 新增 `get_capabilities` HostOperation。
- [x] 返回 Helper 版本、协议版本和支持的固定操作集合。
- [x] 返回 OS、发行版、架构、内核、boot ID、init 系统和容器环境。
- [x] 返回当前用户、有效权限、sudo、root Helper 可用性。
- [x] 返回 YARA、journal、auditd、JDK Attach、Docker/containerd 等能力。
- [x] 返回 SELinux/AppArmor、`hidepid`、文件系统和 namespace 限制。
- [x] 每个检测类别在开始前执行 preflight。
- [x] 能力状态冻结为 `SUPPORTED | PARTIAL | UNSUPPORTED | PERMISSION_DENIED`。
- [x] 所有被跳过路径或数据源记录原因和数量，禁止静默跳过。
- [x] 空数组不能单独推导为 `NO_FINDING`。
- [ ] 未预装 Helper 时允许上传并运行非特权临时 Helper。
- [ ] 需要 root 的检查明确降级为 `PARTIAL`，并提供管理员安装指引。
- [x] 提供 Debian/RPM Helper 安装、卸载和自检脚本，并下发 YARA 规则与 Tomcat 探针、校验 Python 版本下限、支持幂等升级。
- [x] 自检逐项报告 YARA、journald、auditd、JDK Attach、`/proc` 可见性与 SELinux/AppArmor 的能力状态及降级影响。

### 3.3 超时与 Evidence 传输

- [x] 修复 Security Tool 声明的 `timeoutMs` 未传递到 `HostExecutor.invoke()` 的问题。
- [ ] 分离连接超时、操作总超时、无输出空闲超时和任务总超时。
- [x] 二进制 Evidence 不再以 Base64 塞入 Helper JSON 输出。
- [x] Helper 将待采集内容写入受控临时文件并返回 artifact token、大小和 SHA-256。
- [x] SSH Transport 使用 SFTP 分块下载，边下载边计算 SHA-256。
- [ ] 支持断点续传或明确重试，临时文件有容量和生命周期上限。
- [x] 验证 10 MiB 文件和 Class Dump 不受当前 2 MiB JSON 输出限制影响。
- [x] 大日志改为流式窗口读取，禁止整文件 `read_text().splitlines()`。
- [x] YARA 改为批量扫描候选集合，禁止为每个文件重复启动一个进程。

### 3.4 检测范围冻结与 Finding 聚合

- [x] 只注册当前任务所选择类别对应的工具包。
- [x] `record_finding` 拒绝记录任务未选择的检测类别。
- [x] 每个检测包拥有独立的最低必执行图。
- [x] 覆盖状态由确定性执行图维护，不由模型自由声明。
- [x] 同类别多条 Finding 按固定严重度、置信度和完整度规则聚合。
- [x] 后续 `NO_FINDING` 不能覆盖已经存在的高风险 Finding。
- [ ] 保存扫描范围、跳过数量、截止原因和主机时间偏差。

## 4. 核心架构演进

> 本节描述的是 v1 演进方向。Transport 抽象与"确定性调查内核"两条仍然有效，但**协议与工具面的目标形态已由 v2 设计取代**，实现时以 v2 设计 §4、§11、§14、§15 为准。

### 4.1 分离平台与接入方式

SSH 是 Transport，不是主机平台。目标模型应拆分为：

- 平台：Linux、Windows、Container、Kubernetes Workload、Kubernetes Node、Offline Snapshot。
- Transport：SSH、Local、Collector、Offline Import、WinRM、Kubernetes API，云命令通道后置。

- [ ] 将当前 SSH 专用 `TargetConfig` 重构为可辨识联合类型 `TargetBinding`。
- [ ] 新增 `TargetIdentity` 和不可变目标标识。
- [ ] 新增 `TargetCapabilities` 能力快照。
- [ ] 新增 `EvidenceProvenance`，记录 Transport、目标身份、Helper/Collector 版本和采集时间。
- [ ] 新增统一 `TargetTransport`：

```ts
interface TargetTransport {
  discover(): Promise<TargetIdentity>;
  capabilities(): Promise<TargetCapabilities>;
  invoke<T extends HostOperation>(
    request: HostOperationRequest<T>,
    signal?: AbortSignal,
  ): Promise<HostOperationOutput<T>>;
  collect(ref: ArtifactReference, sink: EvidenceSink): Promise<ArtifactReceipt>;
  queryActionReceipt(actionId: string): Promise<ActionReceipt>;
  close(): Promise<void>;
}
```

必须保持：

- 模型永远看不到 Shell、PowerShell、`kubectl exec` 或任意命令文本。
- Transport 只能调用冻结的结构化 `HostOperation`。
- Task 创建后不能通过 Transport 扩大目标范围。
- 每种 Transport 对超时、断线、Abort、Evidence 和 Action Receipt 使用一致语义。

### 4.2 确定性调查内核

目标执行流程：

```text
目标身份确认
  → 能力预检
  → 检测包最低必执行图
  → 确定性规则产生候选与基础 Finding
  → Agent 基于异常事实继续深挖
  → 覆盖校验
  → 用户复核并生成报告
```

- [x] 定义 `CheckDefinition`：类别、最低执行图和版本化规则注册（适用平台/资源预算元数据继续完善）。
- [x] 新增不依赖 LLM 的 Scan Planner。
- [x] Agent 只能扩展调查，不能跳过最低执行图。
- [x] Provider 不可用时仍能完成最低调查并展示结构化结果。
- [ ] 高风险 Finding 必须可以由结构化事实和规则重新计算。
- [ ] 模型输出不能直接提升确定性规则的风险等级，必须补充 Evidence。

### 4.3 外部威胁情报富化

- [x] 首个 Provider 接入安恒威胁情报开放接口，Key 只进入系统安全存储或进程环境，不进入 YAML、模型上下文、Evidence 或报告。
- [x] 网络查询只接受任务内 `SOCK-*` 引用和分析师预置的 IP/域名 IOC；文件查询只接受任务创建时由分析师预置的哈希 IOC。
- [x] 私网、回环、链路本地、文档网段和其他保留地址在本地过滤，模型不能任意扩大查询集合。
- [x] 批量查询、Profile 级缓存、额度感知的人工 API 测试、类型化错误、Evidence、审计和 GUI“情报”页已经接通。
- [x] 外部情报命中不能单独形成 `CONFIRMED`，必须与主机侧 Evidence 结合。
- [x] 使用真实 DBAPP TI Key 完成人工在线验收（2026-08-10）；自动化测试仍使用假客户端，不消耗在线额度。
- [ ] 扩充恶意、良性和未知 IOC 的人工回归样本，并记录情报更新时间、命中差异和误报反馈。
- [ ] 增加显式 opt-in 的 CI/发布前在线冒烟任务；默认 CI 继续禁止访问真实情报接口。

## 5. Sprint 1：真实主机准入层

范围：完成第 3 节全部 P0 项及 Transport 基础抽象。

首批明确支持矩阵：

- Ubuntu 22.04 / 24.04
- Debian 12
- Rocky Linux / AlmaLinux 9
- Amazon Linux 2023
- x86_64 和 arm64

验收：

- [x] 标准和 hashed `known_hosts` 均可正确匹配。
- [x] Host Key 发现不会自动信任。
- [x] 指纹变化时 SSH 测试和任务创建均被阻止。
- [x] 无 root、无 YARA、无 auditd、Attach 禁止时产生能力状态与 `PARTIAL/ERROR`（真实发行版矩阵仍待验收）。
- [x] 10 MiB Evidence 可流式采集且哈希一致。
- [x] 大目录和大日志达到预算后返回部分结果及明确原因。
- [x] 当前五个 Docker Lab 在结构化 SSH HostOperation 下行为保持不变。

## 6. Sprint 2：通用 Linux 入侵分诊

新增第五个 CheckCategory：`linux_intrusion_triage`。

### 6.1 进程与网络

- [x] `capture_volatile_snapshot`
- [x] `list_suspicious_processes`
- [x] `inspect_process_tree`
- [x] `inspect_process_fds`
- [x] `inspect_process_memory_maps`
- [x] `collect_process_executable`
- [x] `list_process_connections` 扩展到通用进程调查。
- [x] 检测 `/proc/<pid>/exe -> (deleted)`。
- [x] 检测 memfd、匿名可执行映射和用户可写目录可执行文件。
- [x] 返回父进程、UID、CWD、root、namespace、cgroup 和可执行哈希。
- [x] 环境变量只返回变量名和风险标签，不返回 Token、密码或云凭据明文。

稳定引用：

- [x] `processRef` 绑定 `bootId + pid + startTicks + executable inode/hash`。
- [x] 新增 `fileRef` 类型并用于文件后续调用；`socketRef/timelineRef` 领域类型已预留，专用工具仍待补齐。
- [x] 进程与文件后续工具禁止直接接受 PID、路径和网络目标。

### 6.2 文件、提权与完整性

- [x] `list_recent_executables`
- [x] `list_privileged_files`
- [x] `verify_package_integrity`
- [x] `inspect_dynamic_loader`
- [x] 检查 `/tmp`、`/var/tmp`、`/dev/shm` 和用户可写目录中的近期 ELF/脚本。
- [x] 检查 SUID/SGID 和文件 Capabilities。
- [x] 支持 dpkg/rpm 软件包完整性验证。
- [x] 检测 `/etc/ld.so.preload` 和动态加载异常。

### 6.3 认证日志与时间线

- [x] `query_auth_events`
- [x] `query_exec_events`
- [x] `build_incident_timeline`
- [x] 读取 journald、`auth.log`/`secure`（含轮转与 `.gz`）、auditd 日志，多源并存时去重合并。
- [ ] 补齐 wtmp/btmp 与独立 sudo 日志来源。
- [ ] 关联 SSH 登录、sudo/su、进程、文件、持久化和网络连接。
- [x] 日志缺失、窗口截断、数据源缺失与时间预算到期均产生明确警告并置 `PARTIAL`。

### 6.4 扫描预设

- [x] 快速分诊：按 25% 预算执行核心进程与关联调查。
- [x] 标准调查：按 50% 预算开放日志与近期文件调查。
- [x] 深度调查：开放包完整性与完整时间线工具。
- [x] 用户可配置调查时间窗和资源预算（文件系统边界固定在 Helper 白名单）。
- [x] 支持输入 IOC：哈希、域名、IP、路径和进程名；自定义 YARA 规则仍待安全导入设计。

### 6.5 Lab-Linux-IR

- [x] 新建第五套 `Lab-Linux-IR`，SSH 端口 `2226`。
- [x] Cron 与 `/tmp/.update` 场景并连接本地模拟 C2。
- [x] 已删除但仍在运行的无害 ELF。
- [ ] 模拟矿工进程连接本地假矿池，并具有可疑父进程。
- [x] `/etc/ld.so.preload` 指向无害测试库。
- [x] 软件包管理文件被替换。
- [x] 新 SSH Key、成功登录、sudo 行为组成完整时间线。
- [x] 加入正常维护脚本作为阴性对照（logrotate/系统更新语料继续扩充）。

## 7. Sprint 3：现有四类专项检测加深

### 7.1 WebShell 与 Web 攻击链

- [x] `inventory_web_stacks`
- [x] `discover_effective_web_roots`
- [x] `list_recent_web_artifacts`
- [x] `list_upload_temp_artifacts`
- [x] `inspect_web_runtime_config`
- [x] `correlate_web_requests`
- [x] `find_web_related_processes`
- [x] 支持 Nginx `-T` 与固定 Apache/PHP 配置盘点；复杂 PHP-FPM Pool 生效合并继续验收。
- [x] 支持虚拟主机、`root`、`alias` 和固定/配置上传临时目录。
- [x] 检查 `.user.ini`、`.htaccess` 和 `auto_prepend_file`。
- [x] 支持 PHP、JSP、WAR/JAR、模板和无扩展名脚本。
- [x] 检查被删除但仍被 Web 进程打开的文件。
- [x] 关联上传/访问请求与稳定 Web 进程；跨进程网络外联由 processRef 网络工具继续调查。
- [ ] 支持发布清单或历史基线比较，识别时间戳回改。
- [x] 正常框架中动态分派与危险关键词作为误报语料。

### 7.2 Java/Tomcat

- [x] `classRef` 绑定 ClassLoader、模块、CodeSource 和 ProtectionDomain。
- [x] 一次 Attach 完成组件枚举和运行时诊断，减少重复 Attach。
- [ ] 支持自定义 `CATALINA_BASE/HOME` 和 mount namespace。
- [ ] 搜索展开目录及 JAR/WAR 内的 Class 来源。
- [ ] 支持 Tomcat 8.5、9、10 与 JDK 8、11、17、21。
- [x] 新增 Valve、WebSocket Endpoint、Spring Interceptor/Controller 映射。
- [x] 新增 Java/native Agent、JVM 参数、线程栈和 Tomcat Connector 诊断；OS socket 由主机工具关联。
- [x] Class Dump 通过 Artifact/SFTP 只保存为本地 Evidence，完整 Class 永不上云。
- [x] Attach/反射采集失败返回诊断原因和 `PARTIAL/ERROR`。
- [ ] 合法 APM、CGLIB、ByteBuddy、JSP 生成类作为阴性对照。

### 7.3 后门账户与认证

- [x] 解析 `/etc/sudoers`、`sudoers.d`、doas 和 polkit。**（v1 能力；v2 未迁移，相关 collector 已随 v1 残留清理删除，见 `docs/SUPPORT_MATRIX.md`）**
- [x] 使用 NSS `id/getent` 结果并标识 local/nss_directory 来源；真实 SSSD/LDAP 嵌套组待 VM 验收。
- [x] 解析 sshd `Include`、`Match` 和有效 `AuthorizedKeysFile`。
- [x] 检查 `AuthorizedKeysCommand`、SSH CA 和 authorized principals。
- [ ] 关联 journal/auditd、失败登录、sudo/su 和云登录记录。
- [x] 将 `checkAuthorizedKeys`、`checkLoginHistory` 配置真正接入执行图。

### 7.4 Linux 持久化

- [x] systemd drop-in、timer、generator、transient unit、user linger 文件面调查。
- [x] 解析 Unit、drop-in、EnvironmentFile 和 `OnCalendar`。
- [x] at/anacron、SysV init、rc.local。
- [x] XDG Autostart 和更多 Shell 启动文件。
- [x] PAM、`ld.so.preload`、udev、modprobe 和 modules-load；initramfs 内容解析仍待实现。
- [x] SSH Include/Match、AuthorizedKeysCommand、CA/Principals。
- [x] cloud-init、包管理器 Hook；容器启动入口归入 Sprint 4。
- [x] 进程关联返回稳定引用并绑定可执行文件身份，候选匹配仍保留受控命令特征作为入口信号。

## 8. Sprint 4：非 SSH 接入与容器

### 8.1 LocalExecutor

- [ ] 在 Linux 目标本机执行同一组 HostOperation。
- [ ] 本机 GUI/CLI 以普通用户运行，提权操作仍通过固定 Helper。
- [ ] 使用固定 argv 或 Unix Domain Socket，禁止 Shell。
- [ ] 断网时仍可完成确定性调查、Evidence 保存和恢复。
- [ ] 本机模式与 SSH 模式在相同样本上产生等价结构化结果。

### 8.2 一次性 Collector 与离线采集

- [ ] 将只读采集核心封装为一次性 Collector。
- [ ] Collector 接受固定 Manifest、操作白名单、有效期和资源预算。
- [ ] 输出结构化结果、原始 Evidence、SHA-256 清单和 Collector 日志。
- [ ] GUI 支持导入离线采集包。
- [ ] 导入限制文件数、总大小、路径、压缩比和 Schema，防止 Zip Slip/Zip Bomb。
- [ ] 任意文件或 Manifest 被修改时拒绝导入。
- [ ] 重复导入相同 acquisition ID 不重复产生 Evidence/Finding。
- [ ] 离线任务永久禁用处置，并明确“实时状态未知”。

### 8.3 Docker/containerd

- [ ] `list_container_runtimes`
- [ ] `list_containers`
- [ ] `inspect_container_security`
- [ ] `inspect_container_mounts`
- [ ] `list_container_processes`
- [ ] `list_container_connections`
- [ ] `list_container_layer_changes`
- [ ] `collect_container_artifact`
- [ ] 检查 privileged、hostPID、hostNetwork、hostPath 和 Docker Socket 暴露。
- [ ] 检查容器镜像可写层新增/修改的 ELF、脚本和 WebShell。
- [ ] 支持已停止容器的文件层调查。
- [ ] 将宿主机、容器、镜像 digest 和 namespace 绑定到引用。
- [ ] 首期不提供删除容器、镜像或 Volume。

### 8.4 Kubernetes（后半阶段）

- [ ] 第一版仅支持 Pod/Container 只读调查。
- [ ] 绑定 `clusterUid + namespace + podUid + containerId`。
- [ ] 固定 Collector 镜像 digest，不允许模型提交 `kubectl exec`。
- [ ] Pod 重建后旧引用失效。
- [ ] 后续单独增加 Node 调查，不与 Workload 目标混用。
- [ ] Kubernetes 处置首期保持关闭。

## 9. Sprint 5：受控查杀、恢复与复扫

### 9.0 现有两个写动作的补强

`quarantine_file` 与 `disable_account` 已具备两阶段回执、`actionId` 幂等、控制端永久拒绝 `root` 与当前 SSH 执行账户，以及恢复时的 `UNKNOWN` 状态保留。剩余缺口在补齐前不要新增处置动作。

- [ ] `disable_account` 目前只执行 `usermod --lock --expiredate 1`，不终止活动会话、不处理 `authorized_keys` 与 `AuthorizedKeysCommand`/CA 信任：密钥型后门账户仍可登录，而回执报告 `SUCCEEDED`。需扩展为“锁定 + 会话终止 + 密钥信任面处置”，或在能力不足时明确降级并拒绝报告成功。
- [ ] 两个动作执行后均无自动定向复扫，`disable_account` 亦未验证密钥面结果。复扫结论必须关联到 Action Receipt。
- [ ] `restore_quarantined_file` / `restore_account_state` 缺失导致处置不可逆，应作为 Sprint 5 的第一批实现项。

### 9.1 处置动作实现顺序

按风险顺序实施：

- [ ] `restore_quarantined_file`
- [ ] `restore_account_state`
- [ ] `disable_persistence_item`
- [ ] `restore_persistence_item`
- [ ] `suspend_process`
- [ ] `terminate_process`
- [ ] `pause_container`

共同安全条件：

- [ ] 执行前必须存在对应 Evidence。
- [ ] 工具只接受不透明引用，不接受路径、PID、Unit 名或容器 ID。
- [ ] 审批绑定当前哈希、进程启动时间、目标身份、参数摘要和 `actionId`。
- [ ] 修改前保存内容、属主、权限、状态和哈希。
- [ ] 每个动作包含影响预检、执行、验证、失败回滚和恢复说明。
- [ ] 动作成功后自动执行定向复扫，并将复扫结论关联到 Action Receipt。
- [ ] 永久拒绝 PID 1、内核线程、SSH 会话祖先进程、Helper 自身和关键系统服务。
- [ ] 进程处置先 `SIGSTOP`，再由用户决定是否 `SIGTERM`。
- [ ] `SIGKILL` 需要独立的更高风险审批，首版可以不提供。
- [ ] 每个动作最多成功一次，崩溃恢复优先查询目标端回执。

## 10. Sprint 6：Windows 主机

Windows 必须使用独立 Operation Pack，不能把 Linux 操作直接套到 WinRM。

### 10.1 接入

- [ ] Windows Local/Collector。
- [ ] WinRM/PowerShell Remoting Transport。
- [ ] 固定签名的 Windows Helper，只接受结构化操作。
- [ ] Windows 离线采集包。

### 10.2 第一批检测

- [ ] 主机、进程树、可执行文件、网络连接和签名信息。
- [ ] Windows Services。
- [ ] Scheduled Tasks。
- [ ] 注册表 Run/RunOnce 和常见启动位置。
- [ ] WMI 永久事件订阅。
- [ ] 本地管理员、异常账户与 RDP 登录。
- [ ] PowerShell Script Block、Module 和进程创建日志。
- [ ] IIS/ASP.NET WebShell。
- [ ] Defender 状态、排除项和关键安全日志。
- [ ] Windows 处置动作在只读调查稳定后单独设计。

## 11. 实战测试矩阵

Docker Lab 继续用于快速回归，但不能作为唯一实战验收。

### 11.1 真实 VM

- [x] Ubuntu 24.04 ARM64（2026-08-20，真实 GUI + DeepSeek + SSH；完整依赖和 YARA/auditd/JDK 缺失的最低依赖两种形态均完成，记录见 `docs/acceptance/VM_UBUNTU_24.04_ARM64_2026-08-20.md`）。
- [ ] Ubuntu 24.04 x86_64。
- [ ] Ubuntu 22.04 ARM64/x86_64。
- [ ] Debian 12。
- [ ] Rocky/AlmaLinux 9 + SELinux Enforcing。
- [ ] Amazon Linux 2023。
- [ ] x86_64 与 arm64。
- [ ] systemd、auditd、journald 和传统文件日志组合。
- [ ] NFS、大目录、大日志、只读文件系统和受限 sudo。
- [ ] Attach 被禁用、Python 缺失、`hidepid` 和 namespace 不匹配（Ubuntu 24.04 ARM64 的 YARA/JDK Attach 缺失已验证）。

### 11.2 对抗与异常场景

- [ ] Prompt Injection 不得扩展工具或目标范围。
- [ ] 路径穿越、符号链接替换和审批后文件变化。
- [ ] PID 重用和进程在检查期间退出。
- [ ] SSH 断线、Evidence 下载中断和 Helper 超时。
- [ ] 模型超时、Provider 不可用和预算耗尽。
- [ ] 正常运维脚本、系统更新、APM Agent、动态框架类和合法特权容器作为阴性样本。
- [x] 真实 DBAPP TI Key/API/任务富化人工在线验收；私网过滤和单独情报不得形成 `CONFIRMED` 的边界保持有效。

### 11.3 每个 Sprint 的共同 DoD

> 本节是持续性发布门禁，不因某一次测试通过而永久关闭。最近一次完整执行结果记录在 11.4；新增功能后必须重新执行。

- [ ] 每个类别明确输出 `CONFIRMED | HIGHLY_SUSPICIOUS | SUSPICIOUS | NO_FINDING | NOT_CHECKED | ERROR`。
- [ ] 采集失败、无权限和依赖缺失绝不能输出 `NO_FINDING`。
- [ ] 高置信 Finding 至少具有两个独立信号，或一个可验证的确定性信号。
- [ ] Finding 记录规则版本、采集器版本、证据引用、置信度依据和反证信息。
- [ ] 命名攻击场景 100% 产生预期证据链。
- [ ] 扩展变体召回率初始目标不低于 90%。
- [ ] 良性语料 HIGH/CRITICAL 精确率初始目标不低于 95%，稳定后提高至 98%。
- [ ] SCAN 模式远程写成功次数始终为 0。
- [ ] 没有完全匹配的一次性票据时写成功次数始终为 0。
- [ ] 同一处置动作在崩溃和重试条件下最多成功一次。
- [ ] 模型不可用时最低确定性调查仍可运行并展示结果。
- [ ] 原始二进制、Class Dump、完整 SSH Key 和凭据永不上云。
- [ ] 达到数量、时间或存储预算后停止并报告未完成范围。

### 11.4 最近一次完整验收记录

2026-08-17 的完整本地门禁为当前权威记录。执行范围：

```text
npm run build                        PASS
npm test                             PASS（25 文件通过 / 7 跳过；88 项通过 / 34 跳过）
npm run probe:build                  PASS
npm run test:docker                  PASS（10/10）
npm run test:acceptance:real-world   PASS（Debian 12 ARM64 动态场景 6/6）
npm run test:gui:investigation       PASS（4/4）
npm run test:gui:remediation         PASS（3/3）
npm run test:gui:recovery            PASS（6/6）
npm run package:gui                  PASS
npm run release:local                PASS（macOS arm64 ZIP/DMG + 打包 .app 启动冒烟）
npm run audit:prod                   PASS（运行时依赖漏洞 0）
```

该结果证明当前代码、五套 Docker Lab、三条 GUI 主流程和 macOS 未签名应用包形成一致闭环；它不替代第 11.1 节的真实 VM 兼容性验收，也不代表签名、公证或跨平台安装包已经完成。

### 11.5 验收与回归体系缺口

11.4 的 PASS 记录只证明 Lab 与 GUI 主流程闭环，不证明检测质量。11.3 的召回率与精确率目标在下列缺口补齐前不可度量。

**阳性语料不具备真实性**：三处阳性样本均被显式做成不可执行（`labs/web/fixtures/lab-webshell.php`、`acceptance/real-world/entrypoint.sh`、`acceptance/vm/install-safe-fixtures.sh` 仅含关键词字符串）；Tomcat 内存马样本是一个设置响应头的 Filter；`rules/yara/webshell.yar` 仅 5 条有效行为规则。

- [ ] 建立隔离的真实语料库（真实 WebShell 家族、真实内存马注入、混淆/加密/无文件变体），与无害 Lab 样本分离管理并明确使用边界。
- [ ] 建立良性对照基线：至少一套真实 CMS/框架代码库（如 WordPress、ThinkPHP、Spring Boot 应用）作为误报语料。
- [ ] 产出可复算的召回率/精确率报告，作为 11.3 两项数值目标的度量口径。

**部分测试面不在必跑 CI 内**：`docker-validation.yml` 仅在 `host-helper/**`、`labs/**`、`tests/docker/**` 变更时触发，三条 GUI E2E 与 VM 冒烟仍是发布前本机门禁。

- [ ] 为 `src/desktop/electron-safe-storage-cipher.ts` 增加真实后端测试；当前单测使用 `TestCipher`，真实凭据加密路径零覆盖。

**TS 与 Python 之间缺可回归的输出契约**：`tests/fixtures/` 为空目录；Helper 无 Python 单测，仅被 `tests/integration/host-helper.test.ts` 的 8 例覆盖 6 个操作。

- [ ] 为全部 52 个操作固化 golden fixture，使 Helper 输出字段漂移在 CI 即可检出。
- [ ] 增加 Helper Python 侧单测，优先覆盖日志解析、时区与年份推断、输出预算截断、deadline 到期、路径与过宽根校验、两个写动作。

**覆盖率与代码质量门禁不完整**：69 个 `src` 模块中 29 个未被任何测试直接导入，含 `src/tui/App.tsx`、`src/renderer/components/SettingsView.tsx`、`src/agent/model-health.ts` 与 host/webshell/account/persistence/java 五个工具包。

- [ ] 引入覆盖率采集与基线阈值，优先补齐五个检测工具包的行为断言。
- [ ] 清零 Lint 的 19 条既有 warning（15 条 React 19 下多余的 `import React`、2 条未用参数、2 条 optional-chain 建议），随后把 `npm run lint` 改为 error-on-warnings。

## 12. 推荐实际开工顺序

按以下顺序推进，不要同时铺开 Windows、Kubernetes 和云平台。

1. **真实语料与误报基线**
   - 真实 WebShell/内存马语料、真实 CMS 良性对照，产出可复算的召回率/精确率报告。
   - 在此之前无法回答“检测结论可不可信”，也无法度量 11.3 的两项数值目标。
2. **golden fixture 与 Helper Python 单测**
   - 固化 52 个操作的输出契约，以及时区、输出预算、deadline、遍历边界的行为。
3. **真实 Linux VM 只读验收**
   - 完成五发行版、两架构和典型权限/依赖缺失组合。
   - 将每次结果回填 `SUPPORT_MATRIX.md`，不通过的路径形成明确兼容性 TODO。
4. **处置补强**：`disable_account` 的会话终止与密钥信任面处置、动作后定向复扫。
5. **Sprint 5 可逆处置**：`restore_quarantined_file` / `restore_account_state` 优先于其余处置动作。
6. **Sprint 4A：LocalExecutor 与统一 Transport 基础**。
7. **Sprint 4B：一次性 Collector 与离线导入**。
8. **Sprint 4C：Docker/containerd 调查**。
9. 根据真实试用反馈，在 **Windows** 与 **Kubernetes 深入支持**之间选择下一条主线。

当前短板是检测质量不可度量：语料全为惰性自造样本，规则在真实站点上的召回率与误报率未知。只读试用可以开始，但报告中的 `NO_FINDING` 暂不应被当作“已排查干净”。Ubuntu 24.04 ARM64 已提升为“已验证（有限制）”；其它平台仍须完成对应真实 VM 验收。完成 9.0 与 Sprint 5 后，才进入真实主机扩展处置试用阶段。

## 13. 上下文恢复提示

后续新会话或上下文压缩后，优先读取本文件，并遵循：

1. 不把“生产级”重新解释为企业平台治理，本阶段只关注实战检测、目标接入、兼容性和查杀闭环。
2. 未勾选项是唯一的待办来源。当前首项是真实语料与误报基线，不是新功能。
3. 第 2 节的“已实现基线”指 Docker Lab 与本机门禁下成立；与 9.0、11.5 的未勾选项冲突时以后者为准。
4. “host + port 自动解析指纹”是发现功能，绝不自动信任未知 Host Key。
5. 在继续增加检测关键词前，先消除“工具成功但实际没有完整检查”的情况。Helper 输出超预算时会截断为 `partial`，报告必须如实呈现而不能当作已查完。
6. 新 Transport、新检测工具和新处置动作必须继续保持结构化操作、目标绑定、不透明引用和逐动作审批。
