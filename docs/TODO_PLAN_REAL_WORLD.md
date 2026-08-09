# HuntWarden 实战可用版 TODO Plan

> 文档用途：冻结 HuntWarden 从 Docker Lab MVP 演进为真实主机专项检测与受控查杀 Agent 的功能路线，作为后续开发、上下文恢复和验收的唯一长期 TODO 基线。
>
> 最近更新：2026-08-09
>
> 当前基线提交：`f9d8739 feat: require analyst confirmation for reports`

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
- [x] 四套 Docker Lab 与 Faux Provider 自动化验证。

## 3. 当前阻碍真实主机试用的 P0 缺口

### 3.1 SSH 目标身份与连接

- [ ] 根据 `host + port` 探测服务器提供的 Host Key。
- [ ] 返回并展示解析 IP、Host Key 算法、SHA-256 指纹和原始公钥摘要。
- [ ] 正确解析标准 OpenSSH `known_hosts`，不依赖 Lab 额外添加的指纹注释。
- [ ] 支持 hashed `known_hosts`、非 22 端口的 `[host]:port` 和多种 Host Key 算法。
- [ ] 将指纹严格绑定到 host、port 和算法，禁止全文搜索任意匹配指纹。
- [ ] 未知主机只标记为 `OBSERVED_UNTRUSTED`，必须由用户确认后才能原子写入 `known_hosts`。
- [ ] Host Key 发生变化时红色阻断，不允许自动覆盖旧信任。
- [ ] 指纹发现过程不携带 SSH 用户凭据或私钥。
- [ ] 为发现、确认、写入、匹配和不匹配产生本地审计事件。
- [ ] 支持 SSH Agent。
- [ ] 支持加密私钥及从系统安全存储读取 passphrase。
- [ ] 支持 Bastion/ProxyJump。
- [ ] 支持 IPv6、Keepalive、连接重试和连接超时。

安全不变量：自动功能只负责“发现指纹”，绝不能把第一次在线获得的指纹自动转为可信。

### 3.2 Helper 能力协商与降级

- [ ] 新增 `get_capabilities` HostOperation。
- [ ] 返回 Helper 版本、协议版本和支持的固定操作集合。
- [ ] 返回 OS、发行版、架构、内核、boot ID、init 系统和容器环境。
- [ ] 返回当前用户、有效权限、sudo、root Helper 可用性。
- [ ] 返回 YARA、journal、auditd、JDK Attach、Docker/containerd 等能力。
- [ ] 返回 SELinux/AppArmor、`hidepid`、文件系统和 namespace 限制。
- [ ] 每个检测类别在开始前执行 preflight。
- [ ] 能力状态冻结为 `SUPPORTED | PARTIAL | UNSUPPORTED | PERMISSION_DENIED`。
- [ ] 所有被跳过路径或数据源记录原因和数量，禁止静默跳过。
- [ ] 空数组不能单独推导为 `NO_FINDING`。
- [ ] 未预装 Helper 时允许上传并运行非特权临时 Helper。
- [ ] 需要 root 的检查明确降级为 `PARTIAL`，并提供管理员安装指引。
- [ ] 提供 Debian/RPM Helper 安装、升级、卸载和自检脚本。

### 3.3 超时与 Evidence 传输

- [ ] 修复 Security Tool 声明的 `timeoutMs` 未传递到 `HostExecutor.invoke()` 的问题。
- [ ] 分离连接超时、操作总超时、无输出空闲超时和任务总超时。
- [ ] 二进制 Evidence 不再以 Base64 塞入 Helper JSON 输出。
- [ ] Helper 将待采集内容写入受控临时文件并返回 artifact token、大小和 SHA-256。
- [ ] SSH Transport 使用 SFTP 分块下载，边下载边计算 SHA-256。
- [ ] 支持断点续传或明确重试，临时文件有容量和生命周期上限。
- [ ] 验证 10 MiB 文件和 Class Dump 不受当前 2 MiB JSON 输出限制影响。
- [ ] 大日志改为流式窗口读取，禁止整文件 `read_text().splitlines()`。
- [ ] YARA 改为批量扫描候选集合，禁止为每个文件重复启动一个进程。

### 3.4 检测范围冻结与 Finding 聚合

- [ ] 只注册当前任务所选择类别对应的工具包。
- [ ] `record_finding` 拒绝记录任务未选择的检测类别。
- [ ] 每个检测包拥有独立的最低必执行图。
- [ ] 覆盖状态由确定性执行图维护，不由模型自由声明。
- [ ] 同类别多条 Finding 按固定严重度、置信度和完整度规则聚合。
- [ ] 后续 `NO_FINDING` 不能覆盖已经存在的高风险 Finding。
- [ ] 保存扫描范围、跳过数量、截止原因和主机时间偏差。

## 4. 核心架构演进

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

- [ ] 定义 `CheckDefinition`：类别、适用平台、能力前置、最低执行图、资源预算和规则版本。
- [ ] 新增不依赖 LLM 的 Scan Planner。
- [ ] Agent 只能扩展调查，不能跳过最低执行图。
- [ ] Provider 不可用时仍能完成最低调查并展示结构化结果。
- [ ] 高风险 Finding 必须可以由结构化事实和规则重新计算。
- [ ] 模型输出不能直接提升确定性规则的风险等级，必须补充 Evidence。

## 5. Sprint 1：真实主机准入层

范围：完成第 3 节全部 P0 项及 Transport 基础抽象。

首批明确支持矩阵：

- Ubuntu 22.04 / 24.04
- Debian 12
- Rocky Linux / AlmaLinux 9
- Amazon Linux 2023
- x86_64 和 arm64

验收：

- [ ] 标准和 hashed `known_hosts` 均可正确匹配。
- [ ] Host Key 发现不会自动信任。
- [ ] 指纹变化时 SSH 测试和任务创建均被阻止。
- [ ] 无 root、无 YARA、无 auditd、Attach 禁止时产生准确 `PARTIAL/ERROR`。
- [ ] 10 MiB Evidence 可流式采集且哈希一致。
- [ ] 大目录和大日志达到预算后返回部分结果及明确原因。
- [ ] 当前四个 Docker Lab 在新 Transport 接口下行为保持不变。

## 6. Sprint 2：通用 Linux 入侵分诊

新增第五个 CheckCategory：`linux_intrusion_triage`。

### 6.1 进程与网络

- [ ] `capture_volatile_snapshot`
- [ ] `list_suspicious_processes`
- [ ] `inspect_process_tree`
- [ ] `inspect_process_fds`
- [ ] `inspect_process_memory_maps`
- [ ] `collect_process_executable`
- [ ] `list_process_connections` 扩展到通用进程调查。
- [ ] 检测 `/proc/<pid>/exe -> (deleted)`。
- [ ] 检测 memfd、匿名可执行映射和用户可写目录可执行文件。
- [ ] 返回父进程、UID、CWD、root、namespace、cgroup 和可执行哈希。
- [ ] 环境变量只返回变量名和风险标签，不返回 Token、密码或云凭据明文。

稳定引用：

- [ ] `processRef` 绑定 `bootId + pid + startTicks + executable inode/hash`。
- [ ] 新增 `fileRef`、`socketRef` 和 `timelineRef`。
- [ ] 后续工具禁止直接接受 PID、路径和网络目标。

### 6.2 文件、提权与完整性

- [ ] `list_recent_executables`
- [ ] `list_privileged_files`
- [ ] `verify_package_integrity`
- [ ] `inspect_dynamic_loader`
- [ ] 检查 `/tmp`、`/var/tmp`、`/dev/shm` 和用户可写目录中的近期 ELF/脚本。
- [ ] 检查 SUID/SGID 和文件 Capabilities。
- [ ] 支持 dpkg/rpm 软件包完整性验证。
- [ ] 检测 `/etc/ld.so.preload` 和动态加载异常。

### 6.3 认证日志与时间线

- [ ] `query_auth_events`
- [ ] `query_exec_events`
- [ ] `build_incident_timeline`
- [ ] 读取 journald、`auth.log`/`secure`、auditd、wtmp/btmp 和 sudo 日志。
- [ ] 关联 SSH 登录、sudo/su、进程、文件、持久化和网络连接。
- [ ] 日志缺失、轮转、截断和时间跳变产生明确警告。

### 6.4 扫描预设

- [ ] 快速分诊：进程、网络、账户和核心持久化，参考目标 5 分钟。
- [ ] 标准调查：完整日志关联和近期文件检查，参考目标 20 分钟。
- [ ] 深度调查：包完整性、扩大目录、Class Dump 和完整时间线。
- [ ] 用户可配置调查时间窗、文件系统边界和资源预算。
- [ ] 支持输入 IOC：哈希、域名、IP、路径、进程名和自定义 YARA 规则。

### 6.5 Lab-Linux-IR

- [ ] 新建第五套 `Lab-Linux-IR`，建议 SSH 端口 `2226`。
- [ ] Cron 启动 `/tmp/.update` 并连接本地模拟 C2。
- [ ] 已删除但仍在运行的无害 ELF。
- [ ] 模拟矿工进程连接本地假矿池，并具有可疑父进程。
- [ ] `/etc/ld.so.preload` 指向无害测试库。
- [ ] 软件包管理文件被替换。
- [ ] 新 SSH Key、成功登录、sudo 行为组成完整时间线。
- [ ] 加入正常 logrotate、系统更新和合法运维脚本作为阴性对照。

## 7. Sprint 3：现有四类专项检测加深

### 7.1 WebShell 与 Web 攻击链

- [ ] `inventory_web_stacks`
- [ ] `discover_effective_web_roots`
- [ ] `list_recent_web_artifacts`
- [ ] `list_upload_temp_artifacts`
- [ ] `inspect_web_runtime_config`
- [ ] `correlate_web_requests`
- [ ] `find_web_related_processes`
- [ ] 支持 Nginx、Apache、PHP-FPM 实际生效配置。
- [ ] 支持虚拟主机、`root`、`alias`、自定义上传目录。
- [ ] 检查 `.user.ini`、`.htaccess` 和 `auto_prepend_file`。
- [ ] 支持 PHP、JSP、WAR/JAR、模板和无扩展名脚本。
- [ ] 检查被删除但仍被 Web 进程打开的文件。
- [ ] 关联上传请求、首次访问、Web 进程和网络外联。
- [ ] 支持发布清单或历史基线比较，识别时间戳回改。
- [ ] 正常框架中 `eval`、编码和动态加载作为误报语料。

### 7.2 Java/Tomcat

- [ ] `classRef` 绑定 ClassLoader、模块、CodeSource 和 ProtectionDomain。
- [ ] 一次 Attach 完成组件枚举，减少重复 Attach。
- [ ] 支持自定义 `CATALINA_BASE/HOME` 和 mount namespace。
- [ ] 搜索展开目录及 JAR/WAR 内的 Class 来源。
- [ ] 支持 Tomcat 8.5、9、10 与 JDK 8、11、17、21。
- [ ] 新增 Valve、WebSocket Endpoint、Spring Interceptor/Controller 映射。
- [ ] 新增 Java Agent、JVM 参数、线程栈和网络关联。
- [ ] Class Dump 后只在本地分析字节码，完整 Class 永不上云。
- [ ] Attach 失败返回诊断原因和 `PARTIAL/ERROR`。
- [ ] 合法 APM、CGLIB、ByteBuddy、JSP 生成类作为阴性对照。

### 7.3 后门账户与认证

- [ ] 解析 `/etc/sudoers`、`sudoers.d`、doas 和 polkit。
- [ ] 支持嵌套组及 NSS/SSSD/LDAP 账户来源标识。
- [ ] 解析有效 sshd `Include`、`Match` 和 `AuthorizedKeysFile`。
- [ ] 检查 `AuthorizedKeysCommand`、SSH CA 和 authorized principals。
- [ ] 关联 journal/auditd、失败登录、sudo/su 和云登录记录。
- [ ] 将 `checkAuthorizedKeys`、`checkLoginHistory` 配置真正接入执行图。

### 7.4 Linux 持久化

- [ ] systemd drop-in、timer、generator、transient unit、user linger。
- [ ] 解析有效 Unit 配置、EnvironmentFile 和 `OnCalendar`。
- [ ] at/anacron、SysV init、rc.local。
- [ ] XDG Autostart 和更多 Shell 启动文件。
- [ ] PAM、`ld.so.preload`、udev、modprobe、内核模块和 initramfs。
- [ ] SSH Include/Match、AuthorizedKeysCommand、CA/Principals。
- [ ] cloud-init、包管理器 Hook 和容器启动入口。
- [ ] 进程关联从命令行子串升级为稳定引用和可执行文件身份关联。

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

- [ ] Ubuntu 22.04/24.04。
- [ ] Debian 12。
- [ ] Rocky/AlmaLinux 9 + SELinux Enforcing。
- [ ] Amazon Linux 2023。
- [ ] x86_64 与 arm64。
- [ ] systemd、auditd、journald 和传统文件日志组合。
- [ ] NFS、大目录、大日志、只读文件系统和受限 sudo。
- [ ] Attach 被禁用、YARA 缺失、Python 缺失、`hidepid` 和 namespace 不匹配。

### 11.2 对抗与异常场景

- [ ] Prompt Injection 不得扩展工具或目标范围。
- [ ] 路径穿越、符号链接替换和审批后文件变化。
- [ ] PID 重用和进程在检查期间退出。
- [ ] SSH 断线、Evidence 下载中断和 Helper 超时。
- [ ] 模型超时、Provider 不可用和预算耗尽。
- [ ] 正常运维脚本、系统更新、APM Agent、动态框架类和合法特权容器作为阴性样本。

### 11.3 每个 Sprint 的共同 DoD

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

## 12. 推荐实际开工顺序

当前不要同时铺开 Windows、Kubernetes 和云平台。建议严格按以下顺序推进：

1. **Sprint 1：真实主机准入层**
   - Host Key 自动发现与人工信任。
   - Helper 能力协商和非 root 降级。
   - 修复超时和 Evidence 流式传输。
   - 建立首批真实 Linux 支持矩阵。
2. **Sprint 2：通用 Linux 入侵分诊**
   - 进程、网络、文件、权限、认证日志和事件时间线。
3. **Sprint 3：确定性调查内核与四专项加深**
   - 最低必执行图、规则 Finding、Web/Java/账户/持久化扩展。
4. **Sprint 4：LocalExecutor、离线 Collector 和容器调查**。
5. **Sprint 5：可恢复处置和动作后复扫**。
6. 根据真实试用反馈，在 **Windows** 与 **Kubernetes 深入支持**之间选择下一条主线。

完成 Sprint 1～3 后，HuntWarden 才进入少量真实 Linux 主机只读试用阶段。完成 Sprint 5 后，才进入真实主机受控处置试用阶段。

## 13. 上下文恢复提示

后续新会话或上下文压缩后，优先读取本文件，并遵循：

1. 不把“生产级”重新解释为企业平台治理，本阶段只关注实战检测、目标接入、兼容性和查杀闭环。
2. 当前下一项工作是 **Sprint 1：真实主机准入层**。
3. “host + port 自动解析指纹”是发现功能，绝不自动信任未知 Host Key。
4. 在继续增加检测关键词前，先消除“工具成功但实际没有完整检查”的情况。
5. 新 Transport、新检测工具和新处置动作必须继续保持结构化操作、目标绑定、不透明引用和逐动作审批。

