# HuntWarden 实战试用支持矩阵

> 更新日期：2026-08-30。`已验证`仅表示仓库自动化或明确环境已通过；`待实机验收`不等同于不支持，而是不应在报告中宣称已验证。当前 P1 可复现实现基线为 Tool Protocol v2 Manifest/Helper `2.1.0`、commit `88d8198de6a30a079c245552208edaca3c606890`；`0.2.0` 发布标签仍对应 Manifest `2.0.0`。
>
> 最近基线：Ubuntu 24.04.4 ARM64 已用真实 GUI、Provider、SSH 和 root Helper 完成 QUICK/STANDARD/DEEP 只读 VM 验收，并完成缺少 YARA、auditd、JDK Attach 的最低依赖降级补测，结果为 `PASS_WITH_LIMITATIONS`；详见 [`VM_UBUNTU_24.04_ARM64_2026-08-20.md`](acceptance/VM_UBUNTU_24.04_ARM64_2026-08-20.md)。Rocky Linux 9 x86_64/SELinux 及其余矩阵仍待执行，但不属于 `0.2.0` 的阻塞门槛。
>
> v2 完整 GUI/Provider 基线：[`VM_UBUNTU_24.04_ARM64_V2_2026-08-26.md`](acceptance/VM_UBUNTU_24.04_ARM64_V2_2026-08-26.md)；P1 增量实机复验：[`VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md`](acceptance/VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md)。综合结果为 `PASS_WITH_LIMITATIONS`。
>
> 已产生首个真实 Provider 发布评测结果：冻结的惰性 novel malicious 与独立 benign 场景七项门槛全部通过；详见 [`MODEL_EVAL_2026-08-26.md`](acceptance/MODEL_EVAL_2026-08-26.md)。该语料仍是自造安全夹具，不能外推为真实站点召回率或误报率。

## 目标与接入

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Linux over SSH | 已验证 | 严格 `known_hosts`，host + port + key 绑定；未知 Key 必须人工确认，变化或撤销 Key 阻断。 |
| SSH 私钥文件 | 已验证 | Ed25519 Lab Key；私钥内容不复制到配置。 |
| SSH Agent、加密私钥、ProxyJump | 未实现 | 当前真实试用必须使用无交互私钥文件和直连 SSH。 |
| Local / Collector / Offline / WinRM | 未实现 | 属于后续 Sprint，不应把 SSH 目标描述为这些接入方式。 |
| IPv6 | 代码路径可用，待实机验收 | host/key 绑定支持 IPv6 表达，尚无 VM 验收。 |

## Linux 平台

| 平台 | 状态 | 当前说明 |
| --- | --- | --- |
| Ubuntu 22.04 arm64/x86_64 | Docker 已验证 | 五套 Lab 使用 Ubuntu 22.04；真实 VM 仍需验收。 |
| Ubuntu 24.04 ARM64 | v1 已验证（有限制）；v2 PASS_WITH_LIMITATIONS | v2 在 24.04.4 / kernel 6.8 / systemd / AppArmor 上完成真实 GUI + SiliconFlow DeepSeek V4 Flash + SSH、5 QUICK、1 STANDARD、小上下文 DEEP、smoke 4/4 与 novel/benign 模型评测。最低依赖降级、完整依赖 Helper v2 自检和跨时钟 Artifact 传输均通过；原始高推理大上下文 Profile 的 Provider 长流兼容性仍有限。 |
| Ubuntu 24.04 x86_64 | 待实机验收 | ARM64 结果不能外推为 x86_64。 |
| Debian 12 ARM64 | 动态容器场景已验证，待实机验收 | 非固定 Debian 12 场景 5/5 通过，覆盖发行版识别与行为样本；不等同于标准 systemd VM。 |
| Rocky / AlmaLinux 9 | 待实机验收（非 0.2.0 阻塞） | rpm、`secure` 日志和 SELinux 能力识别已实现；当前主要使用场景以 Ubuntu 为主。 |
| Amazon Linux 2023 | 待实机验收 | rpm 路径已实现，尚无自动化 VM。 |

RE2 已在 macOS ARM64 与 Ubuntu 22.04 ARM64 容器完成真实依赖语义矩阵；匹配成功路径和禁止回退路径均通过。详见 [`RE2_MATRIX_2026-08-25.md`](acceptance/RE2_MATRIX_2026-08-25.md)。

Helper 启动时返回 v2 Capability，包含 Namespace 级别的实际 verb/field/relation 子集、Matcher/Probe 子集与主机时间信息。控制端要求 `protocolVersion === 2` 且 Manifest 精确兼容；缺失能力必须生成 Gap 并降级 Coverage，不能输出安全结论。当前尚不支持自动上传非特权临时 Helper；管理员应使用 [`host-helper/install-helper.sh`](../host-helper/install-helper.sh) 安装（要求 Python 3.8+），并用 [`host-helper/self-check-helper.sh`](../host-helper/self-check-helper.sh) 自检。

## 最近实机检测基线（v1）

> 本表是 v1 实机能力基线，不代表这些 v1 问题工具仍存在于生产工具面。五类 Docker 等价子集已经冻结在 [`tests/fixtures/v1-v2-equivalence.json`](../tests/fixtures/v1-v2-equivalence.json)，由 `v1-v2-equivalence.test.ts` 证明可通过 v2 通用原语到达；这不是尚未执行的真实 VM v2 复测。v2 确定性最低覆盖见 [`src/presets/registry.ts`](../src/presets/registry.ts)，调查面固定为八个只读原语。

> v1 残留清理（2026-08-26）：v1 的 Finding/coverage 结构化结论平面、`findings` 表与 43 个不可达的 v1 collector 已从代码库删除。v1 历史任务只保留任务元数据、Evidence 与已生成的报告文件。2026-08-29 起，v2 以通用 `delegation_rule` / `ssh_trust_config` 事实补回 sudoers/doas/polkit 与 `sshd -T` 默认上下文，不再恢复问题型 collector。

> 日志源身份复验（2026-08-27）：Ubuntu 24.04.4 ARM64 真实 VM 已验证 `enumerate log_source` 返回 `kind=journald`，无害 marker 对应 `log_event.sourceId` 等于该源，重复查询事件 identity 稳定，追加 journal 会推进 generation，`relate log_source contains` 跨 500 条分页后可到达 marker 与 journald auth event。实测同时发现并修复 sudo 调用自身推进 generation 导致的永久 `STALE_REF`/第二页 Cursor 不可用；当前以 `SOURCE_CHANGED` + `CURSOR_BEST_EFFORT` 明示活跃源漂移。该 VM 的 audit EXECVE 仅落独立 audit 源，故 journald→exec 的代码路径仍由 Docker/契约测试覆盖，不宣称本次实机产生了 journald exec event。

| 检测包 | 已验证能力 | 主要限制 |
| --- | --- | --- |
| WebShell / Web 攻击链 | Nginx/Apache 配置发现、`root/alias/DocumentRoot`、近期脚本/模板/WAR/JAR、上传临时目录、`.user.ini/.htaccess`、批量 YARA（规则由 `install-helper.sh` 下发并校验 SHA-256）、Access Log（含轮转与 `.gz` 归档、多站点子目录，返回 `scannedLogs`）、Web 进程与打开文件关联；脚本片段在超预算时返回文件头与文件尾两段 | Apache/PHP-FPM 复杂 Include、发布基线和时间戳回改仍需真实语料验收；`rules/yara/webshell.yar` 仅 5 条有效行为规则，误报率未度量。Access Log 路径仍是固定 glob，尚未从 `nginx -T` 的 `access_log` 指令推导。 |
| Java 内存马 | Tomcat 9/JDK 17 Filter/Servlet/Listener/Valve/WebSocket、Spring MVC 映射/Interceptor、ClassLoader/CodeSource、JVM/线程/Connector 诊断、Class Dump SFTP Evidence | 自动化仅验证 Tomcat 9/JDK 17；Tomcat 8.5/10 和 JDK 8/11/21 尚未列为已验证。 |
| 后门账户 | UID 0、sudo/wheel、账户状态、Key 指纹、sudoers/doas/polkit 委派语句、`sshd -T` 默认上下文有效信任配置、登录历史 | `sshd Match` 的逐用户/逐来源地址上下文、SSSD/LDAP 真实目录、云登录日志仍待扩展与 VM 验收。 |
| Linux 持久化 | Cron、systemd service/timer/drop-in/generated/transient、SSH、Shell、at/anacron、SysV/rc.local、XDG、PAM、udev、modprobe、cloud-init、包管理 Hook、user linger | initramfs 内容解析和 transient unit 的 D-Bus 运行态详情尚未实现。 |
| Linux 入侵分诊 | 稳定进程身份、进程树/FD/maps/socket、删除后运行、Preset 固定绑定 `/usr/bin` 与 `/tmp` file Scope、dpkg/rpm inventory、`package → owns_file → verify(package_db)` 抽样基线、动态加载、按主机时区解析的认证/audit 时间线；journald 与轮转日志多源去重合并 | Scope 枚举与包校验是有界抽样，达到节点上限会明确 `PARTIAL`，不能解释为全盘完整性证明；尚未采集 wtmp/btmp 与独立 sudo 日志，journal cursor 增量采集未实现。 |
| 安恒威胁情报富化 | 当前任务 v2 Socket `OBJ-*` 公网外联引用、分析师预置 IP/域名/文件哈希、批量查询、本地缓存、Evidence、审计与 GUI 情报视图；2026-08-10 使用真实 Key 完成人工在线验收 | 外部命中不能单独形成 `CONFIRMED_MALICIOUS`；情报数据质量仍需持续观察。 |

## 数据与处置边界

- Class Dump、进程可执行文件和原始 Evidence 通过短期 artifact token 与 SFTP 256 KiB 分块落盘，Helper JSON 不携带二进制 Base64。
- 认证/audit/Access Log 只读取最新 64 MiB 窗口，并受单次操作的墙钟预算约束；达到任一上限返回 `PARTIAL`。结构化输出有 1.5 MiB 预算，超出即截断并置 `PARTIAL`。YARA 对候选集合单次批量执行。
- Helper 响应先经 Manifest 校验，以 FactBatch 原子写入 Private/Model Fact Plane。模型只能通过快照化、有界的 `query_facts` 查询 Model Fact；Private Fact、Evidence bytes、数据库路径和 artifact spool 路径不在查询 schema 中。字节截断时 cursor 只能推进到实际进入模型的最后一行。
- 当前真实主机试用建议使用 `SCAN`。默认 REMEDIATE 白名单只开放 WebShell 文件隔离，并要求完整 Evidence、一次性审批票据与目标端原子回执。`disable_account` 只锁定密码认证，未覆盖活动会话及 SSH Key/CA 信任面，因而在 `0.2.0` 默认配置中关闭，不得宣称为完整账户禁用。
- Linux 分诊、Java 内存马和扩展持久化暂不提供自动清除工具。
- 威胁情报默认关闭；私网、回环、链路本地、文档网段和其他保留地址在本地过滤。Key 只从 HuntWarden 安全凭据存储或 `DBAPP_TI_API_KEY` 读取，不进入 YAML、模型上下文或 Evidence。

## 进入真实主机试用前

1. 先在隔离 VM 使用 v2 `capabilities` 与 Helper 自检确认 Manifest、Namespace 和 Probe 降级行为。
2. 人工核验 Host Key 后再写入 `known_hosts`；禁止将首次在线观察自动视为可信。
3. 先运行 `QUICK` 或 `STANDARD` 的只读任务，复核 CoverageRun 的 `PARTIAL/ERROR/NOT_RUN/UNKNOWN`（界面与报告固定呈现为 `INCOMPLETE`）与 Evidence，再决定是否启用处置模式。
4. 真实 VM 验收结果应回填本矩阵；未经验证的平台不要标记为“支持”。
