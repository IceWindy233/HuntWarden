# HuntWarden 支持矩阵

> 更新日期：2026-09-01。本文只描述当前 Tool Protocol v2 状态；历史版本能力不作为当前支持依据。`已验证`表示对应自动化或明确环境已实际通过，`待实机验收`不得解释为已支持。
>
> 当前基线：Manifest/Helper `2.1.0`。Ubuntu 24.04 ARM64 的 P1 实机结果见 [`VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md`](acceptance/VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md)，五类 × QUICK/STANDARD/DEEP 完整矩阵见 [`GUI_PROFILE_MATRIX_V2_P1_2026-09-01.md`](acceptance/GUI_PROFILE_MATRIX_V2_P1_2026-09-01.md)，模型评测见 [`MODEL_EVAL_P1_2026-08-30.md`](acceptance/MODEL_EVAL_P1_2026-08-30.md)。综合结论为 `PASS_WITH_LIMITATIONS`。

## 目标与接入

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Linux over SSH | 已验证 | 严格 `known_hosts`，host + port + key 绑定；未知 Key 必须人工确认，变化或撤销 Key 阻断。 |
| SSH 私钥文件 | 已验证 | 无交互 Ed25519 私钥；配置只保存绝对路径，不复制私钥内容。 |
| IPv6 | 代码路径可用，待实机验收 | Host Key 绑定支持 IPv6 表达，尚无真实 VM 记录。 |
| SSH Agent、加密私钥、ProxyJump | 未实现 | 当前只能使用无交互私钥文件和直连 SSH。 |
| Local / Collector / Offline / WinRM | 未实现 | 不得把 SSH 调查描述为其他接入方式。 |

## Linux 平台

| 平台 | 状态 | 当前说明 |
| --- | --- | --- |
| Ubuntu 22.04 arm64/x86_64 | Docker 已验证 | 五套隔离 Lab 使用 Ubuntu 22.04；真实 VM 尚未验收。 |
| Ubuntu 24.04 ARM64 | `PASS_WITH_LIMITATIONS` | 真实 GUI、SiliconFlow Provider、SSH、root Helper、smoke 4/4、journald 1/1、模型评测 7/7，以及五类 × 三 Profile 的 15 个正式任务已完成。152 次正式 ToolRun 无失败；首跑仍有一次空响应和两次被失败关闭的非法引用。 |
| Ubuntu 24.04 x86_64 | 待实机验收 | ARM64 结果不能外推到 x86_64。 |
| Debian 12 ARM64 | 动态容器场景已验证，待实机验收 | 当前 V2 动态场景 5/5；容器不等同于完整 systemd VM。 |
| Rocky / AlmaLinux 9 | 待实机验收 | rpm、`secure` 日志与 SELinux 能力识别已实现，尚无 SELinux Enforcing 实机记录。 |
| Amazon Linux 2023 | 待实机验收 | rpm 路径已实现，尚无自动化 VM 记录。 |

RE2 已在 macOS ARM64 与 Ubuntu 22.04 ARM64 容器验证真实匹配，以及不支持反向引用时返回 `INVALID_ARGUMENT`；见 [`RE2_MATRIX_2026-08-25.md`](acceptance/RE2_MATRIX_2026-08-25.md)。

## 检测能力

| 检测包 | 当前已验证能力 | 主要限制 |
| --- | --- | --- |
| WebShell / Web 攻击链 | Nginx/Apache 技术栈与有效 Web Root、近期脚本/模板/WAR/JAR、固定 RuleSet YARA、literal/RE2、Access Log、文件/进程关系、受控文本读取和 Evidence 隔离链 | 复杂 Apache/PHP-FPM Include、发布基线、时间戳回改和真实站点误报率尚未验证；Access Log 仍未完整从运行时配置推导。 |
| Java 内存马 | Tomcat 9/JDK 17 的 Filter/Servlet/Listener/Valve/WebSocket、Spring MVC、ClassLoader/CodeSource/ProtectionDomain 与只读 Class Dump | 自动化只覆盖 Tomcat 9/JDK 17；Tomcat 8.5/10 与 JDK 8/11/21 尚未验证。 |
| 后门账户 | UID 0、sudo/wheel、账户状态、SSH Key 指纹、sudoers/doas/polkit 委派、`sshd -T` 默认上下文与登录历史 | `sshd Match` 逐用户/来源上下文、SSSD/LDAP 与云登录日志尚未覆盖。 |
| Linux 持久化 | Cron、systemd service/timer/drop-in/generated/transient、at/anacron、SysV/rc.local、XDG、PAM、udev、modprobe、cloud-init 与包管理 Hook | initramfs 内容和 transient unit 的完整 D-Bus 运行态详情尚未实现。 |
| Linux 入侵分诊 | 稳定进程身份、进程树/FD/maps/socket、删除后运行、固定 `/usr/bin`/`/tmp` Scope、dpkg/rpm inventory、`package_db` 抽样验证、动态加载与认证/执行时间线 | Scope 与包校验均为有界抽样；wtmp/btmp、独立 sudo 日志和 journal 增量采集尚未实现。 |
| 安恒威胁情报富化 | 当前任务 V2 Socket 公网外联引用、分析师预置 IOC、批量查询、本地缓存、Evidence、审计与 GUI 情报视图 | 外部命中不能单独形成 `CONFIRMED_MALICIOUS`；数据质量仍需持续复验。 |

Helper 只接受协议 2 的 `capabilities` 与八个静态白名单只读原语。Capability 只能收紧静态 Manifest；缺失能力必须形成 Gap 并降低 Coverage，不能产生安全结论。Helper 目前需要管理员预先安装，安装与自检见 [`host-helper/README.md`](../host-helper/README.md)。

## 数据与处置边界

- Fact、Object、Cursor、Query、Evidence、Grant、Budget 与 Action Receipt 全部绑定 task、epoch 和目标身份。
- 模型只能查询 Model Fact；Private Fact、Evidence bytes、数据库路径、artifact token、spool 路径和 Provider 原始响应不进入模型上下文。
- 有界采集达到节点、字节或时间上限时返回 `PARTIAL` 与结构化 Gap；`PARTIAL/ERROR/NOT_RUN/UNKNOWN` 在 GUI 和报告中固定呈现为 `INCOMPLETE`。
- `SCAN` 不注册写工具。默认 `REMEDIATE` 只开放 `quarantine_file`，且要求完整 Evidence、一次性审批票据和目标端原子回执。
- `disable_account` 未覆盖活动会话、`authorized_keys`、SSH CA/principals 与恢复验证，因此默认关闭，不得描述为完整账户禁用。
- `restore_quarantined_file` 与 `restore_account_state` 尚未实现，真实目标应优先使用 `SCAN`。

## 真实主机准入

1. 在隔离 VM 运行 Helper 自检并核对 Manifest、Capability 和降级行为。
2. 通过带外通道人工核验 Host Key 后再写入 `known_hosts`。
3. 先运行只读 QUICK/STANDARD，复核 Coverage、Assessment 与 Evidence，再决定是否进入处置模式。
4. 只按实际执行的平台、架构、依赖与 Provider 配置更新本矩阵；环境跳过不计为通过。
