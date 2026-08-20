# HuntWarden 实战试用支持矩阵

> 更新日期：2026-08-20。`已验证`仅表示仓库自动化或明确环境已通过；`待实机验收`不等同于不支持，而是不应在报告中宣称已验证。
>
> 最近基线：Ubuntu 24.04.4 ARM64 已用真实 GUI、Provider、SSH 和 root Helper 完成 QUICK/STANDARD/DEEP 只读 VM 验收，结果为 `PASS_WITH_LIMITATIONS`；详见 [`VM_UBUNTU_24.04_ARM64_2026-08-20.md`](acceptance/VM_UBUNTU_24.04_ARM64_2026-08-20.md)。Rocky Linux 9 x86_64/SELinux 及其余矩阵仍待执行。
>
> 检测质量尚未度量：验收语料全为惰性自造样本，规则在真实站点上的召回率与误报率未知。本矩阵的“已验证”只覆盖能力存在与降级行为，不代表检出效果。

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
| Ubuntu 24.04 ARM64 | 已验证（有限制） | 24.04.4 / kernel 6.8 / systemd / AppArmor；真实 GUI + DeepSeek + SSH，5 QUICK + 1 STANDARD + 1 DEEP 完成。无运行 Tomcat/JVM，Java 为 `NOT_CHECKED`；预算和确定性规则会保留部分发行版基线 `PARTIAL/SUSPICIOUS`。 |
| Ubuntu 24.04 x86_64 | 待实机验收 | ARM64 结果不能外推为 x86_64。 |
| Debian 12 ARM64 | 动态容器场景已验证，待实机验收 | 非固定 Debian 12 场景 6/6 通过，覆盖发行版识别与行为样本；不等同于标准 systemd VM。 |
| Rocky / AlmaLinux 9 | 待实机验收 | rpm、`secure` 日志和 SELinux 能力识别已实现。 |
| Amazon Linux 2023 | 待实机验收 | rpm 路径已实现，尚无自动化 VM。 |

Helper 启动时返回 `SUPPORTED | PARTIAL | UNSUPPORTED | PERMISSION_DENIED` 能力状态，并上报主机时区与 UTC 偏差。root Helper 是完整调查的推荐方式；缺少 YARA、auditd、journald、JDK Attach、systemd 管理器或 `/proc` 可见性时，相关工具必须返回 `PARTIAL/ERROR`，不能输出安全结论。控制端会校验 Helper 协议版本，不兼容时拒绝任务。当前尚不支持自动上传非特权临时 Helper；管理员应使用 [`host-helper/install-helper.sh`](../host-helper/install-helper.sh) 安装（要求 Python 3.8+，会一并下发 YARA 规则与 Tomcat 探针），并用 [`host-helper/self-check-helper.sh`](../host-helper/self-check-helper.sh) 自检。

## 检测能力

| 检测包 | 已验证能力 | 主要限制 |
| --- | --- | --- |
| WebShell / Web 攻击链 | Nginx/Apache 配置发现、`root/alias/DocumentRoot`、近期脚本/模板/WAR/JAR、上传临时目录、`.user.ini/.htaccess`、批量 YARA（规则由 `install-helper.sh` 下发并校验 SHA-256）、Access Log、Web 进程与打开文件关联 | Apache/PHP-FPM 复杂 Include、发布基线和时间戳回改仍需真实语料验收；`rules/yara/webshell.yar` 仅 5 条有效行为规则，误报率未度量。 |
| Java 内存马 | Tomcat 9/JDK 17 Filter/Servlet/Listener/Valve/WebSocket、Spring MVC 映射/Interceptor、ClassLoader/CodeSource、JVM/线程/Connector 诊断、Class Dump SFTP Evidence | 自动化仅验证 Tomcat 9/JDK 17；Tomcat 8.5/10 和 JDK 8/11/21 尚未列为已验证。 |
| 后门账户 | UID 0、sudo/wheel、NSS 来源标识、账户状态、Key 指纹、登录历史、sudo/doas/polkit、有效 sshd 信任配置 | SSSD/LDAP 真实目录、云登录日志尚待 VM 验收。 |
| Linux 持久化 | Cron、systemd service/timer/drop-in/generated/transient、SSH、Shell、at/anacron、SysV/rc.local、XDG、PAM、udev、modprobe、cloud-init、包管理 Hook、user linger | initramfs 内容解析和 transient unit 的 D-Bus 运行态详情尚未实现。 |
| Linux 入侵分诊 | 稳定进程身份、进程树/FD/maps/socket、删除后运行、近期/特权文件、dpkg/rpm、动态加载、按主机时区解析的认证/audit 时间线；journald 与 `auth.log`/`secure` 轮转及 `.gz` 归档多源去重合并 | 尚未采集 wtmp/btmp 与独立 sudo 日志；journal cursor 增量采集未实现。 |
| 安恒威胁情报富化 | 当前任务 `SOCK-*` 公网外联引用、分析师预置 IP/域名/文件哈希、批量查询、本地缓存、Evidence、审计与 GUI 情报视图；2026-08-10 使用真实 Key 完成人工在线验收 | 外部命中不能单独形成 `CONFIRMED`；情报数据质量仍需持续观察。 |

## 数据与处置边界

- Class Dump、进程可执行文件和原始 Evidence 通过短期 artifact token 与 SFTP 256 KiB 分块落盘，Helper JSON 不携带二进制 Base64。
- 认证/audit/Access Log 只读取最新 64 MiB 窗口，并受单次操作的墙钟预算约束；达到任一上限返回 `PARTIAL`。结构化输出有 1.5 MiB 预算，超出即截断并置 `PARTIAL`。YARA 对候选集合单次批量执行。
- 当前真实主机试用建议使用 `SCAN`。已实现的写操作只有 WebShell 文件隔离和账户禁用，均要求 Evidence、一次性审批票据、目标端原子回执与执行后验证。
- Linux 分诊、Java 内存马和扩展持久化暂不提供自动清除工具。
- 威胁情报默认关闭；私网、回环、链路本地、文档网段和其他保留地址在本地过滤。Key 只从 HuntWarden 安全凭据存储或 `DBAPP_TI_API_KEY` 读取，不进入 YAML、模型上下文或 Evidence。

## 进入真实主机试用前

1. 先在隔离 VM 使用 `get_capabilities` 与 Helper 自检确认降级行为。
2. 人工核验 Host Key 后再写入 `known_hosts`；禁止将首次在线观察自动视为可信。
3. 先运行 `QUICK` 或 `STANDARD` 的只读任务，复核 `PARTIAL/ERROR/NOT_CHECKED` 和 Evidence，再决定是否启用处置模式。
4. 真实 VM 验收结果应回填本矩阵；未经验证的平台不要标记为“支持”。
