# HuntWarden 实战试用支持矩阵

> 更新日期：2026-08-10。`已验证`仅表示仓库自动化或明确环境已通过；`待实机验收`不等同于不支持，而是不应在报告中宣称已验证。

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
| Ubuntu 24.04 | 待实机验收 | Helper 仅依赖 Python 标准库和固定 Linux 接口。 |
| Debian 12 | 待实机验收 | dpkg 完整性路径已实现。 |
| Rocky / AlmaLinux 9 | 待实机验收 | rpm、`secure` 日志和 SELinux 能力识别已实现。 |
| Amazon Linux 2023 | 待实机验收 | rpm 路径已实现，尚无自动化 VM。 |

Helper 启动时返回 `SUPPORTED | PARTIAL | UNSUPPORTED | PERMISSION_DENIED` 能力状态。root Helper 是完整调查的推荐方式；缺少 YARA、auditd、journald、JDK Attach、systemd 管理器或 `/proc` 可见性时，相关工具必须返回 `PARTIAL/ERROR`，不能输出安全结论。当前尚不支持自动上传非特权临时 Helper；管理员应使用 [`host-helper/install-helper.sh`](../host-helper/install-helper.sh) 安装，并用 [`host-helper/self-check-helper.sh`](../host-helper/self-check-helper.sh) 自检。

## 检测能力

| 检测包 | 已验证能力 | 主要限制 |
| --- | --- | --- |
| WebShell / Web 攻击链 | Nginx/Apache 配置发现、`root/alias/DocumentRoot`、近期脚本/模板/WAR/JAR、上传临时目录、`.user.ini/.htaccess`、批量 YARA、Access Log、Web 进程与打开文件关联 | Apache/PHP-FPM 复杂 Include、发布基线和时间戳回改仍需真实语料验收。 |
| Java 内存马 | Tomcat 9/JDK 17 Filter/Servlet/Listener/Valve/WebSocket、Spring MVC 映射/Interceptor、ClassLoader/CodeSource、JVM/线程/Connector 诊断、Class Dump SFTP Evidence | 自动化仅验证 Tomcat 9/JDK 17；Tomcat 8.5/10 和 JDK 8/11/21 尚未列为已验证。 |
| 后门账户 | UID 0、sudo/wheel、NSS 来源标识、账户状态、Key 指纹、登录历史、sudo/doas/polkit、有效 sshd 信任配置 | SSSD/LDAP 真实目录、云登录日志尚待 VM 验收。 |
| Linux 持久化 | Cron、systemd service/timer/drop-in/generated/transient、SSH、Shell、at/anacron、SysV/rc.local、XDG、PAM、udev、modprobe、cloud-init、包管理 Hook、user linger | initramfs 内容解析和 transient unit 的 D-Bus 运行态详情尚未实现。 |
| Linux 入侵分诊 | 稳定进程身份、进程树/FD/maps/socket、删除后运行、近期/特权文件、dpkg/rpm、动态加载、认证/audit 时间线 | journald 当前以能力识别与文件日志为主，尚未实现完整 journal cursor 采集。 |
| 安恒威胁情报富化 | 当前任务 `SOCK-*` 公网外联引用、分析师预置 IP/域名/文件哈希、批量查询、本地缓存、Evidence 与 GUI 情报视图 | API 客户端和假响应测试已验证；真实 API Key、额度与生产数据质量需要用户在线验收。外部命中不能单独形成 `CONFIRMED`。 |

## 数据与处置边界

- Class Dump、进程可执行文件和原始 Evidence 通过短期 artifact token 与 SFTP 256 KiB 分块落盘，Helper JSON 不携带二进制 Base64。
- 认证/audit/Access Log 只读取最新 64 MiB 窗口；达到上限返回 `PARTIAL`。YARA 对候选集合单次批量执行。
- 当前真实主机试用建议使用 `SCAN`。已实现的写操作只有 WebShell 文件隔离和账户禁用，均要求 Evidence、一次性审批票据、目标端原子回执与执行后验证。
- Linux 分诊、Java 内存马和扩展持久化暂不提供自动清除工具。
- 威胁情报默认关闭；私网、回环、链路本地、文档网段和其他保留地址在本地过滤。Key 只从 HuntWarden 安全凭据存储或 `DBAPP_TI_API_KEY` 读取，不进入 YAML、模型上下文或 Evidence。

## 进入真实主机试用前

1. 先在隔离 VM 使用 `get_capabilities` 与 Helper 自检确认降级行为。
2. 人工核验 Host Key 后再写入 `known_hosts`；禁止将首次在线观察自动视为可信。
3. 先运行 `QUICK` 或 `STANDARD` 的只读任务，复核 `PARTIAL/ERROR/NOT_CHECKED` 和 Evidence，再决定是否启用处置模式。
4. 真实 VM 验收结果应回填本矩阵；未经验证的平台不要标记为“支持”。
