# Changelog

本文件记录 HuntWarden 的重要用户可见变化，格式参考 Keep a Changelog，版本遵循语义化版本。

## [Unreleased]

### Planned

- Rocky Linux 9 x86_64/SELinux 的授权真实 VM 兼容性验收（非 `v0.1.0` 阻塞项）。
- `v0.1.0` 演示视频与脱敏截图。

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

[Unreleased]: https://github.com/IceWindy233/HuntWarden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/IceWindy233/HuntWarden/releases/tag/v0.1.0
