# Changelog

本文件记录 HuntWarden 的重要用户可见变化，格式参考 Keep a Changelog，版本遵循语义化版本。

## [Unreleased]

### Planned

- Ubuntu 24.04 ARM64 与 Rocky Linux 9 x86_64/SELinux 的授权真实 VM 验收。
- `v0.1.0` 演示视频、脱敏截图与未签名 macOS arm64 发布资产。

## [0.1.0] - Draft

### Added

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
