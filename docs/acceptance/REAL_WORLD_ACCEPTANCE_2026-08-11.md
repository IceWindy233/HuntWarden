# HuntWarden 真实场景功能验收报告（2026-08-11）

## 1. 结论

本轮验收通过。HuntWarden 在一套独立于 `labs/` 固定样板的 Debian 12 ARM64 动态攻击链中完成了能力协商、Web 落地文件发现、YARA/脚本特征、访问日志关联、UID 0 账户、SSH Key 指纹、Cron、删除后运行、隐藏进程、进程到 Socket 关联、认证事件与时间线取证。

正式工具注册表、最低扫描图和确定性规则也完成闭环：阳性事实形成 `SUSPICIOUS`；缺失 journald/auditd、systemd 未运行和瞬态进程竞争继续显示为 `PARTIAL/ERROR`，没有错误形成 `NO_FINDING`。

该结论只证明本轮容器化真实行为验收通过，不等同于 Debian 12 VM、完整 systemd 主机或生产环境兼容性已经完成。

## 2. 依据与场景选择

外部依据均采用公开项目或权威 ATT&CK 定义：

- [MITRE ATT&CK T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/)
- [MITRE ATT&CK T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) 及其 [T1053.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.003/T1053.003.yaml)、[T1070.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.yaml) 可重复测试定义
- [Apache Caldera（原 MITRE Caldera）](https://caldera.mitre.org/) 作为后续多阶段对手仿真候选；本轮未引入整套平台

DetectionLab 未选用：项目已经声明 2023 年起停止积极维护，且主要目标是 Windows 域与日志平台，不匹配 HuntWarden 当前 Linux 主机专项范围。

## 3. 验收环境

| 项目 | 实际值 |
| --- | --- |
| 控制端 | macOS 26.5.2，Apple ARM64 |
| Docker | Server 29.4.0，Compose 5.1.2 |
| 目标基础镜像 | 官方 `debian:12-slim` |
| 目标架构 | AArch64 |
| 接入方式 | `127.0.0.1:2299`，Ed25519，严格 Host Key 指纹校验 |
| Helper | `huntwarden-helper 0.3.1`，固定操作白名单 |
| 外部网络 | Web 端口不映射；Beacon 仅访问容器内 `127.0.0.1:18771` |
| 威胁情报 | 未发起在线查询；场景 IP `198.51.100.42` 是文档保留地址 |

每次启动动态生成事件 ID、Web 文件名、隐藏进程名、Cron 路径和 UID 0 账户名，测试通过运行时 Manifest 获取预期事实，不依赖 `lab-*` 文件名或固定标记。

## 4. 无害攻击链

1. 在 Nginx 生效 Web Root 的上传目录落地随机命名 PHP 文件。
2. 文件包含请求输入、Base64 解码和命令执行原语，但保护条件恒不成立，不能执行输入。
3. Nginx Access Log 记录同一来源的 POST 落地与 GET 访问，敏感查询参数用于验证脱敏。
4. 创建随机命名的额外 UID 0 账户，并配置未知 Ed25519 公钥。
5. 创建随机命名 Cron，指向隐藏 Python Beacon；同时保留正常备份清理 Cron 作为阴性上下文。
6. Beacon 只连接容器回环 Listener，并保持一个 `ESTABLISHED` Socket。
7. 从 `/var/tmp` 启动随机隐藏可执行文件后删除磁盘文件，形成删除后运行事实。
8. 写入当前时间的 SSH 成功认证和 sudo 使用记录，供时间线恢复。

## 5. 验收结果

| 验收项 | 结果 | 说明 |
| --- | --- | --- |
| TypeScript/Electron 构建 | PASS | `npm run build` |
| 常规测试 | PASS | 25 files，88 passed，30 skipped |
| Java 探针 | PASS | Gradle build successful |
| 原五套 Docker Lab | PASS | 2 files，10 passed |
| 动态 Debian 12 场景 | PASS | 1 file，6 passed |
| Electron GUI 调查 E2E | PASS | 1 file，4 passed |
| WebShell 行为链 | PASS | Root、候选、两条行为 YARA、脚本特征、POST/GET 日志关联 |
| 账户与 SSH Key | PASS | 动态 UID 0 账户、指纹提取、公钥正文不泄露 |
| Cron 上下文 | PASS | 异常项与正常备份项均被枚举 |
| 进程与网络 | PASS | 删除后运行、隐藏 Beacon、稳定身份、回环 Socket 关联 |
| 认证时间线 | PASS | `authentication_success` 与 `privilege_use` |
| 最低扫描与规则 | PASS | 账户/进程阳性为 `SUSPICIOUS`；不完整覆盖不产生 `NO_FINDING` |

复现命令：

```bash
npm run test:acceptance:real-world
```

脚本会创建 gitignored SSH 身份，构建并启动目标，执行测试，最后自动删除验收容器与网络。

## 6. 本轮发现并修复的缺陷

### HW-RW-001：能力协商缺少发行版身份

- 现象：Debian 12 的 `get_capabilities` 只返回共享宿主内核版本，无法辨别目标用户态发行版。
- 风险：支持矩阵可能把容器宿主内核误当成目标发行版，无法形成真实兼容性证据。
- 修复：Helper 0.3.1 安全解析固定 `/etc/os-release` 或 `/usr/lib/os-release`，新增 `distribution.id/idLike/name/prettyName/versionId/versionCodename/source`；只解析，不执行 Shell。
- 验证：动态目标返回 `debian / 12 / bookworm / /etc/os-release`，类型、集成和真实场景测试通过。

### HW-RW-002：PARTIAL 输入会抑制已采集阳性规则结论

- 现象：进程枚举期间短生命周期 Nginx/SSH 子进程消失，使结果为 `PARTIAL`；旧规则引擎因此同时跳过已验证的删除后运行和隐藏进程事实。
- 风险：真实繁忙主机上容易丢失确定性阳性提示，过度依赖模型继续识别。
- 修复：可用但 `PARTIAL` 的规则输入允许保留有 Evidence 的 `SUSPICIOUS`；置信度上限降为 `0.7`，并追加未覆盖范围限制。`NO_FINDING` 在任何所需输入为 `PARTIAL` 时仍被强制抑制。
- 验证：新增单元测试和真实扫描图测试，确认阳性保留、限制明确、持久化不完整覆盖仍为 `ERROR` 而非安全结论。

## 7. 仍需完成

1. Debian 12 完整 VM（systemd/journald/auditd）只读验收；本轮容器不升级支持矩阵状态。
2. Ubuntu 22.04/24.04、Rocky/AlmaLinux 9、Amazon Linux 2023 的真实 VM 矩阵。
3. 使用真实 Provider 的端到端 Agent 推理质量验收；本轮 GUI 使用可重复 Faux Provider，模型网络与费用不在范围内。
4. SSH Agent、加密私钥、ProxyJump、IPv6、断线与 Evidence 中断恢复。
5. 在独立虚拟网络中按需接入 Apache Caldera 或经审核的 Atomic Red Team 多阶段编排；仍禁止把真实恶意软件和公网攻击目标纳入默认测试。
