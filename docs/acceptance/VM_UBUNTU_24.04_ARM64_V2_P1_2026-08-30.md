# Ubuntu 24.04 ARM64 Tool Protocol v2 P1 增量验收

## 结论

- 结果：`PASS_WITH_LIMITATIONS`
- 执行时间：2026-08-30（Asia/Shanghai）
- 实现基线：`88d8198de6a30a079c245552208edaca3c606890`
- 目标：Canonical Multipass Ubuntu 24.04 ARM64 临时 VM
- Helper：协议 2，Manifest/Helper `2.1.0`

本轮证明 P1 新增的委派配置、SSH 信任配置、Web effective root、固定 file Scope 与包数据库抽样校验能够在真实 Ubuntu 24.04 ARM64 目标上通过生产 Helper 路径运行。它是对 2026-08-26 完整 GUI/Provider 验收的增量复验，不声称重新执行了五类 QUICK/STANDARD/DEEP 或 Provider 模型能力统计。

## 验收结果

| 层级 | 命令/范围 | 结果 |
| --- | --- | --- |
| PR | `npm test` | 30 个文件通过、10 个环境项跳过；124 项通过、37 项跳过 |
| 静态门禁 | core/Renderer typecheck、build、lint、生产依赖审计、Helper Python 编译、shell 语法 | PASS |
| Docker | 五套 Lab | 11/11 PASS；账户 Lab 覆盖 sudoers、doas、polkit 和 `sshd -T` 默认上下文 |
| 动态发行版 | Debian 12 acceptance | 5/5 PASS；包含 P1 新事实断言 |
| GUI | investigation、remediation、recovery、grant 四套 E2E | 16/16 PASS |
| RE2 | macOS ARM64 与 Ubuntu 22.04 ARM64 | 两端匹配与禁止回退路径 PASS |
| 真实 VM | v2 smoke | 4/4 PASS |
| 真实 VM | journald 身份/generation 回归 | 1/1 PASS |

VM smoke 具体验证：

- Helper capabilities 精确报告 Manifest `2.1.0`，并声明 `delegation_rule`、`ssh_trust_config`。
- 后门账户路径可以枚举 sudoers/doas/polkit 委派事实和 `sshd -T` 默认上下文有效配置。
- Web 路径可得到运行时有效 `web_root.effective`。
- Linux 分诊固定绑定 `/usr/bin`、`/tmp` Scope，并可执行 `package → owns_file → verify(package_db)` 有界链路。
- 原有 collect/SFTP/SHA-256 与 journald source/event 身份回归继续通过。

## 环境准备与清理

第一次 smoke 为 2/4：目标保留自前序验收的最小环境，缺少 nginx 与固定无害 Web fixture，因此涉及 effective root/fixture 的断言失败。这是发布依赖和验收数据未准备，不是协议结果；没有降低断言或把失败改成跳过。

随后安装 nginx，并通过仓库 sentinel 脚本安装固定安全夹具，原命令重跑为 4/4。验收完成后夹具已由 sentinel 清理并复核；nginx 与升级后的 Helper `2.1.0` 保留在该临时 VM。安装依赖时 `apt update` 曾因 VM 时钟落后提示 Release 文件尚未生效，但所需 nginx 包成功安装，不影响最终重跑结果。

## 限制

- `ssh_trust_config` 当前只表示 `sshd -T` 默认连接上下文；尚未使用 `sshd -T -C` 展开逐用户、来源地址及 `Match` 分支。
- file Scope 与 package verify 是有界抽样；节点或关系上限会如实返回 `PARTIAL`，不能解释为全盘完整性证明。
- 本轮没有生成新的 Manifest `2.1.0` Provider 已完成任务语料，因此 2026-08-26 的七项模型门槛只作为 `2.0.0` 基线沿用，不计为 P1 模型复验。
- Rocky/AlmaLinux、Ubuntu x86_64、SSSD/LDAP 与复杂 Apache/PHP-FPM 配置仍待扩展验收。
