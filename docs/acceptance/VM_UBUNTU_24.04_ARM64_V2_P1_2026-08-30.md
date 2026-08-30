# Ubuntu 24.04 ARM64 Tool Protocol v2 P1 增量验收

## 结论

- 结果：`PASS_WITH_LIMITATIONS`
- 执行时间：2026-08-30（Asia/Shanghai）
- 实现基线：`88d8198de6a30a079c245552208edaca3c606890`
- 目标：Canonical Multipass Ubuntu 24.04 ARM64 临时 VM
- Helper：协议 2，Manifest/Helper `2.1.0`

本轮证明 P1 新增的委派配置、SSH 信任配置、Web effective root、固定 file Scope 与包数据库抽样校验能够在真实 Ubuntu 24.04 ARM64 目标上通过生产 Helper 路径运行，并重新创建 Manifest `2.1.0` 的真实 Provider 冻结语料、执行模型能力统计。它仍是对 2026-08-26 五类 QUICK/STANDARD/DEEP GUI 验收的增量复验，不声称重新执行了全部 Profile 矩阵。

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
| 真实 Provider | Manifest `2.1.0` novel malicious + benign | 七项模型能力门槛 7/7 PASS |

VM smoke 具体验证：

- Helper capabilities 精确报告 Manifest `2.1.0`，并声明 `delegation_rule`、`ssh_trust_config`。
- 后门账户路径可以枚举 sudoers/doas/polkit 委派事实和 `sshd -T` 默认上下文有效配置。
- Web 路径可得到运行时有效 `web_root.effective`。
- Linux 分诊固定绑定 `/usr/bin`、`/tmp` Scope，并可执行 `package → owns_file → verify(package_db)` 有界链路。
- 原有 collect/SFTP/SHA-256 与 journald source/event 身份回归继续通过。

## 环境准备与清理

第一次 smoke 为 2/4：目标保留自前序验收的最小环境，缺少 nginx 与固定无害 Web fixture，因此涉及 effective root/fixture 的断言失败。这是发布依赖和验收数据未准备，不是协议结果；没有降低断言或把失败改成跳过。

随后安装 nginx，并通过仓库 sentinel 脚本安装固定安全夹具，原命令重跑为 4/4。验收完成后夹具已由 sentinel 清理并复核；nginx 与升级后的 Helper `2.1.0` 保留在该临时 VM。安装依赖时 `apt update` 曾因 VM 时钟落后提示 Release 文件尚未生效，但所需 nginx 包成功安装，不影响最终重跑结果。

## P1 Provider 模型能力复验

- Provider/模型：`siliconflow/deepseek-ai/DeepSeek-V4-Flash`。
- 发布清单重新绑定本轮 Manifest `2.1.0` 上完成的惰性动态回调 novel malicious 与无 JVM benign control 任务；两类 Preset Coverage 分别为 `COMPLETE/APPLICABLE` 与 `COMPLETE/NOT_APPLICABLE`。
- 评测器结果：事实可达率 2/2、novel recall 1/1；截断损失 0/11、MODEL NOT_CONCLUDED 0/2、Preset partial 0/2、非法工具调用 0/11、良性误报 0/1，七项门槛全部通过。
- 另执行 loopback-only `/tmp` effective-root 专项模型任务，模型以真实对象引用写入 `HIGHLY_SUSPICIOUS`，工具调用无失败；该任务 Coverage 为 `PARTIAL/UNKNOWN`，因此只作为 P1 专项证据，不纳入冻结统计清单，也未降低 `maxPresetPartialRate=0.1` 门槛。
- 报告：[`MODEL_EVAL_P1_2026-08-30.md`](MODEL_EVAL_P1_2026-08-30.md)；机器可读结果：[`MODEL_EVAL_P1_2026-08-30.json`](MODEL_EVAL_P1_2026-08-30.json)。
- 发布评测与 effective-root 专项夹具均已通过 sentinel 脚本移除；最终状态为 PHP 文件 `ABSENT`、Java Sleeper `STOPPED`、nginx 专项配置与 `/tmp` Web 根 `ABSENT`。

## 限制

- `ssh_trust_config` 当前只表示 `sshd -T` 默认连接上下文；尚未使用 `sshd -T -C` 展开逐用户、来源地址及 `Match` 分支。
- file Scope 与 package verify 是有界抽样；节点或关系上限会如实返回 `PARTIAL`，不能解释为全盘完整性证明。
- 模型评测仍只有两条自造安全语料；七项门槛通过不能外推为真实站点召回率、精确率或 Provider 长流稳定性证明。
- Rocky/AlmaLinux、Ubuntu x86_64、SSSD/LDAP 与复杂 Apache/PHP-FPM 配置仍待扩展验收。
