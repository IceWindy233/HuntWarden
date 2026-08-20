# HuntWarden Ubuntu 24.04 ARM64 GUI 只读验收记录

## 1. 结论

- 结果：`PASS_WITH_LIMITATIONS`
- 执行时间：2026-08-20（Asia/Shanghai）
- 执行方式：HuntWarden Electron GUI、真实 DeepSeek Provider、Multipass VM
- 验收基线 commit：`11b7ef6576c98699ab3fe39083d89bf24b41fc25`
- 验收中修复：Helper Artifact 目录穿越权限与可选 Linux 配置缺失语义；最终 Helper `0.4.2`
- GUI 最终报告：验收人已确认生成；`RPT-9b4e2cc0-a87d-4ad6-85f9-5f4a609238b6`，v1，`MODEL`
- 报告 SHA-256：`b45b1e9a11d1e17740976fe18960dd4b7596056405eaca33d7482ff1f51a80dc`

本轮证明 Ubuntu 24.04 ARM64 官方 Multipass VM 上的 GUI 建任务、真实模型 Tool Call、严格 SSH Host Key、root Helper、五类最低扫描、SFTP Evidence、SQLite 持久化和 SCAN 零写入能够形成闭环。完整依赖和最低依赖两种形态均已执行：最低依赖下缺少 YARA、auditd 与 JDK Attach 时，GUI 与结构化 Finding 会保留 `PARTIAL/ERROR/NOT_CHECKED`，不会误报为安全。它不证明真实恶意样本召回率，也不覆盖 Ubuntu 22.04、x86_64、SELinux 或受限 sudo。

## 2. 目标身份

| 项目 | 实际值 |
| --- | --- |
| 镜像来源 | Multipass Ubuntu 24.04 官方镜像 |
| 镜像 Hash | `4a281a921b8d7db952895ab619736f10efe9f63e111fa5b5779ed18f023818aa` |
| 发行版 | Ubuntu 24.04.4 LTS (Noble) |
| 架构 | AArch64 / ARM64 |
| 内核 | `6.8.0-137-generic` |
| init | systemd，`running` |
| LSM | AppArmor enabled；SELinux unavailable |
| Helper | `huntwarden-helper 0.4.2`，协议 1，root EUID |
| Host Key | Ed25519；Multipass 控制台、`known_hosts`、GUI 三方指纹一致 |
| SSH 凭据 | 专用无口令 Ed25519；私钥与 `known_hosts` 均为 `0600`，绝对路径只保存在本机 Profile |
| 快照 | 验收时为 `hw-vm.pre-gui-acceptance-20260820`；验收签署后随 VM 永久删除 |

## 3. 能力与降级

| 能力 | 状态 | 原因/证据 |
| --- | --- | --- |
| root Helper | SUPPORTED | sudo 固定命令入口，Helper 0.4.2 |
| YARA | SUPPORTED | 本地、VM 源文件、安装规则 SHA-256 均为 `6f90570d618fbd00b707148c74cfeddd4cffc1bfb712f1fb8ab397fe077a1660` |
| journald | SUPPORTED | systemd journal 可查询 |
| auditd | SUPPORTED | Helper 自检通过 |
| JDK Attach | SUPPORTED | OpenJDK 17 Attach 能力可用 |
| Tomcat Probe | SUPPORTED | Probe 已安装；当前没有可附加 Tomcat/JVM 进程 |
| `/proc` 可见性 | SUPPORTED | `hidepid=0`，root Helper |
| Docker/containerd | UNSUPPORTED | 目标未安装，符合预期降级 |

缺少运行中的 Tomcat/JVM 没有被描述为安全：QUICK、STANDARD、DEEP 均输出 `java_memory_shell=NOT_CHECKED`。可选的 doas 与旧式 Polkit 配置不存在时不再误报为权限/I/O 丢失。

### 3.1 最低依赖降级补测

- 补测任务：`TASK-4a7068b5-cb50-46ae-b4ca-c8c796a5b83e`，`COMPLETED`，QUICK/SCAN，真实 DeepSeek Provider，20 次工具调用。
- 目标：全新 Multipass Ubuntu 24.04.4 ARM64；不安装 `yara`、`auditd`、`openjdk-17-jdk-headless`，Helper 仍为 0.4.2。
- 严格 SSH 与 Helper 界面测试通过；`npm run test:acceptance:vm` 为 4/4 PASS。
- `get_capabilities` 返回 `partial`：YARA、auditd、JDK Attach 为 `UNSUPPORTED`，journald、root Helper、`/proc` 可见性为 `SUPPORTED`。

| 检测类别 | 结构化结果 | 验收判定 |
| --- | --- | --- |
| WebShell | `FIND-1a4e61a6-8daf-4805-809d-d4010fc5b641`：`NOT_CHECKED` | 明确写出 YARA 未安装、无可扫描对象，且“当前结果不构成安全结论” |
| Java 内存马 | `FIND-3fe35b5b-9410-4199-b238-685d6cbc4ef3`：`NOT_CHECKED` | 明确写出 JDK/JVM Attach 缺失且无 JVM，不输出 `NO_FINDING` |
| Linux 入侵分诊 | `FIND-d68eb32b-4b93-4c86-b2af-eb159c8ff6df`：`ERROR`；另保留确定性 `SUSPICIOUS` | `query_exec_events` 为 `partial`，明确“无法还原历史进程执行事件，本次结果不代表无异常” |

该任务最终覆盖为 `webshell=NOT_CHECKED`、`java_memory_shell=NOT_CHECKED`、`linux_intrusion_triage=SUSPICIOUS`。Approval 与 Action Receipt 均为 0，没有 WRITE/处置调用。GUI 展示与 SQLite 中的 Task、Finding、Tool Run 状态一致。

## 4. GUI 检测包结果

| 检测包 | QUICK 任务 | STANDARD | DEEP | 最终状态 | 关键 Evidence / 限制 |
| --- | --- | --- | --- | --- | --- |
| WebShell | `TASK-ac39053b-a5f7-45cc-ab28-1b69ab9d46fe` | S1 覆盖 | D1 覆盖 | `CONFIRMED` | YARA、脚本检查、两条 nginx Access Log 关联、阳性与良性文件均通过 SFTP 落盘 |
| Java 内存马 | `TASK-1e9aedd7-df00-4b64-8ff7-d42951ec3ae2` | S1 覆盖 | D1 覆盖 | `NOT_CHECKED` | 无运行 JVM/Tomcat；原因明确，未形成 `NO_FINDING` |
| 后门账户 | `TASK-ab601bae-62d5-404f-bebb-4ef26fe05b49` | S1 覆盖 | D1 覆盖 | `NO_FINDING` | UID 0、sudo、SSH 信任、authorized_keys、登录历史完成；Helper 0.4.2 后无错误降级 |
| Linux 持久化 | `TASK-94fd4d6b-675e-494e-801d-370b2e1f922b` | S1 覆盖 | D1 覆盖 | `SUSPICIOUS` | 确定性规则保留发行版 service 信号；模型用原始单元和进程基线给出 `NO_FINDING` 反证；枚举上限保留 PARTIAL |
| Linux 入侵分诊 | `TASK-4c753b7d-ceec-4cbf-a018-a0378ab1f00c` | S1 覆盖 | D1 覆盖 | `SUSPICIOUS` | 确定性进程结构信号保留；模型用进程/网络/文件/时间线复核为标准软件行为；预算跳过项仍可见 |

联合任务：

- STANDARD：`TASK-2819aaf4-5330-4560-9f59-8d8da2946721`，`COMPLETED`，56/56 工具成功，43 份 Evidence，2 份原始文件。
- DEEP：`TASK-bbd559f9-73cd-4c16-9cd5-2c123c6cf517`，`COMPLETED`，66/66 工具成功，50 份 Evidence，2 份原始文件。

## 5. 样本、对照与安全边界

| 场景 | 预期 | 实际 | 结果 |
| --- | --- | --- | --- |
| 惰性 WebShell 阳性夹具 | 形成可追溯 Finding/Evidence | `CONFIRMED`；SHA-256 `a7b44c7e3516506251afd29c57a7bb56499065cf03c51dbaa4d4b536ecc075ab` | PASS |
| 良性 PHP 对照 | 不形成 HIGH/CRITICAL | 未被误判；SHA-256 `bf387fbf1e7d5cb31c117269bcf93eceb955f09ba77fcf1dc517015dddd83b64` | PASS |
| 标准 Access Log | 两个请求均可关联 | `/var/log/nginx/access.log` 两条 200 记录均形成 Evidence | PASS |
| 未选择类别 | 不注册、不调用对应工具 | 五个 QUICK 单类任务只执行所选类别图 | PASS |
| SCAN 写操作 | 成功次数为 0 | 7 个有效任务中 WRITE/处置调用 0、Approval 0、Action Receipt 0 | PASS |
| 凭据保护 | Key 不进入 YAML/DB/Evidence | GUI 显示来自 macOS Keychain；Profile 只保存凭据路径 | PASS |
| 夹具清理 | 验收后显式清理 | 固定 sentinel 脚本删除后，两文件均验证为 `ABSENT`；随后 VM 永久删除 | PASS |

## 6. 性能与数据完整性

| 任务 | 耗时 | Tool Call | Evidence |
| --- | ---: | ---: | ---: |
| 5 个 QUICK 合计 | 约 324 秒 | 83 | 53 |
| STANDARD | 约 99 秒 | 56 | 43 |
| DEEP | 约 138 秒 | 66 | 50 |

- SQLite `PRAGMA integrity_check`：`ok`。
- 7 个有效任务原始文件共 6 份、1464 bytes；每轮 WebShell 调查各保存阳性与良性文件。
- QUICK 持久化的 systemd 枚举达到 250 项展示上限；DEEP/分诊也保留预算导致的 PARTIAL 信息。应用没有把这些未覆盖范围静默转换为安全结论。

## 7. 本轮缺陷与处理

| ID | 严重度 | 现象 | 当前处理 |
| --- | --- | --- | --- |
| HW-VM-001 | HIGH | Artifact 文件已改属 SSH 用户，但 `/var/lib/huntwarden` 为 `0700`，真实 SFTP 无法穿越父目录 | Helper/安装器将状态根目录固定为 root:root `0711`，actions/quarantine 仍为 `0700`；新增回归测试；真实 SFTP 哈希一致 |
| HW-VM-002 | MEDIUM | Ubuntu 未安装 doas、未使用旧式 Polkit 目录时被记为两个 I/O 跳过，账户覆盖错误变为 `ERROR` | Helper 0.4.2 区分可选路径 ENOENT 与真实权限/I/O 错误；同场景重跑为 `NO_FINDING` |
| HW-VM-003 | INFO | QUICK 的 systemd/进程预算与确定性启发式会对发行版组件保留 `PARTIAL/SUSPICIOUS`，模型反证不会抹除规则 Finding | 按安全设计保留；作为已知限制，不把最终覆盖解读为已排查干净 |
| HW-VM-004 | INFO | Playwright 直接拉起的 Electron 进程与正常应用身份不同，不能解密旧 safeStorage 密文 | 验收器改为正常 Electron 启动后通过 CDP 操作；不计为产品运行缺陷 |

失败/修复前任务均保留在审计库中用于追溯：`TASK-1bbbe95f-d4a4-4b2b-80a9-7c4f246f9753`（Artifact 权限）、`TASK-99520ee8-8c48-4bad-bbb3-0cdf339ebbe0`（验收器应用身份）、`TASK-757a0b10-e611-4ff5-ab25-0d67986888a1`（可选配置误降级）。

## 8. 尚需验收人完成

1. [x] GUI 最终报告已由验收人确认生成；文件 `0600`、24272 bytes，数据库与磁盘 SHA-256 一致，47 个完整 Finding/Evidence 引用全部存在，自动校验错误为 0。
2. [x] 完整依赖验收的两个固定夹具先验证为 `ABSENT`，随后 VM、快照和专用 SSH 文件清理；最低依赖补测结束后第二台 `hw-vm` 也已销毁，临时凭据目录移入 macOS 废纸篓，Profile 恢复到现有 Lab 凭据路径。
3. [x] Ubuntu 24.04 ARM64 的完整依赖与最低依赖两种形态均已闭环，平台保持“已验证（有限制）”；其余发行版和架构保持待实机验收，但不阻塞 `v0.1.0`。
