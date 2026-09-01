# Ubuntu 24.04 ARM64 Tool Protocol v2 P1 完整 GUI Profile 矩阵

## 结论

- 结果：`PASS_WITH_LIMITATIONS`
- 执行时间：2026-09-01 10:19～11:22（Asia/Shanghai）
- 实现基线：`331d395e8f00b020490a32ebecf39e297815e36b`（分支 `codex/v2-refactor`）
- 协议：Tool Protocol v2 / Manifest/Helper `2.1.0`
- 执行方式：HuntWarden Electron GUI、真实 SSH、真实 SiliconFlow Provider、Canonical Ubuntu 24.04 ARM64 临时 VM
- Provider：`siliconflow/deepseek-ai/DeepSeek-V4-Flash`
- Agent：`huntwarden-agent-v2`；当前激活配置开启 reasoning、保留 3 轮上下文、单轮 Provider 超时 600 秒、最大输出 16384 token

五类检测包分别以 QUICK、STANDARD、DEEP 运行，共冻结 15 个正式完成任务。正式样本全部 `COMPLETED`，共 152 次 ToolRun、60 轮，失败调用 0、成功写操作 0、Action Receipt 0；每个任务均有对应 CoverageRun 和 MODEL `OBSERVED_CATEGORY` 收尾。

当前高推理配置仍有三条首跑异常：一次 Provider 空 assistant 导致任务失败、一次跨任务 Cursor、一次伪造 Query 引用。后两者均被控制端 fail-close 拒绝；三条异常任务全部保留，并以相同模型/Profile 重跑取得干净完成样本。因此本轮不能表述为“首跑 15/15”，结论保持 `PASS_WITH_LIMITATIONS`。

## 正式 Profile 矩阵

| Profile | 检测包 | Task | Coverage | MODEL 类别收尾 | ToolRun / 失败 | 结果 |
| --- | --- | --- | --- | --- | ---: | --- |
| QUICK | WebShell | `TASK-9f3c2f90-083a-41f4-b813-c9424ffd7691` | `COMPLETE/APPLICABLE` | `INCONCLUSIVE` | 8 / 0 | PASS |
| QUICK | Java 内存马 | `TASK-92ae4186-7d7d-40ec-ae29-43de95473d56` | `COMPLETE/NOT_APPLICABLE` | `NO_OBSERVED_FINDING` | 5 / 0 | PASS |
| QUICK | 后门账户 | `TASK-229ca549-365e-4c28-b78b-c760384ef3ab` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 9 / 0 | PASS |
| QUICK | Linux 持久化 | `TASK-c572a185-2697-4961-a205-525474a56501` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 9 / 0 | PASS |
| QUICK | Linux 入侵分诊 | `TASK-c86daf00-6398-4cad-8505-c6d9f9a6e9d3` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 18 / 0 | PASS |
| STANDARD | WebShell | `TASK-91d46a68-71a5-40ec-979d-5a66101d66d9` | `COMPLETE/APPLICABLE` | `INCONCLUSIVE` | 9 / 0 | PASS |
| STANDARD | Java 内存马 | `TASK-61b8790f-b742-4a4c-a5c3-e6f12085a023` | `COMPLETE/NOT_APPLICABLE` | `NO_OBSERVED_FINDING` | 5 / 0 | PASS |
| STANDARD | 后门账户 | `TASK-2d1b81a0-a898-4d64-a382-357f4c8e9e33` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 11 / 0 | PASS |
| STANDARD | Linux 持久化 | `TASK-30fd09f7-648d-49d7-8fb4-cbc4c6173949` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 9 / 0 | PASS |
| STANDARD | Linux 入侵分诊 | `TASK-493f11ea-2898-4ff6-8ad1-2a73e0877541` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 19 / 0 | PASS（重跑） |
| DEEP | WebShell | `TASK-87c1da9b-652b-441d-aab2-17735269c2c5` | `COMPLETE/APPLICABLE` | `INCONCLUSIVE` | 12 / 0 | PASS |
| DEEP | Java 内存马 | `TASK-da1947a8-14df-43ab-93b9-7441e4e53ed3` | `COMPLETE/NOT_APPLICABLE` | `NO_OBSERVED_FINDING` | 4 / 0 | PASS（重跑） |
| DEEP | 后门账户 | `TASK-469f85fc-9151-47b6-8f00-2fedf2870293` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 7 / 0 | PASS（重跑） |
| DEEP | Linux 持久化 | `TASK-206875bd-77b4-4d7f-ae33-b317fd4b486d` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 9 / 0 | PASS |
| DEEP | Linux 入侵分诊 | `TASK-b591e381-4a00-42c4-ae92-d6bfa2c2a499` | `PARTIAL/UNKNOWN` | `INCONCLUSIVE` | 18 / 0 | PASS |

## Coverage 与安全边界

- WebShell 三个 Profile 均为 `COMPLETE/APPLICABLE`。两份固定安全夹具都只形成 `HW2-WEB-EXECUTABLE-001` 的 `SUSPICIOUS/MEDIUM` 候选规则，理由明确“文件类型本身不是恶意结论”，未升级为 HIGH/CRITICAL。
- Java 三个 Profile 均为 `COMPLETE/NOT_APPLICABLE + NO_OBSERVED_FINDING`；目标没有运行 JVM/Tomcat，该结果不外推为其他 Java 主机安全。
- 后门账户三个 Profile 均仅因 `login-history/PARTIAL_SOURCE` 为 `PARTIAL/UNKNOWN`，MODEL 均以 `INCONCLUSIVE` 收尾；P1 的 delegation 与有效 SSH trust 事实仍正常落库。
- 持久化三个 Profile 的 systemd、SSH、shell/loader、extended 来源均明示 `PARTIAL_SOURCE`；没有把不完整覆盖解释为安全。
- 分诊三个 Profile 均执行固定 `/usr/bin`、`/tmp` Scope 和 `package → owns_file → verify(package_db)` 路径；volatile、file scope、event、package inventory/verify 的有界缺口继续以 `PARTIAL_SOURCE` 呈现。
- 15 个正式任务全部为 `SCAN`，成功写工具 0、Action Receipt 0。为隔离 Profile/Provider 行为，本轮提示禁止 Sensitive-read Grant、`read/match/collect` 与处置；因此本轮不重复声称 Evidence 内容链，该链路由当前 P1 实机记录中的 smoke 4/4 承担。

## 首跑异常与 fail-close

| Task | Profile/类别 | 现象 | 边界结果 | 正式替代样本 |
| --- | --- | --- | --- | --- |
| `TASK-2300237d-2c45-4fef-92d8-cdabae52f73f` | STANDARD / 分诊 | Provider 返回空 assistant；任务 `FAILED`，无 MODEL 类别结论 | Preset 与 16 次 ToolRun 均成功，未写入错误 Assessment | `TASK-493f11ea-2898-4ff6-8ad1-2a73e0877541` |
| `TASK-76eb03d7-91bd-43af-b0fb-8373dd103e93` | DEEP / Java | 模型使用未知或跨 task/epoch 的 Query cursor | `query_facts` fail-close；后续虽收尾，仍排除正式样本 | `TASK-da1947a8-14df-43ab-93b9-7441e4e53ed3` |
| `TASK-8980ac5b-3a53-4e12-b4c6-90d25bf8497f` | DEEP / 账户 | 模型在 Assessment 中引用不存在的 `QUERY-*` | `record_assessment` fail-close；后续虽收尾，仍排除正式样本 | `TASK-469f85fc-9151-47b6-8f00-2fedf2870293` |

全部 18 次尝试共 188 次 ToolRun，仅上述 2 次模型引用调用失败；失败任务 1，成功写操作与 Action Receipt 仍为 0。未出现 402、`terminated` 或 600 秒 Provider 超时。

## 性能与报告

| Profile | 五类正式任务累计耗时 | ToolRun | 轮数 |
| --- | ---: | ---: | ---: |
| QUICK | 843.800 秒 | 49 | 20 |
| STANDARD | 1282.070 秒 | 53 | 22 |
| DEEP | 770.389 秒 | 50 | 18 |

WebShell DEEP 正式任务已由分析师确认生成模型报告：

- Report：`RPT-28e4e818-78f6-4e63-a15e-ec8b1f394143`，version 1。
- SHA-256：`b1c4d9dc0abb96853a1d386c432745c2f484af1fde89e83f07a2a2f903d46127`。
- 引用：1 个 Coverage ID、3 个 Assessment ID；本轮无 Evidence/InvestigationGap 引用。
- 确定性校验：`validationErrors=[]`；审计包含 analyst request、model start/finish 与 `report_generated`。

## 清理状态

- `/var/www/html/huntwarden-acceptance-webshell.php`：`ABSENT`
- `/var/www/html/huntwarden-acceptance-benign.php`：`ABSENT`
- novel PHP 模型夹具：`ABSENT`
- Java Sleeper：`STOPPED`
- loopback-only nginx effective-root 配置与 `/tmp` Web 根：`ABSENT`
- VM、Helper `2.1.0`、nginx 与本机专用 SSH 状态仍保留，便于复核；敏感连接信息未写入本记录或仓库。

## 剩余限制

- 当前 Provider 高推理配置已完成五类 × 三 Profile，但首跑并非 15/15；空响应与引用幻觉仍需作为模型兼容性限制保留。
- 当前 Coverage 的 `PARTIAL_SOURCE` 是真实有界采集结果，不是协议失败，也不能解释为全盘完整或主机安全。
- Rocky/AlmaLinux、Ubuntu x86_64、SSSD/LDAP、复杂 Apache/PHP-FPM、多版本 JVM 仍未由本轮覆盖。
