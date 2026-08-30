# V2 安全不变量验证矩阵

本表是 `TOOL_PROTOCOL_V2_DESIGN.md` 第 15 节的唯一验证归属清单。`PR` 为无外部环境的必跑门禁；`MERGE` 需要 Helper/Docker/GUI 环境；`RELEASE` 需要真实 VM 或平台矩阵。环境门禁未执行时只能标记“待验收”，不能据此宣称已验证。

实现基线：Tool Protocol v2 Manifest/Helper `2.1.0` / `88d8198de6a30a079c245552208edaca3c606890`。`0.2.0` 发布标签仍对应 Manifest `2.0.0`；本表的当前门禁状态描述的是上述 P1 后续实现提交。

## 当前门禁状态（2026-08-30）

| 层级 | 状态 | 本轮结果 |
| --- | --- | --- |
| PR | PASS | `npm test`：30 个文件通过、10 个环境项跳过，124 项通过、37 项跳过；核心/Renderer 类型检查、生产构建、零告警 lint、生产依赖审计、Helper Python 编译、shell 语法与 `git diff --check` 通过。新增 P1 单测走通固定 Scope、真实 `package → owns_file → verify(package_db)` 链及 `MISMATCH` 规则裁定。 |
| MERGE | PASS | 五套 Docker Lab 共 11/11 通过，并新增 sudoers/doas/polkit 与 `sshd -T` 默认上下文事实断言；GUI E2E 16/16：investigation 4/4、remediation 3/3、recovery 6/6、grant 生命周期 3/3；Debian 12 动态场景 5/5，包含 P1 新事实断言。REMEDIATE 默认关闭不完整账户处置的 fail-close 行为由 E2E 明确验证。 |
| RELEASE / RE2 | PASS | macOS ARM64 与 Ubuntu 22.04 ARM64 均验证实际匹配及不支持反向引用时的 `INVALID_ARGUMENT`；见 `acceptance/RE2_MATRIX_2026-08-25.md`。 |
| RELEASE / 真实 VM v2 | PASS_WITH_LIMITATIONS | Ubuntu 24.04.4 ARM64 上将 Helper 升级到 Manifest `2.1.0` 后，P1 smoke 4/4、journald 回归 1/1；新 Namespace、effective web root、固定 Scope 与 package verify 均通过。首次 smoke 因目标缺 nginx 与无害 Web fixture 失败，补齐发布依赖与安全夹具后按原断言重跑通过，夹具随后清理。此前五类 QUICK、联合 STANDARD 与小上下文 DEEP 仍由 2.0.0 基线记录承担，未冒充为 P1 重跑。详见 `acceptance/VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md`。 |
| RELEASE / 模型能力统计 | PASS | Manifest/Helper `2.1.0` 上重新创建并冻结 `siliconflow/deepseek-ai/DeepSeek-V4-Flash` 的 novel malicious + benign 已完成任务：事实可达率与 novel recall 均为 100%，截断损失、MODEL NOT_CONCLUDED、Preset partial、非法工具调用和良性误报均为 0%。七项门槛全部通过，结果见 `acceptance/MODEL_EVAL_P1_2026-08-30.md`。 |

| ID | 层级 | 自动化/验收归属 | 主要断言 |
| --- | --- | --- | --- |
| INV-01 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts` | 工具表只有通用原语；Helper argv 静态白名单拒绝任意 verb |
| INV-02 | PR + MERGE | `protocol-v2-invariants.test.ts`；`known-hash-registry.test.ts`；`host-helper.test.ts` | Predicate 字段/类型/深度 fail-close；YARA 仅固定 RuleSetRef；known_hash_set 仅控制端版本化 DATASET 引用，源码、路径与自由哈希输入被拒 |
| INV-03 | PR | `protocol-v2-invariants.test.ts` | Helper 未知 namespace/field/relation 只能被裁剪并记录异常 |
| INV-04 | PR | `protocol-v2-invariants.test.ts`；`remediation-invariants.test.ts` | 引用严格来自 Fact Store；跨 task/cursor 和替换 Evidence 参数被拒 |
| INV-05 | PR | `protocol-v2-invariants.test.ts`（含目标指纹不符的 FactBatch 整批拒绝负例）；`v2-human-grants.test.ts` | Fact/Object/Grant 均绑定 task、epoch、target fingerprint |
| INV-06 | PR | `protocol-v2-invariants.test.ts` | 五类本地视图仅暴露白名单字段；storagePath、artifactToken 与跨 task 查询被拒 |
| INV-07 | PR + MERGE | `protocol-v2-invariants.test.ts`（read 与 `match includeContext` 共用同一条链路：DENIED_TEXT、无 Grant 的 SENSITIVE_TEXT、非 file 引用一律拒绝且不触达目标，批次内任一对象缺授权即整体失败且不计费；length 上限由工具 Schema 承担）；`host-helper.test.ts`（目标端拒绝目录等特殊文件、O_NOFOLLOW 拒绝符号链接、超限 length 返回 `INVALID_ARGUMENT`；命中上下文按字节偏移标注、脱敏并受总长上限约束） | v2 read 与 match 命中上下文只接受绑定 file identity/locator 的普通文件；DENIED_TEXT、特殊文件和超限 length 被拒 |
| INV-08 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts`；`evidence-stream.test.ts` | 模型侧只见 Evidence 元数据；Artifact token 仅停留在 Controller/Helper 传输边界 |
| INV-09 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts` | SECRET 投影为 presence/hash；进程环境不返回值；SENSITIVE 遵循 exposure |
| INV-10 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts` | Controller 先 reserve；Helper 拒绝无效 Reservation |
| INV-11 | PR + MERGE | `data-sanitizer.test.ts`；`protocol-v2-wire.test.ts`；`host-helper.test.ts`（match 的 1 MiB 扫描窗口写成 `BYTE_LIMIT` gap；enumerate 页内源变化返回 PARTIAL + `SOURCE_CHANGED` + 可续游标） | 截断返回合法 JSON/游标或 CoverageGap；PARTIAL 无 Gap 被拒；不可继续时结构化声明 |
| INV-12 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts`（分页按稳定身份排序，两页不重不漏；cursor 绑定 epoch、请求摘要与 source generation） | Query 快照分页不跳 Fact；自定义排序固化剩余顺序；预算试算不落孤儿引用；远程分页有隐式稳定身份排序键 |
| INV-13 | PR | `protocol-v2-invariants.test.ts` | FactBatch/ObjectRef/ToolRun 终态同一事务提交，失败不泄漏半批事实 |
| INV-14 | PR + GUI | `report-service.test.ts`；`task-workspace-stream.test.tsx`（GUI 覆盖标签下显式渲染 `INCOMPLETE：…` 与 `MODEL: NOT_CONCLUDED：…`）；GUI E2E（IPC 快照层 Coverage/Assessment） | PARTIAL/ERROR/UNKNOWN 显示 INCOMPLETE；MODEL NOT_CONCLUDED 独立呈现 |
| INV-15 | PR | `protocol-v2-invariants.test.ts` | 规则入口只查询当前 PresetRun 来源 Fact |
| INV-16 | PR + GUI | `v2-human-grants.test.ts`；`approval-service.test.ts`；GUI grant E2E（批准后 Grant 绑定申请对象并 ACTIVE、撤销后立即失效且理由进审计） | Active Grant 持久且可撤销；Pending 中断过期；Write Approval 一次消费 |
| INV-17 | PR + GUI | `v2-human-grants.test.ts`；GUI grant E2E（拒绝后无 Grant、`InvestigationGap(GRANT_DENIED, SENSITIVE_READ)` 落库、审计只有 denied 没有 activated） | Grant 拒绝固化 InvestigationGap，投影不转成安全结论 |
| INV-18 | PR | `threat-intel.test.ts`；`protocol-v2-invariants.test.ts` | 私网/保留地址不上送；自由 IOC 被拒；外部事实不能单独确认恶意 |
| INV-19 | PR + GUI | `v2-human-grants.test.ts` | HUMAN/MODEL 只追加 Assessment 与关系，RULE Assessment 保持不可变 |
| INV-20 | PR | `report-service.test.ts` | 报告必须包含投影要求项并拒绝投影外引用；失败回退确定性模板 |
| INV-21 | PR + MERGE | `protocol-v2-invariants.test.ts`；`remediation-invariants.test.ts`；`host-helper.test.ts` | SCAN 工具表无写工具；Helper 写 gate 再次拒绝 SCAN |
| INV-22 | PR + GUI | `remediation-invariants.test.ts`；GUI remediation E2E | Approval 绑定 task/target/tool/args/action，消费后不可复用 |
| INV-23 | PR + GUI | `recovery-invariants.test.ts`；GUI recovery E2E | STARTED/UNKNOWN 写回执不自动重放，任务保留 recoveryRequired |
| INV-24 | PR | `report-service.test.ts`；`runtime-store.test.ts`；Application/Store 运行期校验 | v1 历史任务只读：不能进入 v2 bootstrap、恢复或生成新报告；v1 Finding/coverage 平面已删除，历史任务只保留元数据、Evidence 与既有报告 |
| INV-25 | PR + MERGE | `protocol-v2-invariants.test.ts`；`linux-ir.test.ts`（事件 `sourceId` 全部可在 `log_source` 解析；跨时间窗口同一事件 identity 不变） | 同一稳定身份的强化 Fact 复用 ObjectRef，不创建新引用；跨 namespace 的同名身份字段共用同一派生，事件游标由内容派生而非页内序号 |
| INV-26 | PR + MERGE | `protocol-v2-invariants.test.ts`；`host-helper.test.ts` | task_ioc 首次物化仅允许 SYSTEM；Helper 不声明/枚举该 namespace |
| INV-27 | PR | `protocol-v2-invariants.test.ts`；`protocol-v2-wire.test.ts`（InvestigationGap 码与缺 `resumable` 的 Gap 在 Wire 层被拒） | CoverageGap 与 InvestigationGap 使用不相交白名单，Wire 未知 Gap 被拒 |
| INV-28 | PR | `protocol-v2-invariants.test.ts`；`config-remote-budget.test.ts` | 远程、本地查询、内容、Grant、外部情报独立持久计费，耗尽形成 Gap |

MERGE 额外门禁：`tests/fixtures/v1-v2-equivalence.json` 的五类冻结 v1 能力子集必须由 Docker v2 通用原语全部到达，且不能重新引入按检测问题命名的 Helper 操作。

发布前还必须执行：Docker 五类 Lab、四套 GUI E2E（可用 `npm run test:gui:all` 串行执行）、真实 VM smoke、`npm run test:acceptance:re2`、YARA Docker 平台路径与模型能力统计评测。它们不是本地 `npm test` 的隐式成功项。RE2 门禁必须同时验证实际匹配与不支持反向引用时的 `INVALID_ARGUMENT`，禁止回退成 Python `re`。
