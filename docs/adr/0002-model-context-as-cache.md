# ADR-0002：模型上下文是缓存，SQLite 是事实源

- 状态：Superseded by [`TOOL_PROTOCOL_V2_DESIGN.md`](../TOOL_PROTOCOL_V2_DESIGN.md) §7
- 日期：2026-08-21

## 背景

> 本 ADR 保留 v1 历史决策。v2 已删除 `read_tool_result` / `search_tool_results` / `promote_tool_result_reference` 模型通道，改为 Manifest 规范化的 Fact Plane 与快照化 `query_facts`。

HuntWarden 的运行时用 `@earendil-works/pi-agent-core` 的低层 `Agent`，不使用带 compaction 的 `AgentHarness`：历史消息从 SQLite 全量无 LIMIT 回放（`src/storage/runtime-store.ts` `loadMessages`），上下文只增不减。每条工具结果按 `llmData.maxTextBytes`（默认 64 KiB）限额进入上下文；此前的实现是把 `JSON.stringify(details)` 按 UTF-8 字节硬切。

实测暴露了三个后果：

- 默认全选五类检测、8 个特权账户的普通主机上，注入模型的最低扫描块正好撑满 64 KiB 并被字节切断，`JSON.parse` 失败；5 个持久化源与 2 个分诊步骤的事实**完全没有进入模型上下文**，3 条已命中的确定性规则结论也一条都没进。
- 被丢弃的数据没有任何回取通道。完整 `details` 一直在 `tool_runs` 表里，模型却拿不到；重复调用原工具只会命中 `tool-factory` 的幂等短路，返回同一个开头。
- 单条满额工具结果约 16k token，`gpt-5.6-terra` 可用窗口约 268k，约 16 条即撑满，而 `maxToolCalls` 允许 100 次。

## 决策

把模型上下文当作**缓存**，把 SQLite 当作**事实源**，并给模型一条显式回取通道。

1. **结构化截断取代字节截断**（`src/agent/data-sanitizer.ts`）。超预算时丢弃数组尾部元素并写回 `status: "partial"`、`itemsOmitted`、warning；输出恒为合法 JSON。最低扫描块按"每个 outcome 的 items 配额"压缩而不是从尾部砍 outcome，使所有检测类别公平分享预算；`deterministicFindings` 序列化在最前且永不丢弃。
2. **脱敏移到序列化之前**，按字符串叶子与凭据键名处理。正则作用在 `JSON.stringify` 结果上时，字符串里的换行是 `\` + `n` 两个字符，`\s` 匹配不到，`[^\s,;]+` 会跨行吞掉后续真实代码（实测会删除 `@eval(...)`），并会吃掉 `"}` 破坏 JSON 结构。
3. **新增 `read_tool_result(toolCallId, offset)`**（`risk: "LOCAL"`）。按 `toolCallId` 分页回取本任务已落库的结构化条目。
4. **上下文淘汰取代 compaction**（`transformContext`）。超过 `agent.contextRetainTurns` 个回合的大体量成功工具结果，在发给 Provider 的上下文里换成携带 `toolCallId` 的存根。淘汰只作用于出站上下文，持久化的 `messages` 不变。
5. **任务内结果搜索与来源绑定引用提升。** `search_tool_results` 对本任务已落库条目先脱敏、再做有界字面量搜索；`promote_tool_result_reference` 只接受来源 `toolCallId + itemIndex + JSON Pointer + kind`，引用值完全从事实源读取。来源工具白名单、任务检测范围与各类稳定身份字段由代码校验，模型不能提交引用内容。

## 安全后果

这条通道**不放宽任何既有边界**，必须由测试守住：

- **Evidence 字节仍然完全不可达。** `read_tool_result` 只读本任务 `tool_runs.result_json` 中的结构化条目，并在返回模型前再次通过统一脱敏与字节预算；它不接受 `EV-` 引用，也不返回 `collect_file` / `dump_java_class` / `collect_process_executable` 落盘文件的任何内容。
- **只读本任务。** `RuntimeStore.getToolRun` 只按 `tool_call_id` 查，不带任务作用域；模型可达的回取路径必须走新增的 `getToolRunForTask`，否则一个跨任务 `toolCallId` 就能读到别的任务的采集结果。
- **不新增远程面。** 该工具是 `LOCAL` 风险，不发起 SSH、不新增 Helper 操作、不放宽任何参数白名单。
- **搜索不是任意数据库查询。** 不接受 SQL/正则表达式，不搜索 Evidence 文件，只扫描当前任务最近 500 条工具运行中的结构化 `items`；搜索前先统一脱敏，并有结构节点与结果数量上限。
- **引用提升不是任意对象创建。** 模型不能提供路径、PID、账户、哈希或 Endpoint，只能选择当前任务某个已落库对象的位置；不在允许来源工具、未选检测类别或缺少稳定身份字段时一律拒绝。
- **不触碰写门控。** SCAN 模式不注册写工具、一次性票据绑定参数指纹、`UNKNOWN` 回执强制 `ABORTED + recoveryRequired` 全部不变。
- **省略必须可见。** 任何被省略的条目都带 `itemsOmitted` 与 warning，`status` 降为 `partial`；`summary` 中的真实总数保持不变，模型可对比 `count` 与 `items.length`。"未看到"绝不允许被解读为"不存在"。

## 兼容性后果

- 新增配置键 `agent.contextRetainTurns`、`agent.plannerToolCallShare`、`agent.providerMaxRetries`；旧 Profile 由 `withIncrementalDefaults` 纯增量注入默认值，不拒绝加载。
- `sanitizeForLlm` 保留，只服务真正的纯文本载荷（崩溃恢复的远端回执）。结构化结果一律走 `serializeToolResultForLlm` / `encodeWithinBudget`。
- 最低扫描不再从模型工具表里移除自己用过的工具：移除后，依赖这些工具产出引用的深挖工具（`inspect_persistence_item`、`find_related_processes`、进程树等）在结构上不可调用——引用只存在于被省略的结果里，模型既拿不到也无法重新枚举。
- 存根保留 `toolCallId`、`toolName` 与 `details`，Provider 载荷的 `tool_calls` 与工具结果配对不受影响。

## 不采用 AgentHarness 的理由

`AgentHarness` 自带 compaction，但它引入自己的 session tree 持久化模型，与现有 `messages` 表、最低扫描的稳定 `CORE-` `toolCallId` 复用以及 `recover()` 的重放语义冲突。`transformContext` 配合 `read_tool_result` 能做到**无损**淘汰，代价远小于迁移。
