# Tool Protocol v2 模型能力统计评测

该门禁分析已经由真实 Provider 完成的 v2 任务，不发起模型请求，也不读取 Evidence 原文。它从 RuntimeStore 的 Controller-only QuerySnapshot provenance、Coverage、Assessment、ToolRun、Audit 和消息 usage 计算：

- 事实可达率与查询截断损失；
- `MODEL: NOT_CONCLUDED` 与 Preset partial；
- 新颖恶意场景召回与良性场景误报率；
- 无效工具调用、Token、延迟和远程成本；
- 风险 RULE Assessment 的人工裁定与推翻数量。

## 执行流程

1. 在授权的隔离 Lab/VM 中，用同一待发布模型分别运行标注的恶意、良性任务；至少一个恶意案例必须是未写入 Preset/规则的 `novel` 场景。
2. 复制 `manifest.example.json`，填写每个已结束 v2 任务的 `taskId`、标签和预期 Model Fact。`expectedFacts` 必须描述确实应由目标产生的事实；评测器会把 FactStore 中不存在的标签判为语料错误，而不是模型漏检。
3. 执行：

```bash
npm run eval:model -- \
  --manifest acceptance/model-eval/manifest.release.json \
  --storage-dir "/path/to/HuntWarden/runtime" \
  --database-file runtime.db \
  --json docs/acceptance/MODEL_EVAL_YYYY-MM-DD.json \
  --markdown docs/acceptance/MODEL_EVAL_YYYY-MM-DD.md
```

`--storage-dir` 和 `--database-file` 可省略；省略时使用当前配置档的 `storage`。评估桌面端真实任务时应显式指向桌面端 RuntimeStore，避免误读默认开发库。执行前须退出持有该数据库写锁的 HuntWarden 实例。

只有七个阈值全部通过且没有语料错误时进程才返回 0。报告不包含目标地址、原始事实值、Evidence 路径、凭据或模型原始响应；`rowRefs` 仅保存在本地 QuerySnapshot，用于证明预期事实是否真的到达过模型查询结果。

示例清单中的路径和 Task ID 是不可执行占位符，禁止把它当作发布结果。阈值必须由发布负责人在执行前冻结，不能在看到结果后调低。

当前 P1 冻结清单为 `manifest.release.json`，对应 Manifest/Helper `2.1.0` 的 2026-08-30 真实 Provider 已完成任务；发布结果见 [`MODEL_EVAL_P1_2026-08-30.md`](../../docs/acceptance/MODEL_EVAL_P1_2026-08-30.md)。基础发布语料用 `acceptance/vm/install-model-eval-fixtures.sh --install` 安装。`--install-effective-root` 是独立的 loopback-only P1 专项夹具；若其 Coverage 不是 `COMPLETE`，不得把该任务混入冻结统计清单。两类夹具都由 `--remove` 统一校验 sentinel 后清理。
