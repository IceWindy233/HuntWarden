# 自主调查端到端评测

`scenario-catalog.json` 是冻结的 M2 最小矩阵：4 个恶意、4 个良性和 4 个受限/故障场景。控制端回放验收执行真实的 Fact 提交、增量规则、发现器、Playbook、Action 调度器、Evidence/义务校验、完成快照和评测器；预算耗尽与目标断开场景还必须保存失败的 Action Attempt。它验证控制端状态机，不替代目标 collector 和 SSH 实测。

```bash
npm run test:acceptance:investigation
```

目标端链路由 `npm run test:acceptance:real-world` 和 `npm run test:docker` 验证，覆盖动态路径、未知账户、外连进程、解释器脚本、Cron、删除后运行映像、SSH Match 信任上下文、systemd drop-in 与 Evidence artifact。真值文件不进入 Helper 响应或模型上下文。

正式发布评测生成的 `manifest.release.json` 只引用已完成的真实任务，不提交占位结果，也不包含目标端可读的答案路径。运行端只获得主机、选定类别和零 IOC/单线索入口。场景部署器与真值存放在目标授权目录之外；评测器在调查结束后从控制端数据库计算发现、关系到达、证据保全、义务闭合、受限识别、自主闭合、良性误报和 95% Wilson 区间。

```bash
HUNTWARDEN_DATA_DIR=./data npm run eval:investigation -- acceptance/investigation/manifest.release.json result.json
```

清单 schema v2 要求记录目标环境、提交、控制端/Helper/Manifest/规则/流程版本和预算档位。每个案例用 `runKind=FIRST|RETRY` 标识执行轮次；重试必须用 `retryOfCaseId` 引用同一清单中的首次运行，并保持首次真值定义不变。发布阈值只使用 `FIRST` 总体，`RETRY` 另存于 `retryMetrics`，不能用重跑结果抬高首跑成绩。结果保留每次 Action Attempt 的状态和错误，失败按 `COLLECTION_MISSING`、`INVESTIGATION_NOT_REACHED`、`ADJUDICATION_MISSING`、`PRESERVATION_FAILED`、`OBLIGATION_INCOMPLETE` 和 `EXPECTED_LIMIT_NOT_RECORDED` 分层归因。

正式清单必须设置 `evaluationMode=BLIND_RELEASE`，并声明真值归档 SHA-256、冻结时间、互不相同的维护者与运行者，以及真值未进入目标授权、Helper 或模型上下文的隔离事实。解析器会拒绝少于 100 个恶意首跑、100 个良性首跑或没有独立受限首跑的总体，也会拒绝低于 95% 的发现/保全阈值、高于 5% 的良性误报阈值和非完整固定提交。上述字段是可审计声明；真值归档和人员独立性仍须由发布审阅者核对。

`manifest.example.json` 展示 `DEVELOPMENT` 清单格式。执行正式盲测后，使用上述 `BLIND_RELEASE` 门禁并把实际 taskId/epochId 写入本地 release manifest；不得复制控制端回放任务作为平台或真实样本成绩。
