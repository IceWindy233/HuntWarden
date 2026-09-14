# 自主调查端到端评测

`scenario-catalog.json` 是冻结的 M2 最小矩阵：4 个恶意、4 个良性和 4 个受限/故障场景。控制端回放验收执行真实的 Fact 提交、增量规则、发现器、Playbook、Action 调度器、Evidence/义务校验、完成快照和评测器；预算耗尽与目标断开场景还必须保存失败的 Action Attempt。它验证控制端状态机，不替代目标 collector 和 SSH 实测。

```bash
npm run test:acceptance:investigation
```

目标端链路由 `npm run test:acceptance:real-world` 和 `npm run test:docker` 验证，覆盖动态路径、未知账户、外连进程、解释器脚本、Cron、删除后运行映像、SSH Match 信任上下文、systemd drop-in 与 Evidence artifact。真值文件不进入 Helper 响应或模型上下文。

## 批跑：运行端不接收真值

`run:investigation` 只执行授权调查，不评分。先准备仓库外配置、TargetConfig 和无答案运行清单；配置中的 `storage.baseDir` 必须在仓库外，`storage.databaseFile` 必须是无目录部分的单文件名，指定数据库必须尚不存在。输出父目录须已存在，`--output-dir` 本身必须不存在。目标端必须部署与固定提交匹配的 Helper，并完成带外 Host Key 核对。

TargetConfig 使用 `host`、`port`、`username`、`hostFingerprint`、`privateKeyPath`、`knownHostsPath`，私钥和 known_hosts 使用绝对路径；字段示例见 [`target.example.json`](../platform/target.example.json)。运行目录含本地输入和场景日志，不应作为脱敏发布证据直接公开。

运行清单为严格 schema v1；例如以下是单案例 `DEVELOPMENT` 输入，不是正式盲测：

```json
{
  "schemaVersion": 1,
  "suiteId": "investigation-development",
  "evaluationMode": "DEVELOPMENT",
  "profile": "DEEP",
  "timeWindowHours": 24,
  "cases": [{
    "caseId": "case-001",
    "runKind": "FIRST",
    "targetFile": "target.json",
    "checks": ["linux_intrusion_triage"],
    "entryMode": "ZERO_IOC"
  }]
}
```

`targetFile` 相对运行清单解析；`profile` 为 `QUICK|STANDARD|DEEP`，`checks` 使用五个既有调查类别。`ZERO_IOC` 必须没有 IOC；`SINGLE_LEAD` 必须在 `iocs.hash|domain|ip|path|processName` 中合计恰好一个字符串数组元素。不得加入 disposition、expectedFacts、答案路径或自由文本提示。每个 `caseId` 唯一；`RETRY` 必须以 `retryOfCaseId` 引用此前的 `FIRST`，保持入口、类别数组和 IOC 不变，不得把重跑改记为首跑。

```bash
HUNTWARDEN_INVESTIGATION_CONFIRM=I_HAVE_AUTHORIZATION npm run run:investigation -- \
  --config /outside/repository/runner/config.yaml \
  --manifest /outside/repository/runner/run-manifest.json \
  --controller /outside/repository/scenario/controller \
  --output-dir /outside/repository/runner/run-001
```

场景已另行准备时可省略 `--controller`；提供时必须是明确授权、仓库外的绝对可执行文件。批跑顺序调用 `controller prepare <caseId>` / `controller cleanup <caseId>`，每次上限 180 秒，工作目录为 controller 所在目录，输出写入各案例日志。仅继承 `PATH`、`HOME`、`TMPDIR`、`LANG`、`LC_ALL`、`LC_CTYPE`、`TZ` 环境变量，不转交模型凭据；但这不是进程或文件系统沙箱。场景部署器、真值和 controller 日志仍须由评分方隔离保管，不放入目标授权目录、Helper 响应或模型上下文，不得借 controller 泄露答案。

输出独占创建 `run-input.json`、`events.jsonl` 和 `run-result.json`，记录提交/干净状态、配置/清单/Helper 摘要及实际 Task/Epoch；案例 `epochs` 保留实际 Epoch 的起止提交、干净状态和 Helper 摘要，正式运行身份不符记为失败。事件逐条同步落盘；SIGINT/SIGTERM 会停止批次、尝试清理并保留失败记录，强制终止后也应保留已有账本。失败、未启动案例和未取得 Task/Epoch 的首跑不能删除或伪造；活动任务不会被自动恢复为另一次 `FIRST`。`FINISHED` 只表示批跑完成，不代表调查评分通过。`BLIND_RELEASE` 拒绝脏工作树，且批跑不允许用 `HUNTWARDEN_BUILD_COMMIT` / `HUNTWARDEN_BUILD_CLEAN` 覆盖构建身份。

## 评分：独立真值绑定实际任务

评分方保管的真值清单沿用 evaluator schema v2，但每个案例不得预填 `taskId` / `epochId`；`manifest.example.json` 可供字段参考。调查结束后，评分方将完整运行结果与冻结真值绑定。真值文件、归档原件和输出的真实父目录都必须在 `--run` 的真实所在目录之外，不能借符号链接绕过隔离。以下为 `DEVELOPMENT` 的调用：

```bash
npm run prepare:investigation-evaluation -- \
  --truth /outside/repository/scorer/truth.json \
  --run /outside/repository/runner/run-001/run-result.json \
  --output /outside/repository/scorer/evaluation-manifest.json
HUNTWARDEN_DATA_DIR=/outside/repository/runner/data HUNTWARDEN_DATABASE_FILE=runtime.db \
  npm run eval:investigation -- \
  /outside/repository/scorer/evaluation-manifest.json \
  /outside/repository/scorer/evaluation-result.json
```

数据库目录/文件必须与批跑配置一致；评分清单和评分结果输出文件都必须尚不存在。准备器核对 suiteId、模式、提交、全部计划案例数量和 FIRST/RETRY 关联，只绑定真实 Task/Epoch，不评分也不声明通过。案例未形成 Task/Epoch 或批次未跑全时会阻塞，不能裁掉失败首跑后继续计分。正式准备还须提供 `--truth-archive /outside/repository/scorer/truth-archive.tar`，核对原件 SHA-256 及真值在首次运行前冻结的时间。

正式归档使用 tar 或 tar.gz，固定根成员名 `truth.json`；读取时不解包落盘。该成员同样不得含 `taskId` / `epochId`，仅可省略 `truthSet.archiveSha256` 以避免摘要自引用。外部 `--truth` 必须带真实归档摘要，其完整内容须与补入该摘要后的归档真值严格一致；不能拿任意归档的摘要为另写的答案背书。

`BLIND_RELEASE` 评分必须再次传入原运行账本与同一真值归档；不能因为已运行 prepare 就省略。位置参数仍为 `<manifest.json> [result.json]`，选项放在它们之后：

```bash
HUNTWARDEN_DATA_DIR=/outside/repository/runner/data HUNTWARDEN_DATABASE_FILE=runtime.db \
  npm run eval:investigation -- \
  /outside/repository/scorer/evaluation-manifest.json \
  /outside/repository/scorer/blind-result.json \
  --run /outside/repository/runner/run-001/run-result.json \
  --truth-archive /outside/repository/scorer/truth-archive.tar
```

正式评分重新核对归档内容、完整 FIRST/RETRY 分母和 Task/Epoch 绑定，再从数据库读取每个任务的全部实际 Epoch，检查起止提交/干净状态、匹配 Helper 及时间落在冻结运行区间内，不信任手填账本中的成功状态。结果的 `runIdentity`、`qualificationFailures` 和各案例 `epochs` 共同供发布门禁核对。`DEVELOPMENT` 保持前面的无附加选项调用，不接受正式评分的 `--run` / `--truth-archive`。

真值不能在批跑前交给运行端。准备器不创造独立维护者、所有者确认或新的真值归档；不能把开发结果改写为 `BLIND_RELEASE`。正式资格只接受独立评分方事前冻结、隔离且可外部复核的真值，以及同一干净固定提交、匹配 Helper 的真实执行证据。评测器从控制端数据库计算发现、关系到达、证据保全、义务闭合、受限识别、自主闭合、良性误报和 95% Wilson 区间。

清单 schema v2 要求记录目标环境、提交、控制端/Helper/Manifest/规则/流程版本和预算档位。每个案例用 `runKind=FIRST|RETRY` 标识执行轮次；重试必须用 `retryOfCaseId` 引用同一清单中的首次运行，并保持首次真值定义不变。发布阈值只使用 `FIRST` 总体，`RETRY` 另存于 `retryMetrics`，不能用重跑结果抬高首跑成绩。结果保留每次 Action Attempt 的状态和错误，失败按 `COLLECTION_MISSING`、`INVESTIGATION_NOT_REACHED`、`ADJUDICATION_MISSING`、`PRESERVATION_FAILED`、`OBLIGATION_INCOMPLETE` 和 `EXPECTED_LIMIT_NOT_RECORDED` 分层归因。

正式清单必须设置 `evaluationMode=BLIND_RELEASE`，并声明真值归档 SHA-256、冻结时间、互不相同的维护者与运行者，以及真值未进入目标授权、Helper 或模型上下文的隔离事实。解析器会拒绝少于 100 个恶意首跑、100 个良性首跑或没有独立受限首跑的总体，也拒绝把最低采集覆盖率、恶意场景发现率或证据保全率设为低于 95%、把最高良性误报率设为高于 5%，或绑定非完整固定提交。实际指标仍由评测器计算并对照冻结门槛。恶意场景发现率只计入命中真值主体、引用该主体真值 Fact 且类别正确的有效风险结论；上述隔离与人员字段是可审计声明，真值归档和人员独立性仍须由发布方外部复核。

`manifest.example.json` 仅展示 `DEVELOPMENT` 清单格式。开发回放、小样本、未确认责任人或非干净提交结果均不能计为正式资格；不得复制控制端回放任务作为平台或真实样本成绩。
