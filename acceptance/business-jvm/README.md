# 真实业务 JVM 验收

该验收器通过生产 `SSHExecutor` 调用目标上的 Manifest 3.0.0 Helper，在持续真实 HTTP 业务请求期间连续执行 `jvm.tomcat.inventory`。它验证 JVM selector 唯一性、Attach 支持、每轮组件完整性、Gap、WireCost、冻结耗时门槛、Attach 前后稳定身份、请求失败率、绝对/相对 P95 和 Attach 后健康状态。

正式运行需要两个仓库外文件输入，以及按需提供的请求头环境变量：

- 清单：冻结业务所有者声明摘要、JVM selector、HTTP 端点与业务语义断言、请求门槛、Attach 次数与必需组件；
- TargetConfig：主机、端口、用户、带外核对过的 Host Key 指纹以及 SSH 私钥/known_hosts 的绝对路径；
- 可选请求头环境变量：清单只写环境变量名，密钥值不进入参数、结果或日志。

`manifest.example.json` 和 `target.example.json` 只是结构示例。`fixture` 固定为 `false`，正式清单须在调参前确认，并把单独保存的工作负载声明文件的 SHA-256 写入 `workload.declarationSha256`，记录真实 `attestor` 与 `attestedAt`。声明须确认非夹具业务属性、请求/只读 Attach 授权、端点语义、必需组件和冻结门槛。

本文的业务所有者指验收部署责任人。自有隔离部署可按[单维护者预发布执行边界](../release/README.md)由项目维护者委托 `AI/automation` 实际核对和声明，无需另找上游作者或生产用户代签；授权事实、执行者、时间和冻结清单摘要须另行留存，不构成上游或生产业务用户背书。下文所需的端点及组件确认同样适用这一范围，但非夹具业务属性和运行前冻结要求不变。

执行器不会代签或证明所有者身份；旧 `UNCONFIRMED`、`DEVELOPMENT` 及占位声明不能补签、改标为新资格，必须保留原件并另行生成新清单和新运行结果。URL、selector 和组件名可能属于业务信息，因此正式清单与 TargetConfig 不应提交到仓库。单项验收不替代稳定发布所需的同提交完整证据与 `BLIND_RELEASE`。

```bash
export HUNTWARDEN_BUSINESS_JVM_CONFIRM=I_HAVE_AUTHORIZATION
export BUSINESS_AUTHORIZATION='Bearer ...'
npm run qualify:business-jvm -- \
  --config /path/to/config.yaml \
  --manifest /path/to/business-jvm-manifest.json \
  --target /path/to/target.json \
  --output /outside/repository/business-jvm-result.json
```

命令只允许从干净固定提交运行，并核对目标 Helper 与当前源码摘要。机器可读结果只保留提交、Manifest、输入清单摘要、业务声明摘要、attestor 摘要、聚合流量/Attach 指标、组件定义摘要和失败码；不会写出目标地址、URL、请求头值、JVM 命令、类名、业务所有者、SSH 路径或响应正文。组件漏报、inventory Gap、成本异常、身份漂移或冻结门槛超限会生成 `FAIL` 并以非零状态退出。执行器按 `maxFailureRate` 判定流量门槛；发布资格另要求零请求失败且 `postAttachHealthVerified=true`，不能拿非零失败率的运行补正式证据。

## 不以 HTTP 200 代替业务成功

每个 `traffic.endpoints` 元素可配置 `expectedJson`，在基线、Attach 期间和 Attach 后请求中验证 JSON 业务语义。例如把下面的端点对象放入清单，实际 URL 和断言须由业务所有者确认：

```json
{
  "method": "GET",
  "url": "https://service.example/api/orders",
  "expectedStatus": 200,
  "headersFromEnv": { "Authorization": "BUSINESS_AUTHORIZATION" },
  "expectedJson": [
    { "path": ["status"], "equals": "ok" },
    { "path": ["data", "orders"], "minItems": 1 }
  ]
}
```

`path` 是逐层属性名数组，不是 JSONPath；`equals` 只接受字符串、数字、布尔值或 null，并作严格值比较；`minItems` 要求该路径为达到最小长度的数组。每项断言二选一，不能同时写 `equals` 和 `minItems`。路径缺失/值不符记录 `RESPONSE_JSON_MISMATCH`，非 JSON 记录 `RESPONSE_JSON_INVALID`；即使状态为 200 也计为请求失败。响应读取受 `maxResponseBytes` 限制，正文不写入结果。未配置 `expectedJson` 时只核对状态及响应读取边界，不能据此声称业务语义已验证；当前请求方法只支持 GET。

基线与 Attach 期间负载使用相同的 `concurrency`、`pauseMs`、端点轮询和语义断言模型，避免将串行基线与并发负载错误比较。基线按 `baselineRequests` 发起准确数量的请求，至少 20 次且不少于并发数；Attach 负载至少 100 次，连续 Attach 至少 12 次。并发、请求间隔、绝对/相对 P95 和 Attach 耗时上限应在运行前冻结；门槛失败必须保留原件，不得通过调宽阈值或重新标记结果抹去失败。

## ROOT Context 与实际 ClassLoader 边界

Probe 将 Tomcat 的空 Context 名规范为 `/`（ROOT），既从已加载类也从线程 ContextClassLoader 发现 WebappClassLoader，覆盖部分嵌入式 Tomcat 将业务类委派给父加载器的情况。组件身份按实际已加载类的 ClassLoader 记录，而不是一律冒用 WebappClassLoader；同名类的检查/导出必须使用已观察到的精确 loader，不能猜测或合并身份。

这不是对所有 Spring Boot、所有 Tomcat/JDK 组合或任意非 Tomcat 容器的支持承诺。Spring 映射依赖已初始化的 DispatcherServlet，反射受限、线程枚举上限及组件不可见仍可能产生 Gap，不能忽略后宣称完整。`attach.requiredComponents` 当前只接受 `componentKind`、`className` 和可选 `mappingContains`（匹配组件名或映射子串），没有 Context/ClassLoader 筛选参数；所有者需结合实际 ROOT Context/loader 观测确认业务组件和支持边界，而不是仅凭类名命中或业务 HTTP 200 宣布正式支持。

