# 真实业务 JVM 验收

该验收器通过生产 `SSHExecutor` 调用目标上的 Manifest 3.0.0 Helper，在持续真实 HTTP 业务请求期间连续执行 `jvm.tomcat.inventory`。它验证 JVM selector 唯一性、Attach 支持、每轮组件完整性、Gap、WireCost、冻结耗时门槛、Attach 前后稳定身份、请求失败率、绝对/相对 P95 和 Attach 后健康状态。

正式运行需要三个仓库外输入：

- 清单：冻结业务所有者声明摘要、JVM selector、HTTP 端点、请求门槛、Attach 次数与必需组件；
- TargetConfig：主机、端口、用户、带外核对过的 Host Key 指纹以及 SSH 私钥/known_hosts 的绝对路径；
- 可选请求头环境变量：清单只写环境变量名，密钥值不进入参数、结果或日志。

`manifest.example.json` 和 `target.example.json` 只是结构示例。`fixture` 固定为 `false`，正式清单应由业务所有者在调参前确认，并把其独立工作负载声明文件的 SHA-256 写入 `declarationSha256`。URL、selector 和组件名可能属于业务信息，因此正式清单与 TargetConfig 不应提交到仓库。

```bash
export HUNTWARDEN_BUSINESS_JVM_CONFIRM=I_HAVE_AUTHORIZATION
export BUSINESS_AUTHORIZATION='Bearer ...'
npm run qualify:business-jvm -- \
  --config /path/to/config.yaml \
  --manifest /path/to/business-jvm-manifest.json \
  --target /path/to/target.json \
  --output /outside/repository/business-jvm-result.json
```

命令只允许从干净固定提交运行。机器可读结果只保留提交、Manifest、输入清单摘要、业务声明摘要、attestor 摘要、聚合流量/Attach 指标、组件定义摘要和失败码；不会写出目标地址、URL、请求头、JVM 命令、类名、业务所有者、SSH 路径或响应正文。任何组件漏报、inventory Gap、成本异常、身份漂移、请求失败或门槛超限都会生成 `FAIL` 并以非零状态退出。

