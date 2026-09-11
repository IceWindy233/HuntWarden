# 真实 Provider 联合验收

该流程使用配置 YAML 和两个目标 YAML 创建真实 Linux、Java 调查任务，再由发布资格生成器复核运行库。所有 YAML、运行库和输出结果应放在仓库外；凭据只通过配置指定的环境变量进入进程。

## 1. 准备配置和目标

模型配置沿用完整 HuntWarden 配置，例如 `/secure/profile.yaml`。`model.authentication` 只保存环境变量名：

```yaml
model:
  source: custom
  provider: example-provider
  model: example-tool-model
  protocol: openai-completions
  baseUrl: https://provider.example/v1
  authentication:
    type: api-key-env
    apiKeyEnv: HUNTWARDEN_LLM_API_KEY
```

配置中的 `storage.baseDir` 必须指向仓库外的本次独立数据目录。Linux 和 Java 各准备一个目标 YAML：

正式 Java 链需要完成一次 inventory、最多 20 个 class inspect 和 20 个 class dump，因此 `budgets.preset.probeCalls` 必须至少为 `41`；当前默认值为 `64`。运行器会在创建任务前检查该门槛，避免执行到一半才因 Probe 预算耗尽。

```yaml
host: 192.0.2.10
port: 22
username: analyst
hostFingerprint: SHA256:replace-with-out-of-band-verified-fingerprint
privateKeyPath: /secure/operator_ed25519
knownHostsPath: /secure/known_hosts
```

目标文件严格拒绝额外字段，不能保存密码、私钥正文或 Provider 密钥。私钥和 `known_hosts` 路径必须为绝对路径。

## 2. 检查 Provider

```bash
HUNTWARDEN_LLM_API_KEY='由安全环境注入' npm run model:check -- --config /secure/profile.yaml
HUNTWARDEN_LLM_API_KEY='由安全环境注入' npm run model:smoke -- --config /secure/profile.yaml
```

`model:check` 不联网；`model:smoke` 只发送一个要求调用虚拟 `connection_probe` 的最小请求。

## 3. 创建两条真实任务

先提交全部代码并保持工作树干净，然后运行：

```bash
HUNTWARDEN_LLM_API_KEY='由安全环境注入' npm run qualify:provider:tasks -- \
  --config /secure/profile.yaml \
  --linux-target /secure/linux-target.yaml \
  --java-target /secure/java-target.yaml \
  --output /secure/provider-task-run.json
```

运行器固定任务类别、DEEP 配置、时间窗和验收提示，依次执行 Linux 零 IOC 调查与 Java 运行态调查。模型可见工具不包含八个直接远端原语；模型必须通过 `propose_actions` 建立持久化 Action，再由调度器执行原语。调度器对当前 Epoch 的相同成功调用复用既有结果，避免 Preset、确定性发现和模型动作重复触达目标。每条任务都必须生成报告，且 Task、Epoch、调查状态分别为 `COMPLETED`、`COMPLETED`、`CLOSED_WITH_FINDINGS` 或 `CLOSED_NO_OBSERVED_FINDING`。`LIMITED`、Provider 失败或报告失败会令命令失败，并在输出中保留对应任务 ID、状态和错误。

每次正式重试使用新的 `storage.baseDir` 和输出文件，保留 FIRST 记录，不覆盖失败轨迹。

## 4. 生成资格结果

从 `provider-task-run.json` 读取 Linux、Java 任务 ID，并使用当前提交生成的本机协议合同：

```bash
npm run test:acceptance:provider-contract

HUNTWARDEN_LLM_API_KEY='由安全环境注入' npm run qualify:provider -- \
  --config /secure/profile.yaml \
  --data-dir /secure/provider-run \
  --linux-task TASK-LINUX \
  --java-task TASK-JAVA \
  --provider-contract /secure/provider-contract.json \
  --output /secure/provider-real.json
```

`qualify:provider` 会再次在线冒烟，并核对 DNS、公网端点、两个任务的提议/动作/Assessment、发现检查点、完成快照、冻结报告、Java Evidence、控制端提交和目标 Helper 摘要。系统 DNS 全部返回 RFC 2544 `198.18.0.0/15` 透明代理 fake-IP 时，执行器使用经 TLS 校验的 DNS over HTTPS 获取资格地址，并在结果中保留解析来源和 fake-IP 证明；普通私网解析不会触发该回退。只有输出 `status: PASS` 才能作为发布证据。
