# 发布资格清单

`scripts/build-release.sh` 在安装依赖和生成资产前强制读取 `HUNTWARDEN_RELEASE_QUALIFICATION`。资格清单把当前完整 Git 提交绑定到五类脱敏机器可读证据及其 SHA-256；真实 Provider 项还独立绑定协议故障契约原件：

- Manifest 3.0.0 真实远端 Provider 的 Tool Call、故障降级和 Java Evidence 联合验收；
- `BLIND_RELEASE` 独立盲测结果，发布指标只取 FIRST，总体至少 100 恶意、100 良性和一个受限首跑；
- 非夹具真实业务 JVM 在业务流量下至少 12 次 Attach 的组件、成本、服务可用性和身份稳定结果；
- Ubuntu 24.04 ARM64/x86_64、Debian 12 完整 systemd x86_64、Rocky/Alma 9 x86_64 SELinux Enforcing 与 Amazon Linux 2023 x86_64 的正式记录；
- 固定提交上的全新安装、升级、组件权限/摘要、Action Receipt 保留、默认/彻底卸载、旧 schema 迁移回退与 Evidence 离线导出演练。

平台记录必须显式包含带外 Host Key、Evidence、恢复和清理通过状态。资格清单和结果不得包含 API Key、SSH 私钥、真实目标地址或 Evidence 正文。`qualification.example.json` 及各结果样例只是字段说明，摘要、提交和路径都是不可执行占位符；不能复制模板并手写通过状态。正式盲测、真实 Provider、真实业务 JVM、平台和运维结果必须分别由 `eval:investigation`、`qualify:provider`、`qualify:business-jvm`、`qualify:platform` 与 `qualify:operational` 生成。

带 SemVer 预发布后缀的版本（例如 `0.3.0-beta.1`）可以在未提供完整外部资格清单时生成测试资产，但构建必须写入 `PRERELEASE-NOTICE.txt` 并纳入 `SHA256SUMS`，GitHub Release 必须标记为 Prerelease。该通道不放宽稳定版本门禁，也不能作为正式支持或发布资格证据。

先在同一个干净固定提交运行协议契约，再使用同一 Provider/模型各完成一个 Linux 零 IOC 入侵分诊/持久化任务和一个 Java 运行态任务。两个任务都必须实际调用 `propose_hypothesis`、`propose_actions`，产生成功 MODEL Action/Attempt、模型 Assessment、完整发现检查点和冻结报告；Java Assessment 还必须引用当前 Epoch 完整且校验通过的 `jvm_class_bytecode` Evidence。随后执行：

```bash
npm run test:acceptance:provider-contract
npm run qualify:provider -- \
  --config /path/to/provider.yaml \
  --data-dir /path/to/huntwarden-data \
  --linux-task TASK-LINUX-ID \
  --java-task TASK-JAVA-ID \
  --provider-contract acceptance/provider-contract/result-local.json \
  --output /outside/repository/provider-real.json
```

schema v2 生成器会在在线冒烟前后分别解析端点，要求地址集合一致且全部全局可路由，再验证认证、HTTPS 网络、流式 Tool Call 与非零 usage，然后只从持久化记录计算结果。它还要求两个任务的 Epoch 固定当前控制端提交和当前 Helper 源文件 SHA-256，并拒绝脏工作树、回环/私网/非 HTTPS 端点、版本或模型身份不一致、未闭合任务、重复原语执行、非法工具调用、手工缺失 Evidence 引用等情况；输出只保留解析地址数量和判定，不含 URL、IP、凭据、目标地址、消息正文、Evidence 正文或本地路径。

真实业务 JVM 与每个目标平台分别按 [`acceptance/business-jvm`](../business-jvm/README.md) 和 [`acceptance/platform`](../platform/README.md) 的清单运行：

```bash
HUNTWARDEN_BUSINESS_JVM_CONFIRM=I_HAVE_AUTHORIZATION npm run qualify:business-jvm -- --manifest /path/to/business.json --target /path/to/target.json --output /outside/repository/business-jvm.json
HUNTWARDEN_PLATFORM_CONFIRM=I_HAVE_AUTHORIZATION npm run qualify:platform -- --manifest /path/to/platform.json --target /path/to/target.json --output /outside/repository/platform.json
```

业务 JVM 执行器实际发起基线/负载请求并在流量中连续 Attach，验证组件、Gap、WireCost、延迟、稳定身份及远端 Helper 摘要。平台执行器从 Helper 观测发行版、架构、PID 1 与 SELinux，核对远端 Helper 与当前源码摘要，实际采集和流式下载 Evidence，验证清理后不存在，并在主动 SSH 重连后复核 Host 身份与 Capability。

运维资格分两步执行。先在已授权、可销毁且已构建 Probe 的 Linux 环境运行目标端演练；脚本会改写并最终清理该环境的 `/usr/local/libexec/huntwarden-helper`、`/opt/huntwarden`、`/var/lib/huntwarden` 与 `/etc/sudoers.d/huntwarden`，不得在仍承载生产状态的主机上运行：

```bash
sudo acceptance/operational/qualify-host.sh \
  --executor-user <ssh-user> \
  --commit "$(git rev-parse HEAD)" \
  --output /outside/repository/operational-host.json
```

再准备一份包含至少一个带 Artifact Evidence 的旧 schema 数据库副本，以同一干净提交运行控制端迁移、回退和导出。命令拒绝当前 schema、新建空库、受管数据目录内的输出和已存在的导出目录：

```bash
npm run qualify:operational -- \
  --data-dir /path/to/legacy-data-copy \
  --database runtime.db \
  --task TASK-ID \
  --host-result /outside/repository/operational-host.json \
  --export-directory /outside/repository/evidence-export \
  --output /outside/repository/operational.json
```

完整步骤及破坏性边界见 [`acceptance/operational`](../operational/README.md)。

```bash
npm run release:qualification-check -- --qualification /path/to/qualification.json
HUNTWARDEN_RELEASE_QUALIFICATION=/path/to/qualification.json npm run release:local
```

校验器会把每个引用相对于资格清单所在目录解析，拒绝绝对路径和目录越界，先核对 SHA-256，再检查每份证据的当前 HEAD、Manifest、结果语义和所有必需组合。它还会核对 Provider 故障契约、目标端运维脚本/Helper 摘要、数据库事务前备份、旧任务读取、回退和 Evidence 导出清单。旧提交、协议夹具冒充真实 Provider、小样本、容器替代正式平台、手写运维布尔值、缺失恢复或清理记录都会失败关闭。

资格通过后，发布构建会从干净 HEAD 生成 `dist/build-identity.json`，验证该文件进入 `app.asar`；运行时把其提交写入新 Epoch。发布自检生成的 `COMPONENTS.json` 还会记录构建身份、应用、Manifest、Helper、调查引擎、规则注册表、流程包注册表与 Probe 版本，并对控制端、协议、调查/发现/评测、规则和流程包源码树生成按路径排序的确定性 SHA-256。
