# 发布资格清单

稳定版本的 `scripts/build-release.sh` 在安装依赖和生成资产前强制读取 `HUNTWARDEN_RELEASE_QUALIFICATION`。资格清单把当前完整 Git 提交绑定到五类脱敏机器可读证据及其 SHA-256；真实 Provider 项还独立绑定协议故障契约原件：

- Manifest 3.0.0 真实远端 Provider 的 Tool Call、故障降级和 Java Evidence 联合验收；
- `BLIND_RELEASE` 独立盲测结果，发布指标只取 FIRST，总体至少 100 恶意、100 良性和一个受限首跑；
- 非夹具真实业务 JVM 在业务流量下至少 12 次 Attach 的组件、成本、服务可用性和身份稳定结果；
- Ubuntu 24.04 ARM64/x86_64、Debian 12 完整 systemd x86_64、Rocky/Alma 9 x86_64 SELinux Enforcing 与 Amazon Linux 2023 x86_64 的正式记录；
- 固定提交上的全新安装、升级、组件权限/摘要、Action Receipt 保留、默认/彻底卸载、旧 schema 迁移回退与 Evidence 离线导出演练。

平台记录必须显式包含带外 Host Key、Evidence、恢复和清理通过状态。资格清单和结果不得包含 API Key、SSH 私钥、真实目标地址或 Evidence 正文。`qualification.example.json` 及各结果样例只是字段说明，摘要、提交和路径都是不可执行占位符；不能复制模板并手写通过状态。正式盲测、真实 Provider、真实业务 JVM、平台和运维结果必须分别由 `eval:investigation`、`qualify:provider`、`qualify:business-jvm`、`qualify:platform` 与 `qualify:operational` 生成。

带 SemVer 预发布后缀的版本（例如 `0.3.0-beta.1`）可以在未提供完整外部资格清单时生成测试资产，但构建必须写入 `PRERELEASE-NOTICE.txt` 并纳入 `SHA256SUMS`，GitHub Release 必须标记为 Prerelease。该通道不放宽稳定版本门禁，也不能作为正式支持或发布资格证据。

**单维护者预发布执行边界（2026-09-13）**：项目维护者已明确授权助手在自有隔离环境执行实际验收并整理下一预发布的发布文档，PR 由维护者完成。实际执行者须如实记为 `AI/automation`，不得冒签其他所有者，也不得称为独立第三方验证。这里的业务/平台所有者指验收部署的责任人；对于维护者有权控制的隔离部署，可由其委托自动化核对并声明，无需另找上游作者或生产用户代签，且不构成这些主体的背书。

每轮须在新的仓库外目录留存本次明确授权的原文或可追溯来源、授权范围与记录时间、实际执行者标识、声明核对时间及冻结输入清单的 SHA-256；`attestor`/`attestedAt` 如实记录声明者与核对时间，不能用授权日期冒充运行日期。平台官方镜像来源/摘要及本次串口等带外 Host Key 原件仍须实际核对，业务端点语义、必需组件和性能门槛仍须在新运行前冻结。所有新结果只能来自实际执行；旧 `UNCONFIRMED`、`DEVELOPMENT`、`PREPARATION`、失败及 FIRST 原件保持不变，不补签、不改标、不覆盖。

预发布文档应据实列出本轮观测、失败、未执行项、证据目录与摘要，以及仍未满足的稳定资格；整理并交付这些文档不表示稳定发布获准。稳定版本仍要求同一干净固定提交及匹配 Helper 的完整证据和 `BLIND_RELEASE`，其样本规模、FIRST/RETRY 统计与真值隔离门禁均不因单维护者授权而改变；此授权不赋予自建已知答案样本独立盲测资格。

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

## 汇集执行器原件

`release:assemble-qualification` 只给现有执行器产物建立相对路径与 SHA-256 引用，不执行验收、不代签 attestor，也不生成 PASS 结果。先把上述执行器原件及协议契约原件保存在同一个仓库外资格目录内；保持原始字节不变。`--inputs` 为以下路径映射，路径相对 inputs 文件解析；所有引用的真实路径必须位于 `--output` 所在目录之下：

```json
{
  "provider": "provider-real.json",
  "providerContract": "provider-contract.json",
  "blindEvaluation": "blind-evaluation.json",
  "businessJvm": "business-jvm.json",
  "operational": "operational.json",
  "platforms": {
    "ubuntu-24.04-arm64": "platforms/ubuntu-arm64.json",
    "ubuntu-24.04-x86_64": "platforms/ubuntu-x86_64.json",
    "debian-12-systemd-x86_64": "platforms/debian-x86_64.json",
    "rocky-or-alma-9-x86_64-selinux-enforcing": "platforms/rocky-x86_64.json",
    "amazon-linux-2023-x86_64": "platforms/amazon-x86_64.json"
  }
}
```

```bash
npm run release:assemble-qualification -- \
  --inputs /outside/repository/qualification/inputs.json \
  --output /outside/repository/qualification/qualification.json
```

输出父目录必须已存在且在仓库外，输出文件必须尚不存在。缺项、不可读文件、非法 JSON 或引用越界会写出 `status=BLOCKED`、失败原因及可用引用，并以非零状态退出；该文件不能交给发布构建。引用齐全时生成 schema v1 / Manifest 3.0.0 清单并立即调用 `release:qualification-check`；清单落盘不表示校验通过，仍须检查退出状态。

批跑与评分准备见[调查评测说明](../investigation/README.md)。assembler 不会把 `DEVELOPMENT`、`PREPARATION`、`UNCONFIRMED`、脏工作树或旧提交结果升级为正式证据。全部原件必须绑定同一干净固定提交和匹配 Helper；业务/平台声明按上述授权边界由实际责任人或获委托的执行者核对，独立盲测仍须满足原有资格，不能靠填写布尔值、改写结果或拷贝示例补齐资格。

```bash
npm run release:qualification-check -- --qualification /path/to/qualification.json
HUNTWARDEN_RELEASE_QUALIFICATION=/path/to/qualification.json npm run release:local
```

校验器会把每个引用相对于资格清单所在目录解析，拒绝绝对路径和目录越界，先核对 SHA-256，再检查每份证据的当前 HEAD、Manifest、结果语义和所有必需组合。它还会核对 Provider 故障契约、目标端运维脚本/Helper 摘要、数据库事务前备份、旧任务读取、回退和 Evidence 导出清单。旧提交、协议夹具冒充真实 Provider、小样本、容器替代正式平台、手写运维布尔值、缺失恢复或清理记录都会失败关闭。

正式盲测须由 `eval:investigation` 带 `--run` 与 `--truth-archive` 生成；仅提供 prepare 产物不够。发布门禁要求空 `qualificationFailures`、当前干净提交/Helper 的 `runIdentity`，以及与完整 FIRST/RETRY 总体对应的案例 `epochs` 起止身份，缺少这些字段的旧评分结果不能补写字段后复用。

资格通过后，发布构建会从干净 HEAD 生成 `dist/build-identity.json`，验证该文件进入 `app.asar`；运行时把其提交写入新 Epoch。发布自检生成的 `COMPONENTS.json` 还会记录构建身份、应用、Manifest、Helper、调查引擎、规则注册表、流程包注册表与 Probe 版本，并对控制端、协议、调查/发现/评测、规则和流程包源码树生成按路径排序的确定性 SHA-256。
