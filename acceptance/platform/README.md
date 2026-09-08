# 正式平台资格验收

`qualify:platform` 通过生产 `SSHExecutor` 和目标上的 Manifest 3.0.0 Helper 生成五个发布平台的脱敏机器可读证据。关键环境值来自 `host` 原语的目标观测：`distribution`、`distributionVersion`、`architecture`、`release`、`timezone`、真实 PID 1 的 `initSystem` 与内核 SELinux 状态 `selinuxMode`。执行器不会接受清单自行覆盖这些值。

每次运行还会完成以下动作：

1. 核对 Helper/Manifest 与八个取证原语能力；
2. 从清单给出的普通文件候选中选择一个，按对象身份 `collect`，经 SFTP 流式核对字节数和 SHA-256；
3. 重复 `artifact_release` 确认远端 Artifact 最终不存在；
4. 主动关闭 SSH，再建立新连接，核对 Host 稳定身份与完整 Capability 摘要未变化；
5. 按 `platformId` 内置且不可下调的发行版、版本、架构、systemd 与 SELinux 门槛给出 PASS/FAIL。

正式清单必须记录官方镜像来源、镜像 ID、镜像摘要、attestor 和带外 Host Key 声明。`manifest.example.json` 与 `target.example.json` 仅为结构示例；正式文件可能包含目标信息，不提交仓库。每个平台在独立官方镜像实例上运行：

```bash
export HUNTWARDEN_PLATFORM_CONFIRM=I_HAVE_AUTHORIZATION
npm run qualify:platform -- \
  --config /path/to/config.yaml \
  --manifest /path/to/platform-manifest.json \
  --target /path/to/target.json \
  --output /outside/repository/platform-result.json
```

结果不写出主机名、地址、SSH 用户/路径、Evidence 源路径或内容，只保留目标观测的公开平台字段、镜像声明摘要、Capability 摘要、Evidence 摘要、重连与清理状态。五份 PASS 结果仍必须由发布资格清单逐项引用；另一架构、容器或同一实例改写环境字段不能替代对应平台。

