# 正式平台资格验收

`qualify:platform` 通过生产 `SSHExecutor` 和目标上的 Manifest 3.0.0 Helper 生成五个发布平台的脱敏机器可读证据。关键环境值来自 `host` 原语的目标观测：`distribution`、`distributionVersion`、`architecture`、`release`、`timezone`、真实 PID 1 的 `initSystem` 与内核 SELinux 状态 `selinuxMode`。执行器不会接受清单自行覆盖这些值。

每次运行还会完成以下动作：

1. 核对 Helper/Manifest 与八个取证原语能力；
2. 从清单给出的普通文件候选中选择一个，按对象身份 `collect`，经 SFTP 流式核对字节数和 SHA-256；
3. 重复 `artifact_release` 确认远端 Artifact 最终不存在；
4. 主动关闭 SSH，再建立新连接，核对 Host 稳定身份与完整 Capability 摘要未变化；
5. 按 `platformId` 内置且不可下调的发行版、版本、架构、systemd 与 SELinux 门槛给出 PASS/FAIL。

正式清单必须记录官方镜像来源、镜像 ID、镜像摘要、真实 `attestor`/`attestedAt` 和带外 Host Key 声明。自有隔离部署可按[单维护者预发布执行边界](../release/README.md)由项目维护者委托 `AI/automation` 实际核对和声明，保留授权事实、执行者、时间及冻结清单摘要；无需上游或生产用户代签，也不构成其背书或独立第三方验证。`manifest.example.json` 与 `target.example.json` 仅为结构示例；正式文件可能包含目标信息，不提交仓库。每个平台在独立官方镜像实例上运行：

```bash
export HUNTWARDEN_PLATFORM_CONFIRM=I_HAVE_AUTHORIZATION
npm run qualify:platform -- \
  --config /path/to/config.yaml \
  --manifest /path/to/platform-manifest.json \
  --target /path/to/target.json \
  --output /outside/repository/platform-result.json
```

结果不写出主机名、地址、SSH 用户/路径、Evidence 源路径或内容，只保留目标观测的公开平台字段、镜像声明摘要、Capability 摘要、Evidence 摘要、重连与清理状态。五份 PASS 结果仍必须由发布资格清单逐项引用；另一架构、容器或同一实例改写环境字段不能替代对应平台。

## macOS ARM64 本地准备（不是正式资格）

`prepare-qemu.py` 使用 `qemu-system-x86_64` 的 QEMU TCG 启动真实 x86_64 guest，不将 ARM64 主机改标为 x86_64。支持 `ubuntu|debian|rocky|amazon` 四个选项；Ubuntu ARM64 仍需独立实例。准备机需要 Python 3、QEMU、curl、SSH 工具和 macOS `hdiutil`，以及仓库中已构建的 Probe JAR；脚本不会代为构建缺失资产。只在授权的可销毁实例上运行：`observe` 会安装软件和 Helper，NoCloud 创建的准备账户具有免密 sudo。

固定官方镜像地址、版本与摘要见脚本 `SPECS`。`prepare` 同时核对官方校验列表和镜像实际摘要（Debian 为 SHA-512，其余为 SHA-256），另保存统一的 `imageSha256` 与镜像信息到 `image.json`。这是 HTTPS 官方校验列表信任，不声明已验证独立签名；摘要不符即阻塞，不能改用未经核对的镜像。

```bash
export PLATFORM_STATE=/outside/repository/platform-preparation
python3 acceptance/platform/prepare-qemu.py prepare ubuntu --root "$PLATFORM_STATE"
# 在进程监督器或专用终端中前台运行；该终端保持到 guest 停止。
python3 acceptance/platform/prepare-qemu.py run ubuntu --root "$PLATFORM_STATE"
```

另一个终端在同一状态目录观察并最终停止该 guest：

```bash
export PLATFORM_STATE=/outside/repository/platform-preparation
python3 acceptance/platform/prepare-qemu.py observe ubuntu --root "$PLATFORM_STATE" --timeout 1800
# 完成准备/取证后请求 QMP 关机，并等待 run 退出，再启动下一个平台。
python3 acceptance/platform/prepare-qemu.py stop ubuntu --root "$PLATFORM_STATE"
```

依次替换为 `debian`、`rocky`、`amazon`，不要并行运行 TCG guest。脚本持有用户级和状态目录级互斥锁，覆盖整个 QEMU 生命周期；`QEMU_STARTING` 仅表示进程已启动，不是系统就绪或资格通过。`run` 可选 `--disk-interface virtio-scsi`，默认 `virtio-blk`；两者的 NoCloud seed 都通过 virtio 挂载。

`observe` 从本次启动的串口日志读取 `HW_HOST_KEY`，写入 `host-key-console.json`、`known_hosts` 和 `target.json`，之后才启用严格 Host Key 校验的 SSH；不以 `ssh-keyscan` 自证身份，已信任密钥变化会拒绝覆盖。它检查 guest 的发行版、x86_64、真实 systemd PID 1，并要求 Rocky 保持 SELinux Enforcing，不能通过关闭 SELinux 消除失败。

官方 backing 镜像保持只读，overlay 虚拟容量至少为 `max(24 GiB, backing 镜像虚拟容量)`。不得缩小 overlay；若旧 overlay 小于 backing，先停止 guest、按 backing 容量扩容再启动，不得删掉失败记录来重做首跑。每次操作写入独立 `attempts/` 目录及准备账本，重复操作保留首次记录；查看最新 attempt，不要将旧的顶层样例误认为本轮结果。

Amazon Linux 2023 使用发行版原生 `java-17-amazon-corretto-devel`，不套用 Rocky 的 OpenJDK/YARA 包名。YARA 4.5.8 从脚本固定的上游源码提交下载，核对固定 SHA-256 后在 guest 编译，并保留 `yara-source.json` 与构建日志；不能用未固定版本替代。RE2 按 guest 原生 Python 版本选择固定 wheel，不擅自更换系统 Python。官方 AWS KVM 镜像在 macOS/TCG 上启动也不代表 AWS 对该虚拟化宿主的支持认证。

脚本结果始终属于 `phase=PREPARATION`；即使 `PREPARATION_READY`，仍为 `formalQualification=false`、`ownerAttestationPending=true`。生成的 manifest 特意保留 `officialImage.attestor/attestedAt=null`，不能直接当正式清单。平台部署责任人或上述获委托的执行者须实际核对官方镜像来源、校验列表/镜像摘要和本次串口 Host Key 原件，另存声明与新正式清单，不改写原准备记录或旧 `UNCONFIRMED`/`DEVELOPMENT` 结果；随后从干净固定提交部署匹配 Helper，运行上面的 `qualify:platform`。`PREPARATION_PARTIAL`、`BLOCKED`、未确认声明或安装自检成功都不能替代五平台的正式结果；单项结果也不替代稳定发布的同提交完整证据与 `BLIND_RELEASE`。

