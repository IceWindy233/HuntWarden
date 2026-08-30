# HuntWarden 真实 VM 只读冒烟

该入口用于授权临时 Linux VM 的 v2 只读验收；当前发布门槛为 Ubuntu 24.04 ARM64，Rocky Linux 9 x86_64/SELinux 保留为后续非阻塞兼容性验证。它只调用以下固定 v2 只读/证据动词：

最近一次 P1 增量记录：[`Ubuntu 24.04.4 ARM64 v2 P1 验收`](../../docs/acceptance/VM_UBUNTU_24.04_ARM64_V2_P1_2026-08-30.md)，结果为 `PASS_WITH_LIMITATIONS`。完整 GUI/Provider v2 基线见 [`2026-08-26 记录`](../../docs/acceptance/VM_UBUNTU_24.04_ARM64_V2_2026-08-26.md)；P1 已重新执行冻结 Provider 模型评测，但未重跑五类 QUICK/STANDARD/DEEP 的全部 GUI Profile 矩阵。

- `capabilities`
- `enumerate`（host/process/file/account/cron_entry/unit/persistence/jvm）
- `project`
- `read`
- `verify`
- `collect`（仅固定良性夹具；SFTP 校验后立即释放远端 Artifact）

它不会运行 `probe` 或任何处置写操作，也不能替代 GUI 中五类检测包的 QUICK/STANDARD/DEEP 完整验收。`collect` 会在 Helper 固定 spool 中短暂创建只读 Artifact，不修改源对象。

## 前置条件

1. 目标必须是你拥有或明确获授权的临时 VM。
2. 使用官方镜像并记录镜像 ID、架构和内核。
3. 在 VM 控制台或云平台带外通道核对 SSH Host Key，再写入 `known_hosts`。
4. 按 [`host-helper/README.md`](../../host-helper/README.md) 安装 Helper 并完成自检。
5. 使用专用无交互 SSH 私钥；当前版本不支持 SSH Agent、加密私钥和 ProxyJump。

Rocky/Alma/RHEL 在 SELinux Enforcing 下安装时，`install-helper.sh` 会在系统提供 `restorecon` 时恢复 Helper、sudoers、状态目录和 Probe 的发行版默认标签。不要通过关闭 SELinux 让验收通过。

## 一键准备（Multipass，本机 arm64）

`bootstrap-multipass.sh` 把「起 VM → 注入公钥 → 带外核验 Host Key → 传仓库 → 安装 Helper 并自检 → 生成验收环境变量」串成一条命令。它不执行只读冒烟与 GUI 验收。

```bash
# 最低依赖那一遍：记录缺少 yara/auditd/JDK 时的能力降级
acceptance/vm/bootstrap-multipass.sh

# 补齐完整依赖后复检（YARA、auditd、JDK 与 nginx；Ubuntu 发布 Gate 要求两遍都留档）
acceptance/vm/bootstrap-multipass.sh --full-deps

# 验收完成后销毁
acceptance/vm/bootstrap-multipass.sh --destroy
```

指纹只经 `multipass exec` 的 hypervisor 通道读取，脚本内不使用 `ssh-keyscan`。私钥、`known_hosts` 与含真实地址的环境变量文件全部写入 `~/.huntwarden-vm`（`0700`，文件 `0600`），不进仓库。完整参数见 `--help`。

Rocky Linux 9 x86_64 不在本脚本范围内：在 arm64 主机上它需要模拟；后续如要扩展兼容性矩阵，应改用云上或 x86 主机，按下节的手动步骤执行。该项不阻塞 `v0.1.0`。

## 手动执行只读冒烟

Ubuntu 24.04 ARM64 示例：

```bash
export HUNTWARDEN_VM_CONFIRM_READ_ONLY=I_HAVE_AUTHORIZATION
export HUNTWARDEN_VM_HOST=203.0.113.10
export HUNTWARDEN_VM_PORT=22
export HUNTWARDEN_VM_USER=ubuntu
export HUNTWARDEN_VM_FINGERPRINT='SHA256:...'
export HUNTWARDEN_VM_PRIVATE_KEY=/absolute/path/to/operator_ed25519
export HUNTWARDEN_VM_KNOWN_HOSTS=/absolute/path/to/known_hosts
export HUNTWARDEN_VM_EXPECT_DISTRO=ubuntu
export HUNTWARDEN_VM_EXPECT_VERSION=24.04
export HUNTWARDEN_VM_EXPECT_ARCH=aarch64
npm run test:acceptance:vm
```

Multipass VM 还应执行 journald 身份与源代次专项验收。该测试会通过 Multipass 带外通道写入一条固定标签的无害 journal 记录，用于证明追加已有 journal 文件会推进 generation、事件 `sourceId` 可解析到 `log_source`，且 `relate log_source contains` 可到达该事件：

```bash
export HUNTWARDEN_VM_CONFIRM_JOURNAL_FIXTURE=I_HAVE_AUTHORIZATION
export HUNTWARDEN_VM_MULTIPASS_NAME=hw-vm
npm run test:acceptance:vm:journald
```

Rocky Linux 9 x86_64 使用：

```bash
export HUNTWARDEN_VM_USER=rocky
export HUNTWARDEN_VM_EXPECT_DISTRO=rocky
export HUNTWARDEN_VM_EXPECT_VERSION=9
export HUNTWARDEN_VM_EXPECT_ARCH=x86_64
npm run test:acceptance:vm
```

不要把上述环境值保存到仓库文件。文档网段地址仅用于示例，必须替换为你自己的测试 VM。

冒烟通过后，复制 [`docs/acceptance/VM_ACCEPTANCE_TEMPLATE.md`](../../docs/acceptance/VM_ACCEPTANCE_TEMPLATE.md)，继续在 GUI 中完成五类单项调查、联合调查、无害阳性样本、良性对照和手动报告，并把结果回填 [`docs/SUPPORT_MATRIX.md`](../../docs/SUPPORT_MATRIX.md)。

## 无害阳性与良性对照

仓库提供固定路径、可核验、可回滚的 WebShell 验收夹具。脚本只写入 `/var/www/html` 下两个明确文件；阳性文件只包含 Lab YARA 标记和字符串，不读取请求参数、不执行任何命令。良性文件包含安全关键词但不满足组合规则。

```bash
# 上传 acceptance/vm/install-safe-fixtures.sh 后，在临时 VM 中执行
sudo ./install-safe-fixtures.sh --install
./install-safe-fixtures.sh --status

# 完成 GUI 验收后清理；缺少固定 sentinel 时脚本会拒绝删除
sudo ./install-safe-fixtures.sh --remove
```

验收要求：阳性文件形成引用自身 Evidence 的 WebShell Finding；良性文件不得仅因 `system`/`base64` 等单一关键词被判为 HIGH/CRITICAL。真实主机禁止安装该夹具，只能用于可销毁或可恢复快照的授权临时 VM。

正式模型评测另使用 `install-model-eval-fixtures.sh`：`--install` 创建一个现有 YARA 不命中的、永久禁用分支内动态回调链，并启动普通 Java Sleeper；`--install-effective-root` 单独创建只监听 `127.0.0.1`、根目录位于 `/tmp` 的 P1 Web effective-root 专项夹具。`--remove` 在删除前核对文件 sentinel 与 Java PID 命令行，并统一清理两类夹具。正式任务完成后必须确认 `.phtml` 与 nginx 专项配置/Web 根均为 `ABSENT`、Sleeper 为 `STOPPED`；冻结清单和阈值见 [`acceptance/model-eval/README.md`](../model-eval/README.md)。
