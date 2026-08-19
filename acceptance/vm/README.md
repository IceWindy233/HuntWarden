# HuntWarden 真实 VM 只读冒烟

该入口用于 `v0.1.0` 的 Ubuntu 24.04 ARM64 与 Rocky Linux 9 x86_64/SELinux 验收。它只调用以下固定 READ 操作：

- `get_capabilities`
- `get_host_info`
- `capture_volatile_snapshot`
- `discover_web_roots`
- `list_java_processes`
- `list_privileged_accounts`
- `list_cron_entries`
- `list_systemd_units`
- `list_ssh_persistence`
- `list_shell_startup_files`

它不会运行写操作，也不能替代 GUI 中五类检测包的 QUICK/STANDARD/DEEP 完整验收。

## 前置条件

1. 目标必须是你拥有或明确获授权的临时 VM。
2. 使用官方镜像并记录镜像 ID、架构和内核。
3. 在 VM 控制台或云平台带外通道核对 SSH Host Key，再写入 `known_hosts`。
4. 按 [`host-helper/README.md`](../../host-helper/README.md) 安装 Helper 并完成自检。
5. 使用专用无交互 SSH 私钥；当前版本不支持 SSH Agent、加密私钥和 ProxyJump。

Rocky/Alma/RHEL 在 SELinux Enforcing 下安装时，`install-helper.sh` 会在系统提供 `restorecon` 时恢复 Helper、sudoers、状态目录和 Probe 的发行版默认标签。不要通过关闭 SELinux 让验收通过。

## 执行

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

Rocky Linux 9 x86_64 使用：

```bash
export HUNTWARDEN_VM_USER=rocky
export HUNTWARDEN_VM_EXPECT_DISTRO=rocky
export HUNTWARDEN_VM_EXPECT_VERSION=9
export HUNTWARDEN_VM_EXPECT_ARCH=x86_64
npm run test:acceptance:vm
```

不要把上述环境值保存到仓库文件。文档网段地址仅用于示例，必须替换为你自己的测试 VM。

冒烟通过后，继续在 GUI 中完成五类单项调查、联合调查、无害阳性样本、良性对照和手动报告，并把结果回填 [`docs/SUPPORT_MATRIX.md`](../../docs/SUPPORT_MATRIX.md)。

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
