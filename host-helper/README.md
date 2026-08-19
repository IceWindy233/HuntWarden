# HuntWarden 目标端 Helper

Helper 是 root 所有的固定操作入口，只接受白名单操作名和 stdin JSON，不接受 Shell 字符串。

## 前置依赖与缺失影响

| 依赖 | 缺失后果 | 自检状态 |
| --- | --- | --- |
| `python3` >= 3.8 | Helper 无法运行（安装期直接拒绝，不会留下半装状态） | 安装期拦截 |
| `sudo` / `visudo` | 控制端无法以 root 调用 Helper，所有特权采集被拒 | `sudo` |
| `yara` | WebShell 规则扫描不可用，只剩启发式特征，已知家族漏报、误报率上升 | `yara` |
| `journalctl` + journal 存储 | journald 主导发行版（Rocky/RHEL/Alma）的认证与执行事件缺失，后门账户维度与事件时间线不完整 | `journal` |
| `auditd`（`auditctl`/`ausearch` + `/var/log/audit/audit.log`） | execve 执行事件缺失，事件时间线只剩文件落地与认证两个维度 | `auditd` |
| JDK（`jcmd`/`java`）与探针 JAR | 无法 attach 到 Tomcat JVM，Java 内存马运行时枚举与 Class Dump 不可用 | `javaAttach`、`tomcatProbe` |

Python 3.8 是硬下限：Helper 使用 `pathlib.Path.unlink(missing_ok=)` 等 3.8 引入的 API，更低版本会在运行期抛异常。

## 安装

安装脚本可从任意工作目录执行，源文件位置由脚本自身路径推导。

Debian / Ubuntu：

```bash
sudo apt-get install -y python3 sudo yara auditd
sudo ./host-helper/install-helper.sh --executor-user <SSH用户> --self-check
```

Rocky / AlmaLinux / Amazon Linux（`yara` 位于 EPEL）：

```bash
sudo dnf install -y epel-release && sudo dnf install -y python3 sudo yara audit
sudo ./host-helper/install-helper.sh --executor-user <SSH用户> --self-check
```

## 规则与探针下发

- **YARA 规则**：安装脚本把仓库 `rules/yara/webshell.yar` 下发到 `/opt/huntwarden/rules/webshell.yar`（`root:root 0644`），落地后校验 SHA-256 与源文件一致，不一致即安装失败。该路径由控制端 `webshell.remoteRulePath` 配置决定，两边必须一致。规则源缺失时脚本拒绝安装——没有规则的安装会让 `yara_scan_files` 在真机上直接报错。
- **Tomcat 探针**：默认取 `java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar`，下发到 `/opt/huntwarden/huntwarden-tomcat-probe.jar` 并同样校验 SHA-256。探针未构建时脚本**打印警告并跳过**（不静默），Java 内存马检测降级；补装方式：

```bash
npm run probe:build
sudo ./host-helper/install-helper.sh --executor-user <SSH用户> --self-check
```

规则或探针位于非默认位置时用 `--rule-source <webshell.yar>` / `--probe-source <jar>` 指定；显式指定的路径不存在会直接失败，不会降级为跳过。

## 目标端布局

| 路径 | 属主与权限 | 用途 |
| --- | --- | --- |
| `/usr/local/libexec/huntwarden-helper` | `root:root 0755` | Helper 本体 |
| `/opt/huntwarden/rules/webshell.yar` | `root:root 0644` | WebShell YARA 规则 |
| `/opt/huntwarden/huntwarden-tomcat-probe.jar` | `root:root 0644` | Tomcat 探针 |
| `/etc/sudoers.d/huntwarden` | `root:root 0440` | 只允许执行用户免密调用 Helper |
| `/var/lib/huntwarden/actions` | `root:root 0700` | Action Receipt（处置回执） |
| `/var/lib/huntwarden/artifacts` | `root:<执行用户组> 0711` | Evidence 暂存；`0711` 必须与 Helper `prepare_artifact_dir()` 一致 |

## 升级

重复执行安装脚本即为升级，幂等：

- 打印 `旧版本 → 新版本`（读取已装 Helper 的 `HELPER_VERSION`）。
- 只替换 Helper、规则、探针与 sudoers，逐项打印组件清单与 SHA-256。
- `/var/lib/huntwarden/actions` 下的 Action Receipt 全程只读，不会被删除或改写，并在清单中打印保留数量。

> **警告**：Action Receipt 是 REMEDIATE 处置回滚与崩溃恢复的唯一依据。不要手工删除 `/var/lib/huntwarden/actions`，删除后已执行的隔离/禁用动作无法回滚。只有 `uninstall-helper.sh --purge-state` 会清除它。

## 自检

```bash
sudo ./host-helper/self-check-helper.sh --executor-user <SSH用户>
```

自检以执行用户身份经 sudo 调用 `get_capabilities`，逐项输出：

- **组件就位检查**：协议版本是否为 1、固定操作集合是否齐备、规则文件与探针 JAR 是否就位且权限未漂移。
- **目标端检测能力**：`SUPPORTED / PARTIAL / UNSUPPORTED / PERMISSION_DENIED`，每个非 `SUPPORTED` 项都会打印「哪些检测能力因此降级」。
- **环境事实**：SELinux / AppArmor 状态，仅供参考，不参与判定。

退出码：

| 码 | 含义 |
| --- | --- |
| 0 | 通过。若存在降级项，会打印 `*****` 摘要，调查仍可执行，但相关维度必须按 `PARTIAL` 解读 |
| 1 | 核心能力不可用（`/proc`、root Helper、`sudo`、进程可见性、YARA、规则文件、关键操作缺失），该目标不具备可信调查条件 |
| 2 | 用法错误 |
| 3 | Helper 协议版本与控制端要求不一致，需升级目标端 Helper |

核心项判失败、可选项（journald、auditd、JDK Attach、探针、容器运行时）只降级；SELinux/AppArmor 未启用不影响退出码。

## 卸载

默认卸载移除 Helper、探针、YARA 规则与 sudoers，并回收空的 `/opt/huntwarden`；`/var/lib/huntwarden` 中的回执、Evidence 与隔离内容全部保留：

```bash
sudo ./host-helper/uninstall-helper.sh
```

`--purge-state` 额外删除 `actions`、`artifacts`、`quarantine` 与整个 rules 目录，**回执一并丢失，处置动作不再可回滚**。仅在明确不再需要恢复或取证数据时使用：

```bash
sudo ./host-helper/uninstall-helper.sh --purge-state
```
