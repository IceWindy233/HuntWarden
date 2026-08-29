# HuntWarden 目标端 Helper

Helper 是 root 所有的 v2 类型化取证入口，只接受 `capabilities` 与八个静态白名单原语（`enumerate/project/read/match/relate/verify/collect/probe`）及单个 JSON Envelope，不接受 Shell 字符串。v1 检测问题操作名已不再由运行时分发。

## 前置依赖与缺失影响

| 依赖 | 缺失后果 | 自检状态 |
| --- | --- | --- |
| `python3` >= 3.8 | Helper 无法运行（安装期直接拒绝，不会留下半装状态） | 安装期拦截 |
| `sudo` / `visudo` | 控制端无法以 root 调用 Helper，所有特权采集被拒 | `sudo` |
| `re2` Python 模块 | RE2 matcher 不会出现在 v2 Capability；绝不回退到 Python `re` | `capabilities.matchers` |
| `yara` | 仅在二进制与内置版本化 RuleSet 同时存在时声明 `yara` matcher；不接受模型源码或路径 | `capabilities.matchers` |
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

- **YARA 规则**：安装脚本将内置规则 `rules/yara/webshell.yar` 下发到协议固定位置并校验 SHA-256。Helper 仅在 `yara` 二进制和该内置 RuleSet 同时存在时声明能力；v2 `match` 只接受固定 `RULESET-WEBSHELL-BUILTIN-2`，拒绝规则源码与任意路径。
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
| `/var/lib/huntwarden` | `root:root 0711` | 状态根目录；仅允许 SFTP 穿越随机 Token 路径，不允许列举 |
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

自检以执行用户身份经 sudo 调用 v2 `capabilities`，逐项输出：

- 协议版本是否为 2、Manifest 是否精确为 `2.0.0`；
- 八个取证原语与核心 Namespace 是否齐备，且 Helper 没有错误声明 controller-local `task_ioc`；
- 单次对象、输出、读取与 Evidence 采集硬上限；
- literal/RE2/YARA matcher 与 JVM Probe 的当前可用子集；YARA 只有在内置版本化 RuleSet 与运行时同时可用时才声明。

`known_hash_set` 数据集仅存放在控制端。Helper 的 `verify` 只接受已由控制端校验过的 `DATASET-*` 引用并重观测绑定文件 SHA-256，不接收哈希数组，也不自行作恶意判断。

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
