#!/usr/bin/env bash
set -euo pipefail

# 目标端固定布局。DEFAULT_RULE_PATH 必须与控制端 config.webshell.remoteRulePath 一致；
# DEFAULT_PROBE_PATH 必须与 helper 的 PROBE_JAR 常量一致。
readonly DEFAULT_HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly DEFAULT_OPT_ROOT="/opt/huntwarden"
readonly DEFAULT_RULE_DIR="/opt/huntwarden/rules"
readonly DEFAULT_RULE_PATH="/opt/huntwarden/rules/webshell.yar"
readonly DEFAULT_PROBE_PATH="/opt/huntwarden/huntwarden-tomcat-probe.jar"
readonly DEFAULT_SUDOERS_PATH="/etc/sudoers.d/huntwarden"
readonly DEFAULT_STATE_ROOT="/var/lib/huntwarden"
# SFTP 需要穿越状态根目录才能读取随机 token 命名的 Artifact；目录本身不可列举。
# actions/ 与 quarantine/ 仍分别保持 0700，不会因父目录的 execute bit 暴露内容。
readonly STATE_ROOT_MODE="0711"
# Helper 依赖 pathlib.Path.unlink(missing_ok=) 等 Python 3.8 才有的 API，
# 低于此版本会在运行期崩溃，因此安装期即拒绝。
readonly REQUIRED_PYTHON="3.8"
# 必须与 helper prepare_artifact_dir() 的 os.chmod(ARTIFACT_DIR, 0o711) 保持一致：
# helper 每次落 artifact 都会无条件把该目录改回 0711，安装期用其它值只会造成权限漂移。
readonly ARTIFACT_DIR_MODE="0711"

# 允许从任意工作目录执行：所有源文件位置都由脚本自身位置推导，不依赖 $PWD。
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

usage() {
  >&2 echo "用法: sudo $0 --executor-user <ssh-user> [--helper-source <path>] [--rule-source <webshell.yar>] [--probe-source <jar>] [--self-check]"
  exit 2
}

executor_user=""
helper_source="${script_dir}/huntwarden_helper.py"
rule_source="${repo_root}/rules/yara/webshell.yar"
rule_source_explicit=0
probe_source="${repo_root}/java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar"
probe_source_explicit=0
run_self_check=0

while (($# > 0)); do
  case "$1" in
    --executor-user)
      (($# >= 2)) || usage
      executor_user="$2"
      shift 2
      ;;
    --helper-source)
      (($# >= 2)) || usage
      helper_source="$2"
      shift 2
      ;;
    --rule-source)
      (($# >= 2)) || usage
      rule_source="$2"
      rule_source_explicit=1
      shift 2
      ;;
    --probe-source)
      (($# >= 2)) || usage
      probe_source="$2"
      probe_source_explicit=1
      shift 2
      ;;
    --self-check)
      run_self_check=1
      shift
      ;;
    *) usage ;;
  esac
done

# 逐块读取，避免为大文件一次性分配内存；install 之后用同一函数复核落地内容。
sha256_of() {
  python3 - "$1" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for chunk in iter(lambda: handle.read(1048576), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

# 只读 HELPER_VERSION 常量行；awk 命中即退出，不解析 Python 语义。
helper_version_of() {
  awk -F'"' '/^HELPER_VERSION[[:space:]]*=/ { print $2; exit }' "$1"
}

verify_delivery() {
  local label="$1" source_digest="$2" target="$3" target_digest
  target_digest="$(sha256_of "${target}")"
  [[ ${source_digest} == "${target_digest}" ]] && return 0
  >&2 echo "${label}下发校验失败: 源 SHA-256 ${source_digest}，目标 ${target_digest}"
  >&2 echo "已中止安装。请确认 ${target} 未被并发写入、所在文件系统可写且未启用透明改写。"
  exit 1
}

[[ ${EUID} -eq 0 ]] || { >&2 echo "必须以 root 运行"; exit 1; }
[[ ${executor_user} =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]] || { >&2 echo "executor user 格式无效"; exit 2; }
getent passwd "${executor_user}" >/dev/null || { >&2 echo "用户不存在: ${executor_user}"; exit 2; }
[[ -f ${helper_source} && ! -L ${helper_source} ]] || { >&2 echo "Helper 源文件不是常规文件: ${helper_source}"; exit 2; }
command -v python3 >/dev/null || { >&2 echo "缺少 Python 3（Helper 要求 >= ${REQUIRED_PYTHON}）"; exit 1; }

python_version="$(python3 -c 'import sys; print(".".join(str(part) for part in sys.version_info[:3]))')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || {
  >&2 echo "Python 版本过低: 检测到 ${python_version}，Helper 要求 >= ${REQUIRED_PYTHON}"
  >&2 echo "原因: Helper 使用 pathlib.Path.unlink(missing_ok=) 等 3.8 引入的 API，旧版本会在运行期抛 TypeError。"
  >&2 echo "处理: 安装发行版的 python3.8+ 包，或用满足要求的解释器重新执行安装。"
  exit 1
}
command -v visudo >/dev/null || { >&2 echo "缺少 visudo（Debian/Ubuntu 安装 sudo；Rocky/Alma/Amazon Linux 安装 sudo）"; exit 1; }

if [[ ! -f ${rule_source} || -L ${rule_source} ]]; then
  >&2 echo "YARA 规则源文件不可用: ${rule_source}"
  if ((rule_source_explicit == 0)); then
    >&2 echo "本脚本默认从仓库 rules/yara/webshell.yar 取规则；若只复制了 host-helper 目录，"
    >&2 echo "请用 --rule-source <webshell.yar> 显式指定。"
  fi
  >&2 echo "WebShell 规则扫描固定读取 ${DEFAULT_RULE_PATH}；规则缺失会让 v2 YARA matcher 不可用，因此拒绝安装。"
  exit 2
fi

# 显式指定的探针必须存在：命令行要求下发就不允许降级为跳过。
# 该校验放在任何写操作之前，避免参数错误留下半装状态。
if ((probe_source_explicit == 1)) && [[ ! -f ${probe_source} || -L ${probe_source} ]]; then
  >&2 echo "Probe JAR 不是常规文件: ${probe_source}"
  exit 2
fi

new_version="$(helper_version_of "${helper_source}")"
[[ -n ${new_version} ]] || { >&2 echo "无法从 ${helper_source} 解析 HELPER_VERSION"; exit 2; }

installed_version=""
if [[ -f ${DEFAULT_HELPER_PATH} && ! -L ${DEFAULT_HELPER_PATH} ]]; then
  installed_version="$(helper_version_of "${DEFAULT_HELPER_PATH}")"
  [[ -n ${installed_version} ]] || installed_version="未知版本"
fi
if [[ -n ${installed_version} ]]; then
  install_mode="升级 ${installed_version} → ${new_version}"
else
  install_mode="全新安装 ${new_version}"
fi
echo "安装模式: ${install_mode}"

# 升级不可破坏崩溃恢复：Action Receipt 是回滚与恢复的唯一依据，安装路径全程只读它。
receipt_count=0
if [[ -d ${DEFAULT_STATE_ROOT}/actions ]]; then
  receipt_count="$(find "${DEFAULT_STATE_ROOT}/actions" -maxdepth 1 -type f -print | wc -l | tr -d '[:space:]')"
fi

# install -d 对已存在目录只校正属主与权限，不会清空内容，因此升级安全。
install -d -o root -g root -m 0755 "$(dirname "${DEFAULT_HELPER_PATH}")" "${DEFAULT_OPT_ROOT}" "${DEFAULT_RULE_DIR}"
install -d -o root -g root -m "${STATE_ROOT_MODE}" "${DEFAULT_STATE_ROOT}"
install -d -o root -g root -m 0700 "${DEFAULT_STATE_ROOT}/actions"
install -d -o root -g "$(id -gn "${executor_user}")" -m "${ARTIFACT_DIR_MODE}" "${DEFAULT_STATE_ROOT}/artifacts"
install -o root -g root -m 0755 "${helper_source}" "${DEFAULT_HELPER_PATH}"

# 规则以 root:root 0644 落地：helper 经 sudo 以 root 运行只需可读，禁止可写。
rule_digest="$(sha256_of "${rule_source}")"
install -o root -g root -m 0644 "${rule_source}" "${DEFAULT_RULE_PATH}"
verify_delivery "YARA 规则" "${rule_digest}" "${DEFAULT_RULE_PATH}"

probe_digest=""
if [[ -f ${probe_source} && ! -L ${probe_source} ]]; then
  probe_digest="$(sha256_of "${probe_source}")"
  install -o root -g root -m 0644 "${probe_source}" "${DEFAULT_PROBE_PATH}"
  verify_delivery "Tomcat 探针" "${probe_digest}" "${DEFAULT_PROBE_PATH}"
  probe_state="已下发 ${DEFAULT_PROBE_PATH} (sha256=${probe_digest:0:16}…)"
else
  # 显式跳过并说明后果，禁止静默降级。
  >&2 echo "警告: 未找到 Tomcat 探针 JAR（${probe_source}），本次跳过探针下发。"
  >&2 echo "      影响: Java 内存马检测降级——Tomcat Filter/Servlet/Valve 运行时枚举与 Class Dump 不可用，"
  >&2 echo "            v2 capabilities 的 probes 列表不会包含 JVM Probe。"
  >&2 echo "      补装: 在控制端仓库执行 npm run probe:build 构建探针，然后重新运行本脚本；"
  >&2 echo "            探针位于其它路径时用 --probe-source <jar> 指定。"
  if [[ -f ${DEFAULT_PROBE_PATH} ]]; then
    probe_state="保留既有 ${DEFAULT_PROBE_PATH}（本次未更新）"
  else
    probe_state="缺失（探针 JAR 未构建，Java 内存马检测不可用）"
  fi
fi

sudoers_temp="$(mktemp /etc/sudoers.d/.huntwarden.XXXXXX)"
cleanup() { rm -f "${sudoers_temp}"; }
trap cleanup EXIT
printf '%s ALL=(root) NOPASSWD: %s *\n' "${executor_user}" "${DEFAULT_HELPER_PATH}" > "${sudoers_temp}"
chmod 0440 "${sudoers_temp}"
chown root:root "${sudoers_temp}"
visudo -cf "${sudoers_temp}" >/dev/null
mv -f "${sudoers_temp}" "${DEFAULT_SUDOERS_PATH}"
chmod 0440 "${DEFAULT_SUDOERS_PATH}"
chown root:root "${DEFAULT_SUDOERS_PATH}"
trap - EXIT

# Rocky/Alma/RHEL 系在 SELinux Enforcing 下必须恢复发行版默认标签；
# Debian/Ubuntu 通常没有 restorecon，此步骤因此保持可选且不改变权限模型。
if command -v restorecon >/dev/null; then
  restorecon -F "${DEFAULT_HELPER_PATH}" "${DEFAULT_SUDOERS_PATH}"
  restorecon -RF "${DEFAULT_STATE_ROOT}" "${DEFAULT_OPT_ROOT}"
fi

"${DEFAULT_HELPER_PATH}" capabilities <<<'{"protocolVersion":2,"requestId":"INSTALL-CHECK","epochId":"PRECHECK","deadlineMs":10000,"reservation":{"reservationId":"INSTALL-CHECK","estimate":{"remoteCalls":1,"nodes":1,"bytes":1572864,"wallTimeMs":10000,"probeCalls":0}},"params":{}}' >/dev/null

echo "===== 本次安装/升级组件清单 ====="
echo "模式          : ${install_mode}"
echo "Helper        : ${DEFAULT_HELPER_PATH} (root:root 0755, 版本 ${new_version})"
echo "YARA 规则     : ${DEFAULT_RULE_PATH} (root:root 0644, sha256=${rule_digest:0:16}…)"
echo "Tomcat 探针   : ${probe_state}"
echo "sudoers       : ${DEFAULT_SUDOERS_PATH} (root:root 0440, 授权用户 ${executor_user})"
echo "Python        : ${python_version} (要求 >= ${REQUIRED_PYTHON})"
echo "Action Receipt: ${DEFAULT_STATE_ROOT}/actions 保留 ${receipt_count} 个文件，本次安装未修改"
echo "Artifact 目录 : ${DEFAULT_STATE_ROOT}/artifacts (${ARTIFACT_DIR_MODE}，与 helper prepare_artifact_dir 对齐)"
echo "================================="

if ((run_self_check == 1)); then
  "${script_dir}/self-check-helper.sh" --executor-user "${executor_user}"
fi
