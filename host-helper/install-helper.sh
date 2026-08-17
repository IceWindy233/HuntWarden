#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly DEFAULT_PROBE_PATH="/opt/huntwarden/huntwarden-tomcat-probe.jar"
readonly DEFAULT_SUDOERS_PATH="/etc/sudoers.d/huntwarden"
readonly DEFAULT_STATE_ROOT="/var/lib/huntwarden"

usage() {
  >&2 echo "用法: sudo $0 --executor-user <ssh-user> [--helper-source <path>] [--probe-source <jar>] [--self-check]"
  exit 2
}

executor_user=""
helper_source="$(cd "$(dirname "$0")" && pwd)/huntwarden_helper.py"
probe_source=""
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
    --probe-source)
      (($# >= 2)) || usage
      probe_source="$2"
      shift 2
      ;;
    --self-check)
      run_self_check=1
      shift
      ;;
    *) usage ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { >&2 echo "必须以 root 运行"; exit 1; }
[[ ${executor_user} =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]] || { >&2 echo "executor user 格式无效"; exit 2; }
getent passwd "${executor_user}" >/dev/null || { >&2 echo "用户不存在: ${executor_user}"; exit 2; }
[[ -f ${helper_source} && ! -L ${helper_source} ]] || { >&2 echo "Helper 源文件不是常规文件: ${helper_source}"; exit 2; }
command -v python3 >/dev/null || { >&2 echo "缺少 Python 3"; exit 1; }
command -v visudo >/dev/null || { >&2 echo "缺少 visudo（Debian/Ubuntu 安装 sudo；Rocky/Alma/Amazon Linux 安装 sudo）"; exit 1; }

install -d -o root -g root -m 0755 "$(dirname "${DEFAULT_HELPER_PATH}")" /opt/huntwarden
install -d -o root -g root -m 0700 "${DEFAULT_STATE_ROOT}" "${DEFAULT_STATE_ROOT}/actions"
install -d -o root -g "$(id -gn "${executor_user}")" -m 0710 "${DEFAULT_STATE_ROOT}/artifacts"
install -o root -g root -m 0755 "${helper_source}" "${DEFAULT_HELPER_PATH}"

if [[ -n ${probe_source} ]]; then
  [[ -f ${probe_source} && ! -L ${probe_source} ]] || { >&2 echo "Probe JAR 不是常规文件: ${probe_source}"; exit 2; }
  install -o root -g root -m 0644 "${probe_source}" "${DEFAULT_PROBE_PATH}"
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
  restorecon -RF "${DEFAULT_STATE_ROOT}" /opt/huntwarden
fi

"${DEFAULT_HELPER_PATH}" get_capabilities <<<'{}' >/dev/null
echo "HuntWarden Helper 已安装/升级：${DEFAULT_HELPER_PATH}"
echo "授权执行用户：${executor_user}"

if ((run_self_check == 1)); then
  "$(cd "$(dirname "$0")" && pwd)/self-check-helper.sh" --executor-user "${executor_user}"
fi
