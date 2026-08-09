#!/usr/bin/env bash
set -euo pipefail

readonly HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly PROBE_PATH="/opt/huntwarden/huntwarden-tomcat-probe.jar"
readonly SUDOERS_PATH="/etc/sudoers.d/huntwarden"
readonly STATE_ROOT="/var/lib/huntwarden"

purge_state=0
if [[ ${1:-} == "--purge-state" ]]; then
  purge_state=1
  shift
fi
[[ $# -eq 0 ]] || { >&2 echo "用法: sudo $0 [--purge-state]"; exit 2; }
[[ ${EUID} -eq 0 ]] || { >&2 echo "必须以 root 运行"; exit 1; }

rm -f "${SUDOERS_PATH}" "${HELPER_PATH}" "${PROBE_PATH}"
if ((purge_state == 1)); then
  # 只允许删除冻结的专用目录，避免变量或宽路径造成破坏。
  rm -rf --one-file-system "${STATE_ROOT}/actions" "${STATE_ROOT}/artifacts" "${STATE_ROOT}/quarantine"
  rmdir "${STATE_ROOT}" 2>/dev/null || true
  echo "Helper、Probe、sudoers 与 HuntWarden 目标端状态已删除。"
else
  echo "Helper、Probe 与 sudoers 已删除；${STATE_ROOT} 中的回执、证据和隔离内容已保留。"
fi
