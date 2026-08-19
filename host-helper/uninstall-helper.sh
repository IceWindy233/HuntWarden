#!/usr/bin/env bash
set -euo pipefail

readonly HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly OPT_ROOT="/opt/huntwarden"
readonly RULE_DIR="/opt/huntwarden/rules"
readonly RULE_PATH="/opt/huntwarden/rules/webshell.yar"
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

# 组件文件（Helper、探针、规则、sudoers）在两种模式下都删除；
# ${STATE_ROOT} 下的回执与证据只在 --purge-state 时删除。
rm -f "${SUDOERS_PATH}" "${HELPER_PATH}" "${PROBE_PATH}" "${RULE_PATH}"

if ((purge_state == 1)); then
  # 只允许删除冻结的专用目录，避免变量或宽路径造成破坏。
  rm -rf --one-file-system "${STATE_ROOT}/actions" "${STATE_ROOT}/artifacts" "${STATE_ROOT}/quarantine" "${RULE_DIR}"
  rmdir "${STATE_ROOT}" 2>/dev/null || true
else
  # 非 purge 只回收自己创建的空目录，不使用 rm -rf，管理员额外放入的规则不会被吞掉。
  rmdir "${RULE_DIR}" 2>/dev/null || true
fi
# ${OPT_ROOT} 可能被其它组件共用，因此仅在为空时回收。
rmdir "${OPT_ROOT}" 2>/dev/null || true

if ((purge_state == 1)); then
  echo "Helper、探针、YARA 规则、sudoers 与 HuntWarden 目标端状态（回执/证据/隔离）已全部删除。"
else
  echo "Helper、探针、YARA 规则与 sudoers 已删除；${STATE_ROOT} 中的回执、证据和隔离内容已保留。"
  if [[ -d ${RULE_DIR} ]]; then
    echo "保留 ${RULE_DIR}：目录内仍有非 HuntWarden 下发的文件。"
  fi
  echo "如需连同状态一并清除，使用: $0 --purge-state"
fi
