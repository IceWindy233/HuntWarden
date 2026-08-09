#!/usr/bin/env bash
set -euo pipefail

readonly HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly SUDOERS_PATH="/etc/sudoers.d/huntwarden"

usage() { >&2 echo "用法: $0 --executor-user <ssh-user>"; exit 2; }
executor_user=""
while (($# > 0)); do
  case "$1" in
    --executor-user)
      (($# >= 2)) || usage
      executor_user="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ ${executor_user} =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]] || usage
getent passwd "${executor_user}" >/dev/null || { >&2 echo "用户不存在: ${executor_user}"; exit 1; }
[[ -f ${HELPER_PATH} && ! -L ${HELPER_PATH} ]] || { >&2 echo "Helper 未安装或是符号链接"; exit 1; }
[[ $(stat -c '%U:%G:%a' "${HELPER_PATH}") == "root:root:755" ]] || { >&2 echo "Helper 必须为 root:root:0755"; exit 1; }
[[ -f ${SUDOERS_PATH} && ! -L ${SUDOERS_PATH} ]] || { >&2 echo "sudoers 规则不存在或是符号链接"; exit 1; }
[[ $(stat -c '%U:%G:%a' "${SUDOERS_PATH}") == "root:root:440" ]] || { >&2 echo "sudoers 必须为 root:root:0440"; exit 1; }
command -v visudo >/dev/null && visudo -cf "${SUDOERS_PATH}" >/dev/null

capabilities="$(su -s /bin/sh -c "sudo -n -- ${HELPER_PATH} get_capabilities" "${executor_user}" <<<'{}')"
python3 -c 'import json,sys; value=json.load(sys.stdin); assert value.get("ok") is True; result=value["result"]; assert result["protocolVersion"] >= 1; print(json.dumps(result, ensure_ascii=False, indent=2))' <<<"${capabilities}"
echo "Helper 自检通过。"
