#!/usr/bin/env bash
set -euo pipefail

readonly SUSPICIOUS_FILE="/var/www/html/huntwarden-acceptance-webshell.php"
readonly BENIGN_FILE="/var/www/html/huntwarden-acceptance-benign.php"
readonly SENTINEL="HUNTWARDEN_ACCEPTANCE_FIXTURE_V1"

usage() {
  >&2 echo "用法: sudo $0 --install | sudo $0 --remove | $0 --status"
  exit 2
}

mode="${1:-}"
[[ $# -eq 1 ]] || usage

show_status() {
  for target in "${SUSPICIOUS_FILE}" "${BENIGN_FILE}"; do
    if [[ -f "${target}" && ! -L "${target}" ]]; then
      stat -c '%n %U:%G %a %s bytes %y' "${target}"
      sha256sum "${target}"
    else
      echo "ABSENT ${target}"
    fi
  done
}

case "${mode}" in
  --install)
    [[ ${EUID} -eq 0 ]] || { >&2 echo "安装夹具必须以 root 运行"; exit 1; }
    install -d -o root -g root -m 0755 /var/www /var/www/html
    suspicious_temp="$(mktemp)"
    benign_temp="$(mktemp)"
    cleanup() { rm -f "${suspicious_temp}" "${benign_temp}"; }
    trap cleanup EXIT
    cat >"${suspicious_temp}" <<'PHP'
<?php
// HUNTWARDEN_ACCEPTANCE_FIXTURE_V1
// HUNTWARDEN_LAB_WEBSHELL - inert acceptance fixture; it never executes input or commands.
$encodedExample = "base64_decode";
$executionExample = "shell_exec";
echo "HuntWarden acceptance marker only";
PHP
    cat >"${benign_temp}" <<'PHP'
<?php
// HUNTWARDEN_ACCEPTANCE_FIXTURE_V1
// Benign control: security-related words alone must not become a high-risk finding.
$message = "system health and base64 encoding documentation";
echo htmlspecialchars($message, ENT_QUOTES, "UTF-8");
PHP
    install -o root -g root -m 0644 "${suspicious_temp}" "${SUSPICIOUS_FILE}"
    install -o root -g root -m 0644 "${benign_temp}" "${BENIGN_FILE}"
    command -v restorecon >/dev/null && restorecon -F "${SUSPICIOUS_FILE}" "${BENIGN_FILE}"
    echo "无害验收夹具已安装。两份文件均不读取请求参数、不执行命令。"
    show_status
    ;;
  --remove)
    [[ ${EUID} -eq 0 ]] || { >&2 echo "移除夹具必须以 root 运行"; exit 1; }
    for target in "${SUSPICIOUS_FILE}" "${BENIGN_FILE}"; do
      if [[ -e "${target}" ]]; then
        [[ -f "${target}" && ! -L "${target}" ]] || { >&2 echo "拒绝移除非常规文件: ${target}"; exit 1; }
        grep -Fq "${SENTINEL}" "${target}" || { >&2 echo "拒绝移除缺少固定标记的文件: ${target}"; exit 1; }
        rm -f -- "${target}"
      fi
    done
    echo "无害验收夹具已移除。"
    show_status
    ;;
  --status)
    show_status
    ;;
  *) usage ;;
esac
