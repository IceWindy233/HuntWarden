#!/usr/bin/env bash
set -euo pipefail

readonly FIXTURE_DIR="/opt/huntwarden-model-eval"
readonly NOVEL_FILE="/var/www/html/huntwarden-novel-callback.phtml"
readonly JAVA_SOURCE="${FIXTURE_DIR}/HuntWardenBenignSleeper.java"
readonly JAVA_CLASS="${FIXTURE_DIR}/HuntWardenBenignSleeper.class"
readonly JAVA_PID="${FIXTURE_DIR}/java.pid"
readonly SENTINEL="HUNTWARDEN_MODEL_EVAL_FIXTURE_V1"

usage() {
  >&2 echo "用法: sudo $0 --install | sudo $0 --remove | $0 --status"
  exit 2
}

mode="${1:-}"
[[ $# -eq 1 ]] || usage

java_fixture_pid() {
  [[ -f "${JAVA_PID}" ]] || return 1
  local pid
  pid="$(cat "${JAVA_PID}")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -Fq 'HuntWardenBenignSleeper' || return 1
  printf '%s\n' "${pid}"
}

show_status() {
  if [[ -f "${NOVEL_FILE}" && ! -L "${NOVEL_FILE}" ]]; then
    stat -c '%n %U:%G %a %s bytes %y' "${NOVEL_FILE}"
    sha256sum "${NOVEL_FILE}"
  else
    echo "ABSENT ${NOVEL_FILE}"
  fi
  if pid="$(java_fixture_pid)"; then
    echo "RUNNING HuntWardenBenignSleeper pid=${pid}"
  else
    echo "STOPPED HuntWardenBenignSleeper"
  fi
}

case "${mode}" in
  --install)
    [[ ${EUID} -eq 0 ]] || { >&2 echo "安装夹具必须以 root 运行"; exit 1; }
    command -v javac >/dev/null || { >&2 echo "缺少 javac，无法安装 Java 良性夹具"; exit 1; }
    install -d -o root -g root -m 0755 /var/www /var/www/html
    install -d -o root -g root -m 0755 "${FIXTURE_DIR}"
    novel_temp="$(mktemp)"
    java_temp="$(mktemp --suffix=.java)"
    cleanup() { rm -f "${novel_temp}" "${java_temp}"; }
    trap cleanup EXIT
    cat >"${novel_temp}" <<'PHP'
<?php
// HUNTWARDEN_MODEL_EVAL_FIXTURE_V1
// Inert novel malicious simulation: the branch is permanently disabled, so no input is read and no callback runs.
if (false) {
    $requestValue = $_COOKIE['huntwarden_cmd'];
    $callbackDispatcher = implode('', ['ca', 'll_u', 'ser_fu', 'nc']);
    $simulatedCallable = implode('', ['pro', 'c_o', 'pen']);
    $callbackDispatcher($simulatedCallable, $requestValue, []);
}
echo 'HuntWarden inert model-evaluation fixture';
PHP
    cat >"${java_temp}" <<'JAVA'
// HUNTWARDEN_MODEL_EVAL_FIXTURE_V1
public final class HuntWardenBenignSleeper {
    public static void main(String[] args) throws Exception {
        while (true) Thread.sleep(60_000L);
    }
}
JAVA
    install -o root -g root -m 0644 "${novel_temp}" "${NOVEL_FILE}"
    install -o root -g root -m 0644 "${java_temp}" "${JAVA_SOURCE}"
    javac "${JAVA_SOURCE}"
    chown root:root "${JAVA_CLASS}"
    chmod 0644 "${JAVA_CLASS}"
    if ! java_fixture_pid >/dev/null; then
      nohup java -cp "${FIXTURE_DIR}" HuntWardenBenignSleeper </dev/null >"${FIXTURE_DIR}/java.log" 2>&1 &
      printf '%s\n' "$!" >"${JAVA_PID}"
      sleep 1
      java_fixture_pid >/dev/null || { >&2 echo "Java 良性夹具启动失败"; exit 1; }
    fi
    command -v restorecon >/dev/null && restorecon -F "${NOVEL_FILE}"
    echo "模型评测夹具已安装；PHP 恶意模拟位于永久禁用分支，不读取输入、不调用回调。"
    show_status
    ;;
  --remove)
    [[ ${EUID} -eq 0 ]] || { >&2 echo "移除夹具必须以 root 运行"; exit 1; }
    if pid="$(java_fixture_pid)"; then
      kill "${pid}"
      for _ in 1 2 3 4 5; do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 1
      done
      kill -0 "${pid}" 2>/dev/null && { >&2 echo "Java 良性夹具未能正常停止"; exit 1; }
    fi
    if [[ -e "${NOVEL_FILE}" ]]; then
      [[ -f "${NOVEL_FILE}" && ! -L "${NOVEL_FILE}" ]] || { >&2 echo "拒绝移除非常规文件: ${NOVEL_FILE}"; exit 1; }
      grep -Fq "${SENTINEL}" "${NOVEL_FILE}" || { >&2 echo "拒绝移除缺少固定标记的文件: ${NOVEL_FILE}"; exit 1; }
      rm -f -- "${NOVEL_FILE}"
    fi
    if [[ -e "${FIXTURE_DIR}" ]]; then
      [[ -f "${JAVA_SOURCE}" && ! -L "${JAVA_SOURCE}" ]] || { >&2 echo "拒绝移除异常夹具目录: ${FIXTURE_DIR}"; exit 1; }
      grep -Fq "${SENTINEL}" "${JAVA_SOURCE}" || { >&2 echo "拒绝移除缺少固定标记的 Java 夹具"; exit 1; }
      rm -f -- "${JAVA_SOURCE}" "${JAVA_CLASS}" "${JAVA_PID}" "${FIXTURE_DIR}/java.log"
      rmdir "${FIXTURE_DIR}"
    fi
    echo "模型评测夹具已移除。"
    show_status
    ;;
  --status)
    show_status
    ;;
  *) usage ;;
esac
