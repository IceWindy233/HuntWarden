#!/usr/bin/env bash
set -euo pipefail

readonly HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly SUDOERS_PATH="/etc/sudoers.d/huntwarden"
usage() { >&2 echo "用法: $0 --executor-user <ssh-user>"; exit 2; }
executor_user=""
while (($# > 0)); do
  case "$1" in
    --executor-user) (($# >= 2)) || usage; executor_user="$2"; shift 2 ;;
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

capabilities_file="$(mktemp)"
trap 'rm -f "${capabilities_file}"' EXIT
request='{"protocolVersion":2,"requestId":"SELF-CHECK","epochId":"PRECHECK","deadlineMs":10000,"reservation":{"reservationId":"SELF-CHECK","estimate":{"remoteCalls":1,"nodes":1,"bytes":1572864,"wallTimeMs":10000,"probeCalls":0}},"params":{}}'
set +e
su -s /bin/sh -c "sudo -n -- ${HELPER_PATH} capabilities" "${executor_user}" <<<"${request}" >"${capabilities_file}"
query_status=$?
set -e
if ((query_status != 0)) && [[ ! -s ${capabilities_file} ]]; then
  >&2 echo "以 ${executor_user} 身份调用 Helper v2 capabilities 失败且无输出（${query_status}）"
  exit 1
fi

python3 - "${capabilities_file}" <<'PY'
import json, pathlib, sys

REQUIRED_PROTOCOL = 2
REQUIRED_MANIFEST = "2.1.0"
REQUIRED_VERBS = {"enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"}
REQUIRED_NAMESPACES = {"host", "process", "socket", "file", "account", "delegation_rule", "ssh_trust_config", "jvm"}

raw = pathlib.Path(sys.argv[1]).read_text("utf-8", errors="replace")
try:
    envelope = json.loads(raw)
except ValueError as error:
    print("Helper 输出不是 JSON: {0}".format(error), file=sys.stderr)
    raise SystemExit(1)
if not isinstance(envelope, dict) or envelope.get("status") != "SUCCESS":
    print("Helper v2 capabilities 失败: {0}".format(raw[:512]), file=sys.stderr)
    raise SystemExit(1)
cap = envelope.get("capabilities")
if not isinstance(cap, dict):
    print("capabilities Envelope 缺少 capabilities", file=sys.stderr)
    raise SystemExit(1)
print("===== HuntWarden Helper v2 自检 =====")
print("Helper       : {0} {1}".format(cap.get("helper", {}).get("name", "?"), cap.get("helper", {}).get("version", "?")))
print("协议/Manifest: {0} / {1}".format(cap.get("protocolVersion"), cap.get("manifestVersion")))
if cap.get("protocolVersion") != REQUIRED_PROTOCOL or cap.get("manifestVersion") != REQUIRED_MANIFEST:
    print("协议不兼容：控制端要求 v2 / Manifest {0}".format(REQUIRED_MANIFEST), file=sys.stderr)
    raise SystemExit(3)
verbs = set(cap.get("verbs", [])); namespaces = set(cap.get("namespaces", {}))
missing_verbs = sorted(REQUIRED_VERBS - verbs); missing_namespaces = sorted(REQUIRED_NAMESPACES - namespaces)
print("取证原语     : {0}".format(", ".join(sorted(verbs))))
print("Namespace    : {0}".format(", ".join(sorted(namespaces))))
if "task_ioc" in namespaces:
    print("协议违规：Helper 不得声明 controller-local task_ioc", file=sys.stderr)
    raise SystemExit(1)
if missing_verbs or missing_namespaces:
    print("核心能力缺失：verbs={0}; namespaces={1}".format(missing_verbs, missing_namespaces), file=sys.stderr)
    raise SystemExit(1)
limits = cap.get("limits", {})
print("硬上限       : objects={0}, output={1}, read={2}, collect={3}".format(
    limits.get("maxObjects"), limits.get("maxOutputBytes"), limits.get("maxReadBytes"), limits.get("maxCollectBytes")))
print("YARA         : {0}".format("可用" if "yara" in cap.get("matchers", []) else "降级（版本化 YARA matcher 不可用）"))
print("JVM Probe    : {0}".format(", ".join(cap.get("probes", [])) or "降级（无可用 Probe）"))
print("自检通过：能力声明只表示当前可用子集，最终授权仍由 Manifest ∩ Grant ∩ Budget 决定。")
PY
