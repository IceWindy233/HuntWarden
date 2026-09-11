#!/usr/bin/env bash
set -euo pipefail

usage() {
  >&2 echo "usage: sudo $0 --executor-user <user> --commit <sha1> --output <result.json> [--probe-source <jar>]"
  exit 2
}

executor_user=""
commit=""
output=""
probe_source=""
while (($# > 0)); do
  case "$1" in
    --executor-user) (($# >= 2)) || usage; executor_user="$2"; shift 2 ;;
    --commit) (($# >= 2)) || usage; commit="$2"; shift 2 ;;
    --output) (($# >= 2)) || usage; output="$2"; shift 2 ;;
    --probe-source) (($# >= 2)) || usage; probe_source="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[[ ${EUID} -eq 0 ]] || { >&2 echo "must run as root"; exit 1; }
[[ ${executor_user} =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]] || usage
[[ ${commit} =~ ^[a-f0-9]{40}$ ]] || usage
[[ -n ${output} && ! -e ${output} ]] || { >&2 echo "output must not exist"; exit 2; }
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
install_script="${repo_root}/host-helper/install-helper.sh"
uninstall_script="${repo_root}/host-helper/uninstall-helper.sh"
helper_source="${repo_root}/host-helper/huntwarden_helper.py"
rule_source="${repo_root}/rules/yara/webshell.yar"
[[ -x ${install_script} && -x ${uninstall_script} && -f ${helper_source} && -f ${rule_source} ]] || { >&2 echo "repository assets unavailable"; exit 1; }
if [[ -z ${probe_source} ]]; then probe_source="${repo_root}/java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar"; fi
[[ -f ${probe_source} && ! -L ${probe_source} ]] || { >&2 echo "probe JAR required"; exit 1; }
getent passwd "${executor_user}" >/dev/null || { >&2 echo "executor user missing"; exit 1; }

helper_path="/usr/local/libexec/huntwarden-helper"
rule_path="/opt/huntwarden/rules/webshell.yar"
probe_path="/opt/huntwarden/huntwarden-tomcat-probe.jar"
sudoers_path="/etc/sudoers.d/huntwarden"
state_root="/var/lib/huntwarden"
action_dir="${state_root}/actions"
receipt="${action_dir}/operational-qualification.receipt"
target_job="huntwarden-operational-qualification"
target_job_path="/etc/systemd/system/${target_job}.service"
failures=()

sha256_file() {
  python3 - "$1" <<'PY'
import hashlib
import sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1048576), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}
mode_is() { [[ $(stat -c '%a' "$1") == "$2" ]]; }
record_failure() { failures+=("$1"); }
cleanup() {
  rm -f "${target_job_path}"
  if command -v systemctl >/dev/null; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  "${uninstall_script}" --purge-state >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${uninstall_script}" --purge-state >/dev/null 2>&1 || true
install_args=(--executor-user "${executor_user}" --helper-source "${helper_source}" --rule-source "${rule_source}" --probe-source "${probe_source}" --self-check)
"${install_script}" "${install_args[@]}"
[[ -f ${helper_path} && -f ${rule_path} && -f ${probe_path} && -f ${sudoers_path} ]] || record_failure "fresh install components missing"
helper_digest="$(sha256_file "${helper_source}")"
rule_digest="$(sha256_file "${rule_source}")"
probe_digest="$(sha256_file "${probe_source}")"
[[ $(sha256_file "${helper_path}") == "${helper_digest}" && $(sha256_file "${rule_path}") == "${rule_digest}" && $(sha256_file "${probe_path}") == "${probe_digest}" ]] || record_failure "component digest mismatch"
[[ $(stat -c '%U:%G' "${helper_path}") == "root:root" && $(stat -c '%U:%G' "${rule_path}") == "root:root" && $(stat -c '%U:%G' "${probe_path}") == "root:root" && $(stat -c '%U:%G' "${sudoers_path}") == "root:root" ]] || record_failure "component ownership mismatch"
mode_is "${helper_path}" 755 && mode_is "${rule_path}" 644 && mode_is "${probe_path}" 644 && mode_is "${sudoers_path}" 440 && mode_is "${action_dir}" 700 || record_failure "component permission mismatch"

printf '%s\n' "qualification-receipt-${commit}" > "${receipt}"
chmod 0600 "${receipt}"
receipt_digest="$(sha256_file "${receipt}")"
if command -v systemctl >/dev/null && [[ $(ps -p 1 -o comm= | tr -d '[:space:]') == systemd ]]; then
  cat > "${target_job_path}" <<UNIT
[Unit]
Description=HuntWarden operational qualification marker
[Service]
Type=oneshot
ExecStart=/usr/bin/true
UNIT
  systemctl daemon-reload
else
  target_job_path="/run/${target_job}.service"
  printf '%s\n' "qualification job marker" > "${target_job_path}"
fi

"${install_script}" "${install_args[@]}"
[[ -f ${receipt} && $(sha256_file "${receipt}") == "${receipt_digest}" ]] || record_failure "upgrade changed action receipt"
"${uninstall_script}"
[[ -f ${receipt} && $(sha256_file "${receipt}") == "${receipt_digest}" ]] || record_failure "default uninstall did not preserve state"
[[ ! -e ${helper_path} && ! -e ${rule_path} && ! -e ${probe_path} && ! -e ${sudoers_path} ]] || record_failure "default uninstall left components"
"${uninstall_script}" --purge-state
[[ ! -e ${state_root} ]] || record_failure "purge uninstall left state"
rm -f "${target_job_path}"
if command -v systemctl >/dev/null; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
[[ ! -e ${target_job_path} && ! -e ${sudoers_path} ]] || record_failure "qualification target job or sudo credential remains"

platform_distribution="unknown"
platform_version="unknown"
if [[ -r /etc/os-release ]]; then
  platform_distribution="$(. /etc/os-release; printf '%s' "${ID:-unknown}")"
  platform_version="$(. /etc/os-release; printf '%s' "${VERSION_ID:-unknown}")"
fi
script_digest="$(sha256_file "$0")"
evaluated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
status="PASS"
if ((${#failures[@]} > 0)); then status="FAIL"; fi
python3 - "${output}" "${status}" "${commit}" "${helper_digest}" "${script_digest}" "${evaluated_at}" "${platform_distribution}" "${platform_version}" "$(uname -m)" "${#failures[@]}" "${failures[@]}" <<'PY'
import json
import os
import sys
path, status, commit, helper, script, evaluated, distribution, version, architecture, count, *failures = sys.argv[1:]
result = {
    "schemaVersion": 1,
    "status": status,
    "commit": commit,
    "helperSha256": helper,
    "scriptSha256": script,
    "evaluatedAt": evaluated,
    "platform": {"distribution": distribution, "version": version, "architecture": architecture},
    "install": {"freshInstall": status == "PASS", "upgrade": status == "PASS", "permissions": status == "PASS", "componentDigests": status == "PASS", "receiptPreserved": status == "PASS"},
    "uninstall": {"defaultPreservedState": status == "PASS", "purgeRemovedState": status == "PASS", "credentialsAbsent": status == "PASS", "targetJobsAbsent": status == "PASS"},
    "failures": failures[:int(count)],
}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(result, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
PY
trap - EXIT
if [[ ${status} != PASS ]]; then
  >&2 printf 'operational qualification failed:\n- %s\n' "${failures[@]}"
  exit 1
fi
printf 'operational host qualification passed; result=%s\n' "${output}"
