#!/usr/bin/env bash
set -euo pipefail

readonly HELPER_PATH="/usr/local/libexec/huntwarden-helper"
readonly SUDOERS_PATH="/etc/sudoers.d/huntwarden"

# 退出码语义:
#   0  通过（可能存在非核心降级，摘要中会醒目列出）
#   1  核心检测能力不可用、组件缺失或 Helper 调用失败
#   2  用法错误
#   3  Helper 协议版本与控制端要求不一致，需升级目标端 Helper
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

capabilities_file="$(mktemp)"
trap 'rm -f "${capabilities_file}"' EXIT

# Helper 失败时也会输出 JSON 错误信封，因此先取回退出码再交给分析器打印原因。
set +e
su -s /bin/sh -c "sudo -n -- ${HELPER_PATH} get_capabilities" "${executor_user}" <<<'{}' > "${capabilities_file}"
query_status=$?
set -e
if ((query_status != 0)) && [[ ! -s ${capabilities_file} ]]; then
  >&2 echo "以 ${executor_user} 身份通过 sudo 调用 Helper 失败（退出码 ${query_status}），且没有任何输出。"
  >&2 echo "排查: sudoers 是否为 '${executor_user} ALL=(root) NOPASSWD: ${HELPER_PATH} *'；"
  >&2 echo "      Helper 是否可执行；SELinux/AppArmor 是否阻止 ${HELPER_PATH} 执行。"
  exit 1
fi

# 分析器负责功能性判定与退出码；stdin 被 heredoc 占用，能力 JSON 通过 argv 传路径。
python3 - "${capabilities_file}" <<'PY'
import json
import pathlib
import stat
import sys

REQUIRED_PROTOCOL_VERSION = 1
RULE_PATH = pathlib.Path("/opt/huntwarden/rules/webshell.yar")
PROBE_PATH = pathlib.Path("/opt/huntwarden/huntwarden-tomcat-probe.jar")
DEGRADED = ("PARTIAL", "UNSUPPORTED", "PERMISSION_DENIED")
FATAL = ("UNSUPPORTED", "PERMISSION_DENIED")
ESSENTIAL_OPERATIONS = (
    "get_capabilities", "yara_scan_files", "query_auth_events",
    "query_exec_events", "build_incident_timeline", "collect_file",
)

# key -> (显示名, 角色, 降级影响)
# core = 影响核心检测，UNSUPPORTED/PERMISSION_DENIED 即自检失败
# optional = 仅降级，退出码保持 0
# info = 只报告环境事实，不参与判定
CAPABILITY_MAP = {
    "linuxProc": ("Linux /proc 与 boot ID", "core",
                  "进程稳定身份（bootId + startTicks + inode）无法建立，可疑进程、进程连接与内存马检测全部失效"),
    "rootHelper": ("root 权限 Helper", "core",
                   "/proc/<pid>/exe、/root、/var/log/audit、shadow 等受限路径不可读，持久化与分诊大面积漏报"),
    "sudo": ("sudo", "core",
             "控制端无法以 root 身份调用 Helper，所有需要特权的采集都会被拒绝"),
    "procVisibility": ("/proc 进程可见性 (hidepid)", "core",
                       "非当前用户的进程不可见，可疑进程、进程连接与 Java 内存马检测漏报"),
    "yara": ("YARA 引擎", "core",
             "WebShell 规则扫描不可用，只剩启发式特征，已知家族漏报且误报率上升"),
    "journal": ("journald", "optional",
                "journald 主导发行版（Rocky/RHEL/Alma）的认证与执行事件缺失，后门账户维度与事件时间线不完整"),
    "auditd": ("auditd", "optional",
               "execve 执行事件缺失，事件时间线只剩文件落地与认证两个维度"),
    "javaAttach": ("JDK Attach 运行时", "optional",
                   "无法 attach 到 Tomcat JVM，Java 内存马运行时枚举与 Class Dump 不可用"),
    "tomcatProbe": ("Tomcat 探针 JAR", "optional",
                    "Tomcat Filter/Servlet/Valve 运行时枚举与 Class Dump 不可用"),
    "docker": ("Docker", "optional",
               "容器内进程与镜像维度不可见，容器化 Web 服务的 WebShell 与内存马排查受限"),
    "containerd": ("containerd", "optional",
                   "containerd 容器维度不可见，容器化目标排查受限"),
    "selinux": ("SELinux", "info", ""),
    "apparmor": ("AppArmor", "info", ""),
}

records = []


def record(section, status, name, reason, role, impact=""):
    records.append({
        "section": section, "status": status, "name": name,
        "reason": reason, "role": role, "impact": impact,
    })


def show(entry):
    reason = entry["reason"]
    print("[{0:<17}] {1}{2}".format(entry["status"], entry["name"], ": " + reason if reason else ""))
    if entry["impact"] and entry["status"] in DEGRADED:
        print(" " * 20 + "降级影响: " + entry["impact"])


def section_of(section):
    return [entry for entry in records if entry["section"] == section]


def file_record(section, path, label, expected_mode, role, impact):
    try:
        info = path.lstat()
    except OSError as error:
        record(section, "UNSUPPORTED", label, "缺失或不可访问: {0} ({1})".format(path, error.strerror), role, impact)
        return
    if stat.S_ISLNK(info.st_mode):
        record(section, "UNSUPPORTED", label, "{0} 是符号链接，拒绝信任".format(path), role, impact)
        return
    if not stat.S_ISREG(info.st_mode):
        record(section, "UNSUPPORTED", label, "{0} 不是常规文件".format(path), role, impact)
        return
    mode = stat.S_IMODE(info.st_mode)
    detail = "{0} ({1}, uid={2}, gid={3}, {4} 字节)".format(path, format(mode, "04o"), info.st_uid, info.st_gid, info.st_size)
    if mode != expected_mode or info.st_uid != 0 or info.st_gid != 0:
        record(section, "PARTIAL", label,
               "{0}；期望 root:root {1}，权限已漂移".format(detail, format(expected_mode, "04o")), role,
               "文件可被非 root 改写或读取受限，来源不再可信；重新执行 install-helper.sh 可恢复目标权限")
        return
    record(section, "SUPPORTED", label, detail, role, impact)


raw = pathlib.Path(sys.argv[1]).read_text("utf-8", errors="replace")
try:
    envelope = json.loads(raw)
except ValueError as error:
    print("Helper 输出不是合法 JSON: {0}".format(error), file=sys.stderr)
    print("原始输出前 512 字节: {0}".format(raw[:512]), file=sys.stderr)
    raise SystemExit(1)

if not isinstance(envelope, dict) or envelope.get("ok") is not True:
    failure = envelope.get("error") if isinstance(envelope, dict) else None
    if isinstance(failure, dict):
        print("Helper get_capabilities 返回失败: {0} / {1}".format(failure.get("code"), failure.get("message")), file=sys.stderr)
    else:
        print("Helper get_capabilities 返回非成功信封: {0}".format(raw[:512]), file=sys.stderr)
    raise SystemExit(1)

result = envelope.get("result")
if not isinstance(result, dict):
    print("Helper 成功信封缺少 result 对象", file=sys.stderr)
    raise SystemExit(1)

protocol = result.get("protocolVersion")
helper = result.get("helper") if isinstance(result.get("helper"), dict) else {}
platform_info = result.get("platform") if isinstance(result.get("platform"), dict) else {}
distribution = platform_info.get("distribution") if isinstance(platform_info.get("distribution"), dict) else {}
runtime = result.get("runtime") if isinstance(result.get("runtime"), dict) else {}
security = result.get("securityContext") if isinstance(result.get("securityContext"), dict) else {}
feature_status = result.get("featureStatus") if isinstance(result.get("featureStatus"), dict) else {}
operations = result.get("operations") if isinstance(result.get("operations"), list) else []

timezone_name = result.get("timezone") or runtime.get("timezone")
host_time = result.get("hostTimeUtc") or runtime.get("hostTimeUtc")
offset_seconds = result.get("utcOffsetSeconds")
if offset_seconds is None:
    offset_seconds = runtime.get("utcOffsetSeconds")
if isinstance(offset_seconds, int):
    sign = "+" if offset_seconds >= 0 else "-"
    offset_text = "UTC{0}{1:02d}:{2:02d}".format(sign, abs(offset_seconds) // 3600, abs(offset_seconds) % 3600 // 60)
else:
    offset_text = "偏移未知"

print("===== HuntWarden 目标端功能自检 =====")
print("Helper 版本   : {0} (协议版本 {1})".format(helper.get("version", "未知"), protocol))
print("目标系统      : {0} {1} {2}".format(platform_info.get("system", "未知"), platform_info.get("release", ""), platform_info.get("architecture", "")).rstrip())
print("发行版        : {0} (ID={1}, 版本 {2})".format(distribution.get("prettyName", "未知"), distribution.get("id", "未知"), distribution.get("versionId", "未知")))
print("Python        : {0}".format(platform_info.get("python", "未知")))
print("init / 容器   : {0} / {1}".format(runtime.get("initSystem", "未知"), runtime.get("container", "未知")))
print("Helper 身份   : euid={0} user={1} bootId={2}".format(runtime.get("euid", "未知"), runtime.get("currentUser", "未知"), runtime.get("bootId", "不可用")))
print("namespace     : pid={0} mnt={1} hidepid={2}".format(security.get("pidNamespace", "未知"), security.get("mountNamespace", "未知"), security.get("hidepid", "未知")))
if host_time or timezone_name:
    print("主机时间      : {0} (时区 {1}, {2})".format(host_time or "未知", timezone_name or "未知", offset_text))
else:
    print("主机时间      : Helper 未返回时区字段")
print("固定操作数    : {0}".format(len(operations)))

if protocol != REQUIRED_PROTOCOL_VERSION:
    record("component", "UNSUPPORTED", "Helper 协议版本",
           "目标端返回 {0}，控制端要求 {1}".format(protocol, REQUIRED_PROTOCOL_VERSION), "core",
           "控制端会直接拒绝该目标；请升级目标端 Helper 后重新安装")
else:
    record("component", "SUPPORTED", "Helper 协议版本", "协议版本 {0}，与控制端要求一致".format(protocol), "core")

missing_operations = [name for name in ESSENTIAL_OPERATIONS if name not in operations]
if missing_operations:
    record("component", "UNSUPPORTED", "固定操作集合",
           "缺少关键操作: {0}".format("、".join(missing_operations)), "core",
           "Helper 文件不完整或版本过旧，对应检测维度直接不可用；请重新执行 install-helper.sh")
else:
    record("component", "SUPPORTED", "固定操作集合", "关键操作齐备，共 {0} 个固定操作".format(len(operations)), "core")

file_record("component", RULE_PATH, "YARA 规则文件", 0o644, "core",
            "WebShell 规则扫描会以 INVALID_ARGUMENT 直接失败；执行 install-helper.sh 下发 rules/yara/webshell.yar")
file_record("component", PROBE_PATH, "Tomcat 探针 JAR", 0o644, "optional",
            "Java 内存马运行时枚举与 Class Dump 不可用；先 npm run probe:build，再以 --probe-source 重新安装")

if not (host_time or timezone_name):
    record("capability", "PARTIAL", "目标主机时区上报",
           "get_capabilities 未返回 timezone/hostTimeUtc", "optional",
           "无法核对目标主机时区，syslog 传统格式时间线可能整体偏移；请升级目标端 Helper")

for key, definition in CAPABILITY_MAP.items():
    label, role, impact = definition
    section = "info" if role == "info" else "capability"
    entry = feature_status.get(key)
    if not isinstance(entry, dict):
        # info 行只报告环境事实，不参与判定，因此不附降级影响。
        record(section, "UNSUPPORTED", label, "Helper 未返回 {0} 能力状态".format(key), role,
               "" if role == "info" else impact)
        continue
    record(section, str(entry.get("status", "UNSUPPORTED")), label, str(entry.get("reason", "")), role, impact)

for key in sorted(set(feature_status) - set(CAPABILITY_MAP)):
    entry = feature_status[key]
    if not isinstance(entry, dict):
        continue
    record("capability", str(entry.get("status", "UNSUPPORTED")), "{0}（自检未登记）".format(key),
           str(entry.get("reason", "")), "optional", "该能力未在自检映射中登记，请人工确认影响范围")

print("")
print("--- 组件就位检查 ---")
for entry in section_of("component"):
    show(entry)

print("")
print("--- 目标端检测能力 ---")
for entry in section_of("capability"):
    show(entry)

print("")
print("--- 环境事实（不参与判定）---")
for entry in section_of("info"):
    show(entry)

helper_warnings = result.get("warnings") if isinstance(result.get("warnings"), list) else []
print("")
print("--- Helper 自报 warning ---")
if helper_warnings:
    for warning in helper_warnings:
        print("- {0}".format(warning))
else:
    print("- 无")


# 同一项可能同时出现在组件检查与能力上报中（如 Tomcat 探针），摘要按名称去重，保留更严重的一条。
def worst_by_name(entries):
    severity = {"PARTIAL": 1, "UNSUPPORTED": 2, "PERMISSION_DENIED": 2}
    best = {}
    for entry in entries:
        current = best.get(entry["name"])
        if current is None or severity.get(entry["status"], 0) > severity.get(current["status"], 0):
            best[entry["name"]] = entry
    return list(best.values())


failures = worst_by_name([entry for entry in records if entry["role"] == "core" and entry["status"] in FATAL])
degradations = worst_by_name([
    entry for entry in records
    if entry["role"] != "info" and (
        entry["status"] == "PARTIAL" or (entry["role"] == "optional" and entry["status"] in FATAL)
    )
])

print("")
print("===== 自检结论 =====")
if failures:
    print("!!!!! 核心检测能力不可用，该目标不具备可信调查条件 !!!!!")
    for entry in failures:
        print("  [{0}] {1}: {2}".format(entry["status"], entry["name"], entry["reason"]))
        if entry["impact"]:
            print("      降级影响: " + entry["impact"])
if degradations:
    print("***** 存在降级项：检测能力不完整，结论会带 PARTIAL *****")
    for entry in degradations:
        print("  [{0}] {1}".format(entry["status"], entry["name"]))
        if entry["impact"]:
            print("      降级影响: " + entry["impact"])

if failures:
    if any(entry["name"] == "Helper 协议版本" for entry in failures):
        print("结论: 失败——Helper 协议版本不匹配，请升级目标端 Helper（退出码 3）")
        raise SystemExit(3)
    print("结论: 失败——请按上述条目修复后重跑自检（退出码 1）")
    raise SystemExit(1)
if degradations:
    print("结论: 通过但存在降级——可以执行调查，报告中相关维度必须按 PARTIAL 解读（退出码 0）")
    raise SystemExit(0)
print("结论: 通过——全部核心与可选能力均为 SUPPORTED（退出码 0）")
PY
