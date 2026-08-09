#!/usr/bin/env python3
"""Root-owned, operation-whitelisted helper used by SSHExecutor.

The helper reads one JSON object from stdin and emits one JSON envelope. It never
uses shell=True and never accepts an arbitrary command from the controller.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import glob
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

MAX_INPUT = 1024 * 1024
MAX_TEXT = 2 * 1024 * 1024
RECEIPT_DIR = pathlib.Path("/var/lib/huntwarden/actions")
ARTIFACT_DIR = pathlib.Path("/var/lib/huntwarden/artifacts") if os.geteuid() == 0 else pathlib.Path(tempfile.gettempdir()) / "huntwarden-artifacts"
ARTIFACT_TOKEN = re.compile(r"^[a-f0-9]{64}$")
ARTIFACT_MAX_BYTES = 100 * 1024 * 1024
ARTIFACT_TTL_SECONDS = 15 * 60
LOG_SCAN_MAX_BYTES = 64 * 1024 * 1024
HELPER_VERSION = "0.3.0"
PROBE_JAR = pathlib.Path("/opt/huntwarden/huntwarden-tomcat-probe.jar")
SCRIPT_EXTENSIONS = {
    ".php", ".phtml", ".php5", ".phar", ".inc", ".jsp", ".jspx", ".asp", ".aspx",
    ".py", ".pl", ".cgi", ".shtml", ".twig", ".tpl", ".vm", ".ftl", ".war", ".jar", ".class",
}
WEB_TEMP_ROOTS = tuple(pathlib.Path(value) for value in ("/tmp", "/var/tmp", "/dev/shm"))
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.I)
CLASS_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]{0,511}$")
PERSISTENCE_KINDS = {"cron", "systemd", "ssh", "shell", "extended"}
SYSTEM_PERSISTENCE_ROOTS = {
    "cron": ("/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"),
    "systemd": ("/etc/systemd", "/usr/lib/systemd", "/lib/systemd", "/run/systemd/system", "/run/systemd/transient",
                "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late"),
    "ssh": ("/etc/ssh",),
    "shell": ("/etc/profile", "/etc/bash.bashrc", "/etc/zsh", "/etc/profile.d"),
    "extended": ("/etc/anacrontab", "/var/spool/at", "/var/spool/cron/atjobs", "/etc/init.d", "/etc/rc.local",
                 "/etc/xdg/autostart", "/etc/pam.d", "/etc/udev/rules.d", "/etc/modprobe.d", "/etc/modules-load.d",
                 "/etc/cloud", "/etc/apt/apt.conf.d", "/etc/yum/pluginconf.d", "/etc/dnf/plugins", "/var/lib/systemd/linger"),
}
TRIAGE_ROOTS = tuple(pathlib.Path(value) for value in (
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
    "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home",
))
TRIAGE_SCAN_LIMIT = 50000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(password|passwd|pwd|token|secret|cookie|authorization|api[_-]?key)\s*[:=]\s*([^\s;,]+)"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/-]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


class HelperError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise HelperError("INVALID_ARGUMENT", "request exceeds 1 MiB")
    value = json.loads(raw or b"{}")
    if not isinstance(value, dict):
        raise HelperError("INVALID_ARGUMENT", "request must be a JSON object")
    return value


def safe_path(value: Any, *, must_exist: bool = True) -> pathlib.Path:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise HelperError("INVALID_ARGUMENT", "path must be absolute")
    path = pathlib.Path(value)
    if ".." in path.parts:
        raise HelperError("INVALID_ARGUMENT", "path traversal is forbidden")
    resolved = path.resolve(strict=must_exist)
    return resolved


def safe_username(value: Any) -> str:
    if not isinstance(value, str) or not USERNAME.fullmatch(value):
        raise HelperError("INVALID_ARGUMENT", "invalid username")
    return value


def safe_int(value: Any, minimum: int, maximum: int, name: str) -> int:
    if not isinstance(value, int) or value < minimum or value > maximum:
        raise HelperError("INVALID_ARGUMENT", f"invalid {name}")
    return value


def run(argv: list[str], timeout: int = 25, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HelperError("TOOL_TIMEOUT", f"operation timed out: {argv[0]}") from exc
    if check and result.returncode != 0:
        message = (result.stderr or result.stdout).strip()[:2000]
        code = "PERMISSION_DENIED" if "permission denied" in message.lower() else "UNSUPPORTED_ENVIRONMENT"
        raise HelperError(code, f"{argv[0]} exited {result.returncode}: {message}")
    return result


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_path(token: str) -> pathlib.Path:
    if not isinstance(token, str) or not ARTIFACT_TOKEN.fullmatch(token):
        raise HelperError("INVALID_ARGUMENT", "invalid artifactToken")
    return ARTIFACT_DIR / f"{token}.artifact"


def prepare_artifact_dir() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True, mode=0o711)
    info = ARTIFACT_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise HelperError("EVIDENCE_COLLECTION", "artifact spool is not a real directory")
    os.chmod(ARTIFACT_DIR, 0o711)
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - ARTIFACT_TTL_SECONDS
    for candidate in ARTIFACT_DIR.glob("*.artifact"):
        try:
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink()
        except OSError:
            continue


def stage_artifact(source: pathlib.Path, maximum: int) -> dict[str, Any]:
    prepare_artifact_dir()
    info = source.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_size > ARTIFACT_MAX_BYTES:
        raise HelperError("EVIDENCE_COLLECTION", "file is not regular or exceeds collection limit")
    token = secrets.token_hex(32)
    destination = artifact_path(token)
    digest = hashlib.sha256()
    size = 0
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(destination, flags, 0o400)
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            for chunk in iter(lambda: reader.read(256 * 1024), b""):
                size += len(chunk)
                if size > maximum or size > ARTIFACT_MAX_BYTES:
                    raise HelperError("EVIDENCE_COLLECTION", "file grew beyond collection limit")
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        sudo_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        sudo_gid = int(os.environ.get("SUDO_GID", os.getgid()))
        if os.geteuid() == 0:
            os.chown(destination, sudo_uid, sudo_gid)
        os.chmod(destination, 0o400)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ARTIFACT_TTL_SECONDS)
    return {
        "artifactToken": token,
        "sha256": digest.hexdigest(),
        "size": size,
        "expiresAt": expires.isoformat(),
    }


def stage_artifact_bytes(data: bytes, maximum: int) -> dict[str, Any]:
    """Stage generated evidence without returning its bytes in the JSON envelope."""
    if len(data) > maximum or len(data) > ARTIFACT_MAX_BYTES:
        raise HelperError("EVIDENCE_COLLECTION", "generated artifact exceeds collection limit")
    prepare_artifact_dir()
    token = secrets.token_hex(32)
    destination = artifact_path(token)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(destination, flags, 0o400)
        with os.fdopen(descriptor, "wb") as writer:
            for offset in range(0, len(data), 256 * 1024):
                writer.write(data[offset:offset + 256 * 1024])
            writer.flush()
            os.fsync(writer.fileno())
        sudo_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        sudo_gid = int(os.environ.get("SUDO_GID", os.getgid()))
        if os.geteuid() == 0:
            os.chown(destination, sudo_uid, sudo_gid)
        os.chmod(destination, 0o400)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ARTIFACT_TTL_SECONDS)
    return {
        "artifactToken": token,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "expiresAt": expires.isoformat(),
    }


def bounded_tail_lines(path: pathlib.Path, maximum_bytes: int = LOG_SCAN_MAX_BYTES):
    """Yield decoded lines from the newest bounded window without loading the file."""
    size = path.stat().st_size
    start = max(0, size - maximum_bytes)
    handle = path.open("rb")

    def iterator():
        with handle:
            handle.seek(start)
            if start:
                handle.readline()  # discard a partial first line
            for raw in handle:
                yield raw.decode("utf-8", errors="replace").rstrip("\r\n")

    return iterator()


def release_artifact(request: dict[str, Any]) -> dict[str, Any]:
    path = artifact_path(request.get("artifactToken"))
    try:
        path.unlink()
        return {"released": True}
    except FileNotFoundError:
        return {"released": False}


def capability_state(status_value: str, reason: str) -> dict[str, str]:
    return {"status": status_value, "reason": reason}


def linux_runtime_snapshot() -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, str]], list[str]]:
    warnings: list[str] = []
    try:
        current_user = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        current_user = str(os.geteuid())
    runtime: dict[str, Any] = {
        "initSystem": "unknown", "container": "unknown", "euid": os.geteuid(),
        "currentUser": current_user, "rootHelper": os.geteuid() == 0,
    }
    security = {"hidepid": "unknown", "pidNamespace": "unknown", "mountNamespace": "unknown", "selinux": "unknown", "apparmor": "unknown"}
    details: dict[str, dict[str, str]] = {}
    if platform.system() != "Linux":
        details["linuxProc"] = capability_state("UNSUPPORTED", "目标不是 Linux")
        return runtime, security, details, ["Linux /proc 能力不可用"]

    try:
        runtime["bootId"] = boot_id()
        details["linuxProc"] = capability_state("SUPPORTED", "Linux /proc 与 boot_id 可读取")
    except HelperError as exc:
        details["linuxProc"] = capability_state("PERMISSION_DENIED", str(exc))
        warnings.append(str(exc))
    try:
        runtime["initSystem"] = pathlib.Path("/proc/1/comm").read_text("utf-8", errors="replace").strip()[:128] or "unknown"
    except OSError:
        warnings.append("无法识别 PID 1 init")

    cgroup = ""
    try:
        cgroup = pathlib.Path("/proc/1/cgroup").read_text("utf-8", errors="replace")[:65536]
    except OSError:
        pass
    if pathlib.Path("/.dockerenv").exists() or "docker" in cgroup:
        runtime["container"] = "docker"
    elif pathlib.Path("/run/.containerenv").exists():
        runtime["container"] = "container"
    elif "kubepods" in cgroup:
        runtime["container"] = "kubernetes"
    elif "containerd" in cgroup:
        runtime["container"] = "containerd"
    else:
        runtime["container"] = "none-detected"

    details["rootHelper"] = capability_state(
        "SUPPORTED" if runtime["rootHelper"] else "PERMISSION_DENIED",
        "Helper 以 root EUID 运行" if runtime["rootHelper"] else f"Helper EUID={os.geteuid()}，部分 /proc 与取证操作可能被拒绝",
    )
    sudo = shutil.which("sudo")
    details["sudo"] = capability_state(
        "SUPPORTED" if sudo else "UNSUPPORTED",
        "sudo 可用；Helper 当前已获得 root 权限" if sudo and runtime["rootHelper"] else "sudo 二进制可用" if sudo else "sudo 不可用",
    )

    journal_binary = shutil.which("journalctl")
    journal_storage = pathlib.Path("/run/log/journal").is_dir() or pathlib.Path("/var/log/journal").is_dir()
    if journal_binary and journal_storage:
        details["journal"] = capability_state("SUPPORTED", "journalctl 与 journal 存储可用")
    elif journal_binary:
        details["journal"] = capability_state("PARTIAL", "journalctl 存在，但未发现 journal 存储")
        warnings.append("journald 数据源不完整")
    else:
        details["journal"] = capability_state("UNSUPPORTED", "journalctl 不可用")

    audit_tool = shutil.which("auditctl") is not None or shutil.which("ausearch") is not None
    audit_log = pathlib.Path("/var/log/audit/audit.log").is_file()
    if audit_tool and audit_log:
        details["auditd"] = capability_state("SUPPORTED", "audit 工具与 audit.log 可用")
    elif audit_tool or audit_log:
        details["auditd"] = capability_state("PARTIAL", "audit 工具或 audit.log 仅有一项可用")
        warnings.append("auditd 数据源不完整")
    else:
        details["auditd"] = capability_state("UNSUPPORTED", "audit 工具与 audit.log 均不可用")

    for runtime_name, socket_path in (("docker", "/var/run/docker.sock"), ("containerd", "/run/containerd/containerd.sock")):
        binary = shutil.which(runtime_name) is not None or (runtime_name == "containerd" and shutil.which("ctr") is not None)
        socket_present = pathlib.Path(socket_path).exists()
        socket_access = socket_present and os.access(socket_path, os.R_OK | os.W_OK)
        if socket_access:
            details[runtime_name] = capability_state("SUPPORTED", f"{socket_path} 可访问")
        elif socket_present:
            details[runtime_name] = capability_state("PERMISSION_DENIED", f"{socket_path} 存在但不可访问")
            warnings.append(f"{runtime_name} socket 权限不足")
        elif binary:
            details[runtime_name] = capability_state("PARTIAL", f"{runtime_name} 客户端存在，但未发现固定 socket")
        else:
            details[runtime_name] = capability_state("UNSUPPORTED", f"未发现 {runtime_name} 客户端或固定 socket")

    selinux_enforce = pathlib.Path("/sys/fs/selinux/enforce")
    if selinux_enforce.is_file():
        try:
            security["selinux"] = "enforcing" if selinux_enforce.read_text("ascii").strip() == "1" else "permissive"
            details["selinux"] = capability_state("SUPPORTED", f"SELinux {security['selinux']}")
        except PermissionError:
            details["selinux"] = capability_state("PERMISSION_DENIED", "SELinux 已启用但状态不可读")
    else:
        security["selinux"] = "disabled-or-unavailable"
        details["selinux"] = capability_state("UNSUPPORTED", "SELinux 未启用或 sysfs 不可用")

    apparmor_enabled = pathlib.Path("/sys/module/apparmor/parameters/enabled")
    if apparmor_enabled.is_file():
        try:
            security["apparmor"] = "enabled" if apparmor_enabled.read_text("ascii").strip().lower().startswith("y") else "disabled"
            details["apparmor"] = capability_state("SUPPORTED" if security["apparmor"] == "enabled" else "UNSUPPORTED", f"AppArmor {security['apparmor']}")
        except PermissionError:
            details["apparmor"] = capability_state("PERMISSION_DENIED", "AppArmor 状态不可读")
    else:
        security["apparmor"] = "unavailable"
        details["apparmor"] = capability_state("UNSUPPORTED", "AppArmor 内核接口不可用")

    try:
        proc_line = next(line for line in pathlib.Path("/proc/mounts").read_text("utf-8", errors="replace").splitlines() if line.split()[1] == "/proc")
        options = proc_line.split()[3].split(",")
        security["hidepid"] = next((value.split("=", 1)[1] for value in options if value.startswith("hidepid=")), "0")
    except (OSError, StopIteration, IndexError):
        warnings.append("无法识别 /proc hidepid")
    try:
        security["pidNamespace"] = os.readlink("/proc/self/ns/pid")
        security["mountNamespace"] = os.readlink("/proc/self/ns/mnt")
        os.stat("/proc/1/exe")
        details["procVisibility"] = capability_state(
            "PARTIAL" if security["hidepid"] not in {"0", "off"} else "SUPPORTED",
            f"hidepid={security['hidepid']}；PID namespace={security['pidNamespace']}",
        )
        if details["procVisibility"]["status"] == "PARTIAL":
            warnings.append("/proc hidepid 限制可能造成采集缺口")
    except PermissionError:
        details["procVisibility"] = capability_state("PERMISSION_DENIED", "无法读取 PID 1 可执行文件或 namespace")
        warnings.append("/proc 进程可见性受权限限制")
    except OSError:
        details["procVisibility"] = capability_state("PARTIAL", "namespace 或 PID 1 信息不可用")
        warnings.append("/proc namespace 信息不完整")
    return runtime, security, details, warnings


def get_capabilities(_: dict[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []
    yara = shutil.which("yara") is not None
    java_attach = pathlib.Path("/usr/bin/jcmd").exists() or shutil.which("java") is not None
    probe = PROBE_JAR.is_file()
    if not yara:
        warnings.append("YARA 不可用，WebShell 规则扫描将为 PARTIAL")
    if not probe:
        warnings.append("Tomcat 探针不可用，Java 组件调查将为 PARTIAL")
    runtime, security, details, context_warnings = linux_runtime_snapshot()
    details.update({
        "yara": capability_state("SUPPORTED" if yara else "UNSUPPORTED", "YARA 可用" if yara else "YARA 未安装"),
        "javaAttach": capability_state("SUPPORTED" if java_attach else "UNSUPPORTED", "Java Attach 运行时可用" if java_attach else "未发现 Java/JDK Attach 运行时"),
        "tomcatProbe": capability_state("SUPPORTED" if probe else "UNSUPPORTED", f"Tomcat 探针位于 {PROBE_JAR}" if probe else f"Tomcat 探针缺失: {PROBE_JAR}"),
    })
    warnings.extend(context_warnings)
    return {
        "protocolVersion": 1,
        "helper": {"name": "huntwarden-helper", "version": HELPER_VERSION},
        "platform": {
            "system": platform.system(), "release": platform.release(),
            "architecture": platform.machine(), "python": platform.python_version(),
        },
        "operations": sorted(OPERATIONS.keys()),
        "artifactTransfer": {"supported": True, "protocolVersion": 1, "maxBytes": ARTIFACT_MAX_BYTES},
        "features": {"yara": yara, "javaAttach": java_attach, "tomcatProbe": probe},
        "featureStatus": details,
        "runtime": runtime,
        "securityContext": security,
        "partial": bool(warnings),
        "warnings": warnings,
    }


def file_facts(path: pathlib.Path) -> dict[str, Any]:
    info = path.stat()
    return {
        "path": str(path), "sha256": sha256_file(path), "size": info.st_size,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid,
        "mtime": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(),
    }


def persistence_limits(request: dict[str, Any]) -> tuple[int, bool]:
    maximum = safe_int(request.get("maxItems"), 1, 5000, "maxItems")
    include_user = request.get("includeUserScope")
    if not isinstance(include_user, bool):
        raise HelperError("INVALID_ARGUMENT", "invalid includeUserScope")
    return maximum, include_user


def interactive_accounts() -> list[pwd.struct_passwd]:
    return [account for account in pwd.getpwall() if (account.pw_uid == 0 or account.pw_uid >= 1000) and account.pw_shell not in {"", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin"}]


def is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validated_persistence_path(kind: Any, value: Any) -> pathlib.Path:
    if kind not in PERSISTENCE_KINDS:
        raise HelperError("INVALID_ARGUMENT", "invalid persistence kind")
    path = safe_path(value)
    allowed = [pathlib.Path(root).resolve(strict=False) for root in SYSTEM_PERSISTENCE_ROOTS[kind]]
    if kind == "systemd":
        allowed.extend((pathlib.Path(account.pw_dir) / ".config/systemd/user").resolve(strict=False) for account in interactive_accounts())
    elif kind == "ssh":
        allowed.extend((pathlib.Path(account.pw_dir) / ".ssh").resolve(strict=False) for account in interactive_accounts())
    elif kind == "shell":
        allowed.extend(pathlib.Path(account.pw_dir).resolve(strict=False) for account in interactive_accounts())
    if not any(path == root or is_within(path, root) for root in allowed):
        raise HelperError("PERMISSION_DENIED", "path is outside fixed persistence scope")
    if not path.is_file() or path.is_symlink():
        raise HelperError("INVALID_ARGUMENT", "persistence path must be a regular non-symlink file")
    if kind == "systemd" and path.suffix not in {".service", ".timer"}:
        raise HelperError("PERMISSION_DENIED", "unsupported systemd file type")
    if kind == "ssh" and path.name != "authorized_keys":
        raise HelperError("PERMISSION_DENIED", "only authorized_keys may be inspected")
    if kind == "shell" and path.name not in {"profile", "bash.bashrc", ".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc", "zshrc", "zprofile"} and path.suffix != ".sh":
        raise HelperError("PERMISSION_DENIED", "unsupported shell startup file type")
    return path


def dangerous_features(text: str) -> list[str]:
    expressions = {
        "download_execute": r"\b(?:curl|wget)\b.*(?:\||-o\s)|\b(?:bash|sh)\s+-c\b",
        "encoded_payload": r"base64\s+(?:-d|--decode)|frombase64string",
        "network_listener": r"\b(?:nc|ncat|socat)\b.*(?:-l|listen)|http\.server",
        "temporary_execution": r"/(?:tmp|dev/shm)/|mktemp",
        "interpreter_execution": r"\b(?:python|perl|ruby|php)\d*\b",
    }
    return [name for name, expression in expressions.items() if re.search(expression, text, re.I)]


def text_file(path: pathlib.Path, maximum: int = 65536) -> str:
    return path.read_bytes()[:maximum].decode("utf-8", errors="replace")


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def action_id(request: dict[str, Any]) -> str:
    value = request.get("actionId")
    if not isinstance(value, str) or not re.fullmatch(r"ACT-[0-9a-f-]{36}", value):
        raise HelperError("INVALID_ARGUMENT", "invalid actionId")
    return value


def receipt_path(value: str) -> pathlib.Path:
    return RECEIPT_DIR / f"{value}.json"


def begin_receipt(value: str, operation: str, request: dict[str, Any]) -> dict[str, Any]:
    path = receipt_path(value)
    incoming_digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
    if path.exists():
        existing = json.loads(path.read_text("utf-8"))
        if existing.get("operation") != operation or existing.get("argsDigest") != incoming_digest:
            raise HelperError("INVALID_ARGUMENT", "actionId was already bound to different arguments")
        return existing
    receipt = {
        "actionId": value,
        "operation": operation,
        "status": "STARTED",
        "argsDigest": incoming_digest,
        "startedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    atomic_json(path, receipt)
    return receipt


def finish_receipt(receipt: dict[str, Any], status_value: str, result: dict[str, Any]) -> dict[str, Any]:
    receipt.update({"status": status_value, "result": result, "finishedAt": dt.datetime.now(dt.timezone.utc).isoformat()})
    atomic_json(receipt_path(str(receipt["actionId"])), receipt)
    return receipt


def java_binary(pid: int | None = None) -> str | None:
    if pid is not None:
        try:
            executable = pathlib.Path(f"/proc/{pid}/exe").resolve(strict=True)
            if executable.name.startswith("java") and executable.is_file():
                return str(executable)
        except OSError:
            pass
    discovered = shutil.which("java")
    if discovered:
        return discovered
    for candidate in ("/opt/java/openjdk/bin/java", "/usr/local/openjdk-17/bin/java", "/usr/lib/jvm/java-17-openjdk/bin/java"):
        if pathlib.Path(candidate).is_file():
            return candidate
    return None


def get_host_info(_: dict[str, Any]) -> dict[str, Any]:
    os_release: dict[str, str] = {}
    release = pathlib.Path("/etc/os-release")
    if release.exists():
        for line in release.read_text("utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip('"')
    java_path = java_binary()
    java = run([java_path, "-version"], check=False).stderr.splitlines()[:2] if java_path else []
    return {
        "hostname": platform.node(), "platform": platform.system(), "kernel": platform.release(),
        "architecture": platform.machine(), "osRelease": os_release, "java": java,
        "yaraAvailable": shutil.which("yara") is not None,
    }


def list_processes(request: dict[str, Any]) -> list[dict[str, Any]]:
    pattern = request.get("pattern")
    if pattern is not None and (not isinstance(pattern, str) or len(pattern) > 128):
        raise HelperError("INVALID_ARGUMENT", "invalid process pattern")
    rows = []
    for line in run(["ps", "-eo", "pid=,ppid=,user=,etimes=,args="], check=True).stdout.splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) != 5 or (pattern and pattern.lower() not in parts[4].lower()):
            continue
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "user": parts[2], "elapsedSeconds": int(parts[3]), "command": parts[4][:4096]})
    return rows[:2000]


def inventory_web_stacks(_: dict[str, Any]) -> dict[str, Any]:
    signatures = ("nginx", "apache2", "httpd", "php-fpm", "catalina", "tomcat")
    processes = [item for item in list_processes({}) if any(value in str(item.get("command", "")).lower() for value in signatures)]
    binaries = {name: shutil.which(name) for name in ("nginx", "apache2", "httpd", "apachectl", "php", "php-fpm")}
    configs = [path for pattern in ("/etc/nginx/**/*.conf", "/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf", "/etc/php/**/php.ini")
               for path in glob.glob(pattern, recursive=True)[:1000] if pathlib.Path(path).is_file()]
    warnings: list[str] = []
    if len(processes) >= 2000:
        warnings.append("Web 进程清单达到上限")
    return {"items": processes[:2000], "processes": processes[:2000], "binaries": binaries, "configPaths": sorted(set(configs))[:2000],
            "partial": bool(warnings), "warnings": warnings}


def web_root_inventory() -> tuple[list[dict[str, Any]], list[str]]:
    roots: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    directive = re.compile(r"^\s*(root|alias|DocumentRoot)\s+['\"]?([^;'\"\s]+)", re.I)

    sources: list[tuple[str, str, str]] = []
    if shutil.which("nginx"):
        effective = run([shutil.which("nginx") or "nginx", "-T"], timeout=20, check=False)
        sources.append((effective.stdout + "\n" + effective.stderr, "nginx", "nginx -T"))
        if effective.returncode != 0:
            warnings.append("nginx -T 未完整成功，已同时解析固定配置目录")
    for expression in ("/etc/nginx/**/*.conf", "/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf"):
        names = glob.glob(expression, recursive=True)
        if len(names) > 1000:
            warnings.append(f"{expression} 配置文件超过 1000 个，仅解析前 1000 个")
        for name in names[:1000]:
            try:
                sources.append((text_file(pathlib.Path(name), 1024 * 1024), "nginx" if "nginx" in name else "apache", name))
            except OSError:
                warnings.append(f"无法读取 Web 配置: {name}")

    for text, server, source in sources:
        for line in text.splitlines():
            match = directive.search(line)
            if not match:
                continue
            value = match.group(2)
            if not value.startswith("/") or "$" in value:
                continue
            candidate = pathlib.Path(value).resolve(strict=False)
            if not candidate.is_dir():
                continue
            roots[str(candidate)] = {"path": str(candidate), "server": server, "directive": match.group(1).lower(), "configSource": source}
    for path, server in (("/var/www/html", "common"), ("/usr/local/tomcat/webapps", "tomcat"), ("/opt/tomcat/webapps", "tomcat")):
        candidate = pathlib.Path(path)
        if candidate.is_dir():
            resolved = str(candidate.resolve())
            roots.setdefault(resolved, {"path": resolved, "server": server, "directive": "fallback", "configSource": "fixed common root"})
    return [roots[path] for path in sorted(roots)], warnings


def discover_effective_web_roots(_: dict[str, Any]) -> dict[str, Any]:
    items, warnings = web_root_inventory()
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def discover_web_roots(_: dict[str, Any]) -> list[dict[str, str]]:
    items, _ = web_root_inventory()
    return [{"path": str(item["path"]), "server": str(item["server"])} for item in items]


def is_web_artifact(path: pathlib.Path) -> bool:
    if path.suffix.lower() in SCRIPT_EXTENSIONS:
        return True
    if path.suffix:
        return False
    try:
        prefix = path.read_bytes()[:512].lower()
    except OSError:
        return False
    return prefix.startswith(b"#!") or b"<?php" in prefix or b"<%@ page" in prefix


def scan_recent_web_artifacts(roots: list[pathlib.Path], hours: int, maximum: int, max_size: int) -> dict[str, Any]:
    cutoff = dt.datetime.now().timestamp() - hours * 3600
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    visited = 0
    skipped = 0
    for root in roots:
        if not root.is_dir():
            skipped += 1
            continue
        for directory, subdirs, files in os.walk(root, followlinks=False):
            subdirs[:] = [name for name in subdirs if not (pathlib.Path(directory) / name).is_symlink()]
            for filename in files:
                visited += 1
                path = pathlib.Path(directory) / filename
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mtime < cutoff or info.st_size > max_size or not is_web_artifact(path):
                        skipped += 1
                        continue
                    items.append({"path": str(path), "size": info.st_size, "inode": str(info.st_ino),
                                  "mtime": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(), "sha256": sha256_file(path),
                                  "extension": path.suffix.lower() or "none"})
                except (OSError, PermissionError):
                    skipped += 1
                    continue
                if len(items) >= maximum:
                    warnings.append("Web Artifact 结果达到配置上限")
                    return {"items": items, "partial": True, "warnings": warnings, "visited": visited, "skipped": skipped}
    return {"items": items, "partial": False, "warnings": warnings, "visited": visited, "skipped": skipped}


def find_recent_web_files(request: dict[str, Any]) -> list[dict[str, Any]]:
    roots = request.get("roots")
    if not isinstance(roots, list) or not roots or len(roots) > 50:
        raise HelperError("INVALID_ARGUMENT", "invalid roots")
    hours = safe_int(request.get("modifiedWithinHours"), 1, 24 * 365, "modifiedWithinHours")
    maximum = safe_int(request.get("maxFiles"), 1, 5000, "maxFiles")
    max_size = safe_int(request.get("maxFileSizeBytes"), 1024, 1024 * 1024 * 100, "maxFileSizeBytes")
    result = scan_recent_web_artifacts([safe_path(value) for value in roots], hours, maximum, max_size)
    return result["items"]


def list_recent_web_artifacts(request: dict[str, Any]) -> dict[str, Any]:
    roots = request.get("roots")
    if not isinstance(roots, list) or not roots or len(roots) > 50:
        raise HelperError("INVALID_ARGUMENT", "invalid roots")
    hours = safe_int(request.get("modifiedWithinHours"), 1, 8760, "modifiedWithinHours")
    maximum = safe_int(request.get("maxFiles"), 1, 5000, "maxFiles")
    max_size = safe_int(request.get("maxFileSizeBytes"), 1024, ARTIFACT_MAX_BYTES, "maxFileSizeBytes")
    return scan_recent_web_artifacts([safe_path(value) for value in roots], hours, maximum, max_size)


def list_upload_temp_artifacts(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("modifiedWithinHours"), 1, 8760, "modifiedWithinHours")
    maximum = safe_int(request.get("maxFiles"), 1, 5000, "maxFiles")
    max_size = safe_int(request.get("maxFileSizeBytes"), 1024, ARTIFACT_MAX_BYTES, "maxFileSizeBytes")
    roots = [root.resolve(strict=False) for root in WEB_TEMP_ROOTS if root.is_dir()]
    # PHP upload_tmp_dir is parsed only from root-owned fixed php.ini files.
    for name in glob.glob("/etc/php/**/php.ini", recursive=True)[:100]:
        try:
            for line in bounded_tail_lines(pathlib.Path(name), 1024 * 1024):
                match = re.match(r"^\s*upload_tmp_dir\s*=\s*([^;\s]+)", line)
                if match and match.group(1).startswith("/"):
                    candidate = pathlib.Path(match.group(1)).resolve(strict=False)
                    if candidate.is_dir() and candidate not in roots:
                        roots.append(candidate)
        except OSError:
            continue
    result = scan_recent_web_artifacts(roots[:50], hours, maximum, max_size)
    result["roots"] = [str(root) for root in roots[:50]]
    return result


def yara_scan_files(request: dict[str, Any]) -> list[dict[str, Any]]:
    if not shutil.which("yara"):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "yara is not installed")
    paths = request.get("paths")
    if not isinstance(paths, list) or len(paths) > 500:
        raise HelperError("INVALID_ARGUMENT", "invalid paths")
    rule_path = safe_path(request.get("rulePath"))
    validated: list[pathlib.Path] = []
    for value in paths:
        path = safe_path(value)
        if "\n" in str(path) or "\r" in str(path):
            raise HelperError("INVALID_ARGUMENT", "YARA path contains a line break")
        validated.append(path)
    if not validated:
        return []
    # --scan-list lets one YARA process compile the rules once for the entire
    # bounded candidate set instead of spawning one process per file.
    list_path: pathlib.Path | None = None
    try:
        descriptor, raw_name = tempfile.mkstemp(prefix="huntwarden-yara-", text=True)
        list_path = pathlib.Path(raw_name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for path in validated:
                handle.write(f"{path}\n")
        output = run(["yara", "--timeout=30", "--scan-list", str(rule_path), str(list_path)], timeout=45, check=False)
    finally:
        if list_path is not None:
            list_path.unlink(missing_ok=True)
    matches_by_path: dict[str, list[str]] = {str(path): [] for path in validated}
    for line in output.stdout.splitlines():
        rule, separator, matched_path = line.partition(" ")
        if separator and matched_path in matches_by_path:
            matches_by_path[matched_path].append(rule)
    error = output.stderr.strip()[:1000] or None
    return [{"path": str(path), "matches": matches_by_path[str(path)], "error": error} for path in validated]


def inspect_script_file(request: dict[str, Any]) -> dict[str, Any]:
    path = safe_path(request.get("path"))
    max_bytes = safe_int(request.get("maxBytes"), 1024, 65536, "maxBytes")
    raw = path.read_bytes()[:max_bytes]
    text = raw.decode("utf-8", errors="replace")
    patterns = {
        "commandExecution": r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|shell_exec|passthru|system\s*\(",
        "dynamicEvaluation": r"\beval\s*\(|\bassert\s*\(|base64_decode\s*\(",
        "obfuscation": r"gzinflate|str_rot13|chr\s*\(|ClassLoader\.defineClass",
    }
    features = {name: len(re.findall(expr, text, re.I)) for name, expr in patterns.items()}
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size, "features": features, "excerpt": text, "truncated": path.stat().st_size > len(raw)}


def search_web_access_log(request: dict[str, Any]) -> list[dict[str, Any]]:
    path = safe_path(request.get("path"))
    name = pathlib.Path(str(request.get("fileName", ""))).name
    if not name or len(name) > 255:
        raise HelperError("INVALID_ARGUMENT", "invalid fileName")
    maximum = safe_int(request.get("maxLines"), 1, 5000, "maxLines")
    matches = []
    for expression in ["/var/log/nginx/access*.log", "/var/log/apache2/access*.log", "/var/log/httpd/access_log*"]:
        for log_name in glob.glob(expression)[:100]:
            try:
                for line in bounded_tail_lines(pathlib.Path(log_name)):
                    if name in line:
                        matches.append({"log": log_name, "line": redact_secret_text(line, 8192)})
                        if len(matches) >= maximum:
                            return matches
            except OSError:
                continue
    return matches


def validated_web_candidate(value: Any, expected_sha256: Any | None = None) -> pathlib.Path:
    path = safe_path(value)
    roots, _ = web_root_inventory()
    allowed = [pathlib.Path(item["path"]).resolve(strict=False) for item in roots]
    allowed.extend(root.resolve(strict=False) for root in WEB_TEMP_ROOTS)
    if not any(path == root or is_within(path, root) for root in allowed):
        raise HelperError("PERMISSION_DENIED", "path is outside discovered Web and fixed upload-temp scope")
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256) or sha256_file(path) != expected_sha256:
            raise HelperError("EVIDENCE_COLLECTION", "Web artifact hash changed")
    return path


def inspect_web_runtime_config(request: dict[str, Any]) -> dict[str, Any]:
    root = safe_path(request.get("root"))
    roots, discovery_warnings = web_root_inventory()
    if str(root) not in {str(item["path"]) for item in roots}:
        raise HelperError("PERMISSION_DENIED", "root is not in the current effective Web Root inventory")
    maximum = safe_int(request.get("maxItems"), 1, 1000, "maxItems")
    items: list[dict[str, Any]] = []
    warnings = list(discovery_warnings)
    for directory, subdirs, files in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if not (pathlib.Path(directory) / name).is_symlink()]
        for filename in files:
            if filename not in {".user.ini", ".htaccess", "web.config"}:
                continue
            path = pathlib.Path(directory) / filename
            try:
                text = redact_secret_text(text_file(path), 65536)
                facts = file_facts(path)
                items.append({**facts, "name": filename, "features": dangerous_features(text),
                              "runtimeDirectives": [line.strip()[:2048] for line in text.splitlines()
                                                    if re.search(r"auto_prepend_file|auto_append_file|AddHandler|SetHandler|php_value|rewrite", line, re.I)][:100]})
            except OSError:
                warnings.append(f"无法读取运行时配置: {path}")
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": warnings + ["Web 运行时配置达到上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def correlate_web_requests(request: dict[str, Any]) -> dict[str, Any]:
    path = validated_web_candidate(request.get("path"), request.get("expectedSha256"))
    maximum = safe_int(request.get("maxEvents"), 1, 5000, "maxEvents")
    name = path.name
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    log_names = [name for expression in ("/var/log/nginx/access*.log", "/var/log/apache2/access*.log", "/var/log/httpd/access_log*")
                 for name in glob.glob(expression)[:100]]
    for log_name in log_names:
        log_path = pathlib.Path(log_name)
        try:
            lines = bounded_tail_lines(log_path)
            if log_path.stat().st_size > LOG_SCAN_MAX_BYTES:
                warnings.append(f"{log_name} 超过 64 MiB，仅关联最新窗口")
            for line in lines:
                if name not in line:
                    continue
                request_match = re.search(r'"([A-Z]{3,10})\s+([^\s"]+)\s+HTTP/[0-9.]+"\s+(\d{3})', line)
                ip_match = re.match(r"([0-9a-fA-F:.]{3,64})\s", line)
                time_match = re.search(r"\[([^\]]{5,64})\]", line)
                uri = request_match.group(2)[:4096] if request_match else None
                if uri:
                    uri = re.sub(r"(?i)(token|key|secret|password|session)=([^&\s]+)", r"\1=[REDACTED]", uri)
                items.append({"log": log_name, "sourceIp": ip_match.group(1) if ip_match else None,
                              "timestamp": time_match.group(1) if time_match else None,
                              "method": request_match.group(1) if request_match else None, "uri": uri,
                              "status": int(request_match.group(3)) if request_match else None})
                if len(items) >= maximum:
                    return {"items": items, "partial": True, "warnings": warnings + ["Web 请求关联达到上限"]}
        except (OSError, PermissionError):
            warnings.append(f"无法读取访问日志: {log_name}")
    if not log_names:
        warnings.append("未找到 Nginx/Apache Access Log")
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def find_web_related_processes(request: dict[str, Any]) -> dict[str, Any]:
    path = validated_web_candidate(request.get("path"), request.get("expectedSha256"))
    maximum = safe_int(request.get("maxProcesses"), 1, 500, "maxProcesses")
    expected = path.stat()
    web_signatures = ("nginx", "apache2", "httpd", "php-fpm", "catalina", "tomcat")
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    digest_cache: dict[tuple[int, int], str] = {}
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        pid = int(proc.name)
        reasons: list[str] = []
        opened: list[dict[str, Any]] = []
        try:
            command = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()[:65536].replace(b"\0", b" ").decode("utf-8", errors="replace")
            if any(signature in command.lower() for signature in web_signatures):
                reasons.append("web_runtime")
            for fd in (proc / "fd").iterdir():
                try:
                    info = fd.stat()
                    target = os.readlink(fd)
                    if info.st_dev == expected.st_dev and info.st_ino == expected.st_ino:
                        reasons.append("candidate_open_fd")
                        opened.append({"fd": fd.name, "target": target[:4096], "deleted": target.endswith(" (deleted)")})
                    elif target.endswith(" (deleted)") and any(str(pathlib.Path(root)) in target for root in (path.parent, *WEB_TEMP_ROOTS)):
                        reasons.append("deleted_web_file_open")
                        opened.append({"fd": fd.name, "target": target[:4096], "deleted": True})
                except OSError:
                    continue
            if not reasons:
                continue
            process = stable_process(pid, digest_cache)
            items.append({**process, "commandSummary": redact_secret_text(command, 4096),
                          "relationship": sorted(set(reasons)), "openedFiles": opened[:100]})
        except HelperError as exc:
            warnings.append(f"PID {pid}: {exc}")
        except (OSError, PermissionError):
            continue
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings[:199] + ["Web 相关进程达到上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def collect_file(request: dict[str, Any]) -> dict[str, Any]:
    path = safe_path(request.get("path"))
    maximum = safe_int(request.get("maxBytes"), 1, ARTIFACT_MAX_BYTES, "maxBytes")
    artifact = stage_artifact(path, maximum)
    return {"artifact": artifact, "sha256": artifact["sha256"], "size": artifact["size"]}


def list_java_processes(_: dict[str, Any]) -> list[dict[str, Any]]:
    return list_processes({"pattern": "java"})


def detect_java_container(request: dict[str, Any]) -> dict[str, Any]:
    pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
    lowered = cmdline.lower()
    container = "tomcat" if "catalina" in lowered or "tomcat" in lowered else "unknown"
    return {"pid": pid, "container": container, "command": cmdline[:8192], "supported": container == "tomcat"}


def run_tomcat_probe(request: dict[str, Any]) -> dict[str, Any]:
    if not PROBE_JAR.is_file():
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"probe jar missing: {PROBE_JAR}")
    pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    java_path = java_binary(pid)
    if not java_path:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "target JVM executable is unavailable")
    command = request.get("command")
    if command not in {"list_components", "inspect_class", "dump_class"}:
        raise HelperError("INVALID_ARGUMENT", "invalid probe command")
    argv = [java_path, "--add-modules", "jdk.attach", "-jar", str(PROBE_JAR), "attach", str(pid), str(command)]
    class_name = request.get("className")
    if command != "list_components":
        if not isinstance(class_name, str) or not CLASS_NAME.fullmatch(class_name):
            raise HelperError("INVALID_ARGUMENT", "invalid className")
        argv.append(class_name)
    result = run(argv, timeout=30)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "probe returned invalid JSON")
    if command == "dump_class" and isinstance(value.get("dataBase64"), str):
        try:
            data = base64.b64decode(value.pop("dataBase64"), validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise HelperError("EVIDENCE_COLLECTION", "probe returned invalid Class Dump bytes") from exc
        artifact = stage_artifact_bytes(data, ARTIFACT_MAX_BYTES)
        value["artifact"] = artifact
        value["sha256"] = artifact["sha256"]
        value["size"] = artifact["size"]
    return value


def search_class_on_disk(request: dict[str, Any]) -> dict[str, Any]:
    pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    class_name = request.get("className")
    if not isinstance(class_name, str) or not CLASS_NAME.fullmatch(class_name):
        raise HelperError("INVALID_ARGUMENT", "invalid className")
    relative = class_name.replace(".", "/") + ".class"
    roots = [pathlib.Path(f"/proc/{pid}/cwd"), pathlib.Path("/usr/local/tomcat"), pathlib.Path("/opt/tomcat")]
    matches = []
    for root in roots:
        try:
            resolved = root.resolve()
            for candidate in resolved.glob(f"**/{pathlib.Path(relative).name}"):
                if str(candidate).endswith(relative):
                    matches.append(str(candidate))
                    if len(matches) >= 20:
                        break
        except (OSError, PermissionError):
            continue
    return {"pid": pid, "className": class_name, "found": bool(matches), "paths": matches}


def list_privileged_accounts(_: dict[str, Any]) -> list[dict[str, Any]]:
    sudo_users: set[str] = set()
    for group_name in ("sudo", "wheel"):
        result = run(["getent", "group", group_name], check=False)
        if result.returncode == 0 and result.stdout.strip():
            fields = result.stdout.strip().split(":")
            if len(fields) >= 4:
                sudo_users.update(filter(None, fields[3].split(",")))
    local_accounts: set[str] = set()
    try:
        with pathlib.Path("/etc/passwd").open("r", encoding="utf-8", errors="replace") as handle:
            local_accounts.update(line.split(":", 1)[0] for line in handle if ":" in line)
    except OSError:
        pass
    rows = []
    for account in pwd.getpwall():
        privileged = account.pw_uid == 0 or account.pw_name in sudo_users
        interactive = account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""}
        if privileged or (account.pw_uid < 1000 and interactive):
            rows.append({"username": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid, "shell": account.pw_shell, "home": account.pw_dir,
                         "sudo": account.pw_name in sudo_users, "interactive": interactive,
                         "accountSource": "local" if account.pw_name in local_accounts else "nss_directory"})
    return rows


def inspect_privilege_delegation(request: dict[str, Any]) -> dict[str, Any]:
    maximum = safe_int(request.get("maxItems"), 1, 5000, "maxItems")
    candidates: list[tuple[str, pathlib.Path]] = [("sudoers", pathlib.Path("/etc/sudoers")), ("doas", pathlib.Path("/etc/doas.conf"))]
    for root, kind, pattern in ((pathlib.Path("/etc/sudoers.d"), "sudoers", "*"),
                                (pathlib.Path("/etc/polkit-1/rules.d"), "polkit", "*.rules"),
                                (pathlib.Path("/etc/polkit-1/localauthority"), "polkit", "*.pkla")):
        if root.is_dir():
            candidates.extend((kind, path) for path in root.rglob(pattern) if path.is_file() and not path.is_symlink())
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for kind, path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            resolved = path.resolve()
            if str(resolved) in seen:
                continue
            seen.add(str(resolved))
            text = text_file(resolved, 1024 * 1024)
            directives = [redact_secret_text(line.strip(), 4096) for line in text.splitlines()
                          if line.strip() and not line.lstrip().startswith(("#", "//"))][:500]
            items.append({**file_facts(resolved), "kind": kind, "directives": directives,
                          "signals": [name for name, expression in {
                              "passwordless": r"\bNOPASSWD\b|\bnopass\b", "wildcard_command": r"\sALL\s*$|\*",
                              "shell_command": r"/(?:ba|z|da)?sh\b", "polkit_allow": r"YES|ALLOW|Result\.YES",
                          }.items() if re.search(expression, text, re.I)]})
        except PermissionError:
            warnings.append(f"无权读取权限委派配置: {path}")
        except OSError:
            warnings.append(f"无法读取权限委派配置: {path}")
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings + ["权限委派配置达到上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def inspect_account(request: dict[str, Any]) -> dict[str, Any]:
    username = safe_username(request.get("username"))
    try:
        account = pwd.getpwnam(username)
    except KeyError as exc:
        raise HelperError("INVALID_ARGUMENT", "account does not exist") from exc
    groups = run(["id", "-nG", username]).stdout.strip().split()
    shadow = run(["getent", "shadow", username], check=False).stdout.strip().split(":")
    return {
        "username": username, "uid": account.pw_uid, "gid": account.pw_gid, "groups": groups,
        "shell": account.pw_shell, "home": account.pw_dir,
        "passwordLocked": bool(shadow and (shadow[1].startswith("!") or shadow[1].startswith("*"))),
        "accountExpireDays": shadow[7] if len(shadow) > 7 else "",
    }


def inspect_authorized_keys(request: dict[str, Any]) -> list[dict[str, Any]]:
    username = safe_username(request.get("username"))
    account = pwd.getpwnam(username)
    path = pathlib.Path(account.pw_dir) / ".ssh" / "authorized_keys"
    if not path.exists():
        return []
    items = []
    for index, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        fields = value.split()
        key_index = next((i for i, item in enumerate(fields) if item.startswith(("ssh-", "ecdsa-", "sk-"))), -1)
        if key_index < 0 or key_index + 1 >= len(fields):
            continue
        try:
            decoded = base64.b64decode(fields[key_index + 1], validate=True)
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(decoded).digest()).decode().rstrip("=")
        except ValueError:
            fingerprint = "INVALID"
        items.append({"line": index, "type": fields[key_index], "fingerprint": fingerprint, "comment": " ".join(fields[key_index + 2:])[:256], "hasOptions": key_index > 0})
    return items


def get_login_history(request: dict[str, Any]) -> list[dict[str, Any]]:
    username = safe_username(request.get("username"))
    maximum = safe_int(request.get("maxEntries"), 1, 500, "maxEntries")
    result = run(["last", "-F", "-n", str(maximum), username], check=False)
    return [{"raw": line[:2048]} for line in result.stdout.splitlines() if line.strip() and not line.startswith(("wtmp begins", "reboot"))]


def list_cron_entries(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    paths: list[pathlib.Path] = []
    for value in SYSTEM_PERSISTENCE_ROOTS["cron"]:
        candidate = pathlib.Path(value)
        if candidate.is_file():
            paths.append(candidate)
        elif candidate.is_dir():
            paths.extend(item for item in candidate.rglob("*") if item.is_file() and not item.is_symlink())
    if include_user:
        for spool in (pathlib.Path("/var/spool/cron/crontabs"), pathlib.Path("/var/spool/cron")):
            if spool.is_dir():
                paths.extend(item for item in spool.iterdir() if item.is_file() and not item.is_symlink())
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            facts = file_facts(path.resolve())
            lines = text_file(path).splitlines()
        except OSError:
            continue
        periodic = next((name for name in ("hourly", "daily", "weekly", "monthly") if f"/cron.{name}/" in str(path)), None)
        if periodic:
            items.append({**facts, "kind": "cron", "line": 0, "schedule": f"@{periodic}", "username": "root",
                          "commandSummary": str(path.resolve()), "features": dangerous_features(text_file(path))})
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": ["Cron 结果达到配置上限"]}
            continue
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#") or ("=" in line and not line.startswith("@") and len(line.split()) == 1):
                continue
            fields = line.split()
            if not (line.startswith("@") or len(fields) >= 6):
                continue
            schedule_fields = 1 if line.startswith("@") else 5
            command_fields = fields[schedule_fields:]
            username = None
            if str(path) == "/etc/crontab" or "/etc/cron.d/" in str(path):
                if command_fields:
                    username = command_fields.pop(0)
            command = " ".join(command_fields)[:4096]
            items.append({**facts, "kind": "cron", "line": number, "schedule": " ".join(fields[:schedule_fields]),
                          "username": username, "commandSummary": command, "features": dangerous_features(command)})
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": ["Cron 结果达到配置上限"]}
    return {"items": items, "partial": False, "warnings": []}


def parse_systemd_unit(path: pathlib.Path) -> dict[str, Any]:
    section = ""
    values: dict[str, list[str]] = {}
    for raw in text_file(path).splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(f"{section}.{key}", []).append(value[:4096])
    exec_start = values.get("Service.ExecStart", [])
    return {
        "unitType": path.suffix.lstrip("."), "execStart": exec_start,
        "runAs": (values.get("Service.User") or ["root"])[-1],
        "wantedBy": values.get("Install.WantedBy", []),
        "onCalendar": values.get("Timer.OnCalendar", []),
        "environmentFiles": values.get("Service.EnvironmentFile", []),
        "features": dangerous_features("\n".join(exec_start)),
    }


def list_systemd_units(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    roots = [pathlib.Path(value) for value in SYSTEM_PERSISTENCE_ROOTS["systemd"]]
    if include_user:
        roots.extend(pathlib.Path(account.pw_dir) / ".config/systemd/user" for account in interactive_accounts())
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.suffix not in {".service", ".timer"} or not path.is_file():
                continue
            resolved = path.resolve()
            if str(resolved) in seen:
                continue
            seen.add(str(resolved))
            try:
                enabled_links = [str(link) for link in pathlib.Path("/etc/systemd").rglob(path.name) if link.is_symlink()][:20]
                drop_ins: list[dict[str, Any]] = []
                dropin_dirs = [resolved.parent / f"{path.name}.d"]
                dropin_dirs.extend(candidate for dropin_root in roots if dropin_root.is_dir()
                                   for candidate in dropin_root.rglob(f"{path.name}.d") if candidate.is_dir())
                for dropin_dir in dict.fromkeys(dropin_dirs):
                    if not dropin_dir.is_dir():
                        continue
                    for override in sorted(dropin_dir.glob("*.conf"))[:100]:
                        try:
                            drop_ins.append({**file_facts(override.resolve()), **parse_systemd_unit(override.resolve())})
                        except OSError:
                            continue
                items.append({**file_facts(resolved), "kind": "systemd", "unit": path.name,
                              "scope": "user" if "/.config/systemd/user/" in str(resolved) else "system",
                              "enabled": bool(enabled_links), "enabledLinks": enabled_links, "dropIns": drop_ins,
                              "generated": str(resolved).startswith("/run/systemd/generator"),
                              "transient": str(resolved).startswith("/run/systemd/transient"), **parse_systemd_unit(resolved)})
            except OSError:
                continue
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": ["systemd 结果达到配置上限"]}
    manager_available = pathlib.Path("/run/systemd/system").is_dir()
    warnings = [] if manager_available else ["systemd 管理器未运行；仅完成 Unit 文件与启用链接检查"]
    return {"items": items, "partial": not manager_available, "warnings": warnings}


def list_extended_persistence(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    roots = [pathlib.Path(value) for value in SYSTEM_PERSISTENCE_ROOTS["extended"]]
    if include_user:
        for account in interactive_accounts():
            roots.extend((pathlib.Path(account.pw_dir) / ".config/autostart", pathlib.Path(account.pw_dir) / ".config/systemd/user"))
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for root in roots:
        candidates = [root] if root.is_file() else (item for item in root.rglob("*") if item.is_file() and not item.is_symlink()) if root.is_dir() else []
        try:
            for path in candidates:
                resolved = path.resolve()
                if str(resolved) in seen:
                    continue
                seen.add(str(resolved))
                text = text_file(resolved)
                category = "other"
                value = str(resolved)
                for marker, label in (("/init.d/", "sysv"), ("rc.local", "rc_local"), ("autostart", "xdg_autostart"),
                                      ("/pam.d/", "pam"), ("/udev/", "udev"), ("modprobe", "modprobe"),
                                      ("modules-load", "kernel_module"), ("/cloud/", "cloud_init"),
                                      ("apt.conf", "package_hook"), ("yum", "package_hook"), ("dnf", "package_hook"),
                                      ("/linger/", "user_linger"), ("anacron", "anacron"), ("atjobs", "at")):
                    if marker in value:
                        category = label
                        break
                items.append({**file_facts(resolved), "kind": "extended", "persistenceType": category,
                              "features": dangerous_features(text),
                              "commandSummaries": [redact_secret_text(line.strip(), 2048) for line in text.splitlines()
                                                   if dangerous_features(line)][:50]})
                if len(items) >= maximum:
                    return {"items": items, "partial": True, "warnings": warnings + ["扩展持久化结果达到上限"]}
        except PermissionError:
            warnings.append(f"无权读取扩展持久化目录: {root}")
        except OSError:
            warnings.append(f"无法读取扩展持久化目录: {root}")
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def effective_sshd_config() -> dict[str, Any]:
    binary = shutil.which("sshd")
    if not binary:
        return {"available": False}
    result = run([binary, "-T"], check=False)
    selected: dict[str, str] = {}
    wanted = {"authorizedkeysfile", "authorizedkeyscommand", "authorizedkeyscommanduser", "trustedusercakeys",
              "authorizedprincipalsfile", "revokedkeys", "permitrootlogin", "passwordauthentication",
              "pubkeyauthentication", "permituserenvironment", "allowusers", "allowgroups", "denyusers", "denygroups"}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in wanted:
            selected[key] = value[:2048]
    return {"available": result.returncode == 0, **selected}


def inspect_ssh_trust_configuration(_: dict[str, Any]) -> dict[str, Any]:
    roots = [pathlib.Path("/etc/ssh/sshd_config"), pathlib.Path("/etc/ssh/sshd_config.d")]
    files: list[dict[str, Any]] = []
    warnings: list[str] = []
    for root in roots:
        candidates = [root] if root.is_file() else list(root.glob("*.conf"))[:500] if root.is_dir() else []
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            try:
                text = text_file(path, 1024 * 1024)
                directives = []
                in_match = False
                for number, raw in enumerate(text.splitlines(), 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    key, _, value = line.partition(" ")
                    if key.lower() == "match":
                        in_match = True
                    if key.lower() in {"include", "match", "authorizedkeysfile", "authorizedkeyscommand", "authorizedkeyscommanduser",
                                      "trustedusercakeys", "authorizedprincipalsfile", "revokedkeys", "permitrootlogin",
                                      "passwordauthentication", "pubkeyauthentication", "permituserenvironment"}:
                        directives.append({"line": number, "key": key.lower(), "value": redact_secret_text(value.strip(), 2048), "inMatch": in_match})
                files.append({**file_facts(path.resolve()), "directives": directives})
            except PermissionError:
                warnings.append(f"无权读取 sshd 配置: {path}")
            except OSError:
                warnings.append(f"无法读取 sshd 配置: {path}")
    effective = effective_sshd_config()
    trust_files: list[dict[str, Any]] = []
    for key in ("trustedusercakeys", "authorizedprincipalsfile", "revokedkeys"):
        value = effective.get(key)
        if not isinstance(value, str) or not value.startswith("/") or "%" in value:
            continue
        candidate = pathlib.Path(value)
        try:
            if candidate.is_file() and not candidate.is_symlink():
                trust_files.append({"directive": key, **file_facts(candidate.resolve())})
        except OSError:
            warnings.append(f"无法核验 sshd 信任文件: {value}")
    if not effective.get("available"):
        warnings.append("sshd -T 未成功，effective 字段不完整")
    return {"items": files, "effective": effective, "trustFiles": trust_files,
            "partial": bool(warnings), "warnings": warnings[:200]}


def list_ssh_persistence(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    accounts = interactive_accounts() if include_user else []
    items: list[dict[str, Any]] = []
    for account in accounts:
        path = pathlib.Path(account.pw_dir) / ".ssh/authorized_keys"
        if not path.is_file() or path.is_symlink():
            continue
        try:
            facts = file_facts(path.resolve())
            keys = inspect_authorized_keys({"username": account.pw_name})
        except (OSError, KeyError):
            continue
        for key in keys:
            items.append({**facts, "kind": "ssh", "username": account.pw_name, **key})
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": ["SSH Key 结果达到配置上限"], "sshdConfig": effective_sshd_config()}
    return {"items": items, "partial": False, "warnings": [], "sshdConfig": effective_sshd_config()}


def list_shell_startup_files(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    paths = [pathlib.Path("/etc/profile"), pathlib.Path("/etc/bash.bashrc")]
    for root in (pathlib.Path("/etc/profile.d"), pathlib.Path("/etc/zsh")):
        if root.is_dir():
            paths.extend(item for item in root.rglob("*") if item.is_file() and not item.is_symlink())
    if include_user:
        for account in interactive_accounts():
            paths.extend(pathlib.Path(account.pw_dir) / name for name in (".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc"))
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            resolved = path.resolve()
            if str(resolved) in seen:
                continue
            seen.add(str(resolved))
            text = text_file(resolved)
            suspicious = [line.strip()[:1024] for line in text.splitlines() if dangerous_features(line)][:20]
            items.append({**file_facts(resolved), "kind": "shell", "features": dangerous_features(text), "commandSummaries": suspicious})
        except OSError:
            continue
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": ["Shell 启动文件结果达到配置上限"]}
    return {"items": items, "partial": False, "warnings": []}


def inspect_persistence_item(request: dict[str, Any]) -> dict[str, Any]:
    kind = request.get("kind")
    path = validated_persistence_path(kind, request.get("path"))
    expected = request.get("expectedSha256")
    current = sha256_file(path)
    if expected is not None and (not isinstance(expected, str) or current != expected):
        raise HelperError("EVIDENCE_COLLECTION", "persistence item hash changed")
    facts = file_facts(path)
    if kind == "ssh":
        username = safe_username(request.get("username"))
        return {**facts, "kind": kind, "username": username, "keys": inspect_authorized_keys({"username": username})}
    text = text_file(path)
    return {**facts, "kind": kind, "features": dangerous_features(text), "excerpt": text, "truncated": path.stat().st_size > 65536}


def find_related_processes(request: dict[str, Any]) -> list[dict[str, Any]]:
    kind = request.get("kind")
    path = validated_persistence_path(kind, request.get("path"))
    expected = request.get("expectedSha256")
    if expected is not None and sha256_file(path) != expected:
        raise HelperError("EVIDENCE_COLLECTION", "persistence item hash changed")
    maximum = safe_int(request.get("maxProcesses"), 1, 500, "maxProcesses")
    hint = request.get("commandHint", "")
    if not isinstance(hint, str) or len(hint) > 4096:
        raise HelperError("INVALID_ARGUMENT", "invalid commandHint")
    tokens = re.findall(r"/[A-Za-z0-9_./-]+|[A-Za-z0-9_.-]+", hint)
    useful = [pathlib.Path(token).name for token in tokens if pathlib.Path(token).name not in {"sh", "bash", "dash", "python", "python3", "env", "sudo", "root"}]
    if not useful:
        return []
    matches = []
    digest_cache: dict[tuple[int, int], str] = {}
    for process in list_processes({}):
        command = str(process.get("command", ""))
        if any(token in command for token in useful[:10]):
            try:
                stable = stable_process(int(process["pid"]), digest_cache)
            except (HelperError, OSError):
                continue
            summary = redact_secret_text(command, 4096)
            matches.append({**stable, "command": summary, "commandSummary": summary, "executable": stable["exePath"], "matchedTokens": useful[:10]})
            if len(matches) >= maximum:
                break
    return matches


def decode_endpoint(value: str, ipv6: bool) -> str:
    address_hex, port_hex = value.split(":")
    raw = bytes.fromhex(address_hex)
    if ipv6:
        address = socket.inet_ntop(socket.AF_INET6, b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4)))
    else:
        address = socket.inet_ntop(socket.AF_INET, raw[::-1])
    return f"{address}:{int(port_hex, 16)}"


def list_process_connections(request: dict[str, Any]) -> dict[str, Any]:
    stable_keys = {"bootId", "startTicks", "exeInode", "exeSha256"}
    if any(key in request for key in stable_keys):
        # Triage callers must provide all fields; process_request rejects partial or stale identities.
        pid = int(process_request(request)["pid"])
    else:
        # Compatibility for legacy persistence references. New triage tools never use this path.
        pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    maximum = safe_int(request.get("maxConnections"), 1, 20000, "maxConnections")
    proc = pathlib.Path(f"/proc/{pid}")
    if not proc.is_dir():
        raise HelperError("INVALID_ARGUMENT", "process no longer exists")
    inodes: set[str] = set()
    try:
        for fd in (proc / "fd").iterdir():
            try:
                match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
                if match:
                    inodes.add(match.group(1))
            except OSError:
                continue
    except OSError as exc:
        raise HelperError("PERMISSION_DENIED", "cannot inspect process descriptors") from exc
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN"}
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    for protocol, name, ipv6 in (("tcp", "/proc/net/tcp", False), ("tcp6", "/proc/net/tcp6", True), ("udp", "/proc/net/udp", False), ("udp6", "/proc/net/udp6", True)):
        path = pathlib.Path(name)
        if not path.is_file():
            continue
        for line in path.read_text("ascii", errors="replace").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[9] not in inodes:
                continue
            try:
                items.append({"protocol": protocol, "local": decode_endpoint(fields[1], ipv6), "remote": decode_endpoint(fields[2], ipv6),
                              "state": states.get(fields[3], fields[3]), "inode": fields[9]})
            except (ValueError, OSError):
                warnings.append(f"无法解析 {protocol} socket")
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": warnings + ["网络连接结果达到配置上限"]}
    return {"items": items, "partial": False, "warnings": warnings}


def collect_persistence_artifact(request: dict[str, Any]) -> dict[str, Any]:
    path = validated_persistence_path(request.get("kind"), request.get("path"))
    expected = request.get("expectedSha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or sha256_file(path) != expected:
        raise HelperError("EVIDENCE_COLLECTION", "persistence item hash changed")
    maximum = safe_int(request.get("maxBytes"), 1, 10 * 1024 * 1024, "maxBytes")
    if path.stat().st_size > maximum:
        raise HelperError("EVIDENCE_COLLECTION", "persistence artifact exceeds collection limit")
    artifact = stage_artifact(path, maximum)
    if artifact["sha256"] != expected:
        artifact_path(artifact["artifactToken"]).unlink(missing_ok=True)
        raise HelperError("EVIDENCE_COLLECTION", "persistence item changed during collection")
    return {"artifact": artifact, "sha256": artifact["sha256"], "size": artifact["size"]}


def redact_secret_text(value: str, maximum: int = 2048) -> str:
    """Redact credential-shaped material before it crosses the helper boundary."""
    text = value[:maximum]
    text = SECRET_PATTERNS[0].sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = SECRET_PATTERNS[1].sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = SECRET_PATTERNS[2].sub("[PRIVATE KEY REDACTED]", text)
    return text


def triage_path(value: Any, *, must_exist: bool = True) -> pathlib.Path:
    path = safe_path(value, must_exist=must_exist)
    roots = [root.resolve(strict=False) for root in TRIAGE_ROOTS]
    if not any(path == root or is_within(path, root) for root in roots):
        raise HelperError("PERMISSION_DENIED", "path is outside fixed triage scope")
    return path


def boot_id() -> str:
    try:
        value = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip()
    except OSError as exc:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "Linux /proc boot identity is unavailable") from exc
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", value):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "invalid Linux boot identity")
    return value.lower()


def proc_stat_fields(pid: int) -> dict[str, Any]:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text("ascii", errors="replace")
    except (FileNotFoundError, ProcessLookupError) as exc:
        raise HelperError("EVIDENCE_COLLECTION", "process no longer exists") from exc
    except PermissionError as exc:
        raise HelperError("PERMISSION_DENIED", "cannot read process identity") from exc
    closing = raw.rfind(")")
    if closing < 0:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "invalid /proc process record")
    tail = raw[closing + 2:].split()
    if len(tail) < 20:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "incomplete /proc process record")
    return {
        "comm": raw[raw.find("(") + 1:closing][:256],
        "state": tail[0],
        "ppid": int(tail[1]),
        "startTicks": tail[19],
    }


def process_start_time(start_ticks: str) -> str | None:
    try:
        clock_ticks = os.sysconf("SC_CLK_TCK")
        boot_seconds = next(
            int(line.split()[1]) for line in pathlib.Path("/proc/stat").read_text("ascii").splitlines()
            if line.startswith("btime ")
        )
        timestamp = boot_seconds + int(start_ticks) / int(clock_ticks)
        return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
    except (OSError, ValueError, StopIteration):
        return None


def process_uid(pid: int) -> int:
    for line in pathlib.Path(f"/proc/{pid}/status").read_text("ascii", errors="replace").splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise OSError("Uid is absent")


def process_launcher_path(pid: int) -> str | None:
    """Return only an absolute interpreter target, never command arguments."""
    try:
        fields = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()[:65536].split(b"\0")[:3]
    except OSError:
        return None
    for raw in fields[1:]:
        value = raw.decode("utf-8", errors="replace")
        if not value.startswith("/") or "\x00" in value or ".." in pathlib.Path(value).parts:
            continue
        candidate = pathlib.Path(value)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        roots = [root.resolve(strict=False) for root in TRIAGE_ROOTS]
        if any(resolved == root or is_within(resolved, root) for root in roots):
            return str(resolved)
    return None


def process_environment_metadata(pid: int) -> dict[str, Any]:
    """Return environment variable names and risk tags only, never values."""
    try:
        with pathlib.Path(f"/proc/{pid}/environ").open("rb") as handle:
            raw = handle.read(1024 * 1024 + 1)
    except (OSError, PermissionError):
        return {"variableNames": [], "riskLabels": [], "partial": True}
    names: list[str] = []
    risks: set[str] = set()
    for entry in raw[:1024 * 1024].split(b"\0"):
        name_bytes, separator, _ = entry.partition(b"=")
        if not separator:
            continue
        name = name_bytes.decode("ascii", errors="ignore")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
            continue
        names.append(name)
        upper = name.upper()
        if re.search(r"TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL", upper): risks.add("credential_variable_present")
        if re.search(r"AWS_|AZURE_|GOOGLE_|GCP_", upper): risks.add("cloud_variable_present")
        if upper in {"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB", "RUBYLIB"}: risks.add("loader_influence_variable")
        if upper in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}: risks.add("proxy_variable_present")
        if len(names) >= 512:
            break
    return {"variableNames": sorted(set(names)), "riskLabels": sorted(risks),
            "partial": len(raw) > 1024 * 1024 or len(names) >= 512}


def stable_process(pid: int, digest_cache: dict[tuple[int, int], str] | None = None) -> dict[str, Any]:
    before = proc_stat_fields(pid)
    proc_exe = pathlib.Path(f"/proc/{pid}/exe")
    try:
        info = proc_exe.stat()
        raw_path = os.readlink(proc_exe)
        key = (info.st_dev, info.st_ino)
        digest = digest_cache.get(key) if digest_cache is not None else None
        if digest is None:
            digest = sha256_file(proc_exe)
            if digest_cache is not None:
                digest_cache[key] = digest
        uid = process_uid(pid)
    except FileNotFoundError as exc:
        raise HelperError("EVIDENCE_COLLECTION", "process executable disappeared") from exc
    except PermissionError as exc:
        raise HelperError("PERMISSION_DENIED", "cannot inspect process executable") from exc
    after = proc_stat_fields(pid)
    if before["startTicks"] != after["startTicks"]:
        raise HelperError("EVIDENCE_COLLECTION", "PID was reused during collection")
    deleted = raw_path.endswith(" (deleted)")
    clean_path = raw_path[:-10] if deleted else raw_path
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = str(uid)
    return {
        "bootId": boot_id(),
        "pid": pid,
        "startTicks": before["startTicks"],
        "exeInode": str(info.st_ino),
        "exeSha256": digest,
        "ppid": before["ppid"],
        "state": before["state"],
        "comm": before["comm"],
        "uid": uid,
        "username": username,
        "exePath": clean_path,
        "exeDeleted": deleted,
        "exeSize": info.st_size,
        "startedAt": process_start_time(before["startTicks"]),
        "launcherPath": process_launcher_path(pid),
        "environment": process_environment_metadata(pid),
    }


def process_request(request: dict[str, Any]) -> dict[str, Any]:
    pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    expected_boot = request.get("bootId")
    start_ticks = request.get("startTicks")
    inode = request.get("exeInode")
    digest = request.get("exeSha256")
    if not isinstance(expected_boot, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", expected_boot) or not isinstance(start_ticks, str) or not start_ticks.isdigit():
        raise HelperError("INVALID_ARGUMENT", "invalid stable process identity")
    if not isinstance(inode, str) or not inode.isdigit() or not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise HelperError("INVALID_ARGUMENT", "invalid stable process executable identity")
    current = stable_process(pid)
    if any((
        current["bootId"] != expected_boot.lower(),
        current["startTicks"] != start_ticks,
        current["exeInode"] != inode,
        current["exeSha256"] != digest,
    )):
        raise HelperError("EVIDENCE_COLLECTION", "stable process identity changed; refusing PID reuse")
    return current


def enumerate_stable_processes(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    cache: dict[tuple[int, int], str] = {}
    proc_entries = sorted((item for item in pathlib.Path("/proc").iterdir() if item.name.isdigit()), key=lambda item: int(item.name))
    for entry in proc_entries:
        if len(items) >= maximum:
            return items, warnings + ["进程结果达到配置上限"], True
        try:
            items.append(stable_process(int(entry.name), cache))
        except HelperError as exc:
            # Kernel threads and racing processes are expected, but inability to collect is explicit.
            warnings.append(f"PID {entry.name}: {str(exc)}")
    return items, warnings[:100], bool(warnings)


def read_global_connections(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN"}
    for protocol, name, ipv6 in (("tcp", "/proc/net/tcp", False), ("tcp6", "/proc/net/tcp6", True), ("udp", "/proc/net/udp", False), ("udp6", "/proc/net/udp6", True)):
        path = pathlib.Path(name)
        if not path.is_file():
            warnings.append(f"{name} 不可用")
            continue
        try:
            lines = path.read_text("ascii", errors="replace").splitlines()[1:]
        except PermissionError:
            warnings.append(f"无权读取 {name}")
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                warnings.append(f"无法解析 {name} 记录")
                continue
            try:
                items.append({"protocol": protocol, "local": decode_endpoint(fields[1], ipv6),
                              "remote": decode_endpoint(fields[2], ipv6), "state": states.get(fields[3], fields[3]),
                              "inode": fields[9]})
            except (ValueError, OSError):
                warnings.append(f"无法解析 {protocol} socket")
            if len(items) >= maximum:
                return items, warnings[:100] + ["网络连接结果达到配置上限"], True
    return items, warnings[:100], bool(warnings)


def capture_volatile_snapshot(request: dict[str, Any]) -> dict[str, Any]:
    max_processes = safe_int(request.get("maxProcesses"), 1, 10000, "maxProcesses")
    max_connections = safe_int(request.get("maxConnections"), 1, 20000, "maxConnections")
    processes, process_warnings, process_partial = enumerate_stable_processes(max_processes)
    connections, connection_warnings, connection_partial = read_global_connections(max_connections)
    socket_owners: dict[str, int] = {}
    for process in processes:
        try:
            for descriptor in pathlib.Path(f"/proc/{process['pid']}/fd").iterdir():
                try:
                    match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(descriptor))
                    if match:
                        socket_owners[match.group(1)] = int(process["pid"])
                except OSError:
                    continue
        except PermissionError:
            process_warnings.append(f"PID {process['pid']}: 无权映射 socket 所有者")
            process_partial = True
        except FileNotFoundError:
            process_warnings.append(f"PID {process['pid']}: socket 映射时进程已退出")
            process_partial = True
    unmapped = 0
    for connection in connections:
        owner = socket_owners.get(str(connection.get("inode", "")))
        if owner is None:
            unmapped += 1
        else:
            connection["processPid"] = owner
    if unmapped:
        connection_warnings.append(f"{unmapped} 条全局 socket 无法稳定映射到已采集进程")
        connection_partial = True
    memory: dict[str, int] = {}
    try:
        for line in pathlib.Path("/proc/meminfo").read_text("ascii").splitlines():
            key, _, raw = line.partition(":")
            if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                memory[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        process_warnings.append("无法读取 /proc/meminfo")
        process_partial = True
    return {
        "capturedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "bootId": boot_id(),
        "hostname": platform.node(),
        "uptimeSeconds": float(pathlib.Path("/proc/uptime").read_text("ascii").split()[0]),
        "loadAverage": list(os.getloadavg()),
        "memory": memory,
        "processes": processes,
        "connections": connections,
        "partial": process_partial or connection_partial,
        "warnings": (process_warnings + connection_warnings)[:200],
    }


def suspicious_signals(process: dict[str, Any]) -> list[str]:
    signals: list[str] = []
    path = str(process.get("exePath", ""))
    launcher = str(process.get("launcherPath") or "")
    inspected = launcher or path
    if process.get("exeDeleted"):
        signals.append("deleted_executable")
    if inspected.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        signals.append("temporary_executable")
    if pathlib.Path(inspected).name.startswith("."):
        signals.append("hidden_executable")
    if process.get("uid") == 0 and inspected.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        signals.append("root_temporary_executable")
    try:
        info = pathlib.Path(f"/proc/{process['pid']}/exe").stat()
        if info.st_mode & stat.S_IWOTH:
            signals.append("world_writable_executable")
    except OSError:
        pass
    try:
        maps = pathlib.Path(f"/proc/{process['pid']}/maps").read_text("utf-8", errors="replace")
        if any("w" in line.split()[1] and "x" in line.split()[1] for line in maps.splitlines() if len(line.split()) > 1):
            signals.append("writable_executable_mapping")
        if " (deleted)" in maps:
            signals.append("deleted_memory_mapping")
    except OSError:
        pass
    if int(process.get("ppid", 0)) > 0 and not pathlib.Path(f"/proc/{process['ppid']}").exists():
        signals.append("missing_parent")
    return signals


def list_suspicious_processes(request: dict[str, Any]) -> dict[str, Any]:
    maximum = safe_int(request.get("maxProcesses"), 1, 10000, "maxProcesses")
    processes, warnings, partial = enumerate_stable_processes(maximum)
    items = []
    for process in processes:
        signals = suspicious_signals(process)
        if signals:
            items.append({**process, "signals": signals})
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings + ["可疑进程结果达到配置上限"]}
    return {"items": items, "partial": partial, "warnings": warnings}


def inspect_process_tree(request: dict[str, Any]) -> dict[str, Any]:
    target = process_request(request)
    maximum_depth = safe_int(request.get("maxDepth"), 1, 32, "maxDepth")
    maximum_nodes = safe_int(request.get("maxNodes"), 1, 10000, "maxNodes")
    processes, warnings, partial = enumerate_stable_processes(10000)
    by_pid = {int(item["pid"]): item for item in processes}
    children: dict[int, list[int]] = {}
    for item in processes:
        children.setdefault(int(item["ppid"]), []).append(int(item["pid"]))
    items: list[dict[str, Any]] = [{**target, "relation": "target", "depth": 0}]
    seen = {int(target["pid"])}
    parent = int(target["ppid"])
    depth = 1
    while parent > 0 and depth <= maximum_depth and len(items) < maximum_nodes:
        value = by_pid.get(parent)
        if value is None:
            warnings.append(f"父进程 PID {parent} 已消失或不可读取")
            partial = True
            break
        items.append({**value, "relation": "ancestor", "depth": depth})
        seen.add(parent)
        parent = int(value["ppid"])
        depth += 1
    queue = [(int(target["pid"]), 0)]
    while queue and len(items) < maximum_nodes:
        current, current_depth = queue.pop(0)
        if current_depth >= maximum_depth:
            continue
        for child in children.get(current, []):
            if child in seen:
                continue
            seen.add(child)
            items.append({**by_pid[child], "relation": "descendant", "depth": current_depth + 1})
            queue.append((child, current_depth + 1))
            if len(items) >= maximum_nodes:
                warnings.append("进程树结果达到配置上限")
                partial = True
                break
    return {"items": items, "partial": partial, "warnings": warnings[:200]}


def inspect_process_fds(request: dict[str, Any]) -> dict[str, Any]:
    target = process_request(request)
    maximum = safe_int(request.get("maxItems"), 1, 5000, "maxItems")
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        descriptors = sorted(pathlib.Path(f"/proc/{target['pid']}/fd").iterdir(), key=lambda item: int(item.name))
    except PermissionError:
        return {"items": [], "partial": True, "warnings": ["无权读取进程文件描述符"]}
    except FileNotFoundError as exc:
        raise HelperError("EVIDENCE_COLLECTION", "process disappeared after identity validation") from exc
    for descriptor in descriptors:
        try:
            raw = os.readlink(descriptor)
            kind = "socket" if raw.startswith("socket:[") else "pipe" if raw.startswith("pipe:[") else "anon" if raw.startswith("anon_inode:") else "file"
            items.append({"fd": int(descriptor.name), "type": kind, "target": redact_secret_text(raw, 4096)})
        except PermissionError:
            warnings.append(f"无权读取 FD {descriptor.name}")
        except FileNotFoundError:
            warnings.append(f"FD {descriptor.name} 在采集时关闭")
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings + ["文件描述符结果达到配置上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def inspect_process_memory_maps(request: dict[str, Any]) -> dict[str, Any]:
    target = process_request(request)
    maximum = safe_int(request.get("maxItems"), 1, 5000, "maxItems")
    try:
        lines = pathlib.Path(f"/proc/{target['pid']}/maps").read_text("utf-8", errors="replace").splitlines()
    except PermissionError:
        return {"items": [], "partial": True, "warnings": ["无权读取进程内存映射"]}
    except FileNotFoundError as exc:
        raise HelperError("EVIDENCE_COLLECTION", "process disappeared after identity validation") from exc
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    for line in lines:
        fields = line.split(None, 5)
        if len(fields) < 5:
            warnings.append("发现无法解析的内存映射记录")
            continue
        path = redact_secret_text(fields[5], 4096) if len(fields) > 5 else None
        items.append({"address": fields[0], "permissions": fields[1], "offset": fields[2], "device": fields[3],
                      "inode": fields[4], "path": path, "deleted": bool(path and path.endswith(" (deleted)"))})
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings + ["内存映射结果达到配置上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def collect_process_executable(request: dict[str, Any]) -> dict[str, Any]:
    target = process_request(request)
    maximum = safe_int(request.get("maxBytes"), 1, ARTIFACT_MAX_BYTES, "maxBytes")
    artifact = stage_artifact(pathlib.Path(f"/proc/{target['pid']}/exe"), maximum)
    if artifact["sha256"] != target["exeSha256"]:
        artifact_path(artifact["artifactToken"]).unlink(missing_ok=True)
        raise HelperError("EVIDENCE_COLLECTION", "process executable changed during collection")
    identity = {key: target[key] for key in ("bootId", "pid", "startTicks", "exeInode", "exeSha256")}
    return {"artifact": artifact, "sha256": artifact["sha256"], "size": artifact["size"], "process": identity}


def executable_candidate(path: pathlib.Path, info: os.stat_result) -> bool:
    if info.st_mode & 0o111:
        return True
    try:
        magic = path.open("rb").read(4)
        return magic.startswith(b"\x7fELF") or magic.startswith(b"#!")
    except OSError:
        return False


def triage_file_facts(path: pathlib.Path, info: os.stat_result | None = None) -> dict[str, Any]:
    current = info or path.stat()
    return {
        "path": str(path), "inode": str(current.st_ino), "sha256": sha256_file(path), "size": current.st_size,
        "mode": format(stat.S_IMODE(current.st_mode), "04o"), "uid": current.st_uid, "gid": current.st_gid,
        "mtime": dt.datetime.fromtimestamp(current.st_mtime, dt.timezone.utc).isoformat(),
    }


def scan_triage_files(predicate: Callable[[pathlib.Path, os.stat_result], bool]) -> tuple[list[tuple[pathlib.Path, os.stat_result]], list[str], bool]:
    candidates: list[tuple[pathlib.Path, os.stat_result]] = []
    warnings: list[str] = []
    visited: set[tuple[int, int]] = set()
    scanned = 0
    for configured_root in TRIAGE_ROOTS:
        root = configured_root.resolve(strict=False)
        if not root.is_dir():
            continue
        for directory, directories, files in os.walk(root, followlinks=False):
            directories[:] = [name for name in directories if not (pathlib.Path(directory) / name).is_symlink()]
            for filename in files:
                scanned += 1
                if scanned > TRIAGE_SCAN_LIMIT:
                    return candidates, warnings + ["文件扫描达到固定 50000 项上限"], True
                path = pathlib.Path(directory) / filename
                try:
                    info = path.lstat()
                    key = (info.st_dev, info.st_ino)
                    if key in visited or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        continue
                    visited.add(key)
                    if predicate(path, info):
                        candidates.append((path.resolve(strict=True), info))
                except PermissionError:
                    warnings.append(f"无权检查目录项: {directory}")
                except OSError:
                    continue
    return candidates, warnings[:100], bool(warnings)


def list_recent_executables(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("modifiedWithinHours"), 1, 8760, "modifiedWithinHours")
    maximum = safe_int(request.get("maxItems"), 1, 50000, "maxItems")
    max_size = safe_int(request.get("maxFileSizeBytes"), 1, ARTIFACT_MAX_BYTES, "maxFileSizeBytes")
    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - hours * 3600
    candidates, warnings, partial = scan_triage_files(
        lambda path, info: info.st_mtime >= cutoff and info.st_size <= max_size and executable_candidate(path, info)
    )
    candidates.sort(key=lambda item: item[1].st_mtime, reverse=True)
    if len(candidates) > maximum:
        candidates = candidates[:maximum]
        warnings.append("近期可执行文件结果达到配置上限")
        partial = True
    items: list[dict[str, Any]] = []
    for path, info in candidates:
        try:
            facts = triage_file_facts(path, info)
            signals = []
            if str(path).startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                signals.append("temporary_location")
            if path.name.startswith("."):
                signals.append("hidden_name")
            if info.st_mode & stat.S_IWOTH:
                signals.append("world_writable")
            items.append({**facts, "signals": signals})
        except PermissionError:
            warnings.append(f"无权哈希近期可执行文件: {path}")
            partial = True
        except OSError:
            warnings.append(f"近期可执行文件在采集时发生变化: {path}")
            partial = True
    return {"items": items, "partial": partial, "warnings": warnings[:200]}


def list_privileged_files(request: dict[str, Any]) -> dict[str, Any]:
    maximum = safe_int(request.get("maxItems"), 1, 50000, "maxItems")
    candidates, warnings, partial = scan_triage_files(lambda _path, info: bool(info.st_mode & (stat.S_ISUID | stat.S_ISGID)))
    capabilities: dict[str, str] = {}
    getcap = shutil.which("getcap")
    if getcap:
        for root in TRIAGE_ROOTS:
            if not root.exists():
                continue
            result = run([getcap, "-r", str(root)], timeout=25, check=False)
            if result.returncode not in {0, 1}:
                warnings.append(f"getcap 无法扫描 {root}")
                partial = True
            for line in result.stdout.splitlines():
                path_value, _, capability = line.partition(" ")
                if path_value.startswith("/") and capability:
                    capabilities[str(pathlib.Path(path_value).resolve(strict=False))] = capability[:1024]
    else:
        warnings.append("getcap 不可用；未检查文件 capabilities")
        partial = True
    known = {str(path) for path, _ in candidates}
    for path_value in capabilities:
        path = pathlib.Path(path_value)
        if path_value in known or not path.is_file():
            continue
        try:
            candidates.append((path, path.stat()))
        except OSError:
            warnings.append(f"capability 文件在采集时消失: {path_value}")
            partial = True
    candidates.sort(key=lambda item: str(item[0]))
    if len(candidates) > maximum:
        candidates = candidates[:maximum]
        warnings.append("特权文件结果达到配置上限")
        partial = True
    items = []
    for path, info in candidates:
        try:
            items.append({**triage_file_facts(path, info), "setuid": bool(info.st_mode & stat.S_ISUID),
                          "setgid": bool(info.st_mode & stat.S_ISGID), "capabilities": capabilities.get(str(path), "")})
        except OSError:
            warnings.append(f"特权文件无法读取: {path}")
            partial = True
    return {"items": items, "partial": partial, "warnings": warnings[:200]}


def verify_package_integrity(request: dict[str, Any]) -> dict[str, Any]:
    path = triage_path(request.get("path"))
    if not path.is_file() or path.is_symlink():
        raise HelperError("INVALID_ARGUMENT", "package candidate must be a regular non-symlink file")
    expected_inode = request.get("expectedInode")
    expected_sha = request.get("expectedSha256")
    if not isinstance(expected_inode, str) or not expected_inode.isdigit() or not isinstance(expected_sha, str) or not SHA256.fullmatch(expected_sha):
        raise HelperError("INVALID_ARGUMENT", "invalid executable identity")
    info = path.stat()
    current_sha = sha256_file(path)
    if str(info.st_ino) != expected_inode or current_sha != expected_sha:
        raise HelperError("EVIDENCE_COLLECTION", "executable identity changed before package verification")
    warnings: list[str] = []
    manager = None
    package = None
    verification: list[str] = []
    if shutil.which("dpkg-query") and shutil.which("dpkg"):
        manager = "dpkg"
        owner = run(["dpkg-query", "-S", str(path)], check=False)
        if owner.returncode == 0 and ":" in owner.stdout:
            package = owner.stdout.split(":", 1)[0].strip()
            result = run(["dpkg", "--verify", package], timeout=25, check=False)
            verification = [redact_secret_text(line, 2048) for line in result.stdout.splitlines() if str(path) in line][:100]
            if result.returncode not in {0, 1}:
                warnings.append("dpkg 完整性校验未完整执行")
        else:
            warnings.append("文件不属于已安装的 dpkg 软件包")
    elif shutil.which("rpm"):
        manager = "rpm"
        owner = run(["rpm", "-qf", str(path)], check=False)
        if owner.returncode == 0:
            package = owner.stdout.strip().splitlines()[0][:512]
            result = run(["rpm", "-V", package], timeout=25, check=False)
            verification = [redact_secret_text(line, 2048) for line in result.stdout.splitlines() if str(path) in line][:100]
            if result.returncode not in {0, 1}:
                warnings.append("rpm 完整性校验未完整执行")
        else:
            warnings.append("文件不属于已安装的 rpm 软件包")
    else:
        warnings.append("dpkg/rpm 不可用；无法核验软件包完整性")
    return {"path": str(path), "inode": str(info.st_ino), "sha256": current_sha, "packageManager": manager,
            "package": package, "changed": bool(verification), "verification": verification,
            "partial": bool(warnings), "warnings": warnings}


def inspect_dynamic_loader(request: dict[str, Any]) -> dict[str, Any]:
    maximum = safe_int(request.get("maxItems"), 1, 50000, "maxItems")
    configured = [pathlib.Path("/etc/ld.so.preload"), pathlib.Path("/etc/ld.so.conf")]
    configured.extend(pathlib.Path(value) for value in glob.glob("/etc/ld.so.conf.d/*.conf")[:1000])
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    partial = False
    seen: set[str] = set()
    for config_path in configured:
        if not config_path.is_file() or config_path.is_symlink():
            continue
        try:
            config_facts = file_facts(config_path.resolve(strict=True))
            entries = []
            for raw in text_file(config_path, 65536).splitlines():
                value = raw.strip()
                if not value or value.startswith("#") or value.startswith("include "):
                    continue
                if value.startswith("/"):
                    candidate = pathlib.Path(value).resolve(strict=False)
                    roots = [root.resolve(strict=False) for root in TRIAGE_ROOTS]
                    if any(candidate == root or is_within(candidate, root) for root in roots):
                        entries.append(str(candidate))
            items.append({**config_facts, "kind": "loader_config", "entries": entries[:500]})
            for value in entries:
                if value in seen:
                    continue
                seen.add(value)
                candidate = pathlib.Path(value)
                if candidate.is_file() and not candidate.is_symlink():
                    try:
                        items.append({**triage_file_facts(candidate), "kind": "loaded_library", "referencedBy": str(config_path)})
                    except PermissionError:
                        warnings.append(f"无权读取动态加载库: {value}")
                        partial = True
                else:
                    warnings.append(f"动态加载配置引用不存在文件: {value}")
                    partial = True
                if len(items) >= maximum:
                    return {"items": items[:maximum], "partial": True, "warnings": warnings + ["动态加载结果达到配置上限"]}
        except PermissionError:
            warnings.append(f"无权读取动态加载配置: {config_path}")
            partial = True
        if len(items) >= maximum:
            return {"items": items[:maximum], "partial": True, "warnings": warnings + ["动态加载结果达到配置上限"]}
    if not items:
        warnings.append("未找到可读取的动态加载配置")
        partial = True
    return {"items": items, "partial": partial, "warnings": warnings[:200]}


def parse_syslog_time(raw: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.strptime(f"{dt.datetime.now(dt.timezone.utc).year} {raw}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def query_auth_events(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    paths = [pathlib.Path("/var/log/auth.log"), pathlib.Path("/var/log/secure")]
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    available = False
    for path in paths:
        if not path.is_file():
            continue
        available = True
        try:
            lines = bounded_tail_lines(path)
        except PermissionError:
            warnings.append(f"无权读取 {path}")
            continue
        if path.stat().st_size > LOG_SCAN_MAX_BYTES:
            warnings.append(f"{path} 超过 64 MiB，仅流式读取最新窗口")
        for line in lines:
            timestamp = parse_syslog_time(line[:15])
            if timestamp is None or timestamp < cutoff:
                continue
            event_type = "other"
            if "Accepted " in line:
                event_type = "authentication_success"
            elif "Failed " in line or "failure" in line.lower():
                event_type = "authentication_failure"
            elif "sudo:" in line:
                event_type = "privilege_use"
            if event_type == "other":
                continue
            user_match = re.search(r"(?:for (?:invalid user )?|sudo:\s*)([A-Za-z_][A-Za-z0-9_.-]{0,63})", line)
            ip_match = re.search(r"\bfrom\s+([0-9a-fA-F:.]{3,64})", line)
            program_match = re.search(r"\s([A-Za-z0-9_.-]+)(?:\[\d+\])?:", line[16:])
            username = user_match.group(1) if user_match else None
            source_ip = ip_match.group(1) if ip_match else None
            program = program_match.group(1) if program_match else None
            items.append({"timestamp": timestamp.isoformat(), "eventType": event_type,
                          "username": username, "sourceIp": source_ip, "program": program,
                          "summary": f"{event_type}; user={username or 'unknown'}; source={source_ip or 'local'}; program={program or 'unknown'}",
                          "source": str(path)})
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": warnings + ["认证事件达到配置上限"]}
    if not available:
        warnings.append("auth.log/secure 不可用；未配置 journald 导出采集")
    return {"items": items, "partial": bool(warnings), "warnings": warnings}


def query_exec_events(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    path = pathlib.Path("/var/log/audit/audit.log")
    if not path.is_file():
        return {"items": [], "partial": True, "warnings": ["audit.log 不可用；无法还原历史进程执行事件"]}
    try:
        lines = bounded_tail_lines(path)
    except PermissionError:
        return {"items": [], "partial": True, "warnings": ["无权读取 audit.log"]}
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    if path.stat().st_size > LOG_SCAN_MAX_BYTES:
        warnings.append("audit.log 超过 64 MiB，仅流式读取最新窗口")
    for line in lines:
        if "type=SYSCALL" not in line:
            continue
        epoch_match = re.search(r"msg=audit\((\d+(?:\.\d+)?):", line)
        if not epoch_match:
            warnings.append("发现无法解析时间的 audit SYSCALL")
            continue
        timestamp = dt.datetime.fromtimestamp(float(epoch_match.group(1)), dt.timezone.utc)
        if timestamp < cutoff:
            continue
        def audit_value(name: str) -> str | None:
            match = re.search(rf"\b{name}=(?:\"([^\"]*)\"|(\S+))", line)
            return (match.group(1) or match.group(2)) if match else None
        # Deliberately excludes EXECVE/a0..aN fields because arguments frequently contain secrets.
        items.append({"timestamp": timestamp.isoformat(), "eventType": "process_exec", "pid": audit_value("pid"),
                      "ppid": audit_value("ppid"), "uid": audit_value("uid"), "auid": audit_value("auid"),
                      "comm": redact_secret_text(audit_value("comm") or "", 256),
                      "exe": redact_secret_text(audit_value("exe") or "", 4096), "source": str(path)})
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": warnings + ["进程执行事件达到配置上限"]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


def build_incident_timeline(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    auth = query_auth_events({"sinceHours": hours, "maxEvents": maximum})
    executions = query_exec_events({"sinceHours": hours, "maxEvents": maximum})
    recent = list_recent_executables({"modifiedWithinHours": hours, "maxItems": min(maximum, 500),
                                      "maxFileSizeBytes": ARTIFACT_MAX_BYTES})
    items: list[dict[str, Any]] = []
    items.extend({**item, "timelineSource": "auth"} for item in auth["items"])
    items.extend({**item, "timelineSource": "exec"} for item in executions["items"])
    items.extend({"timestamp": item["mtime"], "eventType": "file_modified", "timelineSource": "recent_executable",
                  "path": item["path"], "inode": item["inode"], "sha256": item["sha256"], "signals": item["signals"]}
                 for item in recent["items"])
    items.sort(key=lambda item: str(item.get("timestamp", "")))
    warnings = list(dict.fromkeys(auth["warnings"] + executions["warnings"] + recent["warnings"]))
    partial = bool(auth["partial"] or executions["partial"] or recent["partial"])
    if len(items) > maximum:
        items = items[-maximum:]
        warnings.append("事件时间线达到配置上限，仅保留最新事件")
        partial = True
    return {"items": items, "partial": partial, "warnings": warnings[:200]}


def get_action_receipt(request: dict[str, Any]) -> dict[str, Any]:
    value = action_id(request)
    path = receipt_path(value)
    if not path.exists():
        return {"actionId": value, "status": "UNKNOWN"}
    return json.loads(path.read_text("utf-8"))


def quarantine_file(request: dict[str, Any]) -> dict[str, Any]:
    value = action_id(request)
    source = safe_path(request.get("path"))
    expected = request.get("expectedSha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise HelperError("INVALID_ARGUMENT", "invalid expectedSha256")
    root = safe_path(request.get("quarantineRoot"), must_exist=False)
    receipt = begin_receipt(value, "quarantine_file", request)
    if receipt["status"] == "SUCCEEDED":
        return receipt
    if sha256_file(source) != expected:
        return finish_receipt(receipt, "FAILED", {"reason": "source hash changed"})
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_dir = root / value
    target_dir.mkdir(mode=0o700, exist_ok=True)
    target = target_dir / source.name
    if source.stat().st_dev != target_dir.stat().st_dev:
        return finish_receipt(receipt, "FAILED", {"reason": "cross-filesystem quarantine refused"})
    metadata = {"originalPath": str(source), "mode": stat.S_IMODE(source.stat().st_mode), "uid": source.stat().st_uid, "gid": source.stat().st_gid, "sha256": expected}
    os.rename(source, target)
    os.chmod(target, 0o000)
    quarantine_mode = stat.S_IMODE(target.stat().st_mode)
    return finish_receipt(receipt, "SUCCEEDED", {
        **metadata,
        "quarantinePath": str(target),
        "quarantineMode": quarantine_mode,
        "verifiedMode000": quarantine_mode == 0,
        "verifiedMissing": not source.exists(),
    })


def disable_account(request: dict[str, Any]) -> dict[str, Any]:
    value = action_id(request)
    username = safe_username(request.get("username"))
    executor = safe_username(request.get("executorUsername"))
    if username in {"root", executor}:
        raise HelperError("PERMISSION_DENIED", "root and active executor account cannot be disabled")
    before = inspect_account({"username": username})
    receipt = begin_receipt(value, "disable_account", request)
    if receipt["status"] == "SUCCEEDED":
        return receipt
    run(["usermod", "--lock", "--expiredate", "1", username])
    after = inspect_account({"username": username})
    succeeded = bool(after.get("passwordLocked")) and str(after.get("accountExpireDays")) not in {"", "-1"}
    return finish_receipt(receipt, "SUCCEEDED" if succeeded else "FAILED", {"before": before, "after": after})


OPERATIONS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "get_capabilities": get_capabilities,
    "capture_volatile_snapshot": capture_volatile_snapshot,
    "list_suspicious_processes": list_suspicious_processes,
    "inspect_process_tree": inspect_process_tree,
    "inspect_process_fds": inspect_process_fds,
    "inspect_process_memory_maps": inspect_process_memory_maps,
    "collect_process_executable": collect_process_executable,
    "list_recent_executables": list_recent_executables,
    "list_privileged_files": list_privileged_files,
    "verify_package_integrity": verify_package_integrity,
    "inspect_dynamic_loader": inspect_dynamic_loader,
    "query_auth_events": query_auth_events,
    "query_exec_events": query_exec_events,
    "build_incident_timeline": build_incident_timeline,
    "get_host_info": get_host_info,
    "list_processes": list_processes,
    "inventory_web_stacks": inventory_web_stacks,
    "discover_effective_web_roots": discover_effective_web_roots,
    "discover_web_roots": discover_web_roots,
    "list_recent_web_artifacts": list_recent_web_artifacts,
    "list_upload_temp_artifacts": list_upload_temp_artifacts,
    "find_recent_web_files": find_recent_web_files,
    "inspect_web_runtime_config": inspect_web_runtime_config,
    "correlate_web_requests": correlate_web_requests,
    "find_web_related_processes": find_web_related_processes,
    "yara_scan_files": yara_scan_files,
    "inspect_script_file": inspect_script_file,
    "search_web_access_log": search_web_access_log,
    "collect_file": collect_file,
    "list_java_processes": list_java_processes,
    "detect_java_container": detect_java_container,
    "run_tomcat_probe": run_tomcat_probe,
    "search_class_on_disk": search_class_on_disk,
    "list_privileged_accounts": list_privileged_accounts,
    "inspect_privilege_delegation": inspect_privilege_delegation,
    "inspect_account": inspect_account,
    "inspect_ssh_trust_configuration": inspect_ssh_trust_configuration,
    "inspect_authorized_keys": inspect_authorized_keys,
    "get_login_history": get_login_history,
    "list_cron_entries": list_cron_entries,
    "list_systemd_units": list_systemd_units,
    "list_extended_persistence": list_extended_persistence,
    "list_ssh_persistence": list_ssh_persistence,
    "list_shell_startup_files": list_shell_startup_files,
    "inspect_persistence_item": inspect_persistence_item,
    "find_related_processes": find_related_processes,
    "list_process_connections": list_process_connections,
    "collect_persistence_artifact": collect_persistence_artifact,
    "release_artifact": release_artifact,
    "get_action_receipt": get_action_receipt,
    "quarantine_file": quarantine_file,
    "disable_account": disable_account,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in OPERATIONS:
        emit({"ok": False, "error": {"code": "INVALID_ARGUMENT", "message": "unknown operation"}})
        return 2
    try:
        request = read_request()
        result = OPERATIONS[sys.argv[1]](request)
        emit({"ok": True, "result": result})
        return 0
    except HelperError as exc:
        emit({"ok": False, "error": {"code": exc.code, "message": str(exc)}})
        return 1
    except Exception as exc:  # defensive boundary: never emit a Python traceback over SSH
        emit({"ok": False, "error": {"code": "UNSUPPORTED_ENVIRONMENT", "message": f"{type(exc).__name__}: {exc}"}})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
