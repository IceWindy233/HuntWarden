#!/usr/bin/env python3
"""Root-owned HuntWarden v2 forensic helper used by SSHExecutor.

The helper reads one JSON object from stdin and emits one JSON envelope. It never
uses shell=True and never accepts an arbitrary command from the controller.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import glob
import gzip
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zlib

try:
    import re2 as re2_engine  # type: ignore[import-not-found]
except ImportError:
    re2_engine = None

MAX_INPUT = 1024 * 1024
MAX_OUTPUT_BYTES = 1_572_864  # 1.5 MiB; leaves envelope headroom under the controller's 2 MiB transport cap
RECEIPT_DIR = pathlib.Path("/var/lib/huntwarden/actions")
ARTIFACT_DIR = pathlib.Path("/var/lib/huntwarden/artifacts") if os.geteuid() == 0 else pathlib.Path(tempfile.gettempdir()) / "huntwarden-artifacts"
ARTIFACT_TOKEN = re.compile(r"^[a-f0-9]{64}$")
ARTIFACT_MAX_BYTES = 100 * 1024 * 1024
ARTIFACT_TTL_SECONDS = 15 * 60
LOG_SCAN_MAX_BYTES = 64 * 1024 * 1024
HELPER_VERSION = "2.1.0"
PROTOCOL_VERSION = 2
MANIFEST_VERSION = "2.1.0"
PROBE_JAR = pathlib.Path("/opt/huntwarden/huntwarden-tomcat-probe.jar")
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.I)
CLASS_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]{0,511}$")
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
DEADLINE_MIN_MS = 1000
DEADLINE_MAX_MS = 600000
DEADLINE_WARNING = "达到时间预算，结果不完整"
TRANSPORT_KEYS = frozenset({"deadlineMs"})
WALK_MAX_DEPTH = 12
WALK_VISIT_LIMIT = 200000
PSEUDO_FILESYSTEM_ROOTS = frozenset({"/proc", "/sys", "/dev", "/run"})
PROCESS_CGROUP_MAX_ENTRIES = 32
PROCESS_CGROUP_MAX_BYTES = 512
PROCESS_ENV_NAME_LIMIT = 128
SKIP_UNREADABLE = "路径因权限或 I/O 错误被跳过"
SKIP_DEPTH = "目录因超过遍历深度上限被跳过"
SKIP_BOUNDARY = "目录因跨越文件系统边界被跳过"
SKIP_SYMLINK = "符号链接目录被跳过"
SKIP_LOG_RECORD = "日志行因无法解析时间被跳过"
JOURNAL_MAX_RECORDS = 5000
JOURNAL_AUTH_FACILITIES = ("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10")
JOURNAL_AUTH_COMMANDS = ("sshd", "sudo", "su", "login", "systemd-logind", "polkitd")
AUTH_LOG_PATTERNS = ("/var/log/auth.log", "/var/log/auth.log.*", "/var/log/secure", "/var/log/secure-*", "/var/log/secure.*")
AUDIT_LOG_PATTERNS = ("/var/log/audit/audit.log", "/var/log/audit/audit.log.*")
SYSTEM_LOG_PATTERNS = (
    "/var/log/syslog", "/var/log/syslog.*", "/var/log/messages", "/var/log/messages-*", "/var/log/messages.*",
    "/var/log/daemon.log", "/var/log/daemon.log.*", "/var/log/kern.log", "/var/log/kern.log.*",
)
# 访问日志必须覆盖轮转与 gzip 归档，并覆盖多站点的子目录布局。
# 只匹配 "access*.log" 会漏掉 access.log.1 / access.log.2.gz 与 /var/log/nginx/<site>/access.log，
# 而 WebShell 落地时的上传请求通常正好落在已轮转的那一段里。
WEB_ACCESS_LOG_PATTERNS = (
    "/var/log/nginx/access*.log", "/var/log/nginx/access*.log.*",
    "/var/log/nginx/*/access*.log", "/var/log/nginx/*/access*.log.*",
    "/var/log/apache2/access*.log", "/var/log/apache2/access*.log.*",
    "/var/log/apache2/*/access*.log", "/var/log/apache2/*/access*.log.*",
    "/var/log/httpd/access_log*", "/var/log/httpd/*/access_log*",
)
LOG_FILE_LIMIT = 20
SYSLOG_PRIORITY = re.compile(r"^<\d{1,3}>(?:\d\s+)?")
SYSLOG_TRADITIONAL = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})(?=\s|$)")
SYSLOG_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:[Zz]|[+-]\d{2}:?\d{2})?)(?=\s|$)")
SYSLOG_HEADER = re.compile(r"^\S+\s+(?P<program>[A-Za-z0-9_.\-/]{1,64})(?:\[(?P<pid>\d{1,10})\])?:\s*(?P<message>.*)$")
AUDIT_EPOCH = re.compile(r"msg=audit\((\d+(?:\.\d+)?):")
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
    text, size = serialized_output(payload)
    sys.stdout.write(text if size <= MAX_OUTPUT_BYTES else budgeted_output(payload))
    sys.stdout.flush()


def serialized_output(payload: dict[str, Any]) -> tuple[str, int]:
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return text, len(text.encode("utf-8"))


def budgeted_output(payload: dict[str, Any]) -> str:
    """Shrink the item list until the envelope fits the transport budget instead of losing it whole."""
    result = payload.get("result")
    items = result.get("items") if isinstance(result, dict) else None
    v2_objects = items is None and isinstance(payload.get("objects"), list)
    if v2_objects:
        result = payload
        items = payload.get("objects")
    if not isinstance(result, dict) or not isinstance(items, list) or not items:
        raise HelperError("OUTPUT_LIMIT_EXCEEDED", f"结构化输出超过 {MAX_OUTPUT_BYTES} 字节传输预算，且没有可截断的 items 列表")
    existing = result.get("warnings")
    base = [str(value) for value in existing[:200]] if isinstance(existing, list) else []
    original = len(items)
    _, size = serialized_output(payload)
    kept = max(1, int(original * MAX_OUTPUT_BYTES / size * 0.9))
    while kept >= 1:
        candidate = dict(payload)
        if v2_objects:
            candidate["objects"] = items[:kept]
            candidate["status"] = "PARTIAL"
            candidate["gaps"] = [*candidate.get("gaps", []), {"code": "OUTPUT_LIMIT",
                "detail": f"输出达到 1.5 MiB 传输预算，已截断 {original - kept} 条结果", "resumable": True}]
        else:
            candidate["result"] = {**result, "items": items[:kept], "partial": True,
                                   "warnings": [*base, f"输出达到 1.5 MiB 传输预算，已截断 {original - kept} 条结果"]}
        text, size = serialized_output(candidate)
        if size <= MAX_OUTPUT_BYTES:
            return text
        kept = kept - 1 if kept <= 8 else int(kept * 0.8)
    raise HelperError("OUTPUT_LIMIT_EXCEEDED", f"单条结果已超过 {MAX_OUTPUT_BYTES} 字节传输预算")


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


_DEADLINE: float | None = None
_HOST_TIMEZONE: tuple[str, int] | None = None


def install_deadline(request: dict[str, Any]) -> None:
    """Establish the single wall-clock budget for this invocation from the request envelope."""
    global _DEADLINE
    value = request.get("deadlineMs")
    _DEADLINE = None if value is None else time.monotonic() + safe_int(value, DEADLINE_MIN_MS, DEADLINE_MAX_MS, "deadlineMs") / 1000.0


def deadline_exceeded() -> bool:
    return _DEADLINE is not None and time.monotonic() >= _DEADLINE


def remaining_timeout(default: int) -> int:
    """Clamp a subprocess timeout so no external command outlives the operation budget."""
    if _DEADLINE is None:
        return default
    return max(1, min(default, int(_DEADLINE - time.monotonic())))


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_iso(value: dt.datetime | float) -> str:
    """Render an absolute instant as UTC ISO8601 with a trailing Z so every source stays comparable."""
    moment = value if isinstance(value, dt.datetime) else dt.datetime.fromtimestamp(value, dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def host_timezone() -> tuple[str, int]:
    """Resolve the target host's zone name and current UTC offset once per invocation."""
    global _HOST_TIMEZONE
    if _HOST_TIMEZONE is not None:
        return _HOST_TIMEZONE
    offset = int((dt.datetime.now().astimezone().utcoffset() or dt.timedelta(0)).total_seconds())
    name = ""
    configured = os.environ.get("TZ", "").strip().lstrip(":")
    if "/" in configured and re.fullmatch(r"[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+){1,3}", configured):
        name = configured
    if not name:
        try:
            link = os.readlink("/etc/localtime")
            name = link.split("/zoneinfo/", 1)[1] if "/zoneinfo/" in link else ""
        except OSError:
            # Fixed zone sources are tried in order; the ±HH:MM fallback below always yields a name.
            name = ""
    if not name:
        try:
            value = pathlib.Path("/etc/timezone").read_text("utf-8", errors="replace").strip()
            name = value if "/" in value else ""
        except OSError:
            # Same ordered fallback as above.
            name = ""
    if not name:
        name = f"{'+' if offset >= 0 else '-'}{abs(offset) // 3600:02d}:{abs(offset) % 3600 // 60:02d}"
    _HOST_TIMEZONE = (name[:64], offset)
    return _HOST_TIMEZONE


def local_naive_to_utc(value: dt.datetime) -> dt.datetime | None:
    """Interpret a zone-less host log timestamp in the host's own zone, honouring DST history."""
    try:
        return dt.datetime.fromtimestamp(time.mktime(value.timetuple()), dt.timezone.utc)
    except (OverflowError, ValueError, OSError):
        return None


class SkipLedger:
    """Aggregate skipped-path counts and one-off notes so degraded coverage is never silent."""

    __slots__ = ("counts", "notes", "expired")

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.notes: list[str] = []
        self.expired = False

    def add(self, reason: str, count: int = 1) -> None:
        self.counts[reason] = self.counts.get(reason, 0) + count

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def expire(self) -> None:
        self.expired = True

    @property
    def partial(self) -> bool:
        return bool(self.counts) or bool(self.notes) or self.expired

    def warnings(self) -> list[str]:
        values = [f"{count} 个{reason}" for reason, count in sorted(self.counts.items())]
        values.extend(self.notes)
        if self.expired:
            values.append(DEADLINE_WARNING)
        return values


def path_kind(path: pathlib.Path, ledger: SkipLedger, *, follow: bool = False) -> str:
    """Classify a path without letting one unreadable entry abort the whole operation.

    pathlib's is_file/is_dir raise PermissionError instead of swallowing it, so a single 0700 home
    directory used to destroy an entire collection. Every failure is recorded as a skip instead.
    """
    try:
        info = path.stat() if follow else path.lstat()
    except OSError:
        ledger.add(SKIP_UNREADABLE)
        return "unavailable"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "file" if stat.S_ISREG(info.st_mode) else "other"


def bounded_walk(root: pathlib.Path, ledger: SkipLedger, *, max_depth: int = WALK_MAX_DEPTH,
                 visit_limit: int = WALK_VISIT_LIMIT) -> Iterator[tuple[pathlib.Path, list[str]]]:
    """Walk a single filesystem under fixed depth, visit and deadline bounds, pruning links and pseudo roots."""
    try:
        root_info = root.stat()
    except OSError:
        ledger.add(SKIP_UNREADABLE)
        return
    if not stat.S_ISDIR(root_info.st_mode):
        return
    base = len(root.parts)
    visited = 0
    for directory, directories, files in os.walk(root, followlinks=False, onerror=lambda _error: ledger.add(SKIP_UNREADABLE)):
        if deadline_exceeded():
            ledger.expire()
            return
        current = pathlib.Path(directory)
        depth = len(current.parts) - base
        keep: list[str] = []
        for name in directories:
            if depth + 1 > max_depth:
                ledger.add(SKIP_DEPTH)
                continue
            child = current / name
            try:
                info = child.lstat()
            except OSError:
                ledger.add(SKIP_UNREADABLE)
                continue
            if stat.S_ISLNK(info.st_mode):
                ledger.add(SKIP_SYMLINK)
            elif info.st_dev != root_info.st_dev or str(child) in PSEUDO_FILESYSTEM_ROOTS:
                ledger.add(SKIP_BOUNDARY)
            else:
                keep.append(name)
        directories[:] = keep
        if visited + len(files) > visit_limit:
            ledger.note(f"目录遍历达到 {visit_limit} 项上限，结果不完整")
            yield current, files[:max(0, visit_limit - visited)]
            return
        visited += len(files)
        yield current, files


def run(argv: list[str], timeout: int = 25, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=remaining_timeout(timeout), check=False)
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
    if os.geteuid() == 0:
        state_root = ARTIFACT_DIR.parent
        state_info = state_root.lstat()
        if not stat.S_ISDIR(state_info.st_mode) or stat.S_ISLNK(state_info.st_mode) or state_info.st_uid != 0:
            raise HelperError("EVIDENCE_COLLECTION", "artifact state root is not a trusted root-owned directory")
        # SFTP 以 SSH 执行用户读取随机 token 文件，需要穿越父目录；0711 不允许列目录。
        # actions/ 与 quarantine/ 自身仍为 0700，因此不会暴露回执或隔离内容。
        os.chmod(state_root, 0o711)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True, mode=0o711)
    info = ARTIFACT_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise HelperError("EVIDENCE_COLLECTION", "artifact spool is not a real directory")
    os.chmod(ARTIFACT_DIR, 0o711)
    cutoff = now_utc().timestamp() - ARTIFACT_TTL_SECONDS
    for candidate in ARTIFACT_DIR.glob("*.artifact"):
        try:
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink()
        except OSError:
            # Best-effort spool hygiene only: a stale artifact stays until the next TTL sweep and never
            # affects the current operation's result, so it needs no warning channel.
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
    expires = now_utc() + dt.timedelta(seconds=ARTIFACT_TTL_SECONDS)
    return {
        "artifactToken": token,
        "sha256": digest.hexdigest(),
        "size": size,
        "expiresAt": utc_iso(expires),
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
    expires = now_utc() + dt.timedelta(seconds=ARTIFACT_TTL_SECONDS)
    return {
        "artifactToken": token,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "expiresAt": utc_iso(expires),
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


def bounded_log_lines(path: pathlib.Path, ledger: SkipLedger, maximum_bytes: int = LOG_SCAN_MAX_BYTES) -> Iterator[str]:
    """Yield lines from a plain or gzip log inside a fixed byte window and the operation deadline."""
    counter = 0
    if path.suffix == ".gz":
        consumed = 0
        try:
            with gzip.open(path, "rb") as handle:
                for raw in handle:
                    consumed += len(raw)
                    if consumed > maximum_bytes:
                        ledger.note(f"{path} 解压后超过 64 MiB 扫描窗口，仅读取前段")
                        return
                    counter += 1
                    if counter % 4096 == 0 and deadline_exceeded():
                        ledger.expire()
                        return
                    yield raw.decode("utf-8", errors="replace").rstrip("\r\n")
        except (OSError, EOFError, ValueError, zlib.error):
            ledger.add(SKIP_UNREADABLE)
        return
    try:
        info = path.stat()
        lines = bounded_tail_lines(path, maximum_bytes)
    except OSError:
        ledger.add(SKIP_UNREADABLE)
        return
    if info.st_size > maximum_bytes:
        ledger.note(f"{path} 超过 64 MiB，仅流式读取最新窗口")
    try:
        for line in lines:
            counter += 1
            if counter % 4096 == 0 and deadline_exceeded():
                ledger.expire()
                return
            yield line
    except OSError:
        ledger.add(SKIP_UNREADABLE)


def log_file_set(patterns: tuple[str, ...], ledger: SkipLedger) -> list[pathlib.Path]:
    """Collect a log plus its rotated and gzip siblings, newest first, so rotation is never missed."""
    found: dict[str, float] = {}
    for pattern in patterns:
        for name in sorted(glob.glob(pattern))[:200]:
            try:
                info = pathlib.Path(name).lstat()
            except OSError:
                ledger.add("轮转日志因权限或 I/O 错误未被读取")
                continue
            if stat.S_ISREG(info.st_mode):
                found[name] = info.st_mtime
    ordered = sorted(found.items(), key=lambda item: item[1], reverse=True)
    return [pathlib.Path(name) for name, _ in ordered[:LOG_FILE_LIMIT]]


def release_artifact(request: dict[str, Any]) -> dict[str, Any]:
    path = artifact_path(request.get("artifactToken"))
    try:
        path.unlink()
        return {"released": True}
    except FileNotFoundError:
        return {"released": False}


def file_facts(path: pathlib.Path) -> dict[str, Any]:
    info = path.stat()
    return {
        "path": str(path), "sha256": sha256_file(path), "size": info.st_size,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid,
        "mtime": utc_iso(info.st_mtime),
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
    action_arguments = {key: item for key, item in request.items() if key not in TRANSPORT_KEYS}
    incoming_digest = hashlib.sha256(json.dumps(action_arguments, sort_keys=True).encode()).hexdigest()
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
        "startedAt": utc_iso(now_utc()),
    }
    atomic_json(path, receipt)
    return receipt


def finish_receipt(receipt: dict[str, Any], status_value: str, result: dict[str, Any]) -> dict[str, Any]:
    receipt.update({"status": status_value, "result": result, "finishedAt": utc_iso(now_utc())})
    atomic_json(receipt_path(str(receipt["actionId"])), receipt)
    return receipt


def java_binary(pid: int | None = None) -> str | None:
    if pid is not None:
        try:
            executable = pathlib.Path(f"/proc/{pid}/exe").resolve(strict=True)
            if executable.name.startswith("java") and executable.is_file():
                return str(executable)
        except OSError:
            # Falls through to the fixed JDK candidates below; a null return already states the gap.
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
            if deadline_exceeded():
                warnings.append(DEADLINE_WARNING)
                break
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


def search_web_access_log(request: dict[str, Any]) -> dict[str, Any]:
    safe_path(request.get("path"))
    name = pathlib.Path(str(request.get("fileName", ""))).name
    if not name or len(name) > 255:
        raise HelperError("INVALID_ARGUMENT", "invalid fileName")
    maximum = safe_int(request.get("maxLines"), 1, 5000, "maxLines")
    ledger = SkipLedger()
    matches: list[dict[str, Any]] = []
    scanned: list[str] = []
    warnings: list[str] = []
    for log_path in log_file_set(WEB_ACCESS_LOG_PATTERNS, ledger):
        if deadline_exceeded():
            ledger.expire()
            break
        scanned.append(str(log_path))
        for line in bounded_log_lines(log_path, ledger):
            if name not in line:
                continue
            matches.append({"log": str(log_path), "line": redact_secret_text(line, 8192)})
            if len(matches) >= maximum:
                warnings.append("访问日志匹配达到上限")
                return {"items": matches, "scannedLogs": scanned, "partial": True, "warnings": (warnings + ledger.warnings())[:200]}
    if not scanned:
        warnings.append("未找到 Nginx/Apache/httpd 访问日志")
    return {
        "items": matches, "scannedLogs": scanned,
        "partial": bool(warnings) or ledger.partial,
        "warnings": (warnings + ledger.warnings())[:200],
    }


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
    # 前面的前置检查负责「目标没有这项能力」（jar/JVM 缺失）；到这里失败的是 Attach 与
    # 探针本身的执行，设计 §5.2 要求它表现为 PROBE_FAILED，而不是被当成能力缺失。
    try:
        result = run(argv, timeout=30)
        value = json.loads(result.stdout)
    except HelperError as exc:
        raise HelperError("PROBE_FAILED", f"probe execution failed: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise HelperError("PROBE_FAILED", "probe returned malformed output") from exc
    if not isinstance(value, dict):
        raise HelperError("PROBE_FAILED", "probe returned invalid JSON")
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


def list_cron_entries(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    ledger = SkipLedger()
    paths: list[pathlib.Path] = []
    for value in SYSTEM_PERSISTENCE_ROOTS["cron"]:
        candidate = pathlib.Path(value)
        kind = path_kind(candidate, ledger, follow=True)
        if kind == "file":
            paths.append(candidate)
        elif kind == "directory":
            paths.extend(item for item in candidate.rglob("*") if path_kind(item, ledger) == "file")
    if include_user:
        for spool in (pathlib.Path("/var/spool/cron/crontabs"), pathlib.Path("/var/spool/cron")):
            if path_kind(spool, ledger, follow=True) != "directory":
                continue
            try:
                entries = sorted(spool.iterdir())
            except OSError:
                ledger.add(SKIP_UNREADABLE)
                continue
            paths.extend(item for item in entries if path_kind(item, ledger) == "file")
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        if deadline_exceeded():
            ledger.expire()
            break
        try:
            resolved = str(path.resolve())
        except OSError:
            ledger.add(SKIP_UNREADABLE)
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        try:
            facts = file_facts(path.resolve())
            lines = text_file(path).splitlines()
        except OSError:
            ledger.add("Cron 配置因权限或 I/O 错误未被解析")
            continue
        periodic = next((name for name in ("hourly", "daily", "weekly", "monthly") if f"/cron.{name}/" in str(path)), None)
        if periodic:
            items.append({**facts, "kind": "cron", "line": 0, "schedule": f"@{periodic}", "username": "root",
                          "commandSummary": str(path.resolve()), "features": dangerous_features(text_file(path))})
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": (ledger.warnings() + ["Cron 结果达到配置上限"])[:200]}
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
                return {"items": items, "partial": True, "warnings": (ledger.warnings() + ["Cron 结果达到配置上限"])[:200]}
    return {"items": items, "partial": ledger.partial, "warnings": ledger.warnings()[:200]}


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
    ledger = SkipLedger()
    seen: set[str] = set()
    for root in roots:
        if path_kind(root, ledger, follow=True) != "directory":
            continue
        if deadline_exceeded():
            ledger.expire()
            break
        for path in root.rglob("*"):
            if deadline_exceeded():
                ledger.expire()
                break
            if path.suffix not in {".service", ".timer"} or path_kind(path, ledger, follow=True) != "file":
                continue
            try:
                resolved = path.resolve()
            except OSError:
                ledger.add(SKIP_UNREADABLE)
                continue
            if str(resolved) in seen:
                continue
            seen.add(str(resolved))
            try:
                enabled_links = [str(link) for link in pathlib.Path("/etc/systemd").rglob(path.name)
                                 if path_kind(link, ledger) == "symlink"][:20]
                drop_ins: list[dict[str, Any]] = []
                dropin_dirs = [resolved.parent / f"{path.name}.d"]
                dropin_dirs.extend(candidate for dropin_root in roots if path_kind(dropin_root, ledger, follow=True) == "directory"
                                   for candidate in dropin_root.rglob(f"{path.name}.d")
                                   if path_kind(candidate, ledger, follow=True) == "directory")
                for dropin_dir in dict.fromkeys(dropin_dirs):
                    if path_kind(dropin_dir, ledger, follow=True) != "directory":
                        continue
                    for override in sorted(dropin_dir.glob("*.conf"))[:100]:
                        try:
                            drop_ins.append({**file_facts(override.resolve()), **parse_systemd_unit(override.resolve())})
                        except OSError:
                            ledger.add("systemd Drop-In 因权限或 I/O 错误未被解析")
                            continue
                items.append({**file_facts(resolved), "kind": "systemd", "unit": path.name,
                              "scope": "user" if "/.config/systemd/user/" in str(resolved) else "system",
                              "enabled": bool(enabled_links), "enabledLinks": enabled_links, "dropIns": drop_ins,
                              "generated": str(resolved).startswith("/run/systemd/generator"),
                              "transient": str(resolved).startswith("/run/systemd/transient"), **parse_systemd_unit(resolved)})
            except OSError:
                ledger.add("systemd Unit 因权限或 I/O 错误未被解析")
                continue
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": (ledger.warnings() + ["systemd 结果达到配置上限"])[:200]}
    manager_available = path_kind(pathlib.Path("/run/systemd/system"), ledger, follow=True) == "directory"
    warnings = [] if manager_available else ["systemd 管理器未运行；仅完成 Unit 文件与启用链接检查"]
    return {"items": items, "partial": not manager_available or ledger.partial, "warnings": (warnings + ledger.warnings())[:200]}


def list_extended_persistence(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    roots = [pathlib.Path(value) for value in SYSTEM_PERSISTENCE_ROOTS["extended"]]
    if include_user:
        for account in interactive_accounts():
            roots.extend((pathlib.Path(account.pw_dir) / ".config/autostart", pathlib.Path(account.pw_dir) / ".config/systemd/user"))
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    ledger = SkipLedger()
    seen: set[str] = set()
    for root in roots:
        if deadline_exceeded():
            warnings.append(DEADLINE_WARNING)
            break
        root_kind = path_kind(root, ledger, follow=True)
        candidates: Any = [root] if root_kind == "file" else (
            (item for item in root.rglob("*") if path_kind(item, ledger) == "file") if root_kind == "directory" else [])
        try:
            for path in candidates:
                if deadline_exceeded():
                    warnings.append(DEADLINE_WARNING)
                    break
                resolved = path.resolve(strict=True)
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
    return {"items": items, "partial": bool(warnings) or ledger.partial, "warnings": (warnings + ledger.warnings())[:200]}


def list_shell_startup_files(request: dict[str, Any]) -> dict[str, Any]:
    maximum, include_user = persistence_limits(request)
    startup_ledger = SkipLedger()
    paths = [pathlib.Path("/etc/profile"), pathlib.Path("/etc/bash.bashrc")]
    for root in (pathlib.Path("/etc/profile.d"), pathlib.Path("/etc/zsh")):
        if path_kind(root, startup_ledger, follow=True) == "directory":
            paths.extend(item for item in root.rglob("*") if path_kind(item, startup_ledger) == "file")
    if include_user:
        for account in interactive_accounts():
            paths.extend(pathlib.Path(account.pw_dir) / name for name in (".profile", ".bash_profile", ".bashrc", ".zprofile", ".zshrc"))
    items: list[dict[str, Any]] = []
    ledger = startup_ledger
    seen: set[str] = set()
    for path in paths:
        if deadline_exceeded():
            ledger.expire()
            break
        if path_kind(path, ledger) != "file":
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
            ledger.add("Shell 启动文件因权限或 I/O 错误未被解析")
            continue
        if len(items) >= maximum:
            return {"items": items, "partial": True, "warnings": (ledger.warnings() + ["Shell 启动文件结果达到配置上限"])[:200]}
    return {"items": items, "partial": ledger.partial, "warnings": ledger.warnings()[:200]}


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
    ledger = SkipLedger()
    try:
        for fd in (proc / "fd").iterdir():
            try:
                match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
                if match:
                    inodes.add(match.group(1))
            except OSError:
                ledger.add("文件描述符因权限或 I/O 错误未被检查")
                continue
    except OSError as exc:
        raise HelperError("PERMISSION_DENIED", "cannot inspect process descriptors") from exc
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN"}
    items: list[dict[str, Any]] = []
    warnings: list[str] = ledger.warnings()
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
                return {"items": items, "partial": True, "warnings": (warnings + ["网络连接结果达到配置上限"])[:200]}
    return {"items": items, "partial": bool(warnings), "warnings": warnings[:200]}


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
        return utc_iso(timestamp)
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
        # A missing cmdline means no launcher can be proven; the null return is the explicit answer.
        return None
    for raw in fields[1:]:
        value = raw.decode("utf-8", errors="replace")
        if not value.startswith("/") or "\x00" in value or ".." in pathlib.Path(value).parts:
            continue
        candidate = pathlib.Path(value)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            # Unresolvable interpreter arguments are simply not evidence of a launcher.
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
        if len(names) >= PROCESS_ENV_NAME_LIMIT:
            break
    return {"variableNames": sorted(set(names)), "riskLabels": sorted(risks),
            "partial": len(raw) > 1024 * 1024 or len(names) >= PROCESS_ENV_NAME_LIMIT}


def process_scope_metadata(pid: int) -> dict[str, Any]:
    links: dict[str, str | None] = {}
    for name in ("cwd", "root"):
        try:
            links[name] = os.readlink(f"/proc/{pid}/{name}")[:4096]
        except OSError:
            links[name] = None
    namespaces: dict[str, str] = {}
    for name in ("pid", "mnt", "net", "user", "uts", "ipc", "cgroup"):
        try:
            namespaces[name] = os.readlink(f"/proc/{pid}/ns/{name}")[:256]
        except OSError:
            # An unreadable namespace link is absent from the map, which is itself the visible signal.
            continue
    cgroups: list[str] = []
    cgroups_truncated = False
    try:
        with pathlib.Path(f"/proc/{pid}/cgroup").open("r", encoding="utf-8", errors="replace") as handle:
            for _, line in zip(range(PROCESS_CGROUP_MAX_ENTRIES + 1), handle):
                value = line.strip()[:PROCESS_CGROUP_MAX_BYTES]
                if not value:
                    continue
                if len(cgroups) >= PROCESS_CGROUP_MAX_ENTRIES:
                    cgroups_truncated = True
                    break
                cgroups.append(value)
    except OSError:
        cgroups_truncated = True
    return {**links, "namespaces": namespaces, "cgroups": cgroups, "cgroupsTruncated": cgroups_truncated}


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
    scope = process_scope_metadata(pid)
    try:
        command = redact_secret_text(pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()[:65536].replace(b"\0", b" ").decode("utf-8", errors="replace"), 4096).strip()
    except OSError:
        command = before["comm"]
    return {
        "bootId": boot_id(),
        "pid": pid,
        "startTicks": before["startTicks"],
        "exeInode": str(info.st_ino),
        "exeSha256": digest,
        "ppid": before["ppid"],
        "state": before["state"],
        "comm": before["comm"],
        "command": command,
        "uid": uid,
        "username": username,
        "exePath": clean_path,
        "exeDeleted": deleted,
        "exeSize": info.st_size,
        "startedAt": process_start_time(before["startTicks"]),
        "launcherPath": process_launcher_path(pid),
        "environment": process_environment_metadata(pid),
        **scope,
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
    truncated = 0
    proc_entries = sorted((item for item in pathlib.Path("/proc").iterdir() if item.name.isdigit()), key=lambda item: int(item.name))
    for entry in proc_entries:
        if len(items) >= maximum:
            return items, warnings[:100] + ["进程结果达到配置上限"], True
        if deadline_exceeded():
            return items, warnings[:100] + [DEADLINE_WARNING], True
        try:
            record = stable_process(int(entry.name), cache)
        except HelperError as exc:
            # Kernel threads and racing processes are expected, but inability to collect is explicit.
            warnings.append(f"PID {entry.name}: {str(exc)}")
            continue
        if record.get("cgroupsTruncated") or record["environment"]["partial"]:
            truncated += 1
        items.append(record)
    if truncated:
        warnings.append(f"{truncated} 个进程的 cgroups 或环境变量名列表因单条体积上限被截断")
    return items, warnings[:100], bool(warnings)


def read_global_connections(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    items: list[dict[str, Any]] = []
    warnings: list[str] = []
    states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "0A": "LISTEN"}
    for protocol, name, ipv6 in (("tcp", "/proc/net/tcp", False), ("tcp6", "/proc/net/tcp6", True), ("udp", "/proc/net/udp", False), ("udp6", "/proc/net/udp6", True)):
        if deadline_exceeded():
            return items, warnings[:100] + [DEADLINE_WARNING], True
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


def collect_process_executable(request: dict[str, Any]) -> dict[str, Any]:
    target = process_request(request)
    maximum = safe_int(request.get("maxBytes"), 1, ARTIFACT_MAX_BYTES, "maxBytes")
    artifact = stage_artifact(pathlib.Path(f"/proc/{target['pid']}/exe"), maximum)
    if artifact["sha256"] != target["exeSha256"]:
        artifact_path(artifact["artifactToken"]).unlink(missing_ok=True)
        raise HelperError("EVIDENCE_COLLECTION", "process executable changed during collection")
    identity = {key: target[key] for key in ("bootId", "pid", "startTicks", "exeInode", "exeSha256")}
    return {"artifact": artifact, "sha256": artifact["sha256"], "size": artifact["size"], "process": identity}


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


def parse_iso_time(raw: str) -> dt.datetime | None:
    """Parse an RFC3339/RFC5424 stamp with its own offset, or in the host zone when it carries none."""
    text = raw.strip().replace(",", ".")
    if text[-1:] in {"z", "Z"}:
        text = f"{text[:-1]}+00:00"
    text = text.replace(" ", "T", 1)
    fractional = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", text)
    if fractional:
        text = f"{fractional.group(1)}.{fractional.group(2)[:6].ljust(6, '0')}{fractional.group(3)}"
    compact = re.match(r"^(.*[+-]\d{2})(\d{2})$", text)
    if compact:
        text = f"{compact.group(1)}:{compact.group(2)}"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return local_naive_to_utc(parsed) if parsed.tzinfo is None else parsed.astimezone(dt.timezone.utc)


def parse_syslog_time(raw: str, reference: dt.datetime | None = None) -> dt.datetime | None:
    """Resolve a syslog stamp to UTC in the host zone, inferring the year from a reference instant."""
    text = raw.strip()
    iso = SYSLOG_ISO.match(text)
    if iso:
        return parse_iso_time(iso.group(1))
    match = SYSLOG_TRADITIONAL.match(text)
    if not match:
        return None
    anchor = reference or now_utc()
    horizon = anchor + dt.timedelta(hours=24)
    candidates: list[dt.datetime] = []
    for year in (anchor.year, anchor.year - 1):
        try:
            naive = dt.datetime.strptime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        moment = local_naive_to_utc(naive)
        if moment is not None:
            candidates.append(moment)
    if not candidates:
        return None
    return next((moment for moment in candidates if moment <= horizon), candidates[-1])


def parse_log_record(line: str, reference: dt.datetime | None = None) -> dict[str, Any] | None:
    """Split one syslog line into an absolute instant plus program, pid and message."""
    text = SYSLOG_PRIORITY.sub("", line, count=1)
    iso = SYSLOG_ISO.match(text)
    traditional = None if iso else SYSLOG_TRADITIONAL.match(text)
    if iso:
        timestamp = parse_iso_time(iso.group(1))
        remainder = text[iso.end(1):].lstrip()
    elif traditional:
        timestamp = parse_syslog_time(traditional.group(1), reference)
        remainder = text[traditional.end(1):].lstrip()
    else:
        return None
    if timestamp is None:
        return None
    header = SYSLOG_HEADER.match(remainder)
    return {
        "timestamp": timestamp,
        "program": header.group("program") if header else None,
        "pid": header.group("pid") if header else None,
        "message": header.group("message") if header else remainder,
        "auditType": "",
    }


JOURNAL_STORAGE_DIRECTORIES = ("/run/log/journal", "/var/log/journal")
JOURNAL_SOURCE = "journald"


def journal_storage_path() -> pathlib.Path | None:
    """Directory backing the journal store; also the `log_source.path` of the journald source."""
    return next(iter(journal_storage_paths()), None)


def journal_storage_paths() -> list[pathlib.Path]:
    """All journal roots read by journalctl, in stable order."""
    return [pathlib.Path(candidate) for candidate in JOURNAL_STORAGE_DIRECTORIES
            if pathlib.Path(candidate).is_dir()]


def journal_generation() -> str | None:
    """Digest journal files, not only their parent directory.

    Appending to an existing ``*.journal`` file does not update the directory mtime on Unix.
    Hashing directory metadata alone therefore misses the normal (non-rotation) write path and
    lets an offset cursor cross newly appended events while claiming the source is unchanged.
    """
    roots = journal_storage_paths()
    if not roots:
        return None
    values: list[Any] = []
    for root in roots:
        try:
            info = root.stat()
            values.append((str(root), str(info.st_dev), str(info.st_ino), info.st_mtime_ns))
        except OSError:
            values.append((str(root), "unreadable"))
            continue
        count = 0
        try:
            for path in sorted(root.rglob("*.journal*")):
                if count >= 2048:
                    values.append((str(root), "journal-file-limit"))
                    break
                try:
                    info = path.stat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                values.append((str(path), str(info.st_dev), str(info.st_ino), info.st_mtime_ns, info.st_size))
                count += 1
        except OSError:
            values.append((str(root), "enumeration-failed"))
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def journal_binary() -> str | None:
    """Return journalctl only when a journal store also exists, so callers never guess."""
    binary = shutil.which("journalctl")
    if not binary or journal_storage_path() is None:
        return None
    return binary


def log_source_id(source: str) -> str:
    """Single derivation of `log_source` identity, shared by the source list and every event.

    Every event namespace must derive `sourceId` through this function using the same `source`
    string that `v2_log_source_rows` reports, otherwise an event carries an identity that
    cannot be resolved in `log_source` and `relate log_source contains` silently returns
    nothing. Files use the resolved path; the journal uses the fixed `JOURNAL_SOURCE` literal.
    """
    return hashlib.sha256(source.encode()).hexdigest()


def log_source_key(path: pathlib.Path) -> str:
    """Canonical `source` string for a log file.

    `v2_log_source_rows` and the event queries must produce byte-identical source strings or
    the same file ends up with two different `sourceId` values. Previously the source list
    used the resolved path while the event queries used the raw glob path, so any symlinked
    log directory silently split one source in two.
    """
    try:
        return str(path.resolve())
    except OSError:
        return str(path)


def log_event_cursor(source: str, timestamp: str, program: str | None, payload: str) -> str:
    """Content-derived stable cursor.

    The cursor is part of the event identity, so it must depend only on the event itself.
    A page-local array index would give the same event a different ObjectRef on every call
    and break ObjectRef reuse for a stable identity.
    """
    payload_digest = hashlib.sha256(payload.encode()).hexdigest()
    return hashlib.sha256(f"{log_source_id(source)}\0{timestamp}\0{program or ''}\0{payload_digest}".encode()).hexdigest()


def journal_text(value: Any) -> str:
    """Decode a journal field that may arrive as text or as a byte array."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        try:
            return bytes(int(item) & 0xFF for item in value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    return ""


def journal_records(since: dt.datetime, maximum: int, matches: tuple[str, ...], ledger: SkipLedger) -> list[dict[str, Any]]:
    """Read structured journald entries through a fixed argv projection; never through a shell."""
    binary = journal_binary()
    if binary is None:
        return []
    budget = max(1, min(maximum, JOURNAL_MAX_RECORDS))
    since_local = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(since.timestamp()))
    argv = [binary, "--output=json", "--no-pager", f"--since={since_local}", f"--lines={budget}", *matches]
    try:
        result = run(argv, timeout=20, check=False)
    except HelperError as exc:
        ledger.note(f"journalctl 未在时间预算内完成：{exc}")
        return []
    if result.returncode != 0:
        ledger.note(f"journalctl 退出码 {result.returncode}，journald 事件不完整")
        return []
    records: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            ledger.add(SKIP_LOG_RECORD)
            continue
        if not isinstance(entry, dict):
            continue
        try:
            moment = dt.datetime.fromtimestamp(int(str(entry.get("__REALTIME_TIMESTAMP"))) / 1_000_000, dt.timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            ledger.add(SKIP_LOG_RECORD)
            continue
        if moment < since:
            continue
        records.append({
            "timestamp": moment,
            "program": journal_text(entry.get("SYSLOG_IDENTIFIER")) or journal_text(entry.get("_COMM")) or None,
            "pid": journal_text(entry.get("SYSLOG_PID")) or journal_text(entry.get("_PID")) or None,
            "message": journal_text(entry.get("MESSAGE")),
            "auditType": journal_text(entry.get("_AUDIT_TYPE_NAME")),
        })
    if len(records) >= budget:
        ledger.note(f"journald 读取达到 {budget} 条上限，更早事件未纳入")
    return records


def auth_event_type(message: str, program: str | None) -> str:
    if "Accepted " in message:
        return "authentication_success"
    if "Failed " in message or "failure" in message.lower():
        return "authentication_failure"
    if program == "sudo" or "sudo:" in message:
        return "privilege_use"
    return "other"


# 按优先级依次尝试，而不是用一个含 `sudo:\s*` 分支的大 alternation。
# 后者对 `pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)`
# 会命中最左侧的 `sudo:` 并把用户名解析成 "session"，报告里出现无意义的账户名。
AUTH_USER_PATTERNS = (
    # 显式 key=value 最可靠，PAM 的 authentication failure 行只有这一种线索。
    re.compile(r"\buser=([A-Za-z_][A-Za-z0-9_.$-]{0,63})"),
    # sshd 的 `for ubuntu` / `for invalid user admin`，以及 PAM 的 `for user root`。
    re.compile(r"\bfor (?:(?:invalid|illegal) )?(?:user )?([A-Za-z_][A-Za-z0-9_.$-]{0,63})\b"),
    # systemd-logind 的 `New session 38 of user ubuntu.`
    re.compile(r"\bof user ([A-Za-z_][A-Za-z0-9_.$-]{0,63})\b"),
    # sudo 的命令行记录 `  ubuntu : PWD=... ; USER=root ; COMMAND=...`
    re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.$-]{0,63})\s*:\s*(?:PWD|TTY|USER)="),
    # PAM 会话行的发起者 `by ubuntu(uid=1000)`
    re.compile(r"\bby ([A-Za-z_][A-Za-z0-9_.$-]{0,63})\(uid="),
)


def auth_username(message: str, program: str | None) -> str | None:
    for pattern in AUTH_USER_PATTERNS:
        found = pattern.search(message)
        if found:
            return found.group(1)
    if program in {"sudo", "su"}:
        opening = re.match(r"\s*([A-Za-z_][A-Za-z0-9_.$-]{0,63})\s*:", message)
        if opening:
            return opening.group(1)
    return None


def auth_event(record: dict[str, Any], source: str) -> dict[str, Any] | None:
    message = str(record["message"])
    program = record["program"]
    event_type = auth_event_type(message, program)
    if event_type == "other":
        return None
    username = auth_username(message, program)
    ip_match = re.search(r"\bfrom\s+([0-9a-fA-F:.]{3,64})", message)
    source_ip = ip_match.group(1) if ip_match else None
    timestamp = utc_iso(record["timestamp"])
    return {"timestamp": timestamp, "eventType": event_type,
            "username": username, "sourceAddress": source_ip, "program": program,
            "success": True if event_type == "authentication_success" else False if event_type == "authentication_failure" else None,
            "pid": record["pid"],
            "summary": f"{event_type}; user={username or 'unknown'}; source={source_ip or 'local'}; program={program or 'unknown'}",
            "source": source,
            "sourceId": log_source_id(source),
            "cursor": log_event_cursor(source, timestamp, program, message)}


def log_record_key(record: dict[str, Any]) -> tuple[int, str, str]:
    """Identity used to merge journald and file log copies of the same event exactly once.

    PID is deliberately excluded. journald exposes `_PID` for every entry, but the file log
    only carries a PID when the program prints `name[pid]:` — `sudo:` and `su:` do not.
    Keying on PID therefore never matched the two copies of the same sudo event and every
    such event was counted twice, which also burned the event budget at double rate.
    """
    message_digest = hashlib.sha256(str(record["message"]).encode()).hexdigest()
    return (int(record["timestamp"].timestamp()), str(record["program"] or ""), message_digest)


def query_auth_events(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    cutoff = now_utc() - dt.timedelta(hours=hours)
    ledger = SkipLedger()
    warnings: list[str] = []
    sources: list[str] = []
    collected: list[tuple[dt.datetime, dict[str, Any]]] = []
    seen: set[tuple[int, str, str, str]] = set()
    ceiling = min(maximum * 2, 100000)
    limited = False

    def absorb(record: dict[str, Any], source: str) -> None:
        nonlocal limited
        if limited or record["timestamp"] < cutoff:
            return
        key = log_record_key(record)
        if key in seen:
            return
        seen.add(key)
        event = auth_event(record, source)
        if event is None:
            return
        collected.append((record["timestamp"], event))
        if len(collected) >= ceiling:
            limited = True

    if journal_binary() is not None:
        sources.append(JOURNAL_SOURCE)
        for matches in (JOURNAL_AUTH_FACILITIES, tuple(f"_COMM={name}" for name in JOURNAL_AUTH_COMMANDS)):
            if limited:
                break
            if deadline_exceeded():
                ledger.expire()
                break
            for record in journal_records(cutoff, maximum, matches, ledger):
                absorb(record, JOURNAL_SOURCE)
    for path in log_file_set(AUTH_LOG_PATTERNS, ledger):
        if limited:
            break
        if deadline_exceeded():
            ledger.expire()
            break
        source = log_source_key(path)
        sources.append(source)
        try:
            reference = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        except OSError:
            ledger.add(SKIP_UNREADABLE)
            continue
        for line in bounded_log_lines(path, ledger):
            record = parse_log_record(line, reference)
            if record is None:
                continue
            absorb(record, source)
            if limited:
                break
    if not sources:
        warnings.append("认证事件数据源不可用：journald 与 auth.log/secure 均不存在，本次结果不代表无异常")
    if limited:
        warnings.append("认证事件采集达到内部上限，仅保留最新事件")
    collected.sort(key=lambda item: item[0])
    items = [event for _, event in collected]
    if len(items) > maximum:
        items = items[-maximum:]
        warnings.append("认证事件达到配置上限")
    return {"items": items, "partial": bool(warnings) or ledger.partial,
            "warnings": (warnings + ledger.warnings())[:200], "sources": sources[:LOG_FILE_LIMIT + 1]}


def query_log_events(request: dict[str, Any]) -> dict[str, Any]:
    """Collect bounded generic system-log events without exposing raw journal metadata or secrets."""
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    cutoff = now_utc() - dt.timedelta(hours=hours)
    ledger = SkipLedger()
    warnings: list[str] = []
    sources: list[str] = []
    collected: list[tuple[dt.datetime, dict[str, Any]]] = []
    seen: set[tuple[int, str, str]] = set()
    ceiling = min(maximum * 2, 100000)

    def absorb(record: dict[str, Any], source: str) -> None:
        if len(collected) >= ceiling or record["timestamp"] < cutoff:
            return
        key = log_record_key(record)
        if key in seen:
            return
        seen.add(key)
        raw_message = str(record.get("message", ""))
        message = redact_secret_text(raw_message, 8192)
        timestamp = utc_iso(record["timestamp"])
        source_id = log_source_id(source)
        # Identity uses the private raw record digest. Redaction belongs to the model plane;
        # deriving identity from redacted text would collapse distinct secret-bearing events.
        cursor = log_event_cursor(source, timestamp, record.get("program"), raw_message)
        metadata = {"pid": record.get("pid"), "auditType": record.get("auditType")}
        collected.append((record["timestamp"], {
            "sourceId": source_id, "cursor": cursor, "timestamp": timestamp,
            "program": record.get("program"), "message": message,
            "fields": {key: value for key, value in metadata.items() if value not in {None, ""}},
        }))

    if journal_binary() is not None:
        sources.append(JOURNAL_SOURCE)
        for record in journal_records(cutoff, maximum, (), ledger):
            absorb(record, JOURNAL_SOURCE)
            if len(collected) >= ceiling or deadline_exceeded():
                break
    for path in log_file_set((*SYSTEM_LOG_PATTERNS, *AUTH_LOG_PATTERNS), ledger):
        if len(collected) >= ceiling or deadline_exceeded():
            if deadline_exceeded():
                ledger.expire()
            break
        source = log_source_key(path)
        sources.append(source)
        try:
            reference = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
        except OSError:
            ledger.add(SKIP_UNREADABLE)
            continue
        for line in bounded_log_lines(path, ledger):
            record = parse_log_record(line, reference)
            if record is None:
                ledger.add(SKIP_LOG_RECORD)
                continue
            absorb(record, source)
            if len(collected) >= ceiling:
                break
    if not sources:
        warnings.append("通用日志数据源不可用：journald 与 syslog/messages 均不存在")
    if len(collected) >= ceiling:
        warnings.append("通用日志采集达到内部上限，仅保留最新事件")
    collected.sort(key=lambda item: item[0])
    items = [event for _, event in collected]
    if len(items) > maximum:
        items = items[-maximum:]
        warnings.append("通用日志事件达到配置上限")
    return {"items": items, "partial": bool(warnings) or ledger.partial,
            "warnings": (warnings + ledger.warnings())[:200], "sources": sources[:LOG_FILE_LIMIT + 1]}


def audit_field(text: str, name: str) -> str | None:
    match = re.search(rf"\b{name}=(?:\"([^\"]*)\"|(\S+))", text)
    return (match.group(1) or match.group(2)) if match else None


def audit_exec_event(text: str, moment: dt.datetime, source: str) -> dict[str, Any]:
    """Project one audit SYSCALL record; EXECVE a0..aN fields stay out because they carry secrets."""
    timestamp = utc_iso(moment)
    comm = redact_secret_text(audit_field(text, "comm") or "", 256)
    return {"timestamp": timestamp, "eventType": "process_exec", "pid": audit_field(text, "pid"),
            "ppid": audit_field(text, "ppid"), "uid": audit_field(text, "uid"), "auid": audit_field(text, "auid"),
            "comm": comm,
            "exe": redact_secret_text(audit_field(text, "exe") or "", 4096), "source": source,
            "sourceId": log_source_id(source),
            # The raw record is the only field that separates two syscalls of the same binary
            # in the same second, so the cursor derives from it rather than from the projection.
            "cursor": log_event_cursor(source, timestamp, comm, text)}


def query_exec_events(request: dict[str, Any]) -> dict[str, Any]:
    hours = safe_int(request.get("sinceHours"), 1, 8760, "sinceHours")
    maximum = safe_int(request.get("maxEvents"), 1, 50000, "maxEvents")
    cutoff = now_utc() - dt.timedelta(hours=hours)
    ledger = SkipLedger()
    warnings: list[str] = []
    sources: list[str] = []
    collected: list[tuple[dt.datetime, dict[str, Any]]] = []
    seen: set[tuple[str, str, str, str]] = set()
    ceiling = min(maximum * 2, 100000)
    limited = False

    def absorb(moment: dt.datetime, event: dict[str, Any]) -> None:
        nonlocal limited
        if limited or moment < cutoff:
            return
        key = (str(event["timestamp"]), str(event["pid"] or ""), str(event["comm"]), str(event["exe"]))
        if key in seen:
            return
        seen.add(key)
        collected.append((moment, event))
        if len(collected) >= ceiling:
            limited = True

    for path in log_file_set(AUDIT_LOG_PATTERNS, ledger):
        if limited:
            break
        if deadline_exceeded():
            ledger.expire()
            break
        source = log_source_key(path)
        sources.append(source)
        for line in bounded_log_lines(path, ledger):
            if "type=SYSCALL" not in line:
                continue
            match = AUDIT_EPOCH.search(line)
            if not match:
                ledger.add(SKIP_LOG_RECORD)
                continue
            try:
                moment = dt.datetime.fromtimestamp(float(match.group(1)), dt.timezone.utc)
            except (ValueError, OverflowError, OSError):
                ledger.add(SKIP_LOG_RECORD)
                continue
            absorb(moment, audit_exec_event(line, moment, source))
            if limited:
                break
    if not limited and not ledger.expired and journal_binary() is not None:
        records = journal_records(cutoff, maximum, ("_TRANSPORT=audit",), ledger)
        if records:
            sources.append(JOURNAL_SOURCE)
        for record in records:
            message = str(record["message"])
            if record["auditType"] != "SYSCALL" and not message.startswith("SYSCALL") and "type=SYSCALL" not in message:
                continue
            absorb(record["timestamp"], audit_exec_event(message, record["timestamp"], JOURNAL_SOURCE))
    if not sources:
        warnings.append("auditd 与 journald audit 传输均不可用；无法还原历史进程执行事件，本次结果不代表无异常")
    if limited:
        warnings.append("进程执行事件采集达到内部上限，仅保留最新事件")
    collected.sort(key=lambda item: item[0])
    items = [event for _, event in collected]
    if len(items) > maximum:
        items = items[-maximum:]
        warnings.append("进程执行事件达到配置上限")
    return {"items": items, "partial": bool(warnings) or ledger.partial,
            "warnings": (warnings + ledger.warnings())[:200], "sources": sources[:LOG_FILE_LIMIT + 1]}


def get_action_receipt(request: dict[str, Any]) -> dict[str, Any]:
    value = action_id(request)
    path = receipt_path(value)
    if not path.exists():
        return {"actionId": value, "status": "UNKNOWN"}
    return json.loads(path.read_text("utf-8"))


def quarantine_file(request: dict[str, Any]) -> dict[str, Any]:
    value = action_id(request)
    descriptor, canonical = v2_open_regular(request.get("path"))
    source = pathlib.Path(canonical)
    expected = request.get("expectedSha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        os.close(descriptor)
        raise HelperError("INVALID_ARGUMENT", "invalid expectedSha256")
    expected_device, expected_inode = request.get("expectedDevice"), request.get("expectedInode")
    before = os.fstat(descriptor)
    if str(before.st_dev) != str(expected_device) or str(before.st_ino) != str(expected_inode):
        os.close(descriptor)
        raise HelperError("STALE_REF", "quarantine file identity changed")
    root = safe_path(request.get("quarantineRoot"), must_exist=False)
    receipt = begin_receipt(value, "quarantine_file", request)
    if receipt["status"] == "SUCCEEDED":
        os.close(descriptor)
        return receipt
    if v2_sha256_fd(descriptor) != expected:
        os.close(descriptor)
        return finish_receipt(receipt, "FAILED", {"reason": "source hash changed"})
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_dir = root / value
    target_dir.mkdir(mode=0o700, exist_ok=True)
    target = target_dir / source.name
    if source.stat().st_dev != target_dir.stat().st_dev:
        os.close(descriptor)
        return finish_receipt(receipt, "FAILED", {"reason": "cross-filesystem quarantine refused"})
    immediate = source.lstat()
    if not stat.S_ISREG(immediate.st_mode) or (immediate.st_dev, immediate.st_ino) != (before.st_dev, before.st_ino):
        os.close(descriptor)
        return finish_receipt(receipt, "FAILED", {"reason": "source identity changed before rename"})
    metadata = {"originalPath": str(source), "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid, "sha256": expected}
    os.rename(source, target)
    moved = target.lstat()
    if (moved.st_dev, moved.st_ino) != (before.st_dev, before.st_ino):
        if not source.exists():
            os.rename(target, source)
        os.close(descriptor)
        return finish_receipt(receipt, "FAILED", {"reason": "rename target identity mismatch; rollback attempted"})
    os.chmod(target, 0o000)
    quarantine_mode = stat.S_IMODE(target.stat().st_mode)
    os.close(descriptor)
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


# v2 只暴露通用取证原语。下方适配器复用 collector 函数，但不会把旧的检测问题、
# suspicious 标签或 operation map 暴露给模型。
V2_NAMESPACE_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("bootId", "hostname", "os", "release", "architecture", "timezone", "observedAt"),
    "process": ("bootId", "pid", "startTicks", "ppid", "uid", "username", "comm", "exe", "exeInode", "exeSha256", "command", "state", "startedAt"),
    "socket": ("protocol", "localAddress", "localPort", "remoteAddress", "remotePort", "state", "inode", "pid"),
    "file": ("mountId", "device", "inode", "path", "canonicalPath", "kind", "size", "mode", "uid", "gid", "mtime", "sha256", "contentClass", "content", "baseline", "baselineStatus"),
    "account": ("uid", "username", "gid", "home", "shell", "groups", "locked", "passwordHash"),
    "ssh_key": ("fingerprint", "ownerUid", "type", "bits", "comment", "sourceFile"),
    "delegation_rule": ("mechanism", "sourceDigest", "line", "ruleDigest", "source", "effect", "subject", "runAs", "statement"),
    "ssh_trust_config": ("scope", "directive", "valueDigest", "value", "source", "effective"),
    "cron_entry": ("source", "line", "digest", "schedule", "user", "command"),
    "unit": ("name", "fragmentDigest", "path", "enabled", "active", "execStart", "user"),
    "persistence": ("kind", "sourceDigest", "source", "user", "command", "enabled"),
    "module": ("name", "address", "size", "path", "sha256"),
    "log_source": ("sourceId", "generation", "kind", "path", "firstEventAt", "lastEventAt"),
    "log_event": ("sourceId", "cursor", "timestamp", "program", "message", "fields"),
    "auth_event": ("sourceId", "cursor", "timestamp", "eventType", "username", "sourceAddress", "program", "success"),
    "exec_event": ("sourceId", "cursor", "timestamp", "pid", "uid", "executable", "arguments", "cwd"),
    "web_stack": ("kind", "instanceId", "version", "pid", "configPaths"),
    "web_root": ("mountId", "device", "inode", "path", "server", "effective"),
    "jvm": ("bootId", "pid", "startTicks", "version", "command", "attachSupported", "container"),
    "java_component": ("jvmDigest", "componentKind", "name", "className", "mappings"),
    "class": ("jvmDigest", "className", "loaderId", "codeSource", "bytecodeSha256", "modifiable"),
    "package": ("manager", "name", "version", "architecture", "installedAt", "integrity"),
}
V2_RELATIONS: dict[str, tuple[str, ...]] = {
    "process": ("parent", "children", "opens", "connects"), "socket": ("owned_by",),
    "file": ("opened_by", "referenced_by_persistence", "requested_in"),
    "account": ("authorized_key", "login_event"), "ssh_key": ("owned_by",),
    "cron_entry": ("executes",), "unit": ("executes",), "persistence": ("executes",),
    "log_source": ("contains",), "web_stack": ("serves_root",), "web_root": ("served_by",),
    "package": ("owns_file",),
}
V2_PROBE_RELATIONS: dict[str, tuple[str, ...]] = {
    "jvm": ("hosts_component", "loads_class"),
    "class": ("loaded_by",),
}
V2_IDENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "host": ("bootId",), "process": ("bootId", "pid", "startTicks", "exeInode", "exeSha256"),
    "socket": ("protocol", "localAddress", "localPort", "remoteAddress", "remotePort", "inode"),
    "file": ("mountId", "device", "inode"), "account": ("uid", "username"),
    "ssh_key": ("fingerprint", "ownerUid"), "cron_entry": ("source", "line", "digest"),
    "delegation_rule": ("mechanism", "sourceDigest", "line", "ruleDigest"),
    "ssh_trust_config": ("scope", "directive", "valueDigest"),
    "unit": ("name", "fragmentDigest"), "persistence": ("kind", "sourceDigest"),
    "module": ("name", "address"), "log_source": ("sourceId", "generation"),
    "log_event": ("sourceId", "cursor"), "auth_event": ("sourceId", "cursor"),
    "exec_event": ("sourceId", "cursor"), "web_stack": ("kind", "instanceId"),
    "web_root": ("mountId", "device", "inode"), "jvm": ("bootId", "pid", "startTicks"),
    "java_component": ("jvmDigest", "componentKind", "name"),
    "class": ("jvmDigest", "className", "loaderId"),
    "package": ("manager", "name", "version", "architecture"),
}
V2_ENUMERABLE_NAMESPACES = {
    "host", "process", "socket", "file", "account", "ssh_key", "delegation_rule", "ssh_trust_config", "cron_entry", "unit", "persistence",
    "module", "log_source", "log_event", "auth_event", "exec_event", "web_stack", "web_root", "jvm", "package",
}
# Fields the Manifest allows but this collector does not produce. They must be advertised as
# unavailable, otherwise the model sees them in the capability set, requests them, and gets a
# PARTIAL result with FIELD_UNAVAILABLE instead of a clear "not supported" answer.
# log_source first/lastEventAt would require reading the head and tail of every log source
# including rotated .gz members, which the source listing deliberately does not do.
V2_UNAVAILABLE_FIELDS: dict[str, set[str]] = {
    "ssh_key": {"bits"},
    "log_source": {"firstEventAt", "lastEventAt"},
    "web_stack": {"version"},
    "jvm": {"version"},
    "package": {"installedAt", "integrity"},
    "module": {"sha256"},
}
V2_NAMESPACE_VERBS: dict[str, tuple[str, ...]] = {
    **{name: ("enumerate",) for name in V2_ENUMERABLE_NAMESPACES},
    "process": ("enumerate", "project", "relate", "collect"),
    "socket": ("enumerate", "relate"),
    "file": ("enumerate", "project", "read", "match", "verify", "collect"),
    "account": ("enumerate", "project"),
    "jvm": ("enumerate", "probe"),
    "java_component": (), "class": (),
}
for _relation_namespace in V2_RELATIONS:
    _verbs = list(V2_NAMESPACE_VERBS.get(_relation_namespace, ()))
    if "relate" not in _verbs:
        _verbs.append("relate")
    V2_NAMESPACE_VERBS[_relation_namespace] = tuple(_verbs)
V2_VERBS = {"capabilities", "enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"}
V2_MAINTENANCE_VERBS = {"scope_resolve", "artifact_release", "get_action_receipt", "quarantine_file", "disable_account"}
V2_WIRE_ERROR_CODES = {
    "INVALID_ARGUMENT", "PERMISSION_DENIED", "UNSUPPORTED_CAPABILITY", "STALE_REF", "EPOCH_MISMATCH",
    "DEADLINE_EXCEEDED", "BUDGET_EXHAUSTED", "SOURCE_CHANGED", "OUTPUT_LIMIT_EXCEEDED",
    "EVIDENCE_COLLECTION_FAILED", "PROBE_FAILED", "TARGET_UNAVAILABLE", "INTERNAL_ERROR",
}
V2_NON_ENUMERABLE_FIELDS = {
    "file": {"sha256", "content", "baseline", "baselineStatus"},
    "module": {"sha256"},
    "account": {"passwordHash"},
}
V2_NON_SORTABLE_FIELDS = {"groups", "configPaths", "mappings", "fields"}
V2_YARA_RULESETS = {
    "RULESET-WEBSHELL-BUILTIN-2": {
        "path": pathlib.Path("/opt/huntwarden/rules/webshell.yar"),
        "sha256": "6f90570d618fbd00b707148c74cfeddd4cffc1bfb712f1fb8ab397fe077a1660",
    },
}


def v2_yara_ruleset_path(rule_set_ref: str) -> pathlib.Path:
    ruleset = V2_YARA_RULESETS[rule_set_ref]
    path = ruleset["path"]
    if not path.is_file() or path.is_symlink() or sha256_file(path) != ruleset["sha256"]:
        raise HelperError("UNSUPPORTED_CAPABILITY", "built-in YARA RuleSet integrity check failed")
    return path


def v2_wire_error_code(helper_code: str) -> str:
    code = {"TOOL_TIMEOUT": "DEADLINE_EXCEEDED", "EVIDENCE_COLLECTION": "EVIDENCE_COLLECTION_FAILED",
            "UNSUPPORTED_ENVIRONMENT": "UNSUPPORTED_CAPABILITY"}.get(helper_code, helper_code)
    return code if code in V2_WIRE_ERROR_CODES else "INTERNAL_ERROR"


def v2_cursor_binding(params: dict[str, Any], epoch_id: str) -> str:
    bound = {key: value for key, value in params.items() if key != "cursor"}
    encoded = json.dumps({"epochId": epoch_id, "params": bound}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def v2_source_generation(namespace: str, params: dict[str, Any]) -> str:
    values: list[Any] = [namespace, platform.node(), platform.machine()]
    if namespace == "file":
        scope, locator = params.get("scope"), params.get("locator")
        path_value = scope.get("canonicalRoot") if isinstance(scope, dict) else locator.get("path") if isinstance(locator, dict) else None
        if not isinstance(path_value, str):
            raise HelperError("INVALID_ARGUMENT", "file cursor has no bound source")
        info = pathlib.Path(path_value).stat()
        values.extend([str(info.st_dev), str(info.st_ino), info.st_mtime_ns, info.st_size])
    elif namespace in {"delegation_rule", "ssh_trust_config"}:
        paths = v2_delegation_config_paths() if namespace == "delegation_rule" else v2_ssh_config_paths()
        for path in paths:
            try:
                info = path.lstat()
                values.extend([str(path), str(info.st_dev), str(info.st_ino), info.st_mtime_ns, info.st_size])
            except OSError:
                continue
    elif namespace in {"log_source", "log_event", "auth_event", "exec_event"}:
        patterns = (*SYSTEM_LOG_PATTERNS, *AUTH_LOG_PATTERNS, *AUDIT_LOG_PATTERNS, *WEB_ACCESS_LOG_PATTERNS)
        for raw in sorted({name for pattern in patterns for name in glob.glob(pattern)}):
            try:
                info = pathlib.Path(raw).stat()
                values.extend([raw, str(info.st_dev), str(info.st_ino), info.st_mtime_ns, info.st_size])
            except OSError:
                continue
        # The journal is one of these sources, so its store must take part in the generation.
        # Leaving it out meant a page could straddle newly written journal entries while the
        # cursor still claimed the source was unchanged.
        generation = journal_generation()
        values.extend([JOURNAL_SOURCE, generation or "journal-unavailable"])
        try:
            values.append(boot_id())
        except (HelperError, OSError):
            values.append("boot-unavailable")
    else:
        try:
            values.append(boot_id())
        except (HelperError, OSError):
            values.append("boot-unavailable")
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def v2_encode_cursor(namespace: str, offset: int, binding: str, source_generation: str) -> str:
    body = {"v": 1, "namespace": namespace, "offset": offset, "binding": binding, "sourceGeneration": source_generation}
    body["integrity"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return base64.urlsafe_b64encode(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")


def v2_cursor_start(namespace: str, params: dict[str, Any], epoch_id: str,
                    tolerate_source_change: bool = False) -> tuple[int, str, str, bool]:
    binding, generation = v2_cursor_binding(params, epoch_id), v2_source_generation(namespace, params)
    token = params.get("cursor")
    if token is None:
        return 0, binding, generation, False
    if not isinstance(token, str) or not 1 <= len(token) <= 4096:
        raise HelperError("INVALID_ARGUMENT", "invalid opaque cursor")
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        integrity = payload.pop("integrity")
        actual = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error) as exc:
        raise HelperError("INVALID_ARGUMENT", "invalid opaque cursor") from exc
    if not secrets.compare_digest(str(integrity), actual) or payload.get("v") != 1 or payload.get("namespace") != namespace:
        raise HelperError("INVALID_ARGUMENT", "opaque cursor identity mismatch")
    if payload.get("binding") != binding:
        raise HelperError("INVALID_ARGUMENT", "opaque cursor request binding mismatch")
    source_changed = payload.get("sourceGeneration") != generation
    if source_changed and not tolerate_source_change:
        raise HelperError("SOURCE_CHANGED", "cursor source generation changed")
    return safe_int(payload.get("offset"), 0, 10_000_000, "cursor offset"), binding, generation, source_changed


def v2_cost(started: float, nodes: int = 0, byte_count: int = 0, probe_calls: int = 0) -> dict[str, int]:
    return {"remoteCalls": 1, "nodes": nodes, "bytes": byte_count,
            "wallTimeMs": max(0, int((time.monotonic() - started) * 1000)), "probeCalls": probe_calls}


def v2_capabilities() -> dict[str, Any]:
    probe_ready = PROBE_JAR.is_file() and java_binary() is not None
    available_names = set(V2_ENUMERABLE_NAMESPACES)
    # These namespaces are produced only as probe results, but still need to be
    # declared so the controller can validate their observations.
    if probe_ready:
        available_names.update({"java_component", "class"})
    available = {name: {"fields": [field for field in V2_NAMESPACE_FIELDS[name] if field not in V2_UNAVAILABLE_FIELDS.get(name, set())], "relations": list((*V2_RELATIONS.get(name, ()), *(V2_PROBE_RELATIONS.get(name, ()) if probe_ready else ()))), "verbs": list(V2_NAMESPACE_VERBS.get(name, ())) }
                 for name in sorted(available_names)}
    matchers = ["literal"]
    if re2_engine is not None:
        matchers.append("re2")
    if shutil.which("yara"):
        try:
            for rule_set_ref in V2_YARA_RULESETS:
                v2_yara_ruleset_path(rule_set_ref)
        except (HelperError, OSError):
            pass
        else:
            matchers.append("yara")
    probes = ["jvm.tomcat.inventory", "jvm.class.inspect"] if probe_ready else []
    return {
        "protocolVersion": PROTOCOL_VERSION, "manifestVersion": MANIFEST_VERSION,
        "helper": {"name": "huntwarden-helper-v2", "version": HELPER_VERSION},
        "namespaces": available, "matchers": matchers,
        "probes": probes,
        "verbs": ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
        "limits": {"maxObjects": 500, "maxOutputBytes": MAX_OUTPUT_BYTES, "maxReadBytes": 65536,
                   "maxCollectBytes": ARTIFACT_MAX_BYTES},
    }


def v2_identity(namespace: str, fields: dict[str, Any]) -> dict[str, Any]:
    names = V2_IDENTITY_FIELDS.get(namespace)
    if not names:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"stable identity is not implemented for {namespace}")
    identity = {name: fields.get(name) for name in names}
    if any(value is None or value == "" for value in identity.values()):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"collector did not produce stable {namespace} identity")
    return identity


def v2_observation(namespace: str, fields: dict[str, Any], consistency: str = "OBJECT_STABLE",
                   requested_fields: tuple[str, ...] | None = None) -> dict[str, Any]:
    allowed = V2_NAMESPACE_FIELDS.get(namespace)
    if not allowed:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"namespace unavailable: {namespace}")
    projected = {name: fields[name] for name in allowed if name in fields and fields[name] is not None}
    identity = v2_identity(namespace, projected)
    unavailable = [{"field": name, "reasonCode": "COLLECTOR_UNAVAILABLE"}
                   for name in (requested_fields or ()) if name not in projected]
    return {"namespace": namespace, "identity": identity, "fields": projected,
            "observedAt": utc_iso(now_utc()), "consistency": consistency, "unavailableFields": unavailable}


def v2_file_fields(path: pathlib.Path, include_hash: bool = False) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise HelperError("INVALID_ARGUMENT", "file primitive only accepts regular files")
    value = {"mountId": str(info.st_dev), "device": str(info.st_dev), "inode": str(info.st_ino),
             "path": str(resolved), "canonicalPath": str(resolved), "kind": "regular", "size": info.st_size,
             "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
             "mtime": utc_iso(info.st_mtime), "contentClass": v2_content_class(resolved)}
    if include_hash:
        value["sha256"] = sha256_file(resolved)
    return value


def v2_open_regular(value: Any) -> tuple[int, str]:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or ".." in pathlib.PurePosixPath(value).parts:
        raise HelperError("INVALID_ARGUMENT", "file locator must be an absolute traversal-free path")
    parts = [part for part in pathlib.PurePosixPath(value).parts if part != "/"]
    if not parts:
        raise HelperError("INVALID_ARGUMENT", "file locator cannot be root")
    directory_flag = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open("/", directory_flag)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flag | nofollow, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | nofollow, dir_fd=directory_fd)
    except OSError as exc:
        raise HelperError("STALE_REF", "file locator changed, escaped, or became unreadable") from exc
    finally:
        os.close(directory_fd)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise HelperError("PERMISSION_DENIED", "file primitive rejects devices, FIFOs, sockets, and directories")
    try:
        canonical = os.readlink(f"/proc/self/fd/{descriptor}").removesuffix(" (deleted)")
    except OSError:
        canonical = value
    return descriptor, canonical


def v2_sha256_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    duplicate = os.dup(descriptor)
    try:
        os.lseek(duplicate, 0, os.SEEK_SET)
        with os.fdopen(duplicate, "rb", closefd=True) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        duplicate = -1
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    return digest.hexdigest()


def v2_file_fields_fd(descriptor: int, canonical: str, include_hash: bool = False) -> dict[str, Any]:
    info = os.fstat(descriptor)
    value = {"mountId": str(info.st_dev), "device": str(info.st_dev), "inode": str(info.st_ino),
             "path": canonical, "canonicalPath": canonical, "kind": "regular", "size": info.st_size,
             "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
             "mtime": utc_iso(info.st_mtime), "contentClass": v2_content_class(pathlib.Path(canonical))}
    if include_hash:
        value["sha256"] = v2_sha256_fd(descriptor)
    return value


def v2_bound_file(params: dict[str, Any], include_hash: bool = False) -> tuple[int, dict[str, Any]]:
    namespace, identity, locator = v2_ref_params(params)
    if namespace != "file":
        raise HelperError("INVALID_ARGUMENT", "operation only accepts file refs")
    descriptor, canonical = v2_open_regular(locator.get("path"))
    try:
        facts = v2_file_fields_fd(descriptor, canonical, include_hash)
        if any(facts.get(key) != identity.get(key) for key in ("mountId", "device", "inode")):
            raise HelperError("STALE_REF", "stable file identity changed")
        return descriptor, facts
    except Exception:
        os.close(descriptor)
        raise


def v2_content_class(path: pathlib.Path) -> str:
    text = str(path)
    denied = ("/etc/shadow", "/etc/gshadow", "/proc/kcore")
    if (text in denied or re.fullmatch(r"/proc/\d+/(?:mem|pagemap)", text)
            or text.endswith(("id_rsa", "id_ed25519")) or "/.ssh/" in text and text.endswith(".pem")
            or re.search(r"/(?:\.aws|\.gnupg|\.kube)/", text)):
        return "DENIED_TEXT"
    # systemd's canonical os-release lives in /usr/lib; /etc/os-release is
    # commonly a symlink to it. File primitives intentionally reject symlink
    # traversal, so both legitimate regular-file locations must be classified
    # as safe system metadata.
    safe = ("/etc/os-release", "/usr/lib/os-release", "/proc/version", "/proc/uptime", "/etc/hostname")
    return "SAFE_TEXT" if text in safe else "SENSITIVE_TEXT"


def v2_validate_predicate(namespace: str, node: Any, depth: int = 1,
                          count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if depth > 4 or count[0] > 32 or not isinstance(node, dict):
        raise HelperError("INVALID_ARGUMENT", "invalid predicate AST")
    op = node.get("op")
    if op in {"and", "or"}:
        args = node.get("args")
        if not isinstance(args, list) or not args:
            raise HelperError("INVALID_ARGUMENT", "invalid predicate group")
        for child in args:
            v2_validate_predicate(namespace, child, depth + 1, count)
        return
    if op == "not":
        v2_validate_predicate(namespace, node.get("arg"), depth + 1, count)
        return
    field = node.get("field")
    if (not isinstance(field, str) or field not in V2_NAMESPACE_FIELDS.get(namespace, ())
            or field in {"passwordHash", "content"}):
        raise HelperError("INVALID_ARGUMENT", "predicate field is not allowed by the v2 manifest")
    if op == "exists":
        if not isinstance(node.get("value", True), bool):
            raise HelperError("INVALID_ARGUMENT", "exists predicate requires a boolean value")
        return
    expected = node.get("value")
    if op in {"eq", "neq"}:
        return
    if op == "in":
        if not isinstance(expected, list) or not 1 <= len(expected) <= 64:
            raise HelperError("INVALID_ARGUMENT", "in predicate requires 1..64 values")
        return
    if op in {"contains", "starts_with"}:
        if not isinstance(expected, str) or len(expected.encode("utf-8")) > 256:
            raise HelperError("INVALID_ARGUMENT", "string predicate value is invalid")
        return
    if op in {"lt", "lte", "gt", "gte"}:
        if isinstance(expected, bool) or not isinstance(expected, (int, float, str)):
            raise HelperError("INVALID_ARGUMENT", "ordered predicate value is invalid")
        return
    raise HelperError("INVALID_ARGUMENT", "unsupported predicate operator")


def v2_predicate(namespace: str, node: Any, fields: dict[str, Any]) -> bool:
    v2_validate_predicate(namespace, node)
    op = node.get("op")
    if op in {"and", "or"}:
        values = [v2_predicate(namespace, child, fields) for child in node["args"]]
        return all(values) if op == "and" else any(values)
    if op == "not":
        return not v2_predicate(namespace, node["arg"], fields)
    actual, expected = fields.get(node["field"]), node.get("value")
    if op == "exists":
        return (actual is not None) == node.get("value", True)
    if op == "eq": return actual == expected
    if op == "neq": return actual != expected
    if op == "in": return actual in expected
    if op in {"contains", "starts_with"}:
        if actual is not None and not isinstance(actual, str):
            raise HelperError("INVALID_ARGUMENT", "string predicate used with a non-string field")
        return isinstance(actual, str) and (expected in actual if op == "contains" else actual.startswith(expected))
    if op in {"lt", "lte", "gt", "gte"}:
        try:
            return {"lt": actual < expected, "lte": actual <= expected, "gt": actual > expected, "gte": actual >= expected}[op]
        except TypeError:
            return False
    raise AssertionError("validated predicate operator is unreachable")


def v2_requested_fields(namespace: str, params: dict[str, Any]) -> tuple[str, ...]:
    requested = params.get("fields")
    if requested is None:
        requested = list(V2_IDENTITY_FIELDS[namespace])
    if (not isinstance(requested, list) or not requested or len(requested) > 32
            or any(not isinstance(field, str) or field not in V2_NAMESPACE_FIELDS[namespace]
                   or field in V2_NON_ENUMERABLE_FIELDS.get(namespace, set())
                   or field in V2_UNAVAILABLE_FIELDS.get(namespace, set()) for field in requested)):
        raise HelperError("INVALID_ARGUMENT", "invalid enumerate fields")
    # Identity is always present even when the caller asks for other cheap fields.
    return tuple(dict.fromkeys((*V2_IDENTITY_FIELDS[namespace], *requested)))


def v2_scope_root(params: dict[str, Any]) -> pathlib.Path:
    scope = params.get("scope")
    if not isinstance(scope, dict) or scope.get("namespace") not in {None, "file"}:
        raise HelperError("PERMISSION_DENIED", "file enumerate requires a resolved file Scope Grant")
    root_value = scope.get("canonicalRoot")
    root = safe_path(root_value)
    if str(root) == "/" or str(root) in PSEUDO_FILESYSTEM_ROOTS:
        raise HelperError("PERMISSION_DENIED", "root and pseudo-filesystem scopes are forbidden")
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise HelperError("INVALID_ARGUMENT", "file scope root must be a directory")
    expected_mount = scope.get("mountId")
    if expected_mount is not None and str(info.st_dev) != str(expected_mount):
        raise HelperError("SOURCE_CHANGED", "file scope mount identity changed")
    return root


def v2_file_inventory(params: dict[str, Any], maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    root = v2_scope_root(params)
    ledger = SkipLedger()
    rows: list[dict[str, Any]] = []
    for directory, files in bounded_walk(root, ledger):
        for filename in sorted(files):
            path = directory / filename
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                facts = v2_file_fields(path)
                if params.get("predicate") is None or v2_predicate("file", params.get("predicate"), facts):
                    rows.append(facts)
            except OSError:
                ledger.add(SKIP_UNREADABLE)
            if len(rows) >= maximum:
                ledger.note("文件枚举达到结果上限")
                return rows, ledger.warnings(), True
    return rows, ledger.warnings(), ledger.partial


def v2_web_stack_rows() -> tuple[list[dict[str, Any]], list[str], bool]:
    inventory = inventory_web_stacks({})
    config_paths = inventory.get("configPaths", [])
    rows: list[dict[str, Any]] = []
    for item in inventory.get("items", []):
        command = str(item.get("command", ""))
        lowered = command.lower()
        kind = next((name for name in ("nginx", "apache2", "httpd", "php-fpm", "tomcat", "catalina") if name in lowered), "web")
        pid = item.get("pid")
        instance = hashlib.sha256(f"{kind}\0{pid}\0{command[:4096]}".encode()).hexdigest()
        # 未采集到的字段一律不产出：v2_observation 会把它写成 unavailableFields，
        # enumerate 再转成 FIELD_UNAVAILABLE gap。产出 "unknown" 之类占位值会让
        # 控制端把「没测到」当成「已观察到的值」。
        rows.append({"kind": kind, "instanceId": instance, "pid": pid, "configPaths": config_paths})
    return rows, list(inventory.get("warnings", [])), bool(inventory.get("partial"))


def v2_socket_row(value: dict[str, Any]) -> dict[str, Any]:
    try:
        local_address, local_port = str(value.get("local", "")).rsplit(":", 1)
        remote_address, remote_port = str(value.get("remote", "")).rsplit(":", 1)
        return {"protocol": value.get("protocol"), "localAddress": local_address,
                "localPort": int(local_port), "remoteAddress": remote_address,
                "remotePort": int(remote_port), "state": value.get("state"),
                "inode": value.get("inode"), "pid": value.get("processPid")}
    except (TypeError, ValueError) as exc:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "collector produced an invalid socket endpoint") from exc


def v2_optional_integer(value: Any) -> int | None:
    """Normalize text-backed log fields to Manifest integers without inventing 0."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(str(value), 10)
    except (TypeError, ValueError):
        return None


# Which event namespaces a log source can contain, keyed by `log_source.kind`. journald backs
# all three, so a journald source must be queried against each of them.
LOG_SOURCE_EVENT_KINDS: dict[str, tuple[str, ...]] = {
    JOURNAL_SOURCE: ("log_event", "auth_event", "exec_event"),
    "auth": ("auth_event", "log_event"), "audit": ("exec_event",), "system": ("log_event",),
}


def v2_event_row(namespace: str, value: dict[str, Any]) -> dict[str, Any]:
    """Project one collector event onto its namespace fields.

    Shared by enumerate and relate so the same event yields identical fields and identity on
    both paths; relate used to build its own literal and drifted from the enumerate shape.
    """
    row: dict[str, Any] = {"sourceId": value.get("sourceId"), "cursor": value.get("cursor"),
                           "timestamp": value.get("timestamp")}
    if namespace == "log_event":
        return {**row, "program": value.get("program"), "message": value.get("message"),
                "fields": value.get("fields") or {}}
    if namespace == "auth_event":
        return {**row, "eventType": value.get("eventType", "auth"), "username": value.get("username"),
                "sourceAddress": value.get("sourceAddress"), "program": value.get("program"),
                "success": value.get("success")}
    return {**row, "pid": v2_optional_integer(value.get("pid")), "uid": v2_optional_integer(value.get("uid")),
            "executable": value.get("executable", value.get("exe")),
            "arguments": value.get("arguments"), "cwd": value.get("cwd")}


def v2_query_events(namespace: str, hours: int, maximum: int) -> dict[str, Any]:
    """Run the collector behind one event namespace."""
    request = {"sinceHours": hours, "maxEvents": maximum}
    if namespace == "log_event":
        return query_log_events(request)
    if namespace == "auth_event":
        return query_auth_events(request)
    return query_exec_events(request)


def v2_cron_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    output = list_cron_entries({"maxItems": maximum, "includeUserScope": False})
    rows: list[dict[str, Any]] = []
    for item in output.get("items", []):
        source = str(item.get("path", ""))
        line = int(item.get("line", 0))
        schedule = str(item.get("schedule", ""))
        command = str(item.get("commandSummary", ""))
        digest = hashlib.sha256(f"{source}\0{line}\0{schedule}\0{command}".encode()).hexdigest()
        rows.append({"source": source, "line": line, "digest": digest, "schedule": schedule,
                     "user": str(item.get("username") or "root"), "command": command})
    return rows, list(output.get("warnings", [])), bool(output.get("partial"))


def v2_ssh_key_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for account in interactive_accounts():
        path = pathlib.Path(account.pw_dir) / ".ssh/authorized_keys"
        try:
            for key in inspect_authorized_keys({"username": account.pw_name}):
                rows.append({"fingerprint": key.get("fingerprint"), "ownerUid": account.pw_uid,
                             "type": key.get("type"), "comment": key.get("comment", ""),
                             "sourceFile": str(path)})
                if len(rows) >= maximum:
                    return rows, warnings + ["SSH Key 结果达到配置上限"], True
        except (OSError, KeyError, PermissionError):
            warnings.append(f"无法读取账户 {account.pw_name} 的 authorized_keys")
    return rows, warnings[:200], bool(warnings)


def v2_unit_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    output = list_systemd_units({"maxItems": maximum, "includeUserScope": False})
    active_names: set[str] | None = None
    if shutil.which("systemctl"):
        runtime = run(["systemctl", "list-units", "--all", "--no-legend", "--plain"], check=False)
        if runtime.returncode == 0:
            active_names = {parts[0] for line in runtime.stdout.splitlines()
                            if len(parts := line.split()) >= 4 and parts[2] == "active"}
    rows: list[dict[str, Any]] = []
    for item in output.get("items", []):
        path = str(item.get("path", ""))
        exec_start = item.get("execStart", [])
        name = str(item.get("unit", pathlib.Path(path).name))
        row = {"name": name,
                     "fragmentDigest": str(item.get("sha256", "")), "path": path,
                     "enabled": bool(item.get("enabled")),
                     "execStart": "\n".join(str(value) for value in exec_start) if isinstance(exec_start, list) else str(exec_start),
                     "user": str(item.get("runAs", "root"))}
        if active_names is not None:
            row["active"] = name in active_names
        rows.append(row)
    return rows, list(output.get("warnings", [])), bool(output.get("partial"))


def v2_persistence_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    partial = False
    for collector in (list_extended_persistence, list_shell_startup_files):
        remaining = max(1, maximum - len(rows))
        output = collector({"maxItems": remaining, "includeUserScope": False})
        warnings.extend(output.get("warnings", []))
        partial = partial or bool(output.get("partial"))
        for item in output.get("items", []):
            source = str(item.get("path", ""))
            kind = str(item.get("persistenceType", item.get("kind", "extended")))
            source_digest = hashlib.sha256(f"{kind}\0{source}\0{item.get('sha256', '')}".encode()).hexdigest()
            commands = item.get("commandSummaries", [])
            # user/enabled 需要解析 Unit/启动项的真实归属与启用状态，当前采集器不产出，
            # 因此留空并由 unavailableFields 表达，而不是恒定写 root/True。
            rows.append({"kind": kind, "sourceDigest": source_digest, "source": source,
                         "command": "\n".join(str(value) for value in commands)})
            if len(rows) >= maximum:
                return rows, warnings + ["持久化结果达到配置上限"], True
    return rows, warnings[:200], partial


def v2_module_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    source = pathlib.Path("/proc/modules")
    if not source.is_file():
        return [], ["/proc/modules 不可用"], True
    rows: list[dict[str, Any]] = []
    try:
        for line in source.read_text(errors="replace").splitlines()[:maximum]:
            fields = line.split()
            if len(fields) < 6:
                continue
            rows.append({"name": fields[0], "size": int(fields[1]), "address": fields[5], "path": f"/sys/module/{fields[0]}"})
    except (OSError, ValueError) as exc:
        return rows, [f"内核模块清单读取不完整: {exc}"], True
    return rows, [], len(rows) >= maximum


def v2_journal_source_row() -> dict[str, Any] | None:
    """The journal as a first-class `log_source`.

    journald is the source of a large share of log/auth/exec events, but it used to be absent
    from this list, so every journald event carried a `sourceId` that no `log_source` object
    could resolve and `relate log_source contains` could never reach it.
    """
    if journal_binary() is None:
        return None
    storage = journal_storage_path()
    if storage is None:
        return None
    generation = journal_generation()
    if generation is None:
        return None
    return {"sourceId": log_source_id(JOURNAL_SOURCE), "generation": generation,
            "kind": JOURNAL_SOURCE, "path": str(storage)}


def v2_log_source_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    paths = sorted({path for pattern in (*SYSTEM_LOG_PATTERNS, *AUTH_LOG_PATTERNS, *AUDIT_LOG_PATTERNS, *WEB_ACCESS_LOG_PATTERNS) for path in glob.glob(pattern)})
    rows: list[dict[str, Any]] = []; warnings: list[str] = []
    # An absent journal store is not a collection defect: the source simply does not exist on
    # this host. Reporting it as a warning would mark every non-systemd target PARTIAL.
    journal = v2_journal_source_row()
    if journal is not None:
        rows.append(journal)
    for raw in paths:
        try:
            path = pathlib.Path(raw)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                continue
            kind = "audit" if "/audit/" in raw else "web_access" if "access" in path.name else "auth" if path.name.startswith(("auth", "secure")) else "system"
            source = log_source_key(path)
            generation = hashlib.sha256(f"{info.st_dev}:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}".encode()).hexdigest()
            rows.append({"sourceId": log_source_id(source), "generation": generation, "kind": kind, "path": source})
            if len(rows) >= maximum:
                return rows, warnings + ["日志源清单达到结果上限"], True
        except OSError as exc:
            warnings.append(f"日志源不可读: {raw}: {exc}")
    return rows, warnings[:200], bool(warnings)


def v2_regular_files(fixed: tuple[str, ...], directories: tuple[tuple[str, tuple[str, ...]], ...]) -> list[pathlib.Path]:
    candidates = [pathlib.Path(value) for value in fixed]
    for raw_directory, suffixes in directories:
        directory = pathlib.Path(raw_directory)
        try:
            for child in directory.iterdir():
                if child.name.startswith(".") or child.name.endswith(("~", ".bak", ".disabled")):
                    continue
                try:
                    child_info = child.lstat()
                except OSError:
                    candidates.append(child)
                    continue
                if stat.S_ISDIR(child_info.st_mode) and not child.is_symlink():
                    try:
                        candidates.extend(grandchild for grandchild in child.iterdir()
                                          if not grandchild.name.startswith(".")
                                          and not grandchild.name.endswith(("~", ".bak", ".disabled"))
                                          and (not suffixes or grandchild.suffix in suffixes))
                    except OSError:
                        continue
                    continue
                if suffixes and child.suffix not in suffixes:
                    continue
                candidates.append(child)
        except FileNotFoundError:
            continue
        except OSError:
            # The collector will surface unreadable configured facilities below when a
            # concrete file is opened. Optional directories that do not exist are not gaps.
            continue
    values: list[pathlib.Path] = []
    for path in sorted(set(candidates), key=str):
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and not path.is_symlink():
                values.append(path)
        except FileNotFoundError:
            continue
        except OSError:
            values.append(path)
    return values


def v2_delegation_config_paths() -> list[pathlib.Path]:
    return v2_regular_files(
        ("/etc/sudoers", "/etc/doas.conf"),
        (("/etc/sudoers.d", ()),
         ("/etc/polkit-1/rules.d", (".rules",)),
         ("/usr/share/polkit-1/rules.d", (".rules",)),
         ("/etc/polkit-1/localauthority", (".pkla",)),
         ("/var/lib/polkit-1/localauthority", (".pkla",))),
    )


def v2_ssh_config_paths() -> list[pathlib.Path]:
    return v2_regular_files(("/etc/ssh/sshd_config",), (("/etc/ssh/sshd_config.d", (".conf",)),))


def v2_bounded_config_lines(path: pathlib.Path) -> tuple[list[tuple[int, str]], str | None]:
    try:
        descriptor, canonical = v2_open_regular(str(path))
    except HelperError as exc:
        return [], f"配置不可读: {path}: {exc}"
    try:
        info = os.fstat(descriptor)
        if info.st_size > 512 * 1024:
            return [], f"配置超过 512 KiB 上限: {canonical}"
        duplicate = os.dup(descriptor)
        with os.fdopen(duplicate, "r", encoding="utf-8", errors="replace", closefd=True) as handle:
            return [(number, line.rstrip("\r\n")) for number, line in enumerate(handle, 1)], None
    except OSError as exc:
        return [], f"配置读取失败: {path}: {exc}"
    finally:
        os.close(descriptor)


def v2_delegation_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in v2_delegation_config_paths():
        lines, warning = v2_bounded_config_lines(path)
        if warning is not None:
            warnings.append(warning)
            continue
        source = str(path)
        mechanism = "sudo" if source == "/etc/sudoers" or source.startswith("/etc/sudoers.d/") else "doas" if source == "/etc/doas.conf" else "polkit"
        source_digest = hashlib.sha256(source.encode()).hexdigest()
        for number, raw in lines:
            statement = raw.strip()
            if not statement or statement.startswith("#"):
                continue
            if len(statement.encode("utf-8")) > 8192:
                warnings.append(f"委派规则行超过 8 KiB，已跳过: {source}:{number}")
                continue
            effect, subject, run_as = "policy", "policy", "unspecified"
            tokens = statement.split()
            if mechanism == "sudo":
                if tokens and not tokens[0].lower().startswith(("defaults", "user_alias", "runas_alias", "host_alias", "cmnd_alias", "@include", "#include")):
                    subject = tokens[0]
                match = re.search(r"\(([^)]{1,256})\)", statement)
                if match is not None:
                    run_as = match.group(1).strip()
            elif mechanism == "doas":
                if tokens and tokens[0].lower() in {"permit", "deny"}:
                    effect = tokens[0].lower()
                    for token in tokens[1:]:
                        if token.lower() not in {"nopass", "nolog", "persist", "keepenv"} and not token.startswith(("setenv", "{")):
                            subject = token
                            break
                    if "as" in tokens:
                        index = tokens.index("as")
                        if index + 1 < len(tokens):
                            run_as = tokens[index + 1]
            else:
                subject, run_as = "dynamic", "dynamic"
            rows.append({"mechanism": mechanism, "sourceDigest": source_digest, "line": number,
                         "ruleDigest": hashlib.sha256(statement.encode()).hexdigest(), "source": source,
                         "effect": effect, "subject": subject, "runAs": run_as, "statement": statement})
            if len(rows) >= maximum:
                return rows, warnings + ["委派规则达到结果上限"], True
    return rows, warnings[:200], bool(warnings)


V2_SSH_TRUST_DIRECTIVES = frozenset({
    "authorizedkeysfile", "authorizedkeyscommand", "authorizedkeyscommanduser", "trustedusercakeys",
    "authorizedprincipalsfile", "permitrootlogin", "pubkeyauthentication", "passwordauthentication",
    "kbdinteractiveauthentication", "authenticationmethods", "allowusers", "allowgroups", "denyusers", "denygroups",
})


def v2_ssh_trust_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    binary = shutil.which("sshd")
    if binary is None:
        return [], [], False
    output = run([binary, "-T"], timeout=20, check=False)
    if output.returncode != 0:
        detail = output.stderr.strip() or f"sshd -T 返回状态 {output.returncode}"
        return [], [detail[:4096]], True
    rows: list[dict[str, Any]] = []
    for raw in output.stdout.splitlines():
        key, separator, value = raw.strip().partition(" ")
        directive = key.lower()
        value = value.strip()
        if not separator or directive not in V2_SSH_TRUST_DIRECTIVES:
            continue
        rows.append({"scope": "default", "directive": directive,
                     "valueDigest": hashlib.sha256(value.encode()).hexdigest(), "value": value,
                     "source": "sshd -T", "effective": True})
        if len(rows) >= maximum:
            return rows, ["sshd 有效信任配置达到结果上限"], True
    return rows, [], False


def v2_package_rows(maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    rows: list[dict[str, Any]] = []
    if shutil.which("dpkg-query"):
        result = run(["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n"], check=False)
        for line in result.stdout.splitlines()[:maximum]:
            parts = line.split("\t")
            if len(parts) == 3:
                rows.append({"manager": "dpkg", "name": parts[0], "version": parts[1], "architecture": parts[2]})
        return rows, ([] if result.returncode == 0 else ["dpkg-query 返回非零状态"]), result.returncode != 0 or len(result.stdout.splitlines()) > maximum
    if shutil.which("rpm"):
        result = run(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"], check=False)
        for line in result.stdout.splitlines()[:maximum]:
            parts = line.split("\t")
            if len(parts) == 3:
                rows.append({"manager": "rpm", "name": parts[0], "version": parts[1], "architecture": parts[2]})
        return rows, ([] if result.returncode == 0 else ["rpm 返回非零状态"]), result.returncode != 0 or len(result.stdout.splitlines()) > maximum
    return [], ["未发现受支持的 dpkg/rpm 软件包数据库"], True


def v2_enumerate(params: dict[str, Any], epoch_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None, list[dict[str, Any]]]:
    namespace = params.get("namespace")
    if namespace == "task_ioc":
        raise HelperError("INVALID_ARGUMENT", "task_ioc is controller-local")
    if namespace not in V2_ENUMERABLE_NAMESPACES:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "namespace unavailable")
    requested_fields = v2_requested_fields(str(namespace), params)
    limit = safe_int(params.get("limit"), 1, 500, "limit")
    predicate = params.get("predicate")
    if predicate is not None:
        # Validate controller input before reading any target data. Otherwise an environment
        # collector failure can mask an invalid Predicate as INTERNAL_ERROR, and an empty data
        # source can accidentally accept malformed input without evaluating it at all.
        v2_validate_predicate(str(namespace), predicate)
    tolerate_cursor_drift = namespace in {"log_source", "log_event", "auth_event", "exec_event"}
    offset, cursor_binding, source_generation, cursor_source_changed = v2_cursor_start(
        str(namespace), params, epoch_id, tolerate_cursor_drift)
    rows: list[dict[str, Any]] = []
    partial = False
    warnings: list[str] = []
    if namespace == "host":
        info = get_host_info({})
        rows = [{"bootId": boot_id(), "hostname": info.get("hostname", platform.node()), "os": info.get("system", platform.system()),
                 "release": info.get("release", platform.release()), "architecture": info.get("machine", platform.machine()),
                 "timezone": host_timezone()[0], "observedAt": utc_iso(now_utc())}]
    elif namespace == "process":
        values, warnings, partial = enumerate_stable_processes(min(5000, offset + limit + 1))
        rows = [{**value, "exe": value.get("exePath"), "command": value.get("command", value.get("comm"))} for value in values]
    elif namespace == "socket":
        values, warnings, partial = read_global_connections(min(20000, offset + limit + 1))
        rows = [v2_socket_row(value) for value in values]
    elif namespace == "account":
        needs_account_details = bool({"groups", "locked"}.intersection(requested_fields))
        for value in pwd.getpwall():
            row = {"uid": value.pw_uid, "username": value.pw_name, "gid": value.pw_gid, "home": value.pw_dir,
                   "shell": value.pw_shell}
            if needs_account_details:
                try:
                    inspected = inspect_account({"username": value.pw_name})
                    if "groups" in requested_fields:
                        row["groups"] = inspected.get("groups", [])
                    if "locked" in requested_fields:
                        row["locked"] = bool(inspected.get("passwordLocked"))
                except (HelperError, OSError) as exc:
                    warnings.append(f"账户 {value.pw_name}: {str(exc)}")
                    partial = True
            rows.append(row)
    elif namespace == "ssh_key":
        rows, warnings, partial = v2_ssh_key_rows(min(5000, offset + limit + 1))
    elif namespace == "delegation_rule":
        rows, warnings, partial = v2_delegation_rows(min(5000, offset + limit + 1))
    elif namespace == "ssh_trust_config":
        rows, warnings, partial = v2_ssh_trust_rows(min(5000, offset + limit + 1))
    elif namespace == "file":
        rows, warnings, partial = v2_file_inventory(params, min(5000, offset + limit + 1))
    elif namespace == "web_stack":
        rows, warnings, partial = v2_web_stack_rows()
    elif namespace == "web_root":
        rows, warnings, partial = v2_web_root_rows()
    elif namespace == "jvm":
        for value in list_java_processes({}):
            try:
                stable = stable_process(int(value["pid"]))
                container = detect_java_container({"pid": value["pid"]})
                rows.append({"bootId": stable["bootId"], "pid": stable["pid"], "startTicks": stable["startTicks"],
                             "command": container.get("command", ""), "attachSupported": PROBE_JAR.is_file(),
                             "container": container.get("container", "unknown")})
            except (HelperError, KeyError, ValueError):
                partial = True
    elif namespace == "cron_entry":
        rows, warnings, partial = v2_cron_rows(min(5000, offset + limit + 1))
    elif namespace == "unit":
        rows, warnings, partial = v2_unit_rows(min(5000, offset + limit + 1))
    elif namespace == "persistence":
        rows, warnings, partial = v2_persistence_rows(min(5000, offset + limit + 1))
    elif namespace == "module":
        rows, warnings, partial = v2_module_rows(min(5000, offset + limit + 1))
    elif namespace == "log_source":
        rows, warnings, partial = v2_log_source_rows(min(5000, offset + limit + 1))
    elif namespace == "package":
        rows, warnings, partial = v2_package_rows(min(5000, offset + limit + 1))
    elif namespace in {"log_event", "auth_event", "exec_event"}:
        hours = safe_int(params.get("sinceHours", 24), 1, 24 * 365, "sinceHours")
        output = v2_query_events(str(namespace), hours, min(5000, offset + limit + 1))
        # sourceId/cursor come from the collector, which derives both from the real originating
        # source. auth_event/exec_event used to get a hardcoded "auth"/"exec" string plus the
        # page-local array index, so no event could be joined back to its log_source and the
        # same event changed identity between calls.
        rows.extend(v2_event_row(str(namespace), value) for value in output.get("items", []))
        partial, warnings = bool(output.get("partial")), list(output.get("warnings", []))
    else:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"collector not available for namespace {namespace}")
    if predicate is not None:
        rows = [row for row in rows if v2_predicate(str(namespace), predicate, row)]
    # 稳定身份是隐式末位排序键（设计 §5.4）：先按身份排序，再用稳定排序施加调用方排序键，
    # 同值行在分页之间才不会互换位置，offset 游标才有意义。
    identity_names = V2_IDENTITY_FIELDS[str(namespace)]
    rows.sort(key=lambda row: tuple(str(row.get(name, "")) for name in identity_names))
    sort_values = params.get("sort", [])
    if not isinstance(sort_values, list) or len(sort_values) > 3:
        raise HelperError("INVALID_ARGUMENT", "invalid sort")
    for sort_value in reversed(sort_values):
        if (not isinstance(sort_value, dict) or sort_value.get("field") not in V2_NAMESPACE_FIELDS[str(namespace)]
                or sort_value.get("field") in V2_NON_SORTABLE_FIELDS
                or sort_value.get("direction") not in {"asc", "desc"}):
            raise HelperError("INVALID_ARGUMENT", "invalid sort")
        field = str(sort_value["field"])
        rows.sort(key=lambda row: (row.get(field) is None, str(row.get(field, ""))), reverse=sort_value["direction"] == "desc")
    window = rows[offset:offset + limit]
    more = offset + limit < len(rows)
    projected_rows = [{field: row[field] for field in requested_fields if field in row} for row in window]
    objects = [v2_observation(str(namespace), row, "CURSOR_BEST_EFFORT", requested_fields) for row in projected_rows]
    gaps = []
    missing_fields = sorted({item["field"] for observation in objects for item in observation.get("unavailableFields", [])})
    for field in missing_fields:
        gaps.append({"code": "FIELD_UNAVAILABLE", "field": field, "detail": "collector did not produce the requested field", "resumable": False})
    if partial: gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
    if more: gaps.append({"code": "NODE_LIMIT", "detail": "enumerate limit reached", "resumable": True})
    # 源在分页期间变化时不能丢弃整页：设计 §5.2 要求存在可用部分数据就返回 PARTIAL + gap
    # + cursor，游标改用当前源代，调用方才能继续；只有一条都没产出时才是纯错误。
    current_generation = v2_source_generation(str(namespace), params)
    if cursor_source_changed or current_generation != source_generation:
        if not objects:
            raise HelperError("SOURCE_CHANGED", "enumerate source changed before any object was produced")
        gaps.append({"code": "SOURCE_CHANGED", "detail": "分页期间数据源发生变化，本页为 CURSOR_BEST_EFFORT 结果", "resumable": True})
    next_cursor = v2_encode_cursor(str(namespace), offset + len(window), cursor_binding, current_generation) if more else None
    return objects, [], next_cursor, gaps


def v2_ref_params(params: dict[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any]]:
    namespace, identity, locator = params.get("namespace"), params.get("identity"), params.get("locator", {})
    if namespace not in V2_NAMESPACE_FIELDS or not isinstance(identity, dict) or not isinstance(locator, dict):
        raise HelperError("INVALID_ARGUMENT", "invalid object reference binding")
    return str(namespace), identity, locator


def v2_project(params: dict[str, Any]) -> list[dict[str, Any]]:
    namespace, identity, locator = v2_ref_params(params)
    fields = params.get("fields")
    if not isinstance(fields, list) or not fields or any(field not in V2_NAMESPACE_FIELDS[namespace] for field in fields):
        raise HelperError("INVALID_ARGUMENT", "invalid projection fields")
    if namespace == "process":
        current = process_request({**identity, **locator})
        current = {**current, "exe": current.get("exePath"), "command": current.get("command", current.get("comm"))}
    elif namespace == "file":
        descriptor, current = v2_bound_file(params, "sha256" in fields)
        os.close(descriptor)
    elif namespace == "account":
        current = inspect_account({"username": identity.get("username")})
        current = {**current, "locked": current.get("passwordLocked")}
        if current.get("uid") != identity.get("uid"):
            raise HelperError("EVIDENCE_COLLECTION", "stable account identity changed")
    else:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", f"project unavailable for {namespace}")
    selected = {name: current.get(name) for name in fields if name in current}
    selected.update(identity)
    return [v2_observation(namespace, selected)]


def v2_edge(from_namespace: str, from_fields: dict[str, Any], relation: str,
            to_namespace: str, to_fields: dict[str, Any]) -> dict[str, Any]:
    return {"relation": relation,
            "fromIdentity": {"namespace": from_namespace, "identity": v2_identity(from_namespace, from_fields)},
            "toIdentity": {"namespace": to_namespace, "identity": v2_identity(to_namespace, to_fields)},
            "observedAt": utc_iso(now_utc())}


def v2_find_identity_row(namespace: str, identity: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    for row in rows:
        try:
            if v2_identity(namespace, row) == identity:
                return row
        except HelperError:
            continue
    raise HelperError("STALE_REF", f"{namespace} object no longer exists")


def v2_related_command_files(command: str, maximum: int = 500) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    candidates = [match.group(1).rstrip(".,:)")
                  for match in re.finditer(r"(?<![A-Za-z0-9_])(/[A-Za-z0-9_./+@:-]{1,4095})", command)]
    # Persistence sources frequently invoke a command through PATH (for example
    # ``run-parts``). Resolve only each shell segment's command position; never
    # execute the source command or treat arbitrary argument tokens as programs.
    for segment in re.split(r"(?:&&|\|\||[;|])", command):
        try:
            tokens = shlex.split(segment.strip().lstrip("("), comments=False, posix=True)
        except ValueError:
            continue
        tokens = [token for token in tokens if token and token not in {"(", ")", "!"}]
        while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens.pop(0)
        if tokens and tokens[0] == "env":
            tokens.pop(0)
            while tokens and (tokens[0].startswith("-") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0])):
                tokens.pop(0)
        if tokens and not tokens[0].startswith(("/", "-")):
            resolved = shutil.which(tokens[0])
            if resolved:
                candidates.append(resolved)
    for raw in candidates:
        try:
            facts = v2_file_fields(safe_path(raw))
        except (HelperError, OSError):
            continue
        key = (str(facts["device"]), str(facts["inode"]))
        if key in seen:
            continue
        seen.add(key)
        rows.append(facts)
        if len(rows) >= maximum:
            break
    return rows


def v2_web_root_rows() -> tuple[list[dict[str, Any]], list[str], bool]:
    inventory, warnings = web_root_inventory()
    rows: list[dict[str, Any]] = []
    for value in inventory:
        try:
            path = safe_path(value.get("path"))
            info = path.stat()
            if not stat.S_ISDIR(info.st_mode):
                continue
            # effective 只有来自运行时生效配置（nginx -T）时才成立；静态配置解析与固定
            # 兜底目录无法证明该 root 正在生效，此时不产出该字段。
            row = {"mountId": str(info.st_dev), "device": str(info.st_dev), "inode": str(info.st_ino),
                   "path": str(path.resolve())}
            if isinstance(value.get("server"), str):
                row["server"] = value["server"]
            if value.get("configSource") == "nginx -T":
                row["effective"] = True
            rows.append(row)
        except (HelperError, OSError):
            warnings.append(f"Web Root 已变化或不可读: {value.get('path')}")
    return rows, warnings[:200], bool(warnings)


def v2_web_request_rows(path: str, maximum: int) -> tuple[list[dict[str, Any]], list[str], bool]:
    output = search_web_access_log({"path": path, "fileName": pathlib.Path(path).name, "maxLines": maximum})
    rows: list[dict[str, Any]] = []
    for item in output.get("items", []):
        source = str(item.get("log", "web-access"))
        message = redact_secret_text(str(item.get("line", "")), 8192)
        rows.append({
            "sourceId": hashlib.sha256(source.encode()).hexdigest(),
            "cursor": hashlib.sha256(f"{source}\0{message}".encode()).hexdigest(),
            "program": "web_access", "message": message, "fields": {},
        })
    return rows, list(output.get("warnings", [])), bool(output.get("partial"))


def v2_relate(params: dict[str, Any], epoch_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None, list[dict[str, Any]]]:
    namespace, identity, locator = v2_ref_params(params)
    relation = params.get("relation")
    if relation not in V2_RELATIONS.get(namespace, ()):
        raise HelperError("INVALID_ARGUMENT", "relation is not available for this namespace")
    limit = safe_int(params.get("limit"), 1, 500, "limit")
    tolerate_cursor_drift = namespace == "log_source" and relation == "contains"
    offset, cursor_binding, source_generation, cursor_source_changed = v2_cursor_start(
        namespace, params, epoch_id, tolerate_cursor_drift)
    rows: list[tuple[str, dict[str, Any]]] = []
    gaps: list[dict[str, Any]] = []
    current: dict[str, Any]
    if namespace == "process":
        current = process_request({**identity, **locator})
        current = {**current, "exe": current.get("exePath"), "command": current.get("command", current.get("comm"))}
        if relation == "parent":
            parent_pid = current.get("ppid")
            if isinstance(parent_pid, int) and parent_pid > 0:
                try:
                    parent = stable_process(parent_pid)
                    rows.append(("process", {**parent, "exe": parent.get("exePath"), "command": parent.get("command", parent.get("comm"))}))
                except HelperError as exc:
                    gaps.append({"code": "SOURCE_CHANGED", "detail": str(exc), "resumable": False})
        elif relation == "children":
            values, warnings, partial = enumerate_stable_processes(5000)
            rows = [("process", {**value, "exe": value.get("exePath"), "command": value.get("command", value.get("comm"))})
                    for value in values if value.get("ppid") == current.get("pid")]
            if partial:
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
        elif relation == "connects":
            output = list_process_connections({**identity, "maxConnections": 20000})
            rows = [("socket", v2_socket_row(value)) for value in output.get("items", [])]
            if output.get("partial"):
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(output.get("warnings", [])[:20]), "resumable": False})
        elif relation == "opens":
            output = inspect_process_fds({**identity, "maxItems": 5000})
            for value in output.get("items", []):
                if value.get("type") != "file":
                    continue
                raw = str(value.get("target", "")).removesuffix(" (deleted)")
                try:
                    path = safe_path(raw)
                    rows.append(("file", v2_file_fields(path)))
                except (HelperError, OSError):
                    continue
            if output.get("partial"):
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(output.get("warnings", [])[:20]), "resumable": False})
    elif namespace == "socket" and relation == "owned_by":
        current = dict(identity)
        processes, warnings, partial = enumerate_stable_processes(5000)
        for process in processes:
            try:
                for descriptor in pathlib.Path(f"/proc/{process['pid']}/fd").iterdir():
                    match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(descriptor))
                    if match and match.group(1) == str(identity.get("inode")):
                        rows.append(("process", {**process, "exe": process.get("exePath"), "command": process.get("command", process.get("comm"))}))
                        break
            except OSError:
                continue
        if partial:
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
    elif namespace == "file":
        descriptor, current = v2_bound_file(params)
        os.close(descriptor)
        if relation == "opened_by":
            processes, warnings, partial = enumerate_stable_processes(5000)
            for process in processes:
                try:
                    for entry in pathlib.Path(f"/proc/{process['pid']}/fd").iterdir():
                        info = entry.stat()
                        if str(info.st_dev) == str(identity.get("device")) and str(info.st_ino) == str(identity.get("inode")):
                            rows.append(("process", {**process, "exe": process.get("exePath"), "command": process.get("command", process.get("comm"))}))
                            break
                except OSError:
                    continue
            if partial:
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
        elif relation == "referenced_by_persistence":
            related: list[tuple[str, list[dict[str, Any]], list[str], bool]] = []
            cron, cron_warnings, cron_partial = v2_cron_rows(5000)
            units, unit_warnings, unit_partial = v2_unit_rows(5000)
            persistence, persistence_warnings, persistence_partial = v2_persistence_rows(5000)
            related.extend((("cron_entry", cron, cron_warnings, cron_partial),
                            ("unit", units, unit_warnings, unit_partial),
                            ("persistence", persistence, persistence_warnings, persistence_partial)))
            for target_namespace, candidates, warnings, partial in related:
                rows.extend((target_namespace, candidate) for candidate in candidates
                            if str(current.get("path")) in str(candidate.get("command", "")))
                if partial:
                    gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
        elif relation == "requested_in":
            request_rows, warnings, partial = v2_web_request_rows(str(current.get("path")), 5000)
            rows = [("log_event", row) for row in request_rows]
            if partial:
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
    elif namespace == "account":
        account = inspect_account({"username": identity.get("username")})
        current = {**account, "locked": account.get("passwordLocked")}
        if current.get("uid") != identity.get("uid"):
            raise HelperError("STALE_REF", "stable account identity changed")
        if relation == "authorized_key":
            keys, warnings, partial = v2_ssh_key_rows(5000)
            rows = [("ssh_key", key) for key in keys if key.get("ownerUid") == identity.get("uid")]
            if partial:
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
        elif relation == "login_event":
            output = v2_query_events("auth_event", 24 * 365, 5000)
            rows.extend(("auth_event", v2_event_row("auth_event", value)) for value in output.get("items", [])
                        if value.get("username") == identity.get("username"))
            if output.get("partial"):
                gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(output.get("warnings", [])[:20]), "resumable": False})
    elif namespace == "ssh_key" and relation == "owned_by":
        keys, warnings, partial = v2_ssh_key_rows(5000)
        current = v2_find_identity_row("ssh_key", identity, keys)
        source_file = pathlib.Path(str(current.get("sourceFile", "")))
        owner_uid = identity.get("ownerUid")
        # UID is not globally unique on a misconfigured or compromised host.
        # Bind the owner through the authorized_keys path first, then confirm UID.
        account_entries = [entry for entry in pwd.getpwall()
                           if entry.pw_uid == owner_uid
                           and source_file == pathlib.Path(entry.pw_dir) / ".ssh/authorized_keys"]
        if account_entries:
            rows = []
            for account_entry in account_entries:
                account = inspect_account({"username": account_entry.pw_name})
                rows.append(("account", {**account, "locked": account.get("passwordLocked")}))
        else:
            gaps.append({"code": "SOURCE_CHANGED", "detail": "SSH Key owner account no longer exists", "resumable": False})
        if partial:
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
    elif namespace in {"cron_entry", "unit", "persistence"} and relation == "executes":
        if namespace == "cron_entry":
            candidates, warnings, partial = v2_cron_rows(5000)
        elif namespace == "unit":
            candidates, warnings, partial = v2_unit_rows(5000)
        else:
            candidates, warnings, partial = v2_persistence_rows(5000)
        current = v2_find_identity_row(namespace, identity, candidates)
        rows = [("file", row) for row in v2_related_command_files(str(current.get("command") or current.get("execStart") or ""), 5000)]
        if partial:
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(warnings[:20]), "resumable": False})
    elif namespace == "log_source" and relation == "contains":
        sources, warnings, partial = v2_log_source_rows(5000)
        # generation belongs to the versioned source identity, but invoking the Helper through
        # sudo can itself append a journald record before this process starts. An exact
        # (sourceId, generation) lookup therefore makes `enumerate log_source` -> `relate`
        # impossible on a healthy, actively logging system. Resolve the logical source by its
        # stable sourceId, retain the caller's generation on the emitted edge, and surface the
        # version drift explicitly instead of silently treating it as the same snapshot.
        source_id, requested_generation = identity.get("sourceId"), identity.get("generation")
        if not isinstance(source_id, str) or not isinstance(requested_generation, str):
            raise HelperError("INVALID_ARGUMENT", "log_source relation requires sourceId and generation")
        observed_source = next((source for source in sources if source.get("sourceId") == source_id), None)
        if observed_source is None:
            raise HelperError("STALE_REF", "log_source object no longer exists")
        if locator.get("path") is not None and locator.get("path") != observed_source.get("path"):
            raise HelperError("STALE_REF", "log_source path no longer matches the bound source")
        if observed_source.get("generation") != requested_generation:
            gaps.append({"code": "SOURCE_CHANGED",
                         "detail": "日志源 generation 已推进；关系按当前源内容执行并绑定原请求引用",
                         "resumable": False})
        current = {**observed_source, "generation": requested_generation}
        # A source contains whichever event namespaces its kind actually produces. Querying only
        # log_event used to return an empty relation for every auth and exec event, and for the
        # journal it returned nothing at all because journald was not even a listed source.
        wanted = LOG_SOURCE_EVENT_KINDS.get(str(observed_source.get("kind")), ())
        if not wanted:
            gaps.append({"code": "CAPABILITY_UNAVAILABLE",
                         "detail": f"日志源类型 {observed_source.get('kind')} 不产生 log_event/auth_event/exec_event 事实",
                         "resumable": False})
        combined = list(warnings)
        for target in wanted:
            output = v2_query_events(target, 24 * 365, 5000)
            rows.extend((target, v2_event_row(target, value)) for value in output.get("items", [])
                        if value.get("sourceId") == identity.get("sourceId"))
            combined.extend(output.get("warnings", []))
            partial = partial or bool(output.get("partial"))
        if partial:
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(combined[:20]), "resumable": False})
    elif namespace == "package" and relation == "owns_file":
        packages, warnings, partial = v2_package_rows(5000)
        current = v2_find_identity_row("package", identity, packages)
        manager, name = str(current.get("manager")), str(current.get("name"))
        if manager == "dpkg" and shutil.which("dpkg-query"):
            output = run(["dpkg-query", "-L", name], check=False)
        elif manager == "rpm" and shutil.which("rpm"):
            output = run(["rpm", "-ql", name], check=False)
        else:
            raise HelperError("UNSUPPORTED_ENVIRONMENT", "package file ownership query is unavailable")
        for raw in output.stdout.splitlines():
            if not raw.startswith("/"):
                continue
            try:
                path = safe_path(raw)
                info = path.stat()
                if stat.S_ISREG(info.st_mode) and not path.is_symlink():
                    rows.append(("file", v2_file_fields(path)))
            except (HelperError, OSError):
                continue
        if partial or output.returncode != 0:
            detail = [*warnings, f"{manager} 文件清单返回状态 {output.returncode}"]
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join(detail[:20]), "resumable": False})
    elif namespace in {"web_stack", "web_root"}:
        stacks, stack_warnings, stack_partial = v2_web_stack_rows()
        roots, root_warnings, root_partial = v2_web_root_rows()
        if namespace == "web_stack" and relation == "serves_root":
            current = v2_find_identity_row("web_stack", identity, stacks)
            kind = str(current.get("kind", "")).lower()
            rows = [("web_root", root) for root in roots
                    if kind in str(root.get("server", "")).lower() or str(root.get("server", "")).lower() in kind]
        elif namespace == "web_root" and relation == "served_by":
            current = v2_find_identity_row("web_root", identity, roots)
            server = str(current.get("server", "")).lower()
            rows = [("web_stack", stack) for stack in stacks
                    if server in str(stack.get("kind", "")).lower() or str(stack.get("kind", "")).lower() in server]
        if stack_partial or root_partial:
            gaps.append({"code": "COLLECTOR_ERROR", "detail": "; ".join([*stack_warnings, *root_warnings][:20]), "resumable": False})
    else:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "remote relation collector is unavailable")
    rows.sort(key=lambda item: (item[0], tuple(str(item[1].get(name, "")) for name in V2_IDENTITY_FIELDS.get(item[0], ()))))
    window = rows[offset:offset + limit]
    more = offset + limit < len(rows)
    current_generation = v2_source_generation(namespace, params)
    changed = cursor_source_changed or current_generation != source_generation
    consistency = "CURSOR_BEST_EFFORT" if changed else "POINT_IN_TIME"
    objects = [v2_observation(target_namespace, fields, consistency) for target_namespace, fields in window]
    edges = [v2_edge(namespace, current, str(relation), target_namespace, fields) for target_namespace, fields in window]
    if more:
        gaps.append({"code": "NODE_LIMIT", "detail": "relate limit reached", "resumable": True})
    if changed:
        if not objects:
            raise HelperError("SOURCE_CHANGED", "relation source changed before any object was produced")
        gaps.append({"code": "SOURCE_CHANGED", "detail": "分页期间关系数据源发生变化，本页为 CURSOR_BEST_EFFORT 结果", "resumable": True})
    next_cursor = v2_encode_cursor(namespace, offset + len(window), cursor_binding, current_generation) if more else None
    return objects, edges, next_cursor, gaps


def v2_read(params: dict[str, Any]) -> list[dict[str, Any]]:
    descriptor, facts = v2_bound_file(params)
    try:
        if facts["contentClass"] == "DENIED_TEXT": raise HelperError("PERMISSION_DENIED", "DENIED_TEXT cannot be read")
        offset = safe_int(params.get("offset"), 0, max(0, facts["size"]), "offset")
        length = safe_int(params.get("length"), 1, 65536, "length")
        os.lseek(descriptor, offset, os.SEEK_SET)
        raw = os.read(descriptor, length)
        facts["content"] = redact_secret_text(raw.decode(str(params.get("encoding", "utf-8")), errors="replace"), length)
        return [v2_observation("file", facts)]
    finally:
        os.close(descriptor)


MATCH_WINDOW_BYTES = 1024 * 1024
# Hit context is a content egress path, so it is bounded the same way `read` is: a fixed number
# of fixed-size windows per object. Offsets are byte offsets into the object so the caller can
# re-read the exact region through `read` instead of guessing.
MATCH_CONTEXT_BYTES = 256
MATCH_CONTEXT_HITS = 4
# `yara -s` prints one `0x<offset>:$<id>: <matched bytes>` line per string hit.
YARA_STRING_OFFSET = re.compile(r"^0x([0-9a-fA-F]+):")


def escape_context_line(text: str) -> str:
    """Keep one context window on exactly one line.

    The content field packs a hit marker and several windows separated by newlines. Window bytes
    routinely contain newlines themselves, so an unescaped window silently splits into several
    lines and the caller cannot tell windows apart.
    """
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def match_context_windows(raw: bytes, byte_offsets: list[int]) -> list[str]:
    """Bounded, redacted, single-line windows around each hit, labelled with the byte offset."""
    windows: list[str] = []
    half = MATCH_CONTEXT_BYTES // 2
    for offset in byte_offsets[:MATCH_CONTEXT_HITS]:
        start = max(0, offset - half)
        window = raw[start:offset + half].decode("utf-8", errors="replace")
        # Redact first so the secret patterns still see their original shape, then escape, then
        # cap: escaping can double the length, so the cap has to apply to the final text.
        escaped = escape_context_line(redact_secret_text(window, MATCH_CONTEXT_BYTES))
        windows.append(f"@{start}:{escaped[:MATCH_CONTEXT_BYTES * 2]}")
    return windows


def literal_offsets(text: str, pattern: str) -> list[int]:
    """Character offsets of the first few literal hits."""
    offsets: list[int] = []
    position = 0
    while len(offsets) < MATCH_CONTEXT_HITS:
        index = text.find(pattern, position)
        if index < 0:
            break
        offsets.append(index)
        position = index + max(1, len(pattern))
    return offsets


def re2_offsets(compiled: Any, text: str) -> list[int]:
    """Character offsets of the first few RE2 hits, without falling back to another engine."""
    offsets: list[int] = []
    position = 0
    while len(offsets) < MATCH_CONTEXT_HITS and position < len(text):
        found = compiled.search(text[position:])
        if found is None:
            break
        offsets.append(position + found.start())
        position += max(1, found.end())
    return offsets


def decode_utf8_with_offsets(raw: bytes) -> tuple[str, list[int]]:
    """Decode UTF-8 while retaining each character's original byte offset.

    Re-encoding text decoded with ``errors=replace`` is not reversible: every invalid input byte
    becomes a three-byte U+FFFD sequence and shifts all later offsets. This scanner follows the
    same replacement policy while advancing one original byte for an invalid sequence.
    """
    characters: list[str] = []
    offsets: list[int] = []
    index = 0
    while index < len(raw):
        first = raw[index]
        width = 1
        if 0xC2 <= first <= 0xDF:
            width = 2
        elif 0xE0 <= first <= 0xEF:
            width = 3
        elif 0xF0 <= first <= 0xF4:
            width = 4
        candidate = raw[index:index + width]
        try:
            if len(candidate) != width:
                raise UnicodeDecodeError("utf-8", raw, index, len(raw), "truncated sequence")
            character = candidate.decode("utf-8")
        except UnicodeDecodeError:
            character = "\ufffd"
            width = 1
        offsets.append(index)
        characters.append(character)
        index += width
    offsets.append(len(raw))
    return "".join(characters), offsets


def character_offsets_to_bytes(byte_offsets: list[int], offsets: list[int]) -> list[int]:
    """Map decoded character offsets back to the original object bytes."""
    return [byte_offsets[offset] for offset in offsets if 0 <= offset < len(byte_offsets)]


def v2_match(params: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    refs, matcher = params.get("objects"), params.get("matcher")
    if not isinstance(refs, list) or not isinstance(matcher, dict): raise HelperError("INVALID_ARGUMENT", "invalid match request")
    engine, pattern, rule_set_ref = matcher.get("engine"), matcher.get("pattern"), matcher.get("ruleSetRef")
    if engine not in {"literal", "re2", "yara"}:
        raise HelperError("INVALID_ARGUMENT", "invalid matcher")
    if engine in {"literal", "re2"} and (not isinstance(pattern, str) or not 1 <= len(pattern.encode()) <= 4096 or rule_set_ref is not None):
        raise HelperError("INVALID_ARGUMENT", "literal/RE2 matcher requires only a bounded pattern")
    if engine == "yara" and (pattern is not None or rule_set_ref not in V2_YARA_RULESETS):
        raise HelperError("INVALID_ARGUMENT", "YARA requires a built-in versioned RuleSet reference")
    if engine == "re2" and re2_engine is None:
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "RE2 is not installed; semantic fallback is forbidden")
    compiled_re2 = None
    if engine == "re2":
        try:
            compiled_re2 = re2_engine.compile(pattern)
        except Exception as exc:
            raise HelperError("INVALID_ARGUMENT", "pattern is not valid RE2 syntax") from exc
    if engine == "yara" and not shutil.which("yara"):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "YARA sandbox runtime is unavailable")
    include_context = params.get("includeContext")
    if not isinstance(include_context, bool):
        raise HelperError("INVALID_ARGUMENT", "includeContext must be a boolean")
    maximum = safe_int(params.get("maxHits"), 1, 500, "maxHits")
    hits: list[dict[str, Any]] = []
    truncated_objects = 0
    contextless_hits = 0
    for binding in refs:
        if len(hits) >= maximum: break
        if not isinstance(binding, dict) or binding.get("namespace") != "file": continue
        try:
            descriptor, facts = v2_bound_file(binding)
            try:
                if facts["contentClass"] == "DENIED_TEXT":
                    # DENIED_TEXT may still be matched — a hit leaks no content — but its bytes
                    # must never reach the model, so a context request over it is refused here
                    # rather than silently downgraded to a context-free hit.
                    if include_context:
                        raise HelperError("PERMISSION_DENIED", "DENIED_TEXT does not permit match context")
                    continue
                raw = os.read(descriptor, MATCH_WINDOW_BYTES)
                if isinstance(facts.get("size"), int) and facts["size"] > len(raw):
                    truncated_objects += 1
                text, text_byte_offsets = decode_utf8_with_offsets(raw)
                match_names: list[str] = []
                byte_offsets: list[int] = []
                if engine == "literal":
                    if include_context:
                        byte_offsets = character_offsets_to_bytes(text_byte_offsets, literal_offsets(text, str(pattern)))
                        matched = bool(byte_offsets)
                    else:
                        matched = pattern in text
                elif engine == "re2":
                    if include_context:
                        byte_offsets = character_offsets_to_bytes(text_byte_offsets, re2_offsets(compiled_re2, text))
                        matched = bool(byte_offsets)
                    else:
                        matched = compiled_re2.search(text) is not None
                else:
                    target = f"/proc/{os.getpid()}/fd/{descriptor}"
                    # `-s` is only added when context was requested: it makes YARA print the
                    # matched strings, and we parse the byte offsets out of that listing. The
                    # printed strings themselves are never forwarded; the window is cut from the
                    # object bytes and redacted like any other content egress.
                    ruleset_path = v2_yara_ruleset_path(str(rule_set_ref))
                    argv = ["yara", "--no-warnings", *(["-s"] if include_context else []),
                            str(ruleset_path), target]
                    result = run(argv, check=False)
                    if result.returncode not in {0, 1}:
                        raise HelperError("EVIDENCE_COLLECTION", "versioned YARA RuleSet execution failed")
                    for line in result.stdout.splitlines():
                        if not line.strip():
                            continue
                        offset_match = YARA_STRING_OFFSET.match(line)
                        if offset_match is not None:
                            if len(byte_offsets) < MATCH_CONTEXT_HITS:
                                byte_offsets.append(int(offset_match.group(1), 16))
                            continue
                        match_names.append(line.split(None, 1)[0])
                    matched = bool(match_names)
                if matched:
                    # The marker shares the content field with the windows, so it is capped too.
                    marker = ("MATCH" if not match_names else f"YARA_MATCH:{','.join(match_names[:100])}")[:MATCH_CONTEXT_BYTES]
                    if include_context:
                        windows = match_context_windows(raw, byte_offsets)
                        if not windows:
                            contextless_hits += 1
                        facts["content"] = "\n".join([marker, *windows])
                    else:
                        facts["content"] = marker
                    hits.append(v2_observation("file", facts))
            finally:
                os.close(descriptor)
        except HelperError:
            # A stale/denied binding is not a valid negative match. Fail the
            # request so Controller records a gap instead of false absence.
            raise
    gaps: list[dict[str, Any]] = []
    if truncated_objects:
        gaps.append({"code": "BYTE_LIMIT", "resumable": False,
                     "detail": f"{truncated_objects} 个对象只匹配了前 {MATCH_WINDOW_BYTES} 字节，未命中不代表整个文件无命中"})
    if contextless_hits:
        gaps.append({"code": "OUTPUT_LIMIT", "resumable": False,
                     "detail": f"{contextless_hits} 个命中未能定位偏移，只返回命中标记而没有上下文"})
    return hits, gaps


def v2_verify(params: dict[str, Any]) -> list[dict[str, Any]]:
    namespace, identity, locator = v2_ref_params(params)
    if namespace != "file": raise HelperError("UNSUPPORTED_ENVIRONMENT", "verify only supports file")
    baseline = params.get("baseline")
    if baseline not in {"package_db", "known_hash_set"}:
        raise HelperError("INVALID_ARGUMENT", "invalid verify baseline")
    data_set_ref = params.get("dataSetRef")
    if baseline == "known_hash_set" and (not isinstance(data_set_ref, str) or re.fullmatch(r"DATASET-[0-9a-f-]{36}", data_set_ref) is None):
        raise HelperError("INVALID_ARGUMENT", "known_hash_set requires a versioned controller dataSetRef")
    if baseline == "package_db" and data_set_ref is not None:
        raise HelperError("INVALID_ARGUMENT", "package_db does not accept dataSetRef")
    descriptor, facts = v2_bound_file(params, include_hash=True)
    try:
        if baseline == "package_db":
            result = verify_package_integrity({"path": facts["path"], "expectedInode": facts["inode"], "expectedSha256": facts["sha256"]})
            status = "UNKNOWN" if result.get("partial") or not result.get("package") else "MISMATCH" if result.get("changed") else "MATCH"
            facts["baseline"] = "package_db"
        else:
            # The versioned hash contents remain controller-local. Helper only
            # re-observes the bound file hash; Controller adjudicates membership.
            status = "UNKNOWN"
            facts["baseline"] = f"known_hash_set:{data_set_ref}"
        if v2_sha256_fd(descriptor) != facts["sha256"]:
            raise HelperError("STALE_REF", "file changed during baseline verification")
        facts["baselineStatus"] = status
        return [v2_observation("file", facts, "EXTERNAL_BASELINE")]
    finally:
        os.close(descriptor)


def v2_write_params(verb: str, params: dict[str, Any]) -> dict[str, Any]:
    authorization = params.get("authorization")
    action = params.get("action")
    if not isinstance(authorization, dict) or not isinstance(action, dict):
        raise HelperError("PERMISSION_DENIED", "write maintenance requires a bound approval envelope")
    if authorization.get("mode") != "REMEDIATE" or authorization.get("tool") != verb:
        raise HelperError("PERMISSION_DENIED", "SCAN mode or mismatched write approval")
    if authorization.get("actionId") != action.get("actionId"):
        raise HelperError("PERMISSION_DENIED", "write approval actionId mismatch")
    expected = hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if authorization.get("wireArgsDigest") != expected:
        raise HelperError("PERMISSION_DENIED", "write approval arguments mismatch")
    return action


def v2_scope_resolve(params: dict[str, Any]) -> dict[str, Any]:
    namespace = params.get("namespace")
    if namespace != "file":
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "only file Scope resolution is implemented")
    root = safe_path(params.get("requestedRoot"))
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or str(root) == "/" or str(root) in PSEUDO_FILESYSTEM_ROOTS:
        raise HelperError("PERMISSION_DENIED", "scope root is not an allowed directory")
    expected = params.get("expectedCanonicalRoot")
    if expected is not None and expected != str(root):
        raise HelperError("SOURCE_CHANGED", "canonical Scope root differs from the approved expectation")
    return {"namespace": "file", "canonicalRoot": str(root), "mountId": str(info.st_dev),
            "device": str(info.st_dev), "inode": str(info.st_ino)}


def v2_validate_request(request: dict[str, Any]) -> None:
    request_id, epoch_id = request.get("requestId"), request.get("epochId")
    if request.get("protocolVersion") != PROTOCOL_VERSION:
        raise HelperError("INVALID_ARGUMENT", "invalid v2 protocolVersion")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise HelperError("INVALID_ARGUMENT", "invalid v2 requestId")
    if not isinstance(epoch_id, str) or not 1 <= len(epoch_id) <= 128:
        raise HelperError("EPOCH_MISMATCH", "invalid or missing v2 epochId")
    deadline = request.get("deadlineMs")
    if isinstance(deadline, bool) or not isinstance(deadline, int) or not DEADLINE_MIN_MS <= deadline <= DEADLINE_MAX_MS:
        raise HelperError("INVALID_ARGUMENT", "invalid v2 deadlineMs")
    reservation = request.get("reservation")
    if not isinstance(reservation, dict) or set(reservation) != {"reservationId", "estimate"}:
        raise HelperError("INVALID_ARGUMENT", "invalid v2 budget reservation")
    reservation_id, estimate = reservation.get("reservationId"), reservation.get("estimate")
    if not isinstance(reservation_id, str) or not 1 <= len(reservation_id) <= 128 or not isinstance(estimate, dict):
        raise HelperError("INVALID_ARGUMENT", "invalid v2 budget reservation identity")
    cost_keys = {"remoteCalls", "nodes", "bytes", "wallTimeMs", "probeCalls"}
    if set(estimate) != cost_keys:
        raise HelperError("INVALID_ARGUMENT", "invalid v2 budget estimate fields")
    if any(isinstance(estimate[key], bool) or not isinstance(estimate[key], int) or estimate[key] < 0 for key in cost_keys):
        raise HelperError("INVALID_ARGUMENT", "invalid v2 budget estimate value")
    if estimate["remoteCalls"] != 1 or estimate["wallTimeMs"] > deadline:
        raise HelperError("BUDGET_EXHAUSTED", "v2 request is not covered by its reservation")


def v2_dispatch(verb: str, request: dict[str, Any]) -> dict[str, Any]:
    v2_validate_request(request)
    params = request.get("params")
    if not isinstance(params, dict): raise HelperError("INVALID_ARGUMENT", "params must be an object")
    started = time.monotonic(); request_id = request["requestId"]
    if verb == "capabilities":
        return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": "SUCCESS",
                "capabilities": v2_capabilities(), "cost": v2_cost(started, 1)}
    if verb == "artifact_release":
        released = release_artifact({"artifactToken": params.get("artifactToken")})
        return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": "SUCCESS",
                "objects": [], "edges": [], "gaps": [], "maintenanceResult": released,
                "cost": v2_cost(started, 1)}
    if verb == "scope_resolve":
        resolved = v2_scope_resolve(params)
        return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": "SUCCESS",
                "objects": [], "edges": [], "gaps": [], "maintenanceResult": resolved,
                "cost": v2_cost(started, 1)}
    if verb == "get_action_receipt":
        receipt = get_action_receipt({"actionId": params.get("actionId")})
        return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": "SUCCESS",
                "objects": [], "edges": [], "gaps": [], "maintenanceResult": receipt,
                "cost": v2_cost(started, 1)}
    if verb in {"quarantine_file", "disable_account"}:
        action = v2_write_params(verb, params)
        result = quarantine_file(action) if verb == "quarantine_file" else disable_account(action)
        return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": "SUCCESS",
                "objects": [], "edges": [], "gaps": [], "maintenanceResult": result,
                "cost": v2_cost(started, 1)}
    objects: list[dict[str, Any]] = []; edges: list[dict[str, Any]] = []; cursor = None; gaps: list[dict[str, Any]] = []; artifact = None
    if verb == "enumerate": objects, edges, cursor, gaps = v2_enumerate(params, request["epochId"])
    elif verb == "project": objects = v2_project(params)
    elif verb == "read": objects = v2_read(params)
    elif verb == "match": objects, gaps = v2_match(params)
    elif verb == "relate": objects, edges, cursor, gaps = v2_relate(params, request["epochId"])
    elif verb == "verify": objects = v2_verify(params)
    elif verb == "collect":
        namespace, identity, _locator = v2_ref_params(params)
        if namespace == "file":
            descriptor, facts = v2_bound_file(params, include_hash=True)
            try:
                # 采集固定经 /proc/self/fd 复用已复核过身份的 fd。procfs 缺失是能力问题，
                # 必须显式声明为 UNSUPPORTED_CAPABILITY，而不是漏成 INTERNAL_ERROR traceback。
                if not pathlib.Path("/proc/self/fd").is_dir():
                    raise HelperError("UNSUPPORTED_CAPABILITY", "procfs is unavailable; fd-based Evidence collection is not supported")
                staged = stage_artifact(pathlib.Path(f"/proc/self/fd/{descriptor}"), safe_int(params.get("maxBytes"), 1, ARTIFACT_MAX_BYTES, "maxBytes"))
                if staged["sha256"] != facts["sha256"]:
                    artifact_path(staged["artifactToken"]).unlink(missing_ok=True)
                    raise HelperError("STALE_REF", "file changed during Evidence collection")
                artifact = {"token": staged["artifactToken"], "sha256": staged["sha256"], "size": staged["size"],
                            "complete": staged["size"] == facts["size"], "expiresAt": staged["expiresAt"]}
                objects = [v2_observation("file", facts)]
            finally:
                os.close(descriptor)
        elif namespace == "process":
            collected = collect_process_executable({**identity, "maxBytes": params.get("maxBytes")})
            staged = collected["artifact"]
            current = process_request(identity)
            process_fields = {**current, "exe": current.get("exePath"), "command": current.get("command", current.get("comm"))}
            artifact = {"token": staged["artifactToken"], "sha256": staged["sha256"], "size": staged["size"],
                        "complete": True, "expiresAt": staged["expiresAt"]}
            objects = [v2_observation("process", process_fields)]
        else:
            raise HelperError("UNSUPPORTED_ENVIRONMENT", "collect only supports file and process executable objects")
    elif verb == "probe":
        namespace, identity, _locator = v2_ref_params(params)
        if namespace != "jvm": raise HelperError("UNSUPPORTED_ENVIRONMENT", "probe only supports jvm")
        kind = params.get("probeKind")
        command = "list_components" if kind == "jvm.tomcat.inventory" else "inspect_class"
        result = run_tomcat_probe({"pid": identity.get("pid"), "command": command, **params.get("parameters", {})})
        jvm_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        if command == "list_components":
            for item in result.get("items", result.get("components", [])):
                if isinstance(item, dict):
                    fields = {"jvmDigest": jvm_digest, "componentKind": str(item.get("kind", "component")),
                              "name": str(item.get("name", item.get("className", "unknown"))), "className": str(item.get("className", "unknown")),
                              "mappings": item.get("mappings", [])}
                    objects.append(v2_observation("java_component", fields, "POINT_IN_TIME"))
                    edges.append(v2_edge("jvm", identity, "hosts_component", "java_component", fields))
        else:
            fields = {"jvmDigest": jvm_digest, "className": str(result.get("className")), "loaderId": str(result.get("loaderId", "unknown")),
                      "codeSource": result.get("codeSource", ""), "bytecodeSha256": result.get("sha256", "unknown"), "modifiable": bool(result.get("modifiable"))}
            objects.append(v2_observation("class", fields, "POINT_IN_TIME"))
            edges.append(v2_edge("jvm", identity, "loads_class", "class", fields))
            edges.append(v2_edge("class", fields, "loaded_by", "jvm", identity))
    status_value = "PARTIAL" if gaps else "SUCCESS"
    response = {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "status": status_value,
                "objects": objects, "edges": edges, "cost": v2_cost(started, len(objects), len(json.dumps(objects).encode()), 1 if verb == "probe" else 0), "gaps": gaps}
    if cursor is not None: response["cursor"] = cursor
    if artifact is not None: response["artifact"] = artifact
    return response


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in V2_VERBS | V2_MAINTENANCE_VERBS:
        emit({"protocolVersion": PROTOCOL_VERSION, "requestId": "UNKNOWN", "status": "ERROR",
              "error": {"code": "INVALID_ARGUMENT", "message": "unknown v2 verb"},
              "cost": {"remoteCalls": 0, "nodes": 0, "bytes": 0, "wallTimeMs": 0, "probeCalls": 0}})
        return 2
    try:
        request = read_request()
        install_deadline(request)
        emit(v2_dispatch(sys.argv[1], request))
        return 0
    except HelperError as exc:
        code = v2_wire_error_code(exc.code)
        emit({"protocolVersion": PROTOCOL_VERSION, "requestId": locals().get("request", {}).get("requestId", "UNKNOWN"),
              "status": "ERROR", "error": {"code": code, "message": str(exc)},
              "cost": {"remoteCalls": 1, "nodes": 0, "bytes": 0, "wallTimeMs": 0, "probeCalls": 0}})
        return 1
    except Exception as exc:  # defensive boundary: never emit a Python traceback over SSH
        emit({"protocolVersion": PROTOCOL_VERSION, "requestId": locals().get("request", {}).get("requestId", "UNKNOWN"),
              "status": "ERROR", "error": {"code": "INTERNAL_ERROR", "message": f"{type(exc).__name__}: {exc}"},
              "cost": {"remoteCalls": 1, "nodes": 0, "bytes": 0, "wallTimeMs": 0, "probeCalls": 0}})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
