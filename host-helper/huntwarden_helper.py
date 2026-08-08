#!/usr/bin/env python3
"""Root-owned, operation-whitelisted helper used by SSHExecutor.

The helper reads one JSON object from stdin and emits one JSON envelope. It never
uses shell=True and never accepts an arbitrary command from the controller.
"""

from __future__ import annotations

import base64
import datetime as dt
import glob
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
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
PROBE_JAR = pathlib.Path("/opt/huntwarden/huntwarden-tomcat-probe.jar")
SCRIPT_EXTENSIONS = {".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".py", ".pl", ".cgi"}
USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.I)
CLASS_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.]{0,511}$")
PERSISTENCE_KINDS = {"cron", "systemd", "ssh", "shell"}
SYSTEM_PERSISTENCE_ROOTS = {
    "cron": ("/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"),
    "systemd": ("/etc/systemd", "/usr/lib/systemd", "/lib/systemd"),
    "ssh": ("/etc/ssh",),
    "shell": ("/etc/profile", "/etc/bash.bashrc", "/etc/zsh", "/etc/profile.d"),
}


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


def discover_web_roots(_: dict[str, Any]) -> list[dict[str, str]]:
    roots: dict[str, str] = {}
    config_globs = ["/etc/nginx/**/*.conf", "/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf"]
    directive = re.compile(r"^\s*(?:root|DocumentRoot)\s+['\"]?([^;'\"\s]+)", re.I)
    for expression in config_globs:
        for name in glob.glob(expression, recursive=True)[:1000]:
            try:
                for line in pathlib.Path(name).read_text("utf-8", errors="replace").splitlines():
                    match = directive.search(line)
                    if match and match.group(1).startswith("/"):
                        roots[str(pathlib.Path(match.group(1)).resolve())] = "nginx" if "nginx" in name else "apache"
            except OSError:
                continue
    for path, server in [("/var/www/html", "common"), ("/usr/local/tomcat/webapps", "tomcat"), ("/opt/tomcat/webapps", "tomcat")]:
        if pathlib.Path(path).is_dir():
            roots[str(pathlib.Path(path).resolve())] = server
    return [{"path": path, "server": server} for path, server in sorted(roots.items())]


def find_recent_web_files(request: dict[str, Any]) -> list[dict[str, Any]]:
    roots = request.get("roots")
    if not isinstance(roots, list) or not roots or len(roots) > 50:
        raise HelperError("INVALID_ARGUMENT", "invalid roots")
    hours = safe_int(request.get("modifiedWithinHours"), 1, 24 * 365, "modifiedWithinHours")
    maximum = safe_int(request.get("maxFiles"), 1, 5000, "maxFiles")
    max_size = safe_int(request.get("maxFileSizeBytes"), 1024, 1024 * 1024 * 100, "maxFileSizeBytes")
    cutoff = dt.datetime.now().timestamp() - hours * 3600
    items: list[dict[str, Any]] = []
    for raw_root in roots:
        root = safe_path(raw_root)
        if not root.is_dir():
            continue
        for directory, _, files in os.walk(root, followlinks=False):
            for filename in files:
                path = pathlib.Path(directory) / filename
                if path.suffix.lower() not in SCRIPT_EXTENSIONS:
                    continue
                try:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_mtime < cutoff or info.st_size > max_size:
                        continue
                    items.append({"path": str(path), "size": info.st_size, "mtime": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(), "sha256": sha256_file(path)})
                except (OSError, PermissionError):
                    continue
                if len(items) >= maximum:
                    return items
    return items


def yara_scan_files(request: dict[str, Any]) -> list[dict[str, Any]]:
    if not shutil.which("yara"):
        raise HelperError("UNSUPPORTED_ENVIRONMENT", "yara is not installed")
    paths = request.get("paths")
    if not isinstance(paths, list) or len(paths) > 500:
        raise HelperError("INVALID_ARGUMENT", "invalid paths")
    rule_path = safe_path(request.get("rulePath"))
    results = []
    for value in paths:
        path = safe_path(value)
        output = run(["yara", "--timeout=10", str(rule_path), str(path)], timeout=15, check=False)
        matches = [line.split(None, 1)[0] for line in output.stdout.splitlines() if line.strip()]
        results.append({"path": str(path), "matches": matches, "error": output.stderr.strip()[:1000] or None})
    return results


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
                for line in pathlib.Path(log_name).read_text("utf-8", errors="replace").splitlines():
                    if name in line:
                        matches.append({"log": log_name, "line": line[:8192]})
                        if len(matches) >= maximum:
                            return matches
            except OSError:
                continue
    return matches


def collect_file(request: dict[str, Any]) -> dict[str, Any]:
    path = safe_path(request.get("path"))
    maximum = safe_int(request.get("maxBytes"), 1, 100 * 1024 * 1024, "maxBytes")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise HelperError("EVIDENCE_COLLECTION", "file is not regular or exceeds collection limit")
    data = path.read_bytes()
    return {"dataBase64": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


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
    rows = []
    for account in pwd.getpwall():
        privileged = account.pw_uid == 0 or account.pw_name in sudo_users
        interactive = account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", ""}
        if privileged or (account.pw_uid < 1000 and interactive):
            rows.append({"username": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid, "shell": account.pw_shell, "home": account.pw_dir, "sudo": account.pw_name in sudo_users, "interactive": interactive})
    return rows


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
                items.append({**file_facts(resolved), "kind": "systemd", "unit": path.name,
                              "scope": "user" if "/.config/systemd/user/" in str(resolved) else "system",
                              "enabled": bool(enabled_links), "enabledLinks": enabled_links, **parse_systemd_unit(resolved)})
            except OSError:
                continue
            if len(items) >= maximum:
                return {"items": items, "partial": True, "warnings": ["systemd 结果达到配置上限"]}
    manager_available = pathlib.Path("/run/systemd/system").is_dir()
    warnings = [] if manager_available else ["systemd 管理器未运行；仅完成 Unit 文件与启用链接检查"]
    return {"items": items, "partial": not manager_available, "warnings": warnings}


def effective_sshd_config() -> dict[str, Any]:
    binary = shutil.which("sshd")
    if not binary:
        return {"available": False}
    result = run([binary, "-T"], check=False)
    selected: dict[str, str] = {}
    wanted = {"authorizedkeysfile", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "allowusers", "allowgroups"}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in wanted:
            selected[key] = value[:2048]
    return {"available": result.returncode == 0, **selected}


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
    processes = list_processes({})
    matches = []
    for process in processes:
        command = str(process.get("command", ""))
        if any(token in command for token in useful[:10]):
            executable = None
            try:
                executable = str(pathlib.Path(f"/proc/{process['pid']}/exe").resolve(strict=True))
            except OSError:
                pass
            matches.append({**process, "executable": executable, "matchedTokens": useful[:10]})
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
    pid = safe_int(request.get("pid"), 1, 2**31 - 1, "pid")
    maximum = safe_int(request.get("maxConnections"), 1, 5000, "maxConnections")
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
    data = path.read_bytes()
    return {"dataBase64": base64.b64encode(data).decode(), "sha256": expected, "size": len(data)}


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
    "get_host_info": get_host_info,
    "list_processes": list_processes,
    "discover_web_roots": discover_web_roots,
    "find_recent_web_files": find_recent_web_files,
    "yara_scan_files": yara_scan_files,
    "inspect_script_file": inspect_script_file,
    "search_web_access_log": search_web_access_log,
    "collect_file": collect_file,
    "list_java_processes": list_java_processes,
    "detect_java_container": detect_java_container,
    "run_tomcat_probe": run_tomcat_probe,
    "search_class_on_disk": search_class_on_disk,
    "list_privileged_accounts": list_privileged_accounts,
    "inspect_account": inspect_account,
    "inspect_authorized_keys": inspect_authorized_keys,
    "get_login_history": get_login_history,
    "list_cron_entries": list_cron_entries,
    "list_systemd_units": list_systemd_units,
    "list_ssh_persistence": list_ssh_persistence,
    "list_shell_startup_files": list_shell_startup_files,
    "inspect_persistence_item": inspect_persistence_item,
    "find_related_processes": find_related_processes,
    "list_process_connections": list_process_connections,
    "collect_persistence_artifact": collect_persistence_artifact,
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
