#!/usr/bin/env python3
"""Prepare real x86_64 guests under QEMU TCG; never performs qualification.

prepare downloads immutable official images and creates independent NoCloud guests.
run stays in the foreground (launch under a process supervisor); stop uses QMP.
observe verifies the serial-console host key before SSH, installs current assets,
and writes immutable PREPARATION evidence. Repeated operations retain first results.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[2]
SPECS = {
    "ubuntu": {
        "platformId": "ubuntu-24.04-x86_64", "port": 2241,
        "source": "https://cloud-images.ubuntu.com/noble/20260826/",
        "imageId": "noble-server-cloudimg-amd64.img", "buildId": "20260826",
        "checksumFile": "SHA256SUMS", "algorithm": "sha256",
        "digest": "d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30",
        "distribution": "ubuntu", "version": "24.04",
    },
    "debian": {
        "platformId": "debian-12-systemd-x86_64", "port": 2242,
        "source": "https://cloud.debian.org/images/cloud/bookworm/20260909-2596/",
        "imageId": "debian-12-genericcloud-amd64-20260909-2596.qcow2", "buildId": "20260909-2596",
        "checksumFile": "SHA512SUMS", "algorithm": "sha512",
        "digest": "08fea112563461f251f3c95a5c5cf8cb25eb60f74cec03e85a97ff91d3efef3059d35837598bbb476008f20db6d3bdc7143c5f2f2a9a6da394a0acc601fd5986",
        "distribution": "debian", "version": "12",
    },
    "rocky": {
        "platformId": "rocky-or-alma-9-x86_64-selinux-enforcing", "port": 2243,
        "source": "https://download.rockylinux.org/pub/rocky/9/images/x86_64/",
        "imageId": "Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2", "buildId": "9.8-20260525.0",
        "checksumFile": "Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2.CHECKSUM", "algorithm": "sha256",
        "digest": "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
        "distribution": "rocky", "version": "9",
    },
    "amazon": {
        "platformId": "amazon-linux-2023-x86_64", "port": 2244,
        "source": "https://cdn.amazonlinux.com/al2023/os-images/2023.12.20260909.0/kvm/",
        "imageId": "al2023-kvm-2023.12.20260909.0-kernel-6.1-x86_64.xfs.gpt.qcow2", "buildId": "2023.12.20260909.0",
        "checksumFile": "SHA256SUMS", "algorithm": "sha256",
        "digest": "60e0defb06db53075fe688153564317cde0e3bbe48ee831b3c2606cb79ca97a2",
        "distribution": "amzn", "version": "2023",
        "supportNote": "Official AWS KVM guest image; macOS/TCG is not an AWS-qualified KVM host. This experiment does not assert AWS support.",
    },
}
ASSETS = ["host-helper/install-helper.sh", "host-helper/self-check-helper.sh", "host-helper/huntwarden_helper.py", "rules/yara/webshell.yar", "java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar"]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path, value, *, exclusive=True):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n" if not isinstance(value, str) else value
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def checkpoint(home, action, result):
    with (home / "preparation.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = home / "preparation.json"
        preparation = json.loads(path.read_text()) if path.exists() else {"phase": "PREPARATION", "platform": home.name, "formalQualification": False, "ownerAttestationPending": True, "operations": {}}
        preparation.setdefault("operations", {})[action] = result
        preparation["updatedAt"] = now()
        if action in ("prepare", "observe"):
            preparation["status"] = result["status"]
        pending = home / "preparation.next.json"
        save(pending, preparation, exclusive=False)
        pending.replace(path)


def digest(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def binary(name):
    found = shutil.which(name)
    if not found and Path("/opt/homebrew/bin", name).is_file():
        found = str(Path("/opt/homebrew/bin", name))
    if not found:
        raise RuntimeError(f"Missing {name}; install QEMU once with brew install qemu")
    return found


def execute(argv, *, timeout=120, input=None, log=None):
    if log is not None:
        with log.open("x", encoding="utf-8") as stream:
            result = subprocess.run([str(a) for a in argv], text=True, input=input, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"{argv[0]} exited {result.returncode}; full output: {log}")
        return ""
    result = subprocess.run([str(a) for a in argv], text=True, input=input, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {result.stdout[-3000:]} {result.stderr[-3000:]}")
    return result.stdout


def download(url, path):
    if path.exists():
        return
    partial = path.with_name(path.name + ".partial")
    execute(["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2", "--connect-timeout", "30", "--max-time", "3600", "--continue-at", "-", "--output", partial, url], timeout=3610)
    partial.rename(path)
    path.chmod(0o600)


def prepare(root, name, attempt):
    spec = SPECS[name]
    home = root / name
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    image = home / spec["imageId"]
    checksums = home / spec["checksumFile"]
    download(spec["source"] + spec["checksumFile"], checksums)
    text = checksums.read_text()
    matching = [line for line in text.splitlines() if spec["imageId"] in line]
    expected = spec.get("digest")
    if not expected:
        candidates = re.findall(r"\b[0-9a-f]{64}\b", "\n".join(matching))
        if len(candidates) != 1:
            raise RuntimeError("Official checksum entry missing or ambiguous")
        expected = candidates[0]
    if not any(expected in line for line in matching):
        raise RuntimeError("Official checksum differs from pinned digest")
    download(spec["source"] + spec["imageId"], image)
    actual = digest(image, spec["algorithm"])
    if actual != expected:
        raise RuntimeError(f"Image digest mismatch: expected {expected}, observed {actual}; preserving download")
    image.chmod(0o400)
    image_info = json.loads(execute([binary("qemu-img"), "info", "--output=json", image]))
    if image_info["format"] != "qcow2" or image_info.get("backing-filename"):
        raise RuntimeError("Official image must be a standalone qcow2")
    provenance = {**spec, "imagePath": str(image), "downloadUrl": spec["source"] + spec["imageId"], "checksumUrl": spec["source"] + spec["checksumFile"], "checksumVerified": True, "checksumDigest": actual, "imageSha256": digest(image), "verifiedAt": now(), "signatureVerified": False, "trustBasis": "HTTPS official publisher checksum; no detached-signature verification claimed", "qemuImageInfo": image_info}
    save(attempt / "image.json", provenance)
    if not (home / "image.json").exists():
        save(home / "image.json", provenance)
    key = home / "operator_ed25519"
    if not key.exists():
        execute(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "huntwarden-platform-preparation", "-f", key])
    key.chmod(0o600)
    seed = home / "seedconfig"
    if not seed.exists():
        seed.mkdir(mode=0o700)
        public = key.with_suffix(".pub").read_text().strip()
        console = "#!/bin/sh\n{ printf 'HW_HOST_KEY='; cat /etc/ssh/ssh_host_ed25519_key.pub; printf 'HW_BOOT_READY\\n'; } >/dev/ttyS0\n"
        cloud = {"users": [{"name": "hwaccept", "groups": ["wheel"] if name in ("rocky", "amazon") else ["sudo"], "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL", "lock_passwd": True, "ssh_authorized_keys": [public]}], "ssh_pwauth": False, "disable_root": True, "write_files": [{"path": "/var/lib/cloud/scripts/per-boot/hw-console-key", "permissions": "0755", "content": console}], "runcmd": [["sh", "/var/lib/cloud/scripts/per-boot/hw-console-key"]]}
        save(seed / "user-data", "#cloud-config\n" + json.dumps(cloud, indent=2) + "\n")
        save(seed / "meta-data", json.dumps({"instance-id": f"hw-{name}-{uuid.uuid4().hex}", "local-hostname": f"hw-{name}"}))
    iso = home / "seed.iso"
    if not iso.exists():
        execute(["hdiutil", "makehybrid", "-o", iso, "-joliet", "-iso", "-default-volume-name", "cidata", seed])
        iso.chmod(0o600)
    overlay = home / "disk.qcow2"
    if not overlay.exists():
        capacity = max(24 * 1024**3, image_info["virtual-size"])
        execute([binary("qemu-img"), "create", "-f", "qcow2", "-F", "qcow2", "-b", image, overlay, str(capacity)])
    else:
        overlay_info = json.loads(execute([binary("qemu-img"), "info", "--output=json", overlay]))
        if overlay_info["virtual-size"] < image_info["virtual-size"]:
            raise RuntimeError("Existing overlay is smaller than its official backing image; stop the guest and grow it before boot")
    return {"status": "IMAGE_AND_SEED_PREPARED", "image": str(home / "image.json"), "overlay": str(overlay), "seed": str(iso), "port": spec["port"]}


def qmp(path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(path))
        stream = sock.makefile("rwb")
        json.loads(stream.readline())
        for operation in ("qmp_capabilities", command):
            stream.write((json.dumps({"execute": operation}) + "\n").encode())
            stream.flush()
            while True:
                reply = json.loads(stream.readline())
                if "error" in reply:
                    raise RuntimeError(str(reply))
                if "return" in reply:
                    break
        return reply


def run(root, name, attempt, disk_interface="virtio-blk"):
    home = root / name
    for path in (home / "disk.qcow2", home / "seed.iso", home / "image.json"):
        if not path.is_file():
            raise RuntimeError(f"Run prepare first: missing {path}")
    # Hold both locks for the complete foreground QEMU lifetime, including shutdown.
    # A user-scoped lock prevents parallel guests even across different state roots.
    lock_paths = [Path.home() / ".huntwarden-qemu-tcg.lock", root / "tcg.lock"]
    locks = []
    try:
        for path in lock_paths:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            locks.append(fd)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        monitor = Path("/tmp") / f"hwq-{uuid.uuid4().hex[:16]}.sock"
        serial = attempt / "serial.log"
        serial.touch(mode=0o600)
        # The Debian cloud kernel omits AHCI; expose NoCloud on the supported virtio bus.
        disk = ["-drive", f"file={home / 'disk.qcow2'},format=qcow2,if=virtio"] if disk_interface == "virtio-blk" else ["-device", "virtio-scsi-pci,id=scsi0", "-drive", f"file={home / 'disk.qcow2'},format=qcow2,if=none,id=rootdisk", "-device", "scsi-hd,drive=rootdisk,bus=scsi0.0"]
        argv = [binary("qemu-system-x86_64"), "-name", f"huntwarden-{name}", "-machine", "q35", "-accel", "tcg,thread=multi", "-cpu", "max", "-smp", "2", "-m", "3072", *disk, "-drive", f"file={home / 'seed.iso'},format=raw,if=virtio,readonly=on", "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{SPECS[name]['port']}-:22", "-device", "virtio-net-pci,netdev=net0", "-device", "virtio-rng-pci", "-display", "none", "-serial", f"file:{serial}", "-monitor", "none", "-qmp", f"unix:{monitor},server=on,wait=off", "-no-reboot"]
        save(attempt / "command.json", argv)
        child = subprocess.Popen(argv)
        state = {"name": name, "pid": child.pid, "qmp": str(monitor), "serial": str(serial), "startedAt": now(), "attempt": str(attempt)}
        save(home / "active.json", state, exclusive=False)
        def terminate(signum, frame):
            if child.poll() is None:
                child.terminate()
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        print(f"QEMU_STARTING {name} pid={child.pid} ssh=127.0.0.1:{SPECS[name]['port']} serial={serial}", flush=True)
        code = child.wait()
        save(attempt / "exit.json", {"exitCode": code, "endedAt": now()})
        return {"status": "STOPPED", "qemuExitCode": code, "serial": str(serial)}
    finally:
        for fd in locks:
            os.close(fd)


def stop(root, name, attempt):
    state = json.loads((root / name / "active.json").read_text())
    path = Path(state["qmp"])
    if not path.exists():
        return {"status": "ALREADY_STOPPED"}
    qmp(path, "system_powerdown")
    deadline = time.monotonic() + 180
    while path.exists() and time.monotonic() < deadline:
        time.sleep(2)
    forced = path.exists()
    if forced:
        qmp(path, "quit")
    return {"status": "POWERDOWN_REQUESTED", "qmpQuitRequired": forced}


def ssh(home, spec, command, *, timeout=120, input=None, log=None):
    return execute(["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={home / 'known_hosts'}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", "-i", home / "operator_ed25519", "-p", str(spec["port"]), "hwaccept@127.0.0.1", command], timeout=timeout, input=input, log=log)


def observe(root, name, attempt, timeout):
    home, spec = root / name, SPECS[name]
    state = json.loads((home / "active.json").read_text())
    serial = Path(state["serial"])
    deadline = time.monotonic() + timeout
    match = None
    while time.monotonic() < deadline:
        text = serial.read_text(errors="replace")
        match = re.search(r"HW_HOST_KEY=(ssh-ed25519 [A-Za-z0-9+/=]+)(?: |\r|\n)", text)
        if match:
            break
        if not Path(state["qmp"]).exists():
            raise RuntimeError(f"Guest exited before console host key; inspect {serial}")
        time.sleep(5)
    if not match:
        raise RuntimeError(f"No host key from VM serial console within {timeout}s; inspect {serial}")
    public = match.group(1)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public.split()[1])).digest()).decode().rstrip("=")
    known = f"[127.0.0.1]:{spec['port']} {public}\n"
    if (home / "known_hosts").exists():
        if (home / "known_hosts").read_text() != known:
            raise RuntimeError("Console host key changed; refusing to replace first trusted key")
    else:
        save(home / "known_hosts", known)
    save(attempt / "host-key-console.json", {"source": str(serial), "hostFingerprint": fingerprint, "hostPublicKey": public, "observedAt": now(), "verificationMethod": "QEMU serial console; not ssh-keyscan"})
    target = {"host": "127.0.0.1", "port": spec["port"], "username": "hwaccept", "hostFingerprint": fingerprint, "privateKeyPath": str(home / "operator_ed25519"), "knownHostsPath": str(home / "known_hosts")}
    save(attempt / "target.json", target)
    if not (home / "target.json").exists():
        save(home / "target.json", target)
    probe = "import json,os,platform,pathlib; d={}; exec(\"for l in pathlib.Path('/etc/os-release').read_text().splitlines():\\n if '=' in l:\\n  k,v=l.split('=',1); d[k]=v.strip(chr(34))\"); print(json.dumps({'architecture':platform.machine(),'uname':list(platform.uname()),'osRelease':d,'pid1':os.path.realpath('/proc/1/exe'),'selinux':pathlib.Path('/sys/fs/selinux/enforce').read_text().strip() if pathlib.Path('/sys/fs/selinux/enforce').exists() else None}))"
    observed = json.loads(ssh(home, spec, "sudo -n python3 -c " + shlex.quote(probe), timeout=180))
    save(attempt / "guest.json", observed)
    if observed["architecture"] != "x86_64" or not observed["pid1"].endswith("/systemd") or observed["osRelease"].get("ID") != spec["distribution"] or not observed["osRelease"].get("VERSION_ID", "").startswith(spec["version"]):
        raise RuntimeError("Guest OS/architecture/PID1 does not satisfy selected platform")
    if name == "rocky" and observed["selinux"] != "1":
        raise RuntimeError("Rocky must remain SELinux Enforcing; not disabling policy")
    checkpoint(home, "observe", {"status": "GUEST_VERIFIED", "attempt": str(attempt), "observation": str(attempt / "guest.json"), "target": str(home / "target.json")})
    sources = {}
    for asset in ASSETS:
        local = REPO / asset
        if not local.is_file():
            raise RuntimeError(f"Required existing asset missing (no project build attempted): {local}")
        sources[asset] = digest(local)
        remote = "/home/hwaccept/HuntWarden/" + asset
        ssh(home, spec, "mkdir -p " + shlex.quote(str(Path(remote).parent)) + " && cat > " + shlex.quote(remote), input=local.read_bytes().decode() if local.suffix != ".jar" else None) if local.suffix != ".jar" else ssh(home, spec, "mkdir -p " + shlex.quote(str(Path(remote).parent)) + " && base64 -d > " + shlex.quote(remote), input=base64.b64encode(local.read_bytes()).decode())
    save(attempt / "source-digests.json", sources)
    if name in ("ubuntu", "debian"):
        deps = "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends openssh-server sudo python3 python3-pip yara auditd iproute2 procps lsof openjdk-17-jdk-headless"
    elif name == "amazon":
        deps = "dnf install -y openssh-server sudo python3 python3-pip audit iproute procps-ng lsof java-17-amazon-corretto-devel gcc make autoconf automake libtool flex bison pkgconf-pkg-config openssl-devel jansson-devel"
    else:
        extra = "dnf install -y epel-release && " if name == "rocky" else ""
        deps = extra + "dnf install -y openssh-server sudo python3 python3-pip yara audit iproute procps-ng lsof java-17-openjdk-devel"
    python_version = json.loads(ssh(home, spec, "python3 -c 'import json,sys; print(json.dumps(list(sys.version_info[:2])))'"))
    # google-re2 dropped CPython 3.9 wheels after its 2024 release; keep the
    # distribution interpreter and require a wheel rather than an unplanned build.
    re2_version = "1.1.20240702" if python_version < [3, 10] else "1.1.20251105"
    save(attempt / "re2-runtime.json", {"pythonVersion": python_version, "googleRe2Version": re2_version})
    commands = [("dependencies", "sudo bash -c " + shlex.quote("set -e; " + deps)), ("re2", "sudo env PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --only-binary=:all: --disable-pip-version-check google-re2==" + re2_version), ("install", "chmod +x /home/hwaccept/HuntWarden/host-helper/*.sh && sudo /home/hwaccept/HuntWarden/host-helper/install-helper.sh --executor-user hwaccept --self-check")]
    if name == "amazon":
        # AL2023 does not ship the Rocky package names for YARA or OpenJDK.
        archive = home / "yara-4.5.8.tar.gz"
        source_url = "https://codeload.github.com/VirusTotal/yara/tar.gz/84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8"
        expected_yara = "da7eb424e88360de6165d4af5fa88d6f72c22676f517d9d436a7cd67624b7119"
        download(source_url, archive)
        if digest(archive) != expected_yara:
            raise RuntimeError("Pinned YARA source archive digest mismatch")
        save(attempt / "yara-source.json", {"version": "4.5.8", "url": source_url, "sha256": expected_yara, "signatureVerified": False})
        ssh(home, spec, "mkdir -p /home/hwaccept/HuntWarden/vendor && base64 -d > /home/hwaccept/HuntWarden/vendor/yara-4.5.8.tar.gz", input=base64.b64encode(archive.read_bytes()).decode())
        build_yara = 'set -e; if [ "$(/usr/local/bin/yara --version 2>/dev/null)" != "4.5.8" ]; then mkdir -p /home/hwaccept/HuntWarden/vendor/yara-4.5.8; tar -xzf /home/hwaccept/HuntWarden/vendor/yara-4.5.8.tar.gz --strip-components=1 -C /home/hwaccept/HuntWarden/vendor/yara-4.5.8; cd /home/hwaccept/HuntWarden/vendor/yara-4.5.8; ./bootstrap.sh; ./configure --prefix=/usr/local --disable-shared; make -j2; sudo make install; fi; /usr/local/bin/yara --version'
        commands.insert(1, ("yara", "bash -c " + shlex.quote(build_yara)))
    failures = []
    for label, command in commands:
        try:
            ssh(home, spec, command, timeout=3600, log=attempt / (label + ".log"))
        except Exception as exc:
            save(attempt / (label + "-error.json"), {"error": str(exc)})
            failures.append({"step": label, "error": str(exc)})
        checkpoint(home, "observe", {"status": "INSTALLING_HELPER", "attempt": str(attempt), "observation": str(attempt / "guest.json"), "lastCompletedStep": label, "failures": failures})
    image = json.loads((home / "image.json").read_text())
    manifest = {"schemaVersion": 1, "suiteId": spec["platformId"] + "-preparation", "platformId": spec["platformId"], "hostKeyOutOfBandVerified": True, "officialImage": {"official": True, "source": spec["source"], "imageId": spec["buildId"] + "/" + spec["imageId"], "imageDigest": image["imageSha256"], "attestor": None, "attestedAt": None}, "evidenceCandidates": ["/etc/hostname", "/usr/lib/os-release"], "maxEvidenceBytes": 1048576}
    save(attempt / "manifest.json", manifest)
    if not (home / "manifest.json").exists():
        save(home / "manifest.json", manifest)
    result = {"status": "PREPARATION_READY" if not failures else "PREPARATION_PARTIAL", "target": str(home / "target.json"), "manifest": str(home / "manifest.json"), "observation": str(attempt / "guest.json"), "failures": failures, "formalQualification": False, "ownerAttestationPending": True}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "run", "stop", "observe"])
    parser.add_argument("platform", choices=list(SPECS))
    parser.add_argument("--root", type=Path, required=True, help="Private state outside the repository")
    parser.add_argument("--timeout", type=int, default=1800, help="Console readiness timeout")
    parser.add_argument("--disk-interface", choices=["virtio-blk", "virtio-scsi"], default="virtio-blk", help="Root disk controller for the run action")
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.expanduser().resolve()
    if root == REPO or REPO in root.parents:
        parser.error("State, images and keys must remain outside the repository")
    if any(c in str(root) for c in (",", "\n")):
        parser.error("QEMU state path cannot contain commas or newlines")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    attempt = root / args.platform / "attempts" / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + args.action + "-" + uuid.uuid4().hex[:8])
    attempt.mkdir(mode=0o700, parents=True)
    result = {"phase": "PREPARATION", "action": args.action, "platform": args.platform, "startedAt": now(), "attempt": str(attempt)}
    code = 0
    try:
        if args.action == "observe":
            result.update(observe(root, args.platform, attempt, args.timeout))
        elif args.action == "run":
            result.update(run(root, args.platform, attempt, args.disk_interface))
        else:
            result.update(globals()[args.action](root, args.platform, attempt))
        if result.get("failures"):
            code = 1
    except Exception as exc:
        result.update(status="BLOCKED", error=str(exc))
        code = 1
    result["endedAt"] = now()
    save(attempt / "result.json", result)
    checkpoint(root / args.platform, args.action, result)
    print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
