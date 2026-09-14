#!/usr/bin/env python3
"""Prepare the existing real-world SSH fixture without exposing its answer file."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def command(*args, capture=False):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None).stdout


def private_json(path, value):
    with open(path, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["prepare", "cleanup"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=23091)
    args = parser.parse_args()
    state = args.root.resolve()
    if state == ROOT or ROOT in state.parents:
        raise SystemExit("development state must be outside the repository")
    identity = hashlib.sha256(str(state).encode()).hexdigest()[:12]
    container = f"huntwarden-development-{identity}"
    if args.operation == "cleanup":
        record = json.loads((state / "prepared.json").read_text())
        if record["container"] != container:
            raise SystemExit("container ownership mismatch")
        command("docker", "rm", "-f", container)
        private_json(state / "cleanup.json", {"container": container, "removed": True})
        return
    if not 1024 <= args.port <= 65535:
        raise SystemExit("invalid port")
    state.mkdir(mode=0o700)
    build = state / "build-context"
    build.mkdir(mode=0o700)
    for relative in ["acceptance/real-world/Dockerfile", "acceptance/real-world/entrypoint.sh", "acceptance/real-world/listener.py", "acceptance/real-world/beacon.py", "host-helper/huntwarden_helper.py", "rules/yara/webshell.yar"]:
        dest = build / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, dest)
    keys = build / "acceptance/real-world/.state"
    keys.mkdir(mode=0o700)
    for key in ["operator_ed25519", "unknown_ed25519"]:
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(state / key))
        shutil.copy2(state / f"{key}.pub", keys / f"{key}.pub")
    image = f"huntwarden-development:{identity}"
    command("docker", "build", "-t", image, "-f", str(build / "acceptance/real-world/Dockerfile"), str(build))
    command("docker", "run", "-d", "--name", container, "--memory", "512m", "--cpus", "2", "-p", f"127.0.0.1:{args.port}:22", image)
    try:
        for _ in range(90):
            ready = subprocess.run(["docker", "exec", container, "test", "-f", "/run/huntwarden-acceptance.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("fixture did not become ready")
        truth = json.loads(command("docker", "exec", container, "cat", "/run/huntwarden-acceptance.json", capture=True))
        # These are deployment/answer materials, not observed evidence. Do not
        # leave them available to Helper or the model during the investigation.
        command("docker", "exec", container, "rm", "/run/huntwarden-acceptance.json", "/opt/huntwarden-acceptance/entrypoint.sh")
        command("docker", "exec", container, "test", "!", "-e", "/run/huntwarden-acceptance.json")
        host_key = command("docker", "exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub", capture=True).strip().split()
        public = state / "host.pub"
        public.write_text(" ".join(host_key[:2]) + "\n")
        fingerprint = command("ssh-keygen", "-lf", str(public), "-E", "sha256", capture=True).split()[1]
        known_hosts = state / "known_hosts"
        known_hosts.write_text(f"[127.0.0.1]:{args.port} {' '.join(host_key[:2])}\n")
        known_hosts.chmod(0o600)
        private_json(state / "target.json", {"host": "127.0.0.1", "port": args.port, "username": "secagent", "hostFingerprint": fingerprint, "privateKeyPath": str(state / "operator_ed25519"), "knownHostsPath": str(known_hosts)})
        scoring = state / "scoring"
        scoring.mkdir(mode=0o700)
        private_json(scoring / "deployment-truth.json", {"evaluationMode": "DEVELOPMENT", "independent": False, "source": "acceptance/real-world/entrypoint.sh", "observedBeforeInvestigation": truth})
        private_json(state / "run-manifest.json", {"schemaVersion": 1, "suiteId": "local-real-world-development", "evaluationMode": "DEVELOPMENT", "profile": "DEEP", "timeWindowHours": 24, "cases": [{"caseId": "local-real-world-first", "runKind": "FIRST", "targetFile": "target.json", "checks": ["webshell"], "entryMode": "ZERO_IOC"}]})
        image_id = command("docker", "image", "inspect", image, "--format", "{{.Id}}", capture=True).strip()
        private_json(state / "prepared.json", {"schemaVersion": 1, "evaluationMode": "DEVELOPMENT", "container": container, "image": image_id, "hostKeyOutOfBandVerified": True, "truthRemovedFromTarget": True, "helperSha256": hashlib.sha256((ROOT / "host-helper/huntwarden_helper.py").read_bytes()).hexdigest()})
        print(json.dumps({"state": "PREPARED", "container": container, "truthRemovedFromTarget": True}))
    except BaseException:
        subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise


if __name__ == "__main__":
    main()
