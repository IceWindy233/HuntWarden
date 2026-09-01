#!/usr/bin/env python3
"""Release-gate smoke for actual RE2 semantics through the production Helper."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile


HELPER = pathlib.Path(sys.argv[1]).resolve()
ESTIMATE = {"remoteCalls": 1, "nodes": 10, "bytes": 1_572_864, "wallTimeMs": 10_000, "probeCalls": 0}


def invoke(verb: str, request_id: str, params: dict[str, object]) -> dict[str, object]:
    request = {
        "protocolVersion": 2,
        "requestId": request_id,
        "epochId": "EPOCH-RE2-MATRIX",
        "deadlineMs": 10_000,
        "reservation": {"reservationId": f"BRES-{request_id}", "estimate": ESTIMATE},
        "params": params,
    }
    result = subprocess.run([sys.executable, str(HELPER), verb], input=json.dumps(request), text=True, capture_output=True, check=False)
    if not result.stdout:
        raise RuntimeError(f"Helper returned no JSON: {result.stderr}")
    return json.loads(result.stdout)


capabilities = invoke("capabilities", "RE2-CAP", {})
assert capabilities["status"] == "SUCCESS", capabilities
assert "re2" in capabilities["capabilities"]["matchers"], capabilities

with tempfile.NamedTemporaryFile("w", prefix="huntwarden-re2-", suffix=".txt", dir=str(HELPER.parent), delete=False) as handle:
    handle.write("HuntWarden   RE2 semantic matrix\n")
    sample = pathlib.Path(handle.name)
try:
    info = sample.stat()
    binding = {
        "namespace": "file",
        "identity": {"mountId": str(info.st_dev), "device": str(info.st_dev), "inode": str(info.st_ino)},
        "locator": {"path": str(sample)},
    }
    matched = invoke("match", "RE2-MATCH", {
        "objects": [binding], "matcher": {"engine": "re2", "pattern": "(?i)huntwarden\\s+re2"},
        "maxHits": 10, "includeContext": False,
    })
    assert matched["status"] == "SUCCESS" and len(matched["objects"]) == 1, matched

    # Python re accepts this backreference; RE2 rejects it. INVALID_ARGUMENT
    # proves the Helper did not silently change engines.
    rejected = invoke("match", "RE2-NO-FALLBACK", {
        "objects": [binding], "matcher": {"engine": "re2", "pattern": r"(HuntWarden)\1"},
        "maxHits": 10, "includeContext": False,
    })
    assert rejected["status"] == "ERROR" and rejected["error"]["code"] == "INVALID_ARGUMENT", rejected
finally:
    sample.unlink(missing_ok=True)

print(json.dumps({"platform": sys.platform, "machine": os.uname().machine, "re2": "PASS", "semanticFallback": "REJECTED"}, separators=(",", ":")))
