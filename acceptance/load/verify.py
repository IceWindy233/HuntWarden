#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import threading
import time

CONTAINER = "huntwarden-load-target"
HELPER = "/usr/local/libexec/huntwarden-helper"


class ResourceSampler:
    """Docker 周期采样；报告采样最大值，不将其描述为内核峰值。"""

    def __init__(self) -> None:
        self.samples: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            ["docker", "stats", "--format", "{{json .}}", CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            # Docker 可能向流添加清屏控制符；只读取 JSON 对象。
            start = line.find("{")
            if start < 0:
                continue
            try:
                sample, _end = json.JSONDecoder().raw_decode(line[start:])
                self.samples.append({"elapsedMs": int((time.monotonic() - self.started) * 1000), **sample})
            except (ValueError, TypeError) as exc:
                self.errors.append(str(exc))

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()

    def report(self) -> dict[str, object]:
        if len(self.samples) < 2 or self.errors:
            raise RuntimeError(f"资源采样不完整: samples={len(self.samples)}, errors={self.errors}")
        return {"source": "docker stats streaming", "sampleCount": len(self.samples),
                "maxSampledCpuPercent": max(float(str(item["CPUPerc"]).rstrip("%")) for item in self.samples),
                "maxSampledPids": max(int(str(item["PIDs"])) for item in self.samples),
                "samples": list(self.samples)}


def invoke(params: dict[str, object], sequence: int) -> dict[str, object]:
    request = {
        "protocolVersion": 2,
        "requestId": f"LOAD-{sequence}",
        "epochId": "EPOCH-LOAD-ACCEPTANCE",
        "deadlineMs": 600000,
        "reservation": {
            "reservationId": f"BRES-LOAD-{sequence}",
            "estimate": {"remoteCalls": 1, "nodes": 5000, "bytes": 1572864, "wallTimeMs": 600000, "probeCalls": 0},
        },
        "params": params,
    }
    completed = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "python3", HELPER, "enumerate"],
        input=json.dumps(request), text=True, capture_output=True, timeout=620, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Helper 退出 {completed.returncode}: {completed.stderr}")
    response = json.loads(completed.stdout)
    if response.get("status") == "ERROR":
        raise RuntimeError(json.dumps(response, ensure_ascii=False))
    return response


def walk(params: dict[str, object], max_pages: int) -> tuple[list[dict[str, object]], dict[str, object]]:
    started = time.monotonic()
    page_latencies: list[int] = []
    objects: list[dict[str, object]] = []
    cursor = None
    sequence = 0
    scanned = 0
    pages = 0
    partial_pages = 0
    gap_codes: set[str] = set()
    cost_nodes = 0
    while True:
        sequence += 1
        pages += 1
        page_params = {**params, **({"cursor": cursor} if cursor else {})}
        page_started = time.monotonic()
        response = invoke(page_params, sequence)
        page_latencies.append(int((time.monotonic() - page_started) * 1000))
        page = response.get("objects")
        scan = response.get("scan")
        if not isinstance(page, list) or not isinstance(scan, dict):
            raise RuntimeError("响应缺少 objects/scan")
        objects.extend(page)
        scanned += int(scan.get("scannedCount", 0))
        cost = response.get("cost")
        if not isinstance(cost, dict) or int(cost.get("nodes", -1)) != int(scan.get("scannedCount", -2)):
            raise RuntimeError("响应成本没有按本页实际扫描节点结算")
        cost_nodes += int(cost["nodes"])
        if response.get("status") == "PARTIAL":
            partial_pages += 1
        for gap in response.get("gaps", []):
            if isinstance(gap, dict) and isinstance(gap.get("code"), str):
                gap_codes.add(str(gap["code"]))
        cursor = response.get("cursor")
        if not cursor:
            if scan.get("complete") is not True:
                raise RuntimeError("无 Cursor 的末页未声明 complete")
            break
        if pages >= max_pages:
            raise RuntimeError(f"超过 {max_pages} 页仍未结束")
    return objects, {"pages": pages, "scanned": scanned, "costNodes": cost_nodes,
                     "elapsedMs": int((time.monotonic() - started) * 1000),
                     "firstPageMs": page_latencies[0], "pageLatenciesMs": page_latencies,
                     "partialPages": partial_pages, "gapCodes": sorted(gap_codes)}


def verify(sampler: ResourceSampler) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--process-count", type=int, required=True)
    parser.add_argument("--file-count", type=int, required=True)
    parser.add_argument("--log-count", type=int, required=True)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    started = time.monotonic()
    processes, process_scan = walk(
        {"namespace": "process", "fields": ["pid", "exe"], "sort": [{"field": "pid", "direction": "asc"}], "limit": 500},
        max_pages=64,
    )
    fixture_processes = [item for item in processes if item.get("fields", {}).get("exe") == "/usr/local/bin/huntwarden-process-fixture"]
    identities = {json.dumps(item.get("identity"), sort_keys=True) for item in fixture_processes}
    expected_processes = args.process_count + 1
    if len(fixture_processes) != expected_processes or len(identities) != expected_processes:
        raise RuntimeError(f"进程总集错误: expected={expected_processes}, returned={len(fixture_processes)}, unique={len(identities)}")

    files, file_scan = walk(
        {"namespace": "file", "scope": {"namespace": "file", "canonicalRoot": "/load/files"}, "fields": ["path"], "sort": [{"field": "path", "direction": "asc"}], "limit": 500},
        max_pages=256,
    )
    expected_files = args.file_count + 1
    paths = [item.get("fields", {}).get("path") for item in files]
    if len(paths) != expected_files or len(set(paths)) != expected_files:
        raise RuntimeError(f"文件总集错误: expected={expected_files}, returned={len(paths)}, unique={len(set(paths))}")
    if "/load/files/fixture-count" not in paths:
        raise RuntimeError("文件分页遗漏 fixture-count 哨兵")

    logs, log_scan = walk(
        {"namespace": "log_event", "fields": ["sourceId", "cursor", "timestamp", "program", "message"], "sinceHours": 1, "limit": 500},
        max_pages=2048,
    )
    expected_logs = args.log_count
    log_identities = {json.dumps(item.get("identity"), sort_keys=True) for item in logs}
    messages = [str(item.get("fields", {}).get("message", "")) for item in logs]
    if len(logs) != expected_logs or len(log_identities) != expected_logs:
        raise RuntimeError(f"日志总集错误: expected={expected_logs}, returned={len(logs)}, unique={len(log_identities)}")
    if not any("HUNTWARDEN_ACTIVE_SENTINEL" in message for message in messages):
        raise RuntimeError("日志窗口遗漏活动日志哨兵")
    if not any("HUNTWARDEN_ROTATED_SENTINEL" in message for message in messages):
        raise RuntimeError("日志窗口遗漏 gzip 轮转哨兵")
    if "COLLECTOR_ERROR" in log_scan["gapCodes"]:
        raise RuntimeError(f"日志夹具在声明边界内却未完整扫描: {log_scan}")

    stats = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", CONTAINER],
        text=True, capture_output=True, timeout=30, check=True,
    ).stdout.strip()
    report = {
        "status": "PASS",
        "processes": {"expected": expected_processes, "returned": len(fixture_processes), **process_scan},
        "files": {"expected": expected_files, "returned": len(paths), **file_scan},
        "logs": {"generated": args.log_count, "expected": expected_logs, "returned": len(logs), **log_scan},
        "elapsedMs": int((time.monotonic() - started) * 1000),
        "containerStats": json.loads(stats) if stats else {},
        "resourceSampling": sampler.report(),
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


def main() -> int:
    sampler = ResourceSampler()
    try:
        return verify(sampler)
    finally:
        sampler.close()


if __name__ == "__main__":
    raise SystemExit(main())
