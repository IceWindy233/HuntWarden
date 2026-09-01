import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { HelperCapabilitiesV2 } from "../../src/protocol-v2/types.js";
import { PROTOCOL_MANIFEST } from "../../src/protocol-v2/manifest.js";
import { PRESET_REGISTRY } from "../../src/presets/registry.js";
import { BUILTIN_YARA_RULESETS } from "../../src/rulesets/registry.js";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const helper = resolve(projectRoot, "host-helper/huntwarden_helper.py");

const collectorHarness = `
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
request = json.loads(sys.stdin.read() or "{}")
try:
    if sys.argv[2] != "v2_wire_error_code":
        ns["install_deadline"](request)
    result = ns[sys.argv[2]](request)
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, separators=(",", ":")))
except ns["HelperError"] as exc:
    print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}, ensure_ascii=False, separators=(",", ":")))
    raise SystemExit(1)
`;
const collectorOnly = new Set([
  "inspect_account", "inspect_process_fds", "verify_package_integrity", "search_web_access_log", "v2_wire_error_code",
]);
/** 在模块内替换源代次函数：第一次固化本页基线，第二次（页面产出后的复核）返回漂移值。 */
const sourceDriftHarness = `
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
request = json.loads(sys.stdin.read() or "{}")
enumerate_fn = ns["v2_enumerate"]
globals_dict = enumerate_fn.__globals__
globals_dict["install_deadline"](request)
original = globals_dict["v2_source_generation"]
calls = {"n": 0}
def drifting(namespace, params):
    calls["n"] += 1
    value = original(namespace, params)
    return value if calls["n"] == 1 else "drifted-" + value
globals_dict["v2_source_generation"] = drifting
objects, edges, cursor, gaps = enumerate_fn(request["params"], request["epochId"])
print(json.dumps({"objects": len(objects), "cursor": cursor, "gaps": gaps,
                  "consistency": sorted({item["consistency"] for item in objects})}, ensure_ascii=False))
`;
/** journald 常见写路径是追加已有文件；目录 mtime 不变时 generation 也必须变化。 */
const journalIdentityHarness = `
import json, pathlib, runpy, sys
ns = runpy.run_path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
generation_fn = ns["journal_generation"]
generation_fn.__globals__["JOURNAL_STORAGE_DIRECTORIES"] = (str(root),)
before = generation_fn()
journal = root / "machine" / "system.journal"
with journal.open("ab") as stream:
    stream.write(b"appended-event")
after = generation_fn()
prefix = "x" * 512
cursor_a = ns["log_event_cursor"]("journald", "2026-08-27T00:00:00.000Z", "sshd", prefix + "A")
cursor_b = ns["log_event_cursor"]("journald", "2026-08-27T00:00:00.000Z", "sshd", prefix + "B")
print(json.dumps({"before": before, "after": after, "cursorA": cursor_a, "cursorB": cursor_b}))
`;
const yaraIntegrityHarness = `
import json, pathlib, runpy, sys
ns = runpy.run_path(sys.argv[1])
reference, path, digest = sys.argv[2], pathlib.Path(sys.argv[3]), sys.argv[4]
ruleset_path_fn = ns["v2_yara_ruleset_path"]
ruleset_path_fn.__globals__["V2_YARA_RULESETS"] = {reference: {"path": path, "sha256": digest}}
accepted = str(ruleset_path_fn(reference))
with path.open("ab") as stream:
    stream.write(b"tampered")
try:
    ruleset_path_fn(reference)
    rejected = None
except ns["HelperError"] as exc:
    rejected = exc.code
print(json.dumps({"accepted": accepted, "rejected": rejected}))
`;
const advancingJournalRelationHarness = `
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
relate_fn = ns["v2_relate"]
globals_dict = relate_fn.__globals__
source_id = "a" * 64
generation = {"value": "relation-generation-a"}
globals_dict["v2_source_generation"] = lambda namespace, params: generation["value"]
globals_dict["v2_log_source_rows"] = lambda maximum: ([{"sourceId": source_id, "generation": "new-generation", "kind": "journald", "path": "/run/log/journal"}], [], False)
globals_dict["v2_query_events"] = lambda namespace, hours, maximum: {"items": [{"sourceId": source_id, "cursor": f"{index:064x}", "timestamp": "2026-08-27T00:00:00.000Z", "program": "fixture", "message": f"marker-{index}", "fields": {}} for index in range(170)], "partial": False, "warnings": []}
params = {"namespace": "log_source", "identity": {"sourceId": source_id, "generation": "old-generation"}, "locator": {"path": "/run/log/journal"}, "relation": "contains", "limit": 500}
objects, edges, cursor, gaps = relate_fn(params, "EPOCH-JOURNAL")
generation["value"] = "relation-generation-b"
next_objects, next_edges, next_cursor, next_gaps = relate_fn({**params, "cursor": cursor}, "EPOCH-JOURNAL")
enumerate_fn = ns["v2_enumerate"]
globals_dict["v2_query_events"] = lambda namespace, hours, maximum: {"items": [{"sourceId": source_id, "cursor": f"{index:064x}", "timestamp": "2026-08-27T00:00:00.000Z", "program": "fixture", "message": f"marker-{index}", "fields": {}} for index in range(510)], "partial": False, "warnings": []}
generation["value"] = "enumerate-generation-a"
enumerate_params = {"namespace": "log_event", "fields": ["sourceId", "cursor", "program", "message"], "sinceHours": 1, "limit": 500}
enum_objects, enum_edges, enum_cursor, enum_gaps = enumerate_fn(enumerate_params, "EPOCH-JOURNAL")
generation["value"] = "enumerate-generation-b"
enum_next_objects, enum_next_edges, enum_next_cursor, enum_next_gaps = enumerate_fn({**enumerate_params, "cursor": enum_cursor}, "EPOCH-JOURNAL")
print(json.dumps({"objects": len(objects), "fromGeneration": edges[0]["fromIdentity"]["identity"]["generation"], "gaps": gaps,
                  "nextObjects": len(next_objects), "nextGaps": next_gaps,
                  "enumNextObjects": len(enum_next_objects), "enumNextGaps": enum_next_gaps}))
`;

function invoke(operation: string, input: unknown) {
  const result = collectorOnly.has(operation)
    ? spawnSync("python3", ["-c", collectorHarness, helper, operation], { input: JSON.stringify(input), encoding: "utf8" })
    : spawnSync("python3", [helper, operation], { input: JSON.stringify(input), encoding: "utf8" });
  return { ...result, envelope: JSON.parse(result.stdout) as Record<string, unknown> };
}

describe("目标辅助程序边界", () => {
  it("返回版本化能力清单并声明 Artifact 传输", () => {
    const result = invoke("capabilities", {
      protocolVersion: 2, requestId: "REQ-CAPABILITIES", epochId: "PRECHECK", deadlineMs: 10_000,
      reservation: { reservationId: "PRECHECK", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } }, params: {},
    });
    expect(result.status).toBe(0);
    expect(result.envelope).toMatchObject({ protocolVersion: 2, requestId: "REQ-CAPABILITIES", status: "SUCCESS", capabilities: {
      protocolVersion: 2, manifestVersion: "2.1.0", helper: { name: "huntwarden-helper-v2", version: "2.1.0" },
      verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
      namespaces: {
        process: { fields: expect.arrayContaining(["pid", "startTicks", "exeInode", "exeSha256"]), relations: expect.arrayContaining(["parent", "children", "opens", "connects"]) },
        file: { relations: expect.arrayContaining(["opened_by", "referenced_by_persistence", "requested_in"]) },
        account: { relations: expect.arrayContaining(["authorized_key", "login_event"]) },
        delegation_rule: { fields: expect.arrayContaining(["mechanism", "sourceDigest", "line", "ruleDigest", "statement"]), verbs: expect.arrayContaining(["enumerate"]) },
        ssh_trust_config: { fields: expect.arrayContaining(["scope", "directive", "valueDigest", "effective"]), verbs: expect.arrayContaining(["enumerate"]) },
        log_event: { fields: expect.arrayContaining(["sourceId", "cursor", "program", "message"]) },
        log_source: { relations: expect.arrayContaining(["contains"]) },
        web_stack: { relations: expect.arrayContaining(["serves_root"]) },
        web_root: { relations: expect.arrayContaining(["served_by"]) },
      },
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536 },
    } });
    const capabilities = result.envelope.capabilities as HelperCapabilitiesV2;
    for (const [namespace, advertised] of Object.entries(capabilities.namespaces)) {
      const manifest = PROTOCOL_MANIFEST.namespaces[namespace as keyof typeof PROTOCOL_MANIFEST.namespaces];
      expect(manifest, `Helper 不得声明 Manifest 外 namespace: ${namespace}`).toBeDefined();
      expect(advertised!.fields.every((field) => Boolean(manifest?.fields[field]))).toBe(true);
      expect(advertised!.relations.every((relation) => manifest?.relations.includes(relation))).toBe(true);
    }
    // Preset 是启动调查时的必经路径；它不能请求 Helper 明确不产出的字段，否则每次运行
    // 都会人为制造 FIELD_UNAVAILABLE，并把 required step 永久降成 PARTIAL。
    for (const preset of PRESET_REGISTRY) {
      for (const step of preset.steps.filter((item) => item.verb === "enumerate")) {
        const namespace = step.params.namespace;
        const fields = step.params.fields;
        if (typeof namespace !== "string" || !Array.isArray(fields)) continue;
        const advertised = capabilities.namespaces[namespace as keyof HelperCapabilitiesV2["namespaces"]];
        expect(advertised, `${preset.presetId}/${step.stepId} 的 namespace 必须由 Helper 声明`).toBeDefined();
        expect(fields.every((field) => typeof field === "string" && advertised!.fields.includes(field)), `${preset.presetId}/${step.stepId} 不得请求不可用字段`).toBe(true);
      }
    }
    expect(capabilities.namespaces.web_stack?.fields).not.toContain("version");
    expect(capabilities.namespaces.jvm?.fields).not.toContain("version");
    expect(capabilities.namespaces.package?.fields).not.toContain("integrity");
    expect(capabilities.namespaces.module?.fields).not.toContain("sha256");
  });

  it("collect 只返回 Artifact Token，并可一次性释放", async () => {
    const source = resolve(projectRoot, "package.json");
    const info = await stat(source);
    const collected = invoke("collect", {
      protocolVersion: 2, requestId: "REQ-COLLECT", epochId: "EPOCH-1", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-COLLECT", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_048_576, wallTimeMs: 10_000, probeCalls: 0 } },
      params: { namespace: "file", identity: { mountId: String(info.dev), device: String(info.dev), inode: String(info.ino) }, locator: { path: source }, maxBytes: 1024 * 1024 },
    });
    if (process.platform !== "linux") {
      // 采集固定经 procfs 复用已复核身份的 fd；控制端为 macOS 时目标能力缺失必须显式声明，
      // 不能漏成 INTERNAL_ERROR。真实采集与释放链路由 Docker MERGE 门禁在 Linux 上覆盖。
      expect(collected.envelope).toMatchObject({ status: "ERROR", error: { code: "UNSUPPORTED_CAPABILITY" } });
      return;
    }
    expect(collected.envelope).toMatchObject({ status: "SUCCESS" });
    const artifact = collected.envelope.artifact as { token: string; sha256: string; size: number; complete: boolean };
    expect(collected.envelope).not.toHaveProperty("dataBase64");
    expect(artifact.token).toMatch(/^[a-f0-9]{64}$/);
    expect(artifact.complete).toBe(true);
    const staged = resolve(tmpdir(), "huntwarden-artifacts", `${artifact.token}.artifact`);
    expect((await readFile(staged)).length).toBe(artifact.size);
    const released = invoke("artifact_release", {
      protocolVersion: 2, requestId: "REQ-RELEASE", epochId: "MAINTENANCE", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-RELEASE", estimate: { remoteCalls: 1, nodes: 1, bytes: 1024, wallTimeMs: 10_000, probeCalls: 0 } },
      params: { artifactToken: artifact.token },
    });
    expect(released.envelope).toMatchObject({ protocolVersion: 2, requestId: "REQ-RELEASE", status: "SUCCESS", maintenanceResult: { released: true } });
    await expect(access(staged)).rejects.toThrow();
  });

  it("不接受任意操作名", () => {
    const result = invoke("bash", { command: "id" });
    expect(result.status).toBe(2);
    expect(result.envelope).toMatchObject({ protocolVersion: 2, status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
  });

  it("生产入口拒绝 v1 operation，并且只声明真实 matcher 能力", () => {
    const legacy = invoke("get_host_info", {});
    expect(legacy.status).toBe(2);
    const capabilities = invoke("capabilities", {
      protocolVersion: 2, requestId: "REQ-MATCHERS", epochId: "PRECHECK", deadlineMs: 10_000,
      reservation: { reservationId: "PRECHECK", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } }, params: {},
    }).envelope.capabilities as { matchers: string[] };
    expect(capabilities.matchers).toContain("literal");
    expect(capabilities.matchers).not.toContain("yara");
  });

  it("YARA 只接受内置版本化 RuleSet 引用，拒绝模型源码和任意路径", () => {
    const base = { protocolVersion: 2, epochId: "EPOCH-YARA", deadlineMs: 10_000, reservation: { reservationId: "BRES-YARA", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
    const source = invoke("match", { ...base, requestId: "REQ-YARA-SOURCE", params: { objects: [], matcher: { engine: "yara", pattern: "rule injected { condition: true }" }, maxHits: 1, includeContext: false } });
    expect(source.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    const path = invoke("match", { ...base, requestId: "REQ-YARA-PATH", params: { objects: [], matcher: { engine: "yara", ruleSetRef: "/tmp/evil.yar" }, maxHits: 1, includeContext: false } });
    expect(path.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
  });

  it("YARA RuleSet 摘要与控制端 Registry 一致，目标文件被篡改后 fail-close", async () => {
    const directory = await mkdtemp(resolve(await realpath(tmpdir()), "huntwarden-v2-yara-"));
    try {
      const rule = resolve(directory, "webshell.yar");
      await writeFile(rule, await readFile(resolve(projectRoot, "rules/yara/webshell.yar")));
      const reference = "RULESET-WEBSHELL-BUILTIN-2";
      const result = spawnSync("python3", ["-c", yaraIntegrityHarness, helper, reference, rule, BUILTIN_YARA_RULESETS[reference].sha256], { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({ accepted: rule, rejected: "UNSUPPORTED_CAPABILITY" });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("SCAN 或缺少绑定审批的维护请求在目标端写 gate 前被拒绝", () => {
    const base = {
      protocolVersion: 2, requestId: "REQ-WRITE-GATE", epochId: "EPOCH-1", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-WRITE", estimate: { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 10_000, probeCalls: 0 } },
    };
    const missing = invoke("quarantine_file", { ...base, params: {} });
    expect(missing.envelope).toMatchObject({ status: "ERROR", error: { code: "PERMISSION_DENIED" } });
    const scan = invoke("quarantine_file", { ...base, params: {
      authorization: { mode: "SCAN", tool: "quarantine_file", actionId: "ACT-00000000-0000-4000-8000-000000000001", wireArgsDigest: "0".repeat(64) },
      action: { actionId: "ACT-00000000-0000-4000-8000-000000000001" },
    } });
    expect(scan.envelope).toMatchObject({ status: "ERROR", error: { code: "PERMISSION_DENIED" } });
  });

  it("enumerate 仅返回显式请求字段和稳定身份", () => {
    const result = invoke("enumerate", {
      protocolVersion: 2, requestId: "REQ-ACCOUNT", epochId: "EPOCH-1", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-ACCOUNT", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } },
      params: { namespace: "account", fields: ["uid", "username"], limit: 1 },
    });
    expect(result.envelope).toMatchObject({ protocolVersion: 2, requestId: "REQ-ACCOUNT", objects: [{ namespace: "account" }] });
    const fields = (result.envelope.objects as Array<{ fields: Record<string, unknown> }>)[0]!.fields;
    expect(Object.keys(fields).sort()).toEqual(["uid", "username"]);
  });

  it("v2 Envelope、Predicate 与错误码在 Helper 边界 fail-close", () => {
    const estimate = { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 };
    const missingEpoch = invoke("enumerate", { protocolVersion: 2, requestId: "REQ-NO-EPOCH", deadlineMs: 10_000, reservation: { reservationId: "BRES-NO-EPOCH", estimate }, params: { namespace: "account", fields: ["uid"], limit: 1 } });
    expect(missingEpoch.envelope).toMatchObject({ status: "ERROR", error: { code: "EPOCH_MISMATCH" } });
    const unreserved = invoke("enumerate", { protocolVersion: 2, requestId: "REQ-BAD-BUDGET", epochId: "EPOCH-1", deadlineMs: 10_000, reservation: { reservationId: "BRES-BAD", estimate: { ...estimate, remoteCalls: 0 } }, params: { namespace: "account", fields: ["uid"], limit: 1 } });
    expect(unreserved.envelope).toMatchObject({ status: "ERROR", error: { code: "BUDGET_EXHAUSTED" } });
    const unknownField = invoke("enumerate", { protocolVersion: 2, requestId: "REQ-BAD-PREDICATE", epochId: "EPOCH-1", deadlineMs: 10_000, reservation: { reservationId: "BRES-PRED", estimate }, params: { namespace: "account", fields: ["uid"], predicate: { op: "eq", field: "invented", value: 0 }, limit: 1 } });
    expect(unknownField.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    const oversizedIn = invoke("enumerate", { protocolVersion: 2, requestId: "REQ-LARGE-IN", epochId: "EPOCH-1", deadlineMs: 10_000, reservation: { reservationId: "BRES-IN", estimate }, params: { namespace: "account", fields: ["uid"], predicate: { op: "in", field: "uid", value: Array.from({ length: 65 }, (_, index) => index) }, limit: 1 } });
    expect(oversizedIn.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    expect(invoke("v2_wire_error_code", "EVIDENCE_COLLECTION").envelope).toMatchObject({ ok: true, result: "EVIDENCE_COLLECTION_FAILED" });
    expect(invoke("v2_wire_error_code", "INVENTED_HELPER_ERROR").envelope).toMatchObject({ ok: true, result: "INTERNAL_ERROR" });
  });

  it("分页 Cursor 是绑定请求与源代次的不透明令牌，源变化后拒绝续页", async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-v2-cursor-"));
    try {
      await writeFile(resolve(directory, "a.txt"), "a"); await writeFile(resolve(directory, "b.txt"), "b");
      const base = { protocolVersion: 2, epochId: "EPOCH-CURSOR", deadlineMs: 10_000, reservation: { reservationId: "BRES-CURSOR", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
      const params = { namespace: "file", scope: { namespace: "file", canonicalRoot: directory }, fields: ["path"], limit: 1 };
      const first = invoke("enumerate", { ...base, requestId: "REQ-CURSOR-1", params });
      expect(first.envelope).toMatchObject({ status: "PARTIAL", cursor: expect.any(String) });
      expect(String(first.envelope.cursor)).not.toMatch(/^\d+$/);
      await writeFile(resolve(directory, "c.txt"), "c");
      const second = invoke("enumerate", { ...base, requestId: "REQ-CURSOR-2", params: { ...params, cursor: first.envelope.cursor } });
      expect(second.envelope).toMatchObject({ status: "ERROR", error: { code: "SOURCE_CHANGED" } });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("INV-07：v2 read 只接受绑定身份的普通文件，目录、符号链接与超限 length 一律 fail-close", async () => {
    // macOS 的 /var 是符号链接，而 Helper 逐段以 O_NOFOLLOW 打开：临时目录必须先取 canonical 路径。
    const directory = await mkdtemp(resolve(await realpath(tmpdir()), "huntwarden-v2-read-"));
    try {
      const plain = resolve(directory, "plain.txt");
      await writeFile(plain, "marker-read-boundary\n");
      await mkdir(resolve(directory, "sub"));
      await symlink(plain, resolve(directory, "link.txt"));
      const info = await stat(plain);
      const identity = { mountId: String(info.dev), device: String(info.dev), inode: String(info.ino) };
      const base = { protocolVersion: 2, epochId: "EPOCH-READ", deadlineMs: 10_000, reservation: { reservationId: "BRES-READ", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
      const read = (requestId: string, path: string, length = 64) => invoke("read", { ...base, requestId, params: { namespace: "file", identity, locator: { path }, offset: 0, length, encoding: "utf-8", purpose: "SYSTEM_TEXT" } });

      const allowed = read("REQ-READ-OK", plain);
      expect(allowed.envelope).toMatchObject({ status: "SUCCESS", objects: [{ namespace: "file", fields: { contentClass: "SENSITIVE_TEXT" } }] });
      expect(String((allowed.envelope.objects as Array<{ fields: { content?: string } }>)[0]?.fields.content)).toContain("marker-read-boundary");
      expect(read("REQ-READ-DIR", resolve(directory, "sub")).envelope).toMatchObject({ status: "ERROR", error: { code: "PERMISSION_DENIED" } });
      expect(read("REQ-READ-LINK", resolve(directory, "link.txt")).envelope).toMatchObject({ status: "ERROR", error: { code: "STALE_REF" } });
      expect(read("REQ-READ-BIG", plain, 70_000).envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("match includeContext 返回带字节偏移的有界脱敏上下文，1 MiB 扫描窗口仍写成 BYTE_LIMIT gap", async () => {
    const directory = await mkdtemp(resolve(await realpath(tmpdir()), "huntwarden-v2-match-"));
    try {
      const target = resolve(directory, "large.txt");
      // 命中串只出现在 1 MiB 窗口之外：此前 Helper 静默只扫描文件头，未命中会被当成真阴性。
      await writeFile(target, `${"a".repeat(1024 * 1024 + 16)}needle-past-window\n`);
      const info = await stat(target);
      const object = { namespace: "file", identity: { mountId: String(info.dev), device: String(info.dev), inode: String(info.ino) }, locator: { path: target } };
      const base = { protocolVersion: 2, epochId: "EPOCH-MATCH", deadlineMs: 10_000, reservation: { reservationId: "BRES-MATCH", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
      const bounded = invoke("match", { ...base, requestId: "REQ-MATCH-WINDOW", params: { objects: [object], matcher: { engine: "literal", pattern: "needle-past-window" }, maxHits: 1, includeContext: false } });
      expect(bounded.envelope).toMatchObject({ status: "PARTIAL", objects: [] });
      expect((bounded.envelope.gaps as Array<{ code: string }>).map((gap) => gap.code)).toContain("BYTE_LIMIT");

      const hit = resolve(directory, "hit.txt");
      // 命中点落在文件中段，才能验证窗口两侧都被截取，而不是恰好等于文件头。
      await writeFile(hit, `${"x".repeat(400)}needle password=hunter2 tail${"y".repeat(400)}\n`);
      const hitInfo = await stat(hit);
      const hitObject = { namespace: "file", identity: { mountId: String(hitInfo.dev), device: String(hitInfo.dev), inode: String(hitInfo.ino) }, locator: { path: hit } };
      const context = invoke("match", { ...base, requestId: "REQ-MATCH-CTX", params: { objects: [hitObject], matcher: { engine: "literal", pattern: "needle" }, maxHits: 1, includeContext: true } });
      expect(context.envelope.status).toBe("SUCCESS");
      const content = String((context.envelope.objects as Array<{ fields: Record<string, unknown> }>)[0]?.fields.content);
      const [marker, ...windows] = content.split("\n");
      expect(marker).toBe("MATCH");
      expect(windows).toHaveLength(1);
      // 偏移是字节偏移，可以直接交给 read；窗口以命中点为中心，因此起点在命中点之前。
      const offset = Number(/^@(\d+):/.exec(windows[0] ?? "")?.[1]);
      expect(offset).toBe(400 - 128);
      expect(windows[0]).toContain("needle");
      // 上下文与 read 共用脱敏，凭据不得原样出境。
      expect(windows[0]).toContain("password=[REDACTED]");
      expect(windows[0]).not.toContain("hunter2");
      expect(content.length).toBeLessThanOrEqual(2560);

      // 无效 UTF-8 会被替换显示，但窗口标签仍必须指向原始文件字节。旧实现把每个
      // U+FFFD 重编码成 3 字节，导致命中点之后的 read offset 持续漂移。
      const invalidUtf8 = resolve(directory, "invalid-utf8.txt");
      await writeFile(invalidUtf8, Buffer.concat([Buffer.alloc(200, 0xff), Buffer.from("needle-after-invalid") ]));
      const invalidUtf8Info = await stat(invalidUtf8);
      const invalidUtf8Object = { namespace: "file", identity: { mountId: String(invalidUtf8Info.dev), device: String(invalidUtf8Info.dev), inode: String(invalidUtf8Info.ino) }, locator: { path: invalidUtf8 } };
      const invalidUtf8Context = invoke("match", { ...base, requestId: "REQ-MATCH-INVALID-UTF8", params: { objects: [invalidUtf8Object], matcher: { engine: "literal", pattern: "needle" }, maxHits: 1, includeContext: true } });
      expect(invalidUtf8Context.envelope.status).toBe("SUCCESS");
      const invalidUtf8Content = String((invalidUtf8Context.envelope.objects as Array<{ fields: Record<string, unknown> }>)[0]?.fields.content);
      expect(/^MATCH\n@72:/.test(invalidUtf8Content)).toBe(true);

      // Helper 自身也要 fail-close；即使控制端被绕过，也不能把 DENIED_TEXT 上下文送出。
      const denied = resolve(directory, "id_rsa");
      await writeFile(denied, "needle-private-key");
      const deniedInfo = await stat(denied);
      const deniedObject = { namespace: "file", identity: { mountId: String(deniedInfo.dev), device: String(deniedInfo.dev), inode: String(deniedInfo.ino) }, locator: { path: denied } };
      const deniedContext = invoke("match", { ...base, requestId: "REQ-MATCH-DENIED-CTX", params: { objects: [deniedObject], matcher: { engine: "literal", pattern: "needle" }, maxHits: 1, includeContext: true } });
      expect(deniedContext.envelope).toMatchObject({ status: "ERROR", error: { code: "PERMISSION_DENIED" } });

      const invalid = invoke("match", { ...base, requestId: "REQ-MATCH-FLAG", params: { objects: [hitObject], matcher: { engine: "literal", pattern: "needle" }, maxHits: 1, includeContext: "yes" } });
      expect(invalid.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("journald 追加写入会推进源代次，事件游标绑定完整原始载荷", async () => {
    const directory = await mkdtemp(resolve(await realpath(tmpdir()), "huntwarden-v2-journal-"));
    try {
      await mkdir(resolve(directory, "machine"));
      await writeFile(resolve(directory, "machine/system.journal"), "initial-event");
      const result = spawnSync("python3", ["-c", journalIdentityHarness, helper, directory], { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
      const report = JSON.parse(result.stdout) as { before: string; after: string; cursorA: string; cursorB: string };
      expect(report.before).not.toBe(report.after);
      expect(report.cursorA).not.toBe(report.cursorB);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });

  it("journald 在 sudo 调用间推进 generation 时 contains 仍可达并显式报告 SOURCE_CHANGED", () => {
    const result = spawnSync("python3", ["-c", advancingJournalRelationHarness, helper], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout) as { objects: number; fromGeneration: string; gaps: Array<{ code: string }>; nextObjects: number; nextGaps: Array<{ code: string }>; enumNextObjects: number; enumNextGaps: Array<{ code: string }> };
    expect(report.objects).toBeGreaterThan(0);
    expect(report.fromGeneration).toBe("old-generation");
    expect(report.gaps).toEqual(expect.arrayContaining([expect.objectContaining({ code: "SOURCE_CHANGED" })]));
    expect(report.nextObjects).toBeGreaterThan(0);
    expect(report.nextGaps).toEqual(expect.arrayContaining([expect.objectContaining({ code: "SOURCE_CHANGED" })]));
    expect(report.enumNextObjects).toBe(10);
    expect(report.enumNextGaps).toEqual(expect.arrayContaining([expect.objectContaining({ code: "SOURCE_CHANGED" })]));
  });

  it("enumerate 分页按稳定身份排序，不重不漏；页内源变化降级为 PARTIAL 而不是丢弃整页", async () => {
    const directory = await mkdtemp(resolve(await realpath(tmpdir()), "huntwarden-v2-page-"));
    try {
      for (const name of ["a.txt", "b.txt", "c.txt"]) await writeFile(resolve(directory, name), name);
      const base = { protocolVersion: 2, epochId: "EPOCH-PAGE", deadlineMs: 10_000, reservation: { reservationId: "BRES-PAGE", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
      const params = { namespace: "file", scope: { namespace: "file", canonicalRoot: directory }, fields: ["path"], limit: 2 };
      const first = invoke("enumerate", { ...base, requestId: "REQ-PAGE-1", params });
      expect(first.envelope).toMatchObject({ status: "PARTIAL", cursor: expect.any(String) });
      const second = invoke("enumerate", { ...base, requestId: "REQ-PAGE-2", params: { ...params, cursor: first.envelope.cursor } });
      expect(second.envelope.cursor).toBeUndefined();
      const paths = [...first.envelope.objects as Array<{ fields: { path: string } }>, ...second.envelope.objects as Array<{ fields: { path: string } }>]
        .map((object) => object.fields.path);
      expect(new Set(paths).size).toBe(3);
      expect(paths.map((path) => path.split("/").pop()).sort()).toEqual(["a.txt", "b.txt", "c.txt"]);

      // 白盒：源代次在页面产出后才变化，无法从 CLI 外部构造，只能在模块内注入。
      const drifted = spawnSync("python3", ["-c", sourceDriftHarness, helper], {
        input: JSON.stringify({ ...base, requestId: "REQ-PAGE-DRIFT", params: { ...params, limit: 1 } }), encoding: "utf8",
      });
      expect(drifted.status, drifted.stderr).toBe(0);
      const report = JSON.parse(drifted.stdout) as { objects: number; cursor: string | null; gaps: Array<{ code: string; resumable: boolean }>; consistency: string[] };
      expect(report.objects).toBe(1);
      expect(report.cursor).toEqual(expect.any(String));
      expect(report.gaps).toEqual(expect.arrayContaining([expect.objectContaining({ code: "SOURCE_CHANGED", resumable: true })]));
      expect(report.consistency).toEqual(["CURSOR_BEST_EFFORT"]);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });


  it("拒绝目录穿越", () => {
    const traversal = invoke("read", {
      protocolVersion: 2, requestId: "REQ-TRAVERSAL", epochId: "EPOCH-1", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-TRAVERSAL", estimate: { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 10_000, probeCalls: 0 } },
      params: { namespace: "file", identity: { mountId: "1", device: "1", inode: "1" }, locator: { path: "/tmp/../etc/passwd" }, offset: 0, length: 64, encoding: "utf-8", purpose: "SYSTEM_TEXT" },
    });
    expect(traversal.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
  });

  it("拒绝危险用户名", () => {
    const result = invoke("inspect_account", { username: "root;id" });
    expect(result.status).toBe(1);
    expect(result.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
  });

  it("拒绝越界枚举预算和不完整的稳定进程身份", () => {
    const base = { protocolVersion: 2, epochId: "EPOCH-1", deadlineMs: 10_000, reservation: { reservationId: "BRES-LIMIT", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
    const limit = invoke("enumerate", { ...base, requestId: "REQ-LIMIT", params: { namespace: "process", fields: ["pid"], limit: 10_001 } });
    expect(limit.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    const identity = invoke("project", { ...base, requestId: "REQ-IDENTITY", params: { namespace: "process", identity: { bootId: "invalid", pid: 1 }, fields: ["comm"] } });
    expect(identity.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
  });

  it("INV-09：process namespace 结构上不暴露环境变量，请求该字段直接被拒", () => {
    const base = { protocolVersion: 2, epochId: "EPOCH-1", deadlineMs: 10_000, reservation: { reservationId: "BRES-ENV", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } } };
    const capabilities = invoke("capabilities", { ...base, requestId: "REQ-ENV-CAP", params: {} }).envelope.capabilities as HelperCapabilitiesV2;
    // v1 曾把进程环境作为快照字段返回（只给变量名）；v2 Manifest 里根本没有该字段，
    // 因此“不返回变量值”不再依赖实现自觉，而是结构上不可请求。
    expect(capabilities.namespaces.process?.fields ?? []).not.toEqual(expect.arrayContaining(["environment", "env"]));
    for (const field of ["environment", "env"]) {
      const rejected = invoke("enumerate", { ...base, requestId: `REQ-ENV-${field}`, params: { namespace: "process", fields: [field], limit: 1 } });
      expect(rejected.envelope).toMatchObject({ status: "ERROR", error: { code: "INVALID_ARGUMENT" } });
    }
  });

  it("包完整性核验拒绝目录穿越和非固定目录", () => {
    const traversal = invoke("verify_package_integrity", {
      path: "/tmp/../etc/passwd", expectedInode: "1", expectedSha256: "0".repeat(64),
    });
    expect(traversal.envelope).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });

    const outside = invoke("verify_package_integrity", {
      path: "/etc/passwd", expectedInode: "1", expectedSha256: "0".repeat(64),
    });
    expect(outside.envelope).toMatchObject({ ok: false, error: { code: "PERMISSION_DENIED" } });
  });

  it("known_hash_set 核验只重观测绑定文件哈希，集合内容留在控制端", async () => {
    const source = resolve(projectRoot, "package.json");
    const info = await stat(source);
    const result = invoke("verify", {
      protocolVersion: 2, requestId: "REQ-KNOWN-HASH", epochId: "EPOCH-KNOWN-HASH", deadlineMs: 10_000,
      reservation: { reservationId: "BRES-KNOWN-HASH", estimate: { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 10_000, probeCalls: 0 } },
      params: { namespace: "file", identity: { mountId: String(info.dev), device: String(info.dev), inode: String(info.ino) }, locator: { path: source }, baseline: "known_hash_set", dataSetRef: "DATASET-00000000-0000-4000-8000-000000000211" },
    });
    expect(result.envelope).toMatchObject({ status: "SUCCESS", objects: [{ fields: { baseline: "known_hash_set:DATASET-00000000-0000-4000-8000-000000000211", baselineStatus: "UNKNOWN", sha256: expect.stringMatching(/^[a-f0-9]{64}$/) } }] });
  });


  it("访问日志搜索返回可降级的信封并列出实际扫描过的日志", () => {
    // 此前该操作返回裸数组，没有 partial/warnings 通道：日志缺失与"扫过但无命中"无法区分。
    const result = invoke("search_web_access_log", { path: "/tmp", fileName: "shell.php", maxLines: 10 });
    expect(result.status).toBe(0);
    const output = result.envelope.result as { items: unknown[]; scannedLogs: string[]; partial: boolean; warnings: string[] };
    expect(Array.isArray(output.items)).toBe(true);
    expect(Array.isArray(output.scannedLogs)).toBe(true);
    expect(typeof output.partial).toBe("boolean");
    if (output.scannedLogs.length === 0) {
      expect(output.partial).toBe(true);
      expect(output.warnings.join(" ")).toContain("访问日志");
    }
  });
});
