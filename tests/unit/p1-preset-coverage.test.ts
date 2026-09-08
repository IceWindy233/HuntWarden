import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { PROTOCOL_MANIFEST } from "../../src/protocol-v2/manifest.js";
import type { HelperCapabilitiesV2, NamespaceName, WireObservation, WireSuccess } from "../../src/protocol-v2/types.js";
import { bootstrapProtocolV2 } from "../../src/runtime/v2-bootstrap.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testConfig, testTask } from "../helpers.js";

const stores: RuntimeStore[] = [];
afterEach(() => { for (const store of stores.splice(0)) store.close(); });

const observedAt = "2026-08-29T00:00:00.000Z";
function observation(namespace: NamespaceName, identity: Record<string, unknown>, fields: Record<string, unknown>, consistency: WireObservation["consistency"] = "POINT_IN_TIME"): WireObservation {
  return { namespace, identity, fields: { ...identity, ...fields }, observedAt, consistency };
}

describe("P1 最低覆盖 Preset", () => {
  it("易失枚举首屏提交后立即推进调查，不等待后续 Cursor 页", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-prelude-page-"));
    const store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
    const task = testTask(); task.protocolVersion = 2; task.checks = ["linux_intrusion_triage"]; task.profile = "DEEP"; store.createTask(task);
    const namespace = (name: NamespaceName) => ({
      fields: Object.keys(PROTOCOL_MANIFEST.namespaces[name].fields), relations: [], verbs: ["enumerate" as const],
    });
    const capabilities: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: { process: namespace("process"), socket: namespace("socket") },
      matchers: [], probes: [], verbs: ["enumerate"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    let sawActionBeforeSecondPage = false;
    let secondPageRunId = "";
    const executor = new FakeProtocolV2Executor(capabilities, async (_verb, request) => {
      const name = request.params.namespace;
      const isSecondProcessPage = name === "process" && typeof request.params.cursor === "string";
      if (isSecondProcessPage) {
        const epochId = task.activeEpochId; if (!epochId) throw new Error("第二页前缺少活动 Epoch");
        sawActionBeforeSecondPage = store.listInvestigationActions(task.taskId, epochId)
          .some((action) => action.requestedBy === "DISCOVERY" && action.operationRef === "collect");
        secondPageRunId = request.requestId;
      }
      const objects = name === "process"
        ? isSecondProcessPage
          ? [observation("process", { bootId: "00000000-0000-4000-8000-000000000001", pid: 11, startTicks: "101", exeInode: "8", exeSha256: "c".repeat(64) }, { ppid: 1, uid: 0, username: "root", comm: "init", exe: "/usr/bin/init", state: "S", startedAt: observedAt })]
          : [observation("process", { bootId: "00000000-0000-4000-8000-000000000001", pid: 10, startTicks: "100", exeInode: "7", exeSha256: "b".repeat(64) }, { ppid: 1, uid: 0, username: "root", comm: ".beacon", exe: "/var/tmp/.beacon", state: "S", startedAt: observedAt })]
        : [];
      return {
        protocolVersion: 2, requestId: request.requestId, status: "SUCCESS", objects, edges: [], gaps: [],
        ...(name === "process" ? {
          scan: { sourceGeneration: "boot:1", scannedCount: objects.length, matchedCount: objects.length, returnedCount: objects.length, nextOffset: isSecondProcessPage ? 2 : 1, complete: isSecondProcessPage },
          ...(isSecondProcessPage ? {} : { cursor: "process-page-2" }),
        } : {
          scan: { sourceGeneration: "socket:1", scannedCount: 0, matchedCount: 0, returnedCount: 0, nextOffset: 0, complete: true },
        }),
        cost: { remoteCalls: 1, nodes: objects.length, bytes: 1024, wallTimeMs: 1, probeCalls: 0 },
      } as WireSuccess;
    });
    const result = await bootstrapProtocolV2({ task, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store) });
    expect(sawActionBeforeSecondPage).toBe(true);
    const events = store.listInvestigationEvents(task.taskId, result.epoch.epochId, 0, 5_000);
    const firstCollect = events.find((event) => event.eventType === "ACTION_CREATED" && event.payload.operationRef === "collect");
    const secondPageBatch = events.find((event) => event.eventType === "FACT_BATCH_COMMITTED" && event.payload.sourceRunId === secondPageRunId);
    expect(firstCollect).toBeDefined(); expect(secondPageBatch).toBeDefined();
    expect(firstCollect!.eventSeq).toBeLessThan(secondPageBatch!.eventSeq);
  });

  it("Linux 分诊自动建立固定 file scopes，并从 package 关系执行真实 package_db verify", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-p1-preset-"));
    const store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
    const task = testTask(); task.protocolVersion = 2; task.checks = ["webshell", "linux_intrusion_triage"]; task.profile = "DEEP"; task.timeWindowHours = 72; store.createTask(task);
    const namespace = (name: NamespaceName, verbs: HelperCapabilitiesV2["verbs"], relations: string[] = []) => ({
      fields: Object.keys(PROTOCOL_MANIFEST.namespaces[name].fields), relations, verbs,
    });
    const capabilities: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: {
        web_stack: namespace("web_stack", ["enumerate"]), web_root: namespace("web_root", ["enumerate"]),
        log_source: namespace("log_source", ["enumerate"]),
        process: namespace("process", ["enumerate"]), socket: namespace("socket", ["enumerate"]),
        file: namespace("file", ["enumerate", "match", "verify"]), auth_event: namespace("auth_event", ["enumerate"]),
        exec_event: namespace("exec_event", ["enumerate"]), module: namespace("module", ["enumerate"]),
        package: namespace("package", ["enumerate", "relate"], ["owns_file"]),
      },
      matchers: ["literal", "yara"], probes: [], verbs: ["enumerate", "match", "relate", "verify"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    const executable = observation("file", { mountId: "1", device: "1", inode: "7" }, { path: "/usr/bin/yes", canonicalPath: "/usr/bin/yes", kind: "regular", size: 100, mode: 493, uid: 0, gid: 0, mtime: observedAt, contentClass: "SENSITIVE_TEXT" });
    const handler = async (verb: string, request: { requestId: string; params: Record<string, unknown> }): Promise<WireSuccess> => {
      let objects: WireObservation[] = [];
      const name = request.params.namespace;
      if (verb === "relate") objects = [executable];
      else if (verb === "verify") objects = [{ ...executable, fields: { ...executable.fields, sha256: "a".repeat(64), baseline: "package_db", baselineStatus: "MISMATCH" }, consistency: "EXTERNAL_BASELINE" }];
      else if (name === "web_stack") objects = [observation("web_stack", { kind: "nginx", instanceId: "nginx-main" }, { pid: 1, configPaths: ["/etc/nginx/nginx.conf"] })];
      else if (name === "web_root") objects = [observation("web_root", { mountId: "1", device: "1", inode: "6" }, { path: "/var/www/html", server: "nginx", effective: true })];
      else if (name === "log_source") objects = [observation("log_source", { sourceId: "1".repeat(64), generation: "boot-1" }, { kind: "file", path: "/var/log/nginx/access.log" })];
      else if (name === "process") objects = [observation("process", { bootId: "00000000-0000-4000-8000-000000000001", pid: 10, startTicks: "100", exeInode: "7", exeSha256: "b".repeat(64) }, { ppid: 1, uid: 0, username: "root", comm: "init", exe: "/usr/bin/init", state: "S", startedAt: observedAt })];
      else if (name === "socket") objects = [observation("socket", { protocol: "tcp", localAddress: "127.0.0.1", localPort: 22, remoteAddress: "0.0.0.0", remotePort: 0, inode: "8" }, { state: "LISTEN", pid: 10 })];
      else if (name === "auth_event") objects = [observation("auth_event", { sourceId: "c".repeat(64), cursor: "d".repeat(64) }, { timestamp: observedAt, eventType: "login", username: "root", sourceAddress: "127.0.0.1", program: "sshd", success: true })];
      else if (name === "exec_event") objects = [observation("exec_event", { sourceId: "e".repeat(64), cursor: "f".repeat(64) }, { timestamp: observedAt, pid: 10, uid: 0, executable: "/usr/bin/yes", arguments: "yes", cwd: "/" })];
      else if (name === "module") objects = [observation("module", { name: "kernel", address: "0x1" }, { size: 1, path: "/sys/module/kernel" })];
      else if (name === "package") objects = [observation("package", { manager: "dpkg", name: "coreutils", version: "1", architecture: "amd64" }, {})];
      else if (name === "file") objects = request.params.scope && (request.params.scope as Record<string, unknown>).canonicalRoot === "/usr/bin"
        ? [executable]
        : Array.isArray(request.params.fields) && !request.params.fields.includes("kind")
          ? [observation("file", { mountId: "1", device: "1", inode: "10" }, { path: "/var/www/html/normal.php", canonicalPath: "/var/www/html/normal.php", kind: "regular", size: 32, mode: 420, uid: 33, gid: 33, mtime: "2010-01-02T03:04:05.000Z", contentClass: "SENSITIVE_TEXT" })]
        : [observation("file", { mountId: "1", device: "1", inode: "9" }, { path: "/tmp/marker", canonicalPath: "/tmp/marker", kind: "regular", size: 1, mode: 420, uid: 0, gid: 0, mtime: observedAt, contentClass: "SENSITIVE_TEXT" })];
      return { protocolVersion: 2, requestId: request.requestId, status: "SUCCESS", objects, edges: [], cost: { remoteCalls: 1, nodes: objects.length, bytes: 1024, wallTimeMs: 1, probeCalls: 0 }, gaps: [] };
    };
    const executor = new FakeProtocolV2Executor(capabilities, handler as never, {}, async (verb, request) => {
      if (verb !== "scope_resolve") throw new Error(`unexpected maintenance ${verb}`);
      const requestedRoot = String(request.params.requestedRoot);
      return { namespace: "file", canonicalRoot: requestedRoot, mountId: "1", device: "1", inode: requestedRoot === "/usr/bin" ? "2" : "3" };
    });

    const result = await bootstrapProtocolV2({ task, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store) });
    expect(executor.calls.slice(0, 2).map((call) => [call.verb, call.request.params.namespace])).toEqual([["enumerate", "process"], ["enumerate", "socket"]]);
    const coverage = store.listCoverageRuns(task.taskId, result.epoch.epochId).find((item) => item.category === "linux_intrusion_triage");
    expect(coverage).toMatchObject({ status: "COMPLETE", completedCriteria: expect.arrayContaining(["file-scopes", "package-inventory", "package-verify"]) });
    expect(store.listInvestigationObligations(task.taskId, result.epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ obligationKind: "CATEGORY_SCOPE_LINUX_INTRUSION_TRIAGE", status: "SATISFIED", resultRefs: [coverage!.coverageId] }),
      expect.objectContaining({ obligationKind: "CATEGORY_SCOPE_WEBSHELL", status: "SATISFIED" }),
    ]));
    expect(executor.maintenanceCalls.filter((call) => call.verb === "scope_resolve").map((call) => call.request.params.requestedRoot)).toEqual(["/usr/bin", "/tmp"]);
    expect(executor.calls.some((call) => call.verb === "relate" && call.request.params.relation === "owns_file")).toBe(true);
    expect(executor.calls.some((call) => call.verb === "verify" && call.request.params.baseline === "package_db")).toBe(true);
    expect(executor.calls.filter((call) => call.verb === "enumerate" && ["auth_event", "exec_event"].includes(String(call.request.params.namespace))).map((call) => call.request.params.sinceHours)).toEqual([72, 72]);
    const filePredicates = executor.calls
      .filter((call) => call.verb === "enumerate" && call.request.params.namespace === "file")
      .map((call) => call.request.params.predicate)
      .filter((value) => value !== undefined);
    expect(filePredicates).toContainEqual({ op: "gte", field: "mtime", value: "1970-01-01T00:00:00.000Z" });
    expect(filePredicates.some((value) => Date.parse(String((value as Record<string, unknown>).value)) > Date.parse("1970-01-01T00:00:00.000Z"))).toBe(false);
    expect(executor.calls.some((call) => call.verb === "match" && (call.request.params.matcher as Record<string, unknown>).ruleSetRef === "RULESET-WEBSHELL-BUILTIN-2")).toBe(true);
    expect(executor.calls.filter((call) => call.verb === "match")).toHaveLength(1);
    expect(store.listAssessments(task.taskId, result.epoch.epochId).some((assessment) => assessment.category === "webshell")).toBe(false);
    expect(store.listFacts(task.taskId, result.epoch.epochId).some((fact) => fact.privatePayload.baselineStatus === "MISMATCH")).toBe(true);
    expect(store.listAssessments(task.taskId, result.epoch.epochId).some((assessment) => assessment.rationale.includes("HW2-PACKAGE-INTEGRITY-001"))).toBe(true);
  });
});
