import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { createKnownHashDataSet, parseKnownHashSetImport } from "../../src/datasets/known-hash-registry.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { gateCapabilities } from "../../src/protocol-v2/capability.js";
import type { HelperCapabilitiesV2, ScanEpoch, TaskGrant } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createV2SecurityTools } from "../../src/tools/v2/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("v2 known_hash_set 数据集注册表", () => {
  it("版本不可变、引用可发现，并在控制端完成 MATCH 裁定且不向目标下发哈希集合", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-known-hash-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = { ...testTask(), protocolVersion: 2 as const };
    store.createTask(task);
    const epoch: ScanEpoch = { epochId: "EPOCH-00000000-0000-4000-8000-000000000211", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "2.1.0", helperVersion: "2.1.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() };
    store.createScanEpoch(epoch);
    store.initializeBudget(task.taskId, epoch.epochId, "MODEL", testConfig(directory).protocolV2.remoteBudget.model);
    const observedAt = new Date().toISOString();
    const observedSha = "a".repeat(64);
    const initial = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "DATASET-SEED", source: { kind: "SYSTEM" }, targetFingerprint: task.target.hostFingerprint, requestId: "DATASET-SEED", collector: { name: "test", version: "2.0.0" }, observations: [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "211" }, fields: { mountId: "1", device: "1", inode: "211", path: "/usr/bin/example", sha256: observedSha }, observedAt, consistency: "OBJECT_STABLE" }], edges: [], gaps: [], wireDigest: "1".repeat(64) });

    const imported = store.putKnownHashDataSet(createKnownHashDataSet({ name: "发行版基线", version: "2026.08", sha256: [observedSha, observedSha.toUpperCase()] }));
    expect(store.listKnownHashDataSets()).toEqual([expect.objectContaining({ dataSetRef: imported.dataSetRef, entryCount: 1 })]);
    expect(store.putKnownHashDataSet(createKnownHashDataSet({ name: "发行版基线", version: "2026.08", sha256: [observedSha] })).dataSetRef).toBe(imported.dataSetRef);
    expect(() => store.putKnownHashDataSet(createKnownHashDataSet({ name: "发行版基线", version: "2026.08", sha256: ["b".repeat(64)] }))).toThrow(/版本不可变/);

    const grant: TaskGrant = { grantId: "GRANT-DATASET", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "webshell" }, createdAt: observedAt };
    store.putTaskGrant(grant);
    const helper: HelperCapabilitiesV2 = { protocolVersion: 2, manifestVersion: "2.1.0", helper: { name: "helper", version: "2.1.0" }, namespaces: { file: { fields: ["path", "sha256", "baseline", "baselineStatus"], relations: [], verbs: ["verify"] } }, matchers: [], probes: [], verbs: ["verify"], limits: { maxObjects: 10, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 1024 } };
    const executor = new FakeProtocolV2Executor(helper, async (_verb, request) => ({ protocolVersion: 2, requestId: request.requestId, status: "SUCCESS", objects: [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "211" }, fields: { mountId: "1", device: "1", inode: "211", path: "/usr/bin/example", sha256: observedSha, baseline: `known_hash_set:${imported.dataSetRef}`, baselineStatus: "UNKNOWN" }, observedAt, consistency: "EXTERNAL_BASELINE" }], edges: [], cost: { remoteCalls: 1, nodes: 1, bytes: 2048, wallTimeMs: 1, probeCalls: 0 }, gaps: [] }));
    const tools = createV2SecurityTools({ task: { ...task, activeEpochId: epoch.epochId }, epoch, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, [grant]), approvals: new ApprovalService(store), budgetOwner: "MODEL" });
    const describe = tools.find((tool) => tool.name === "describe_capabilities");
    const verify = tools.find((tool) => tool.name === "verify");
    if (!describe || !verify) throw new Error("缺少 v2 数据集工具路径");
    const described = await describe.execute("DESCRIBE-DATASET", {});
    expect(JSON.stringify(described.details)).toContain(imported.dataSetRef);
    await verify.execute("VERIFY-DATASET", { ref: initial.facts[0]!.subjectRef, baseline: "known_hash_set", dataSetRef: imported.dataSetRef });
    expect(executor.calls[0]?.request.params).toEqual(expect.objectContaining({ dataSetRef: imported.dataSetRef }));
    expect(JSON.stringify(executor.calls[0]?.request.params)).not.toContain(observedSha);
    expect(store.listFacts(task.taskId, epoch.epochId, { sourceRunId: "VERIFY-DATASET" })[0]?.privatePayload).toMatchObject({ baselineStatus: "MATCH", sha256: observedSha });
    store.close();
  });

  it("导入格式严格拒绝未知字段和非 SHA-256 值", () => {
    expect(() => parseKnownHashSetImport({ name: "x", version: "1", sha256: ["nope"] })).toThrow(/SHA-256/);
    expect(() => parseKnownHashSetImport({ name: "x", version: "1", sha256: ["a".repeat(64)], sourcePath: "/tmp/list" })).toThrow(/未知字段/);
  });
});
