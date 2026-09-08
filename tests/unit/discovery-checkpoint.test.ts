import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { gateCapabilities } from "../../src/protocol-v2/capability.js";
import type { HelperCapabilitiesV2, ScanEpoch, TaskGrant } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createV2SecurityTools } from "../../src/tools/v2/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("远程扫描检查点", () => {
  it.each([false, true])("跨空匹配页累计数量并保留前页采集限制：%s", async (limitedFirstPage) => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-checkpoint-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = { ...testTask(), protocolVersion: 2 as const, checks: ["backdoor_account" as const] }; store.createTask(task);
    const epoch: ScanEpoch = { epochId: "EPOCH-CHECKPOINT", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() }; store.createScanEpoch(epoch); task.activeEpochId = epoch.epochId;
    const helper: HelperCapabilitiesV2 = { protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" }, namespaces: { account: { fields: ["uid", "username", "gid", "home", "shell"], relations: [], verbs: ["enumerate"] } }, matchers: [], probes: [], verbs: ["enumerate"], limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 } };
    const grant: TaskGrant = { grantId: "GRANT-ACCOUNT", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "backdoor_account" }, createdAt: new Date().toISOString() }; store.putTaskGrant(grant);
    let page = 0;
    const executor = new FakeProtocolV2Executor(helper, async (_verb, request) => {
      page += 1;
      return {
        protocolVersion: 2, requestId: request.requestId, status: page === 1 ? "PARTIAL" : "SUCCESS", objects: page === 1 ? [] : [{ namespace: "account", identity: { uid: 1000, username: "alice" }, fields: { uid: 1000, username: "alice", gid: 1000, home: "/home/alice", shell: "/bin/bash" }, observedAt: new Date().toISOString(), consistency: "CURSOR_BEST_EFFORT" }], edges: [],
        ...(page === 1 ? { cursor: "helper-cursor-1", gaps: [{ code: "NODE_LIMIT" as const, resumable: true }, ...(limitedFirstPage ? [{ code: "COLLECTOR_ERROR" as const, resumable: false, detail: "轮转日志来源未扫描" }] : [])] } : { gaps: [] }),
        scan: { sourceGeneration: "generation-1", scannedCount: 3, matchedCount: page === 1 ? 0 : 1, returnedCount: page === 1 ? 0 : 1, nextOffset: page * 3, complete: page !== 1 },
        cost: { remoteCalls: 1, nodes: 3, bytes: 512, wallTimeMs: 5, probeCalls: 0 },
      };
    });
    // enumerate 预留完整扫描页上限（5000 nodes），收到 Wire cost 后再按实际 3 nodes 结算。
    store.initializeBudget(task.taskId, epoch.epochId, "MODEL", { remoteCalls: 10, nodes: 6_000, bytes: 20_000_000, wallTimeMs: 100_000, probeCalls: 0 });
    const tools = createV2SecurityTools({ task, epoch, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, [grant]), approvals: new ApprovalService(store), budgetOwner: "MODEL" });
    const enumerate = tools.find((tool) => tool.name === "enumerate")!;
    const args = { namespace: "account", fields: ["uid", "username", "gid", "home", "shell"], limit: 3 };
    const first = await enumerate.execute("CALL-CHECKPOINT-1", args as never);
    const firstDetails = first.details as { status: string; cursorRef: string; objectRefs: string[] };
    expect(firstDetails).toMatchObject({ status: "partial", cursorRef: expect.any(String), objectRefs: [] });
    expect(store.listDiscoveryCheckpoints(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ status: limitedFirstPage ? "LIMITED" : "RUNNING", scannedCount: 3, matchedCount: 0, returnedCount: 0, cursorRef: firstDetails.cursorRef })]);
    await enumerate.execute("CALL-CHECKPOINT-2", { ...args, cursorRef: firstDetails.cursorRef } as never);
    expect(store.listDiscoveryCheckpoints(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ status: limitedFirstPage ? "LIMITED" : "COMPLETE", scannedCount: 6, matchedCount: 1, returnedCount: 1,
      ...(limitedFirstPage ? { remainingDescription: expect.stringContaining("轮转日志来源未扫描") } : {}),
    })]);
    // 从头重扫拥有独立的范围判定，旧一轮缺口不应永久污染新扫描。
    await enumerate.execute("CALL-CHECKPOINT-RESTART", args as never);
    expect(store.listDiscoveryCheckpoints(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ status: "COMPLETE", scannedCount: 3, returnedCount: 1 })]);
    store.close();
  });
});
