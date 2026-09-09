import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Type } from "typebox";
import { digestObject } from "../../src/common/json.js";
import { VolatileDiscoveryPlanner } from "../../src/discovery/volatile-discovery.js";
import type { SecurityToolDefinition } from "../../src/domain/types.js";
import { InvestigationActionExecutor } from "../../src/investigation/action-executor.js";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import { InvestigationScheduler } from "../../src/investigation/scheduler.js";
import type { InvestigationAction, InvestigationObligation, InvestigationSession } from "../../src/investigation/types.js";
import { InvestigationPlaybookPlanner } from "../../src/playbooks/registry.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import { MAX_ACTIVE_INVESTIGATION_ACTIONS, RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
const stores: RuntimeStore[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-investigation-state-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  stores.push(store);
  const task = testTask();
  task.protocolVersion = 2;
  store.createTask(task);
  const epoch: ScanEpoch = {
    epochId: "EPOCH-00000000-0000-4000-8000-000000000101",
    taskId: task.taskId,
    targetFingerprint: task.target.hostFingerprint,
    protocolVersion: 2,
    manifestVersion: "3.0.0",
    helperVersion: "3.0.0",
    reason: "INITIAL",
    status: "RUNNING",
    startedAt: new Date().toISOString(),
  };
  store.createScanEpoch(epoch);
  task.activeEpochId = epoch.epochId;
  store.saveTask(task);
  const observedAt = new Date().toISOString();
  const fact = store.commitFactBatch({
    taskId: task.taskId,
    epochId: epoch.epochId,
    sourceRunId: "DISCOVERY-1",
    source: { kind: "SYSTEM" },
    targetFingerprint: task.target.hostFingerprint,
    requestId: "DISCOVERY-1",
    collector: { name: "enumerate", version: "2.1.0" },
    observations: [{ namespace: "process", identity: { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "a".repeat(64) }, fields: { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "a".repeat(64), uid: 1000 }, observedAt, consistency: "OBJECT_STABLE" }],
    edges: [],
    gaps: [],
    wireDigest: "b".repeat(64),
  }).facts[0]!;
  return { directory, store, task, epoch, fact, observedAt };
}

function session(taskId: string, epochId: string, now: string): InvestigationSession {
  return {
    sessionId: "ISESS-00000000-0000-4000-8000-000000000001",
    taskId,
    epochId,
    engineVersion: "1.0.0",
    playbookRegistryDigest: "a".repeat(64),
    ruleRegistryDigest: "b".repeat(64),
    authorizationVersion: "AUTH-1",
    executionStatus: "RUNNING",
    investigationStatus: "OPEN",
    revision: 0,
    createdAt: now,
    updatedAt: now,
  };
}

function obligation(taskId: string, epochId: string, subjectRef: string, now: string): InvestigationObligation {
  return {
    obligationId: "OBL-00000000-0000-4000-8000-000000000001",
    taskId,
    epochId,
    obligationKind: "CAPTURE_EXECUTABLE",
    dedupeKey: `CAPTURE_EXECUTABLE:${subjectRef}`,
    subjectRefs: [subjectRef],
    required: true,
    status: "OPEN",
    resultRefs: [],
    gapRefs: [],
    createdAt: now,
    updatedAt: now,
  };
}

function action(input: { id: string; taskId: string; epochId: string; obligationId: string; subjectRef: string; now: string; priority: number; dependsOn?: string[]; replayPolicy?: InvestigationAction["replayPolicy"] }): InvestigationAction {
  const args = { ref: input.subjectRef, fields: ["pid"] };
  return {
    actionId: input.id,
    taskId: input.taskId,
    epochId: input.epochId,
    kind: "REMOTE_PRIMITIVE",
    requestedBy: "PLAYBOOK",
    obligationIds: [input.obligationId],
    subjectRefs: [input.subjectRef],
    entityVersionRefs: [],
    operationRef: "enumerate",
    replayPolicy: input.replayPolicy ?? "SAFE_REOBSERVE",
    args,
    argsDigest: digestObject(args),
    dependsOn: input.dependsOn ?? [],
    authorizationVersion: "AUTH-1",
    observationRound: "ROUND-1",
    idempotencyKey: `${input.taskId}:${input.epochId}:${input.id}`,
    priority: input.priority,
    status: "READY",
    revision: 0,
    createdAt: input.now,
    updatedAt: input.now,
  };
}

describe("持久化调查状态", () => {
  it("文件证据采集按已观察 size 预留而不是固定占用 100 MiB", async () => {
    const { store, task, epoch, observedAt } = await fixture();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const fileIdentity = { mountId: "36", device: "259:2", inode: "9901" };
    const fileSize = 1_234_567;
    const batch = store.commitFactBatch({
      taskId: task.taskId,
      epochId: epoch.epochId,
      sourceRunId: "PROCESS-EXECUTABLE-FILE",
      source: { kind: "SYSTEM" },
      targetFingerprint: task.target.hostFingerprint,
      requestId: "PROCESS-EXECUTABLE-FILE",
      collector: { name: "relate", version: "3.0.0" },
      observations: [{
        namespace: "file",
        identity: fileIdentity,
        fields: { ...fileIdentity, path: "/usr/sbin/nginx", kind: "regular", size: fileSize, mode: 493, uid: 0, gid: 0, mtime: observedAt },
        observedAt,
        consistency: "OBJECT_STABLE",
      }],
      edges: [{
        relation: "executable",
        fromIdentity: {
          namespace: "process",
          identity: { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "a".repeat(64) },
        },
        toIdentity: { namespace: "file", identity: fileIdentity },
        observedAt,
      }],
      gaps: [],
      wireDigest: "e".repeat(64),
    });
    const investigation = session(task.taskId, epoch.epochId, observedAt);
    store.createInvestigationSession(investigation);

    new InvestigationPlaybookPlanner(store).plan(task.taskId, epoch.epochId, investigation, [batch.facts[0]!.factId]);

    const preserve = store.listInvestigationActions(task.taskId, epoch.epochId)
      .find((item) => item.operationRef === "collect" && item.subjectRefs.includes(batch.facts[0]!.subjectRef));
    expect(preserve).toMatchObject({
      requestedBy: "PLAYBOOK",
      args: { ref: batch.facts[0]!.subjectRef, maxBytes: fileSize, purpose: "PROCESS_RELATED_FILE_PRESERVATION" },
    });
  });

  it.each([101, 501])("易失发现分批推进且在容量释放后继续：%s 个候选", async (candidateCount) => {
    const { store, task, epoch, observedAt } = await fixture();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "SOCKET-BREADTH", source: { kind: "SYSTEM" },
      targetFingerprint: task.target.hostFingerprint, requestId: "SOCKET-BREADTH", collector: { name: "enumerate", version: "3.0.0" },
      observations: Array.from({ length: candidateCount }, (_, index) => ({
        namespace: "socket" as const,
        identity: { protocol: "tcp", localAddress: "10.0.0.1", localPort: 10000 + index, remoteAddress: "8.8.8.8", remotePort: 443, inode: String(index + 1) },
        fields: { protocol: "tcp", localAddress: "10.0.0.1", localPort: 10000 + index, remoteAddress: "8.8.8.8", remotePort: 443, inode: String(index + 1) },
        observedAt, consistency: "CURSOR_BEST_EFFORT" as const,
      })), edges: [], gaps: [], wireDigest: "c".repeat(64),
    });
    const planner = new VolatileDiscoveryPlanner(store);
    const investigation = session(task.taskId, epoch.epochId, observedAt);
    store.putCoverageRun({ coverageId: "COV-BREADTH", taskId: task.taskId, epochId: epoch.epochId,
      category: "linux_intrusion_triage", presetId: "PRESET-LINUX-TRIAGE", presetVersion: "2.5.0",
      status: "COMPLETE", applicability: "APPLICABLE", completedCriteria: ["process_inventory", "socket_inventory"],
      missingCriteria: [], createdAt: observedAt });
    expect(planner.plan(task.taskId, epoch.epochId, investigation).leadIds).toHaveLength(100);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId).find((item) => item.obligationKind === "VOLATILE_DISCOVERY_SCOPE"))
      .toMatchObject({ status: "LIMITED", gapRefs: ["CANDIDATE_QUEUE_LIMIT"] });
    if (candidateCount === 101) {
      const unplanned = store.listFacts(task.taskId, epoch.epochId).find((fact) => fact.namespace === "socket" && fact.privatePayload.localPort === 10100)!;
      const template = store.listInvestigationActions(task.taskId, epoch.epochId)[0]!;
      for (let index = 0; index < 2; index += 1) {
        const args = { ref: unplanned.subjectRef, relation: "unrelated", limit: index + 1 };
        store.putInvestigationAction({ ...template, actionId: `UNRELATED-${index}`, subjectRefs: [unplanned.subjectRef], args,
          argsDigest: digestObject(args), idempotencyKey: `UNRELATED-${index}` });
      }
    }
    if (candidateCount === 501) {
      for (let round = 0; round < 4; round += 1) expect(planner.plan(task.taskId, epoch.epochId, investigation).leadIds).toHaveLength(100);
      expect(planner.plan(task.taskId, epoch.epochId, investigation).leadIds).toHaveLength(0);
      expect(store.listInvestigationActions(task.taskId, epoch.epochId).every((action) => action.status === "READY")).toBe(true);
      for (let index = 0; index < 2; index += 1) {
        const claim = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "capacity-test", "AUTH-1")!;
        store.finishInvestigationAction(claim.action.actionId, claim.action.revision, "SUCCEEDED");
      }
    }
    expect(planner.plan(task.taskId, epoch.epochId, investigation).leadIds).toHaveLength(1);
    expect(planner.plan(task.taskId, epoch.epochId, investigation).leadIds).toHaveLength(0);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId).find((item) => item.obligationKind === "VOLATILE_DISCOVERY_SCOPE"))
      .toMatchObject({ status: "SATISFIED", gapRefs: [] });
    expect(store.listInvestigationLeads(task.taskId, epoch.epochId)).toHaveLength(candidateCount);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toHaveLength(candidateCount * 2 + (candidateCount === 101 ? 2 : 0));
  });
  it("Fact 提交自动形成实体版本区间和可追溯关系", async () => {
    const { store, task, epoch, fact } = await fixture();
    const later = new Date(Date.now() + 1_000).toISOString();
    const parentIdentity = { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "a".repeat(64) };
    const childIdentity = { bootId: "boot", pid: 43, startTicks: "11", exeInode: "21", exeSha256: "c".repeat(64) };
    const second = store.commitFactBatch({
      taskId: task.taskId,
      epochId: epoch.epochId,
      sourceRunId: "DISCOVERY-2",
      source: { kind: "SYSTEM" },
      targetFingerprint: task.target.hostFingerprint,
      requestId: "DISCOVERY-2",
      collector: { name: "relate", version: "2.1.0" },
      observations: [
        { namespace: "process", identity: parentIdentity, fields: { ...parentIdentity, uid: 0 }, observedAt: later, consistency: "OBJECT_STABLE" },
        { namespace: "process", identity: childIdentity, fields: { ...childIdentity, uid: 1000 }, observedAt: later, consistency: "OBJECT_STABLE" },
      ],
      edges: [{ relation: "children", fromIdentity: { namespace: "process", identity: parentIdentity }, toIdentity: { namespace: "process", identity: childIdentity }, observedAt: later }],
      gaps: [],
      wireDigest: "c".repeat(64),
    });
    const versions = store.listEntityVersions(task.taskId, epoch.epochId, fact.subjectRef);
    expect(versions).toHaveLength(2);
    expect(versions[0]?.validTo).toBe(later);
    expect(versions[1]?.sourceFactRef).toBe(second.facts[0]?.factId);
    expect(store.listRelationProvenance(task.taskId, epoch.epochId)).toEqual([
      expect.objectContaining({ edgeRef: second.edges[0]?.edgeId, derivation: "OBSERVED", fromVersionRef: versions[1]?.versionRef, toVersionRef: expect.any(String) }),
    ]);
  });

  it("会话使用 revision CAS，Lead 和 Obligation 按稳定键去重", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    const created = session(task.taskId, epoch.epochId, observedAt);
    store.createInvestigationSession(created);
    store.updateInvestigationSession({ ...created, revision: 1, executionStatus: "PAUSED", updatedAt: new Date().toISOString() }, 0);
    expect(() => store.updateInvestigationSession({ ...created, revision: 1, executionStatus: "FAILED", updatedAt: new Date().toISOString() }, 0)).toThrow(/其他执行路径/);

    const lead = { leadId: "LEAD-1", taskId: task.taskId, epochId: epoch.epochId, subjectRef: fact.subjectRef, triggerKind: "NEW_EXTERNAL_CONNECTION", triggerVersion: "1", triggerFactRefs: [fact.factId], observationRound: "ROUND-1", priority: 100, status: "OPEN" as const, createdAt: observedAt, updatedAt: observedAt };
    expect(store.putInvestigationLead(lead).leadId).toBe("LEAD-1");
    expect(store.putInvestigationLead({ ...lead, leadId: "LEAD-DUPLICATE" }).leadId).toBe("LEAD-1");
    const firstObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    const duplicateObligation = store.putInvestigationObligation({ ...firstObligation, obligationId: "OBL-DUPLICATE" });
    expect(duplicateObligation.obligationId).toBe(firstObligation.obligationId);
    expect(store.listInvestigationLeads(task.taskId, epoch.epochId)).toHaveLength(1);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toHaveLength(1);
    expect(store.listInvestigationEvents(task.taskId, epoch.epochId).map((item) => item.eventType)).toEqual(["FACT_BATCH_COMMITTED", "SESSION_CREATED", "SESSION_UPDATED", "LEAD_CREATED", "OBLIGATION_CREATED"]);
  });

  it("相同调查缺口按语义键去重，避免调度重试淹没真实原因", async () => {
    const { store, task, epoch, observedAt } = await fixture();
    for (const gapId of ["IGAP-FIRST", "IGAP-RETRY"]) store.putInvestigationGap({
      gapId, taskId: task.taskId, epochId: epoch.epochId,
      code: "BUDGET_DENIED", reasonCode: "EVIDENCE_BYTES", createdAt: observedAt,
    });
    store.putInvestigationGap({
      gapId: "IGAP-OTHER", taskId: task.taskId, epochId: epoch.epochId,
      code: "BUDGET_DENIED", reasonCode: "BUDGET_EXHAUSTED", createdAt: observedAt,
    });
    const gaps = store.listInvestigationGaps(task.taskId, epoch.epochId);
    expect(gaps).toHaveLength(2);
    expect(gaps).toEqual(expect.arrayContaining([
      expect.objectContaining({ gapId: "IGAP-FIRST", reasonCode: "EVIDENCE_BYTES" }),
      expect.objectContaining({ gapId: "IGAP-OTHER", reasonCode: "BUDGET_EXHAUSTED" }),
    ]));
  });

  it("Evidence 配额按最大授权预留，并在已知实际大小后归还未使用部分", async () => {
    const { store, task, epoch } = await fixture();
    store.initializeUsageCounter(task.taskId, epoch.epochId, "EVIDENCE_BYTES", 1_000);
    store.consumeUsage(task.taskId, epoch.epochId, "EVIDENCE_BYTES", 800);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "EVIDENCE_BYTES")).toBe(200);
    store.refundUsage(task.taskId, epoch.epochId, "EVIDENCE_BYTES", 700);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "EVIDENCE_BYTES")).toBe(900);
    expect(() => store.refundUsage(task.taskId, epoch.epochId, "UNKNOWN", 1)).toThrow(/不存在/);
  });

  it("Action 依赖、授权版本、幂等键和 CAS 领取共同阻止重复执行", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const savedObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    const first = store.putInvestigationAction(action({ id: "ACTION-1", taskId: task.taskId, epochId: epoch.epochId, obligationId: savedObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10 }));
    const duplicate = store.putInvestigationAction({ ...first, actionId: "ACTION-DUPLICATE" });
    expect(duplicate.actionId).toBe(first.actionId);
    store.putInvestigationAction(action({ id: "ACTION-2", taskId: task.taskId, epochId: epoch.epochId, obligationId: savedObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 100, dependsOn: [first.actionId] }));

    expect(store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-OLD")).toBeUndefined();
    const claimedFirst = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1");
    expect(claimedFirst?.action.actionId).toBe("ACTION-1");
    expect(store.claimNextInvestigationAction(task.taskId, epoch.epochId, "other", "AUTH-1")).toBeUndefined();
    expect(() => store.finishInvestigationAction("ACTION-1", 0, "SUCCEEDED")).toThrow(/revision/);
    store.finishInvestigationAction("ACTION-1", claimedFirst!.action.revision, "SUCCEEDED", [fact.factId]);
    const claimedSecond = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1");
    expect(claimedSecond?.action.actionId).toBe("ACTION-2");
    expect(store.listInvestigationActionAttempts(task.taskId, epoch.epochId)).toHaveLength(2);
  });

  it("语义去重的终态 Action 会挂接并结算后来创建的共享义务", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const firstObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    const first = store.putInvestigationAction(action({
      id: "ACTION-SHARED-FIRST", taskId: task.taskId, epochId: epoch.epochId,
      obligationId: firstObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10,
    }));
    const claim = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1")!;
    store.finishInvestigationAction(first.actionId, claim.action.revision, "SUCCEEDED", [fact.factId]);
    store.updateInvestigationObligation({ ...firstObligation, status: "SATISFIED", resultRefs: [fact.factId], updatedAt: new Date().toISOString() }, "OPEN");

    const secondObligation = store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationId: "OBL-00000000-0000-4000-8000-000000000099",
      obligationKind: "SHARED_PROJECT_RESULT",
      dedupeKey: `SHARED_PROJECT_RESULT:${fact.subjectRef}`,
    });
    const reused = store.putInvestigationAction({
      ...first,
      actionId: "ACTION-SHARED-DUPLICATE",
      obligationIds: [secondObligation.obligationId],
      priority: 100,
    });
    expect(reused).toMatchObject({
      actionId: first.actionId,
      obligationIds: expect.arrayContaining([firstObligation.obligationId, secondObligation.obligationId]),
      priority: 100,
      status: "SUCCEEDED",
    });
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toContainEqual(expect.objectContaining({
      obligationId: secondObligation.obligationId, status: "SATISFIED", resultRefs: [fact.factId],
    }));
    expect(store.listInvestigationActionAttempts(task.taskId, epoch.epochId)).toHaveLength(1);
  });

  it("Action 执行器自动消费发现游标并用全部页面结果结算义务", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const createdObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    store.putInvestigationAction(action({
      id: "ACTION-PAGED", taskId: task.taskId, epochId: epoch.epochId,
      obligationId: createdObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10,
    }));
    const calls: Array<{ toolCallId: string; args: Record<string, unknown> }> = [];
    const tool: SecurityToolDefinition = {
      name: "enumerate", label: "enumerate", description: "paged enumerate",
      parameters: Type.Object({
        ref: Type.String(), fields: Type.Array(Type.String()), cursorRef: Type.Optional(Type.String()),
      }),
      risk: "LOCAL", replayPolicy: "SAFE_REOBSERVE", timeoutMs: 1_000, auditEvent: "enumerate",
      execute: async (toolCallId, args) => {
        const callArgs = args as Record<string, unknown>;
        calls.push({ toolCallId, args: callArgs });
        const continuation = typeof callArgs.cursorRef === "string";
        return {
          content: [{ type: "text", text: "{}" }],
          details: continuation
            ? { status: "success", factRefs: ["FACT-PAGE-2"], objectRefs: ["OBJ-PAGE-2"] }
            : { status: "partial", factRefs: ["FACT-PAGE-1"], objectRefs: ["OBJ-PAGE-1"], cursorRef: "CURSOR-PAGE-2", gaps: [{ code: "NODE_LIMIT", resumable: true }] },
        };
      },
    };

    const summary = await new InvestigationActionExecutor(store, [tool], task.taskId, epoch.epochId, "AUTH-1").runUntilIdle();
    expect(summary).toEqual({ executed: 1, succeeded: 1, partial: 0, failed: 0 });
    expect(calls).toHaveLength(2);
    expect(calls[0]?.args.cursorRef).toBeUndefined();
    expect(calls[1]?.args.cursorRef).toBe("CURSOR-PAGE-2");
    expect(calls[1]?.toolCallId).toMatch(/-PAGE-2$/);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toEqual([
      expect.objectContaining({ status: "SUCCEEDED", resultRefs: expect.arrayContaining(["FACT-PAGE-1", "OBJ-PAGE-1", "FACT-PAGE-2", "OBJ-PAGE-2"]) }),
    ]);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toEqual([
      expect.objectContaining({ status: "SATISFIED", resultRefs: expect.arrayContaining(["FACT-PAGE-1", "OBJ-PAGE-1", "FACT-PAGE-2", "OBJ-PAGE-2"]) }),
    ]);
    expect(store.listInvestigationActionAttempts(task.taskId, epoch.epochId)).toHaveLength(1);
  });

  it("Action 执行器复用同一 Epoch 任意已完成的相同原语结果", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const createdObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    const args = { ref: fact.subjectRef, fields: ["pid"] };
    store.putInvestigationAction({
      ...action({ id: "ACTION-REUSE-PRESET", taskId: task.taskId, epochId: epoch.epochId, obligationId: createdObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10 }),
      operationRef: "project", args, argsDigest: digestObject(args),
    });
    const presetResult = { content: [{ type: "text" as const, text: "{}" }], details: { status: "success", factRefs: [fact.factId], objectRefs: [fact.subjectRef] } };
    store.startToolRun({ toolCallId: "DIRECT-REUSABLE", taskId: task.taskId, epochId: epoch.epochId, toolName: "project", risk: "READ", replayPolicy: "SAFE_REOBSERVE", args });
    store.finishToolRun("DIRECT-REUSABLE", "SUCCEEDED", presetResult);
    let calls = 0;
    const tool: SecurityToolDefinition = {
      name: "project", label: "project", description: "project",
      parameters: Type.Object({ ref: Type.String(), fields: Type.Array(Type.String()) }),
      risk: "READ", replayPolicy: "SAFE_REOBSERVE", timeoutMs: 1_000, auditEvent: "project",
      execute: async () => { calls += 1; return presetResult; },
    };

    const summary = await new InvestigationActionExecutor(store, [tool], task.taskId, epoch.epochId, "AUTH-1").runUntilIdle();
    expect(summary).toEqual({ executed: 1, succeeded: 1, partial: 0, failed: 0 });
    expect(calls).toBe(0);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toContainEqual(expect.objectContaining({ status: "SUCCEEDED", resultRefs: [fact.factId, fact.subjectRef] }));
    expect(store.listAudit(task.taskId, 100).some((event) => event.event === "investigation_action_reused_primitive")).toBe(true);
  });

  it("活动 Action 队列达到上限后阻塞新增动作并把受影响义务收敛为受限", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    const filler = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    for (let index = 0; index < MAX_ACTIVE_INVESTIGATION_ACTIONS; index += 1) {
      store.putInvestigationAction(action({
        id: `ACTION-FILL-${index}`, taskId: task.taskId, epochId: epoch.epochId,
        obligationId: filler.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: index,
      }));
    }
    const overflowObligation = store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationId: "OBL-QUEUE-OVERFLOW", obligationKind: "QUEUE_OVERFLOW_TARGET",
      dedupeKey: `QUEUE_OVERFLOW_TARGET:${fact.subjectRef}`,
    });
    const overflow = store.putInvestigationAction(action({
      id: "ACTION-OVERFLOW", taskId: task.taskId, epochId: epoch.epochId,
      obligationId: overflowObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 100,
    }));

    expect(overflow).toMatchObject({ status: "BLOCKED", error: `ACTION_QUEUE_CAPACITY:${MAX_ACTIVE_INVESTIGATION_ACTIONS}` });
    expect(store.listInvestigationActions(task.taskId, epoch.epochId).filter((item) => item.status === "READY")).toHaveLength(MAX_ACTIVE_INVESTIGATION_ACTIONS);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toContainEqual(expect.objectContaining({
      obligationId: overflowObligation.obligationId, status: "LIMITED",
      gapRefs: [expect.stringContaining(`${MAX_ACTIVE_INVESTIGATION_ACTIONS}`)],
    }));
    expect(store.listInvestigationGaps(task.taskId, epoch.epochId)).toContainEqual(expect.objectContaining({
      code: "QUEUE_CAPACITY", reasonCode: `ACTIVE_ACTION_LIMIT:${MAX_ACTIVE_INVESTIGATION_ACTIONS}`,
    }));
    const maxSeq = store.maxInvestigationEventSeq(task.taskId, epoch.epochId);
    expect(store.listInvestigationEvents(task.taskId, epoch.epochId, Math.max(0, maxSeq - 10), 20).map((item) => item.eventType)).toContain("ACTION_QUEUE_CAPACITY_REACHED");
  });

  it("恢复时只重新排队安全读取，未知侵入式结果保持 BLOCKED", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const savedObligation = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    store.putInvestigationAction(action({ id: "ACTION-SAFE", taskId: task.taskId, epochId: epoch.epochId, obligationId: savedObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 20 }));
    store.putInvestigationAction(action({ id: "ACTION-UNKNOWN", taskId: task.taskId, epochId: epoch.epochId, obligationId: savedObligation.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10, replayPolicy: "RESUME_OR_RECOLLECT" }));
    store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1");
    store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1");

    const recovered = store.recoverInterruptedInvestigationActions(task.taskId, epoch.epochId);
    expect(recovered).toEqual(expect.arrayContaining([
      expect.objectContaining({ actionId: "ACTION-SAFE", status: "READY" }),
      expect.objectContaining({ actionId: "ACTION-UNKNOWN", status: "BLOCKED" }),
    ]));
    expect(store.listInvestigationActionAttempts(task.taskId, epoch.epochId).map((item) => item.status).sort()).toEqual(["BLOCKED", "FAILED"]);
  });

  it("完成校验拒绝跳过 required obligation，并将证据缺失明确收敛为 LIMITED", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const created = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    const validator = new InvestigationCompletionValidator(store);
    expect(validator.evaluate(task.taskId, epoch.epochId)).toMatchObject({ canClose: false, status: "OPEN", openRequiredObligationIds: [created.obligationId] });
    expect(() => validator.freeze(task.taskId, epoch.epochId)).toThrow(/不能结束/);

    const updatedAt = new Date().toISOString();
    store.updateInvestigationObligation({ ...created, status: "SATISFIED", resultRefs: [], updatedAt }, "OPEN");
    const evaluation = validator.evaluate(task.taskId, epoch.epochId);
    expect(evaluation).toMatchObject({ canClose: true, status: "LIMITED", limitedObligationIds: [created.obligationId] });
    const snapshot = validator.freeze(task.taskId, epoch.epochId);
    expect(snapshot.investigationStatus).toBe("LIMITED");
    expect(store.getInvestigationSession(task.taskId, epoch.epochId)).toMatchObject({ executionStatus: "STOPPED", investigationStatus: "LIMITED", completionSnapshotRef: snapshot.snapshotRef });
  });

  it("可选动作失败保持可见但不降低已闭合发现，必需动作失败仍收敛为 LIMITED", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const required = store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationKind: "REVIEW_COUNTEREVIDENCE",
      dedupeKey: `REVIEW_COUNTEREVIDENCE:${fact.subjectRef}`,
      status: "SATISFIED",
      resultRefs: [fact.factId],
    });
    const optional = store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationId: "OBL-00000000-0000-4000-8000-000000000002",
      obligationKind: "TRACE_OPTIONAL_CONTEXT",
      dedupeKey: `TRACE_OPTIONAL_CONTEXT:${fact.subjectRef}`,
      required: false,
      status: "LIMITED",
    });
    store.putAssessment({
      assessmentId: "ASM-OPTIONAL-FAILURE", taskId: task.taskId, epochId: epoch.epochId,
      authorType: "RULE", category: "linux_intrusion_triage", subjectRef: fact.subjectRef,
      scope: "SUBJECT", verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.8,
      rationale: "确定性规则命中", evidenceRefs: [], factRefs: [fact.factId], queryRefs: [], createdAt: observedAt,
    });
    const optionalAction = store.putInvestigationAction(action({
      id: "ACTION-OPTIONAL", taskId: task.taskId, epochId: epoch.epochId,
      obligationId: optional.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 20,
    }));
    const optionalClaim = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1")!;
    store.finishInvestigationAction(optionalAction.actionId, optionalClaim.action.revision, "FAILED", [], "可选上下文不可用");

    const validator = new InvestigationCompletionValidator(store);
    expect(validator.evaluate(task.taskId, epoch.epochId)).toMatchObject({ canClose: true, status: "CLOSED_WITH_FINDINGS" });

    const requiredAction = store.putInvestigationAction(action({
      id: "ACTION-REQUIRED", taskId: task.taskId, epochId: epoch.epochId,
      obligationId: required.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10,
    }));
    const requiredClaim = store.claimNextInvestigationAction(task.taskId, epoch.epochId, "worker", "AUTH-1")!;
    store.finishInvestigationAction(requiredAction.actionId, requiredClaim.action.revision, "FAILED", [], "必需动作失败");
    expect(validator.evaluate(task.taskId, epoch.epochId)).toMatchObject({ canClose: true, status: "LIMITED" });
  });

  it("完成校验只采用有效裁定，并将未裁定冲突收敛为 LIMITED", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationKind: "REVIEW_COUNTEREVIDENCE",
      dedupeKey: `REVIEW_COUNTEREVIDENCE:${fact.subjectRef}`,
      status: "SATISFIED",
      resultRefs: [fact.factId],
    });
    const riskAt = observedAt;
    const humanAt = new Date(Date.parse(observedAt) + 1_000).toISOString();
    const risk = {
      assessmentId: "ASM-RISK", taskId: task.taskId, epochId: epoch.epochId, authorType: "RULE" as const,
      category: "linux_intrusion_triage" as const, subjectRef: fact.subjectRef, scope: "SUBJECT" as const,
      verdict: "SUSPICIOUS" as const, severity: "MEDIUM" as const, confidence: 0.8,
      rationale: "规则命中", evidenceRefs: [], factRefs: [fact.factId], queryRefs: [], createdAt: riskAt,
    };
    const benign = {
      ...risk, assessmentId: "ASM-HUMAN", authorType: "HUMAN" as const, verdict: "BENIGN" as const,
      severity: "INFO" as const, confidence: 1, rationale: "人工复核为良性", createdAt: humanAt,
    };
    store.putAssessment(risk);
    store.putAssessment(benign);
    const validator = new InvestigationCompletionValidator(store);
    expect(validator.evaluate(task.taskId, epoch.epochId)).toMatchObject({
      canClose: true, status: "LIMITED", findingAssessmentIds: [],
      reasons: expect.arrayContaining(["存在未裁定的 Assessment 冲突"]),
    });

    store.putAssessmentRelation({
      relationId: "AREL-HUMAN", taskId: task.taskId, epochId: epoch.epochId, kind: "ADJUDICATES",
      fromAssessmentId: benign.assessmentId, toAssessmentId: risk.assessmentId,
      createdAt: new Date(Date.parse(humanAt) + 1_000).toISOString(),
    });
    const adjudicated = validator.evaluate(task.taskId, epoch.epochId);
    expect(adjudicated.findingAssessmentIds).toEqual([]);
    expect(adjudicated.reasons).not.toContain("存在未裁定的 Assessment 冲突");
  });

  it("冻结时基于完整确定性范围生成 SYSTEM 无发现结论，不依赖模型收尾", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    store.putCoverageRun({
      coverageId: "COV-DETERMINISTIC",
      taskId: task.taskId,
      epochId: epoch.epochId,
      category: "linux_intrusion_triage",
      presetId: "PRESET-LINUX-TRIAGE",
      presetVersion: "2.5.0",
      status: "COMPLETE",
      applicability: "APPLICABLE",
      completedCriteria: ["process_inventory", "socket_inventory"],
      missingCriteria: [],
      createdAt: observedAt,
    });
    store.putInvestigationObligation({
      ...obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt),
      obligationKind: "REVIEW_COUNTEREVIDENCE",
      status: "SATISFIED",
      resultRefs: [fact.factId],
    });

    const validator = new InvestigationCompletionValidator(store);
    expect(validator.evaluate(task.taskId, epoch.epochId).status).toBe("LIMITED");
    const snapshot = validator.freeze(task.taskId, epoch.epochId);
    expect(snapshot.investigationStatus).toBe("CLOSED_NO_OBSERVED_FINDING");
    expect(store.listAssessments(task.taskId, epoch.epochId)).toEqual([
      expect.objectContaining({ authorType: "SYSTEM", scope: "OBSERVED_CATEGORY", verdict: "NO_OBSERVED_FINDING" }),
    ]);
  });

  it("无候选的良性范围也由 Coverage 建立并闭合类别义务", async () => {
    const { store, task, epoch, observedAt } = await fixture();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const running = session(task.taskId, epoch.epochId, observedAt);
    store.createInvestigationSession(running);
    store.putCoverageRun({
      coverageId: "COV-BENIGN",
      taskId: task.taskId,
      epochId: epoch.epochId,
      category: "linux_intrusion_triage",
      presetId: "PRESET-LINUX-TRIAGE",
      presetVersion: "2.5.0",
      status: "COMPLETE",
      applicability: "APPLICABLE",
      completedCriteria: ["process_inventory", "socket_inventory"],
      missingCriteria: [],
      createdAt: observedAt,
    });
    await new InvestigationScheduler(store, task.taskId, epoch.epochId, running, []).runUntilQuiescent();
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ obligationKind: "CATEGORY_SCOPE_LINUX_INTRUSION_TRIAGE", required: true, status: "SATISFIED" }),
    ]));
    expect(new InvestigationCompletionValidator(store).freeze(task.taskId, epoch.epochId).investigationStatus).toBe("CLOSED_NO_OBSERVED_FINDING");
  });

  it("人工取消会冻结 CANCELLED 快照并保留未完成义务和未知动作原因", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    store.createInvestigationSession(session(task.taskId, epoch.epochId, observedAt));
    const created = store.putInvestigationObligation(obligation(task.taskId, epoch.epochId, fact.subjectRef, observedAt));
    store.putInvestigationAction(action({ id: "ACTION-CANCEL", taskId: task.taskId, epochId: epoch.epochId, obligationId: created.obligationId, subjectRef: fact.subjectRef, now: observedAt, priority: 10 }));
    const snapshot = new InvestigationCompletionValidator(store).freezeCancelled(task.taskId, epoch.epochId, "ANALYST_ABORT");
    expect(snapshot).toMatchObject({ investigationStatus: "CANCELLED", runningActionIds: [] });
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ status: "BLOCKED", error: "ANALYST_ABORT" })]);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ status: "CANCELLED", gapRefs: ["ANALYST_ABORT"] })]);
    expect(store.getInvestigationSession(task.taskId, epoch.epochId)).toMatchObject({ executionStatus: "STOPPED", investigationStatus: "CANCELLED", completionSnapshotRef: snapshot.snapshotRef });
  });

  it("事件水位驱动发现与规则，重复调度不重复执行 Action", async () => {
    const { store, task, epoch, fact, observedAt } = await fixture();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const unusual = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "DISCOVERY-TEMP", source: { kind: "MODEL", evidenceOrigin: "TARGET_OBSERVATION" },
      targetFingerprint: task.target.hostFingerprint, requestId: "DISCOVERY-TEMP", collector: { name: "enumerate", version: "2.1.0" },
      observations: [{ namespace: "process", identity: { bootId: "boot", pid: 99, startTicks: "20", exeInode: "30", exeSha256: "e".repeat(64) }, fields: { bootId: "boot", pid: 99, startTicks: "20", exeInode: "30", exeSha256: "e".repeat(64), exe: "/tmp/agent" }, observedAt, consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "f".repeat(64),
    }).facts[0]!;
    const running = session(task.taskId, epoch.epochId, observedAt);
    store.createInvestigationSession(running);
    const executed: string[] = [];
    const tools = ["project", "relate", "collect", "query_facts"].map((name): SecurityToolDefinition => ({
      name, label: name, description: name, parameters: Type.Object({}, { additionalProperties: true }), risk: "LOCAL", replayPolicy: "SAFE_REOBSERVE", timeoutMs: 1_000, auditEvent: name,
      execute: async (toolCallId) => {
        executed.push(toolCallId);
        return { content: [{ type: "text", text: "{}" }], details: { status: "success", factRefs: [unusual.factId] } };
      },
    }));
    const scheduler = new InvestigationScheduler(store, task.taskId, epoch.epochId, running, tools);
    const first = await scheduler.runUntilQuiescent();
    expect(first.executed).toBe(10);
    expect(first.assessmentsCreated).toHaveLength(1);
    expect(store.listInvestigationLeads(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ subjectRef: unusual.subjectRef })]);
    expect(first.hypothesisIds).toHaveLength(1);
    const actions = store.listInvestigationActions(task.taskId, epoch.epochId);
    expect(actions).toHaveLength(10);
    expect(actions.filter((item) => item.operationRef === "relate").map((item) => item.args.relation)).toEqual(expect.arrayContaining([
      "executable", "command_file", "parent", "connects", "started_by", "opens",
    ]));
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId).filter((item) => item.subjectRefs.includes(unusual.subjectRef)).every((item) => ["SATISFIED", "LIMITED"].includes(item.status))).toBe(true);
    const second = await scheduler.runUntilQuiescent();
    expect(second.executed).toBe(0);
    expect(second.assessmentsCreated).toHaveLength(0);
    // 一个 DERIVE 动作由控制端解析器完成，其余九个动作调用工具；两个规划器的
    // 同语义动作由共同幂等键合并。
    expect(executed).toHaveLength(9);
    expect(store.listAssessments(task.taskId, epoch.epochId).filter((item) => item.factRefs.includes(unusual.factId))).toHaveLength(1);
    expect(fact.subjectRef).not.toBe(unusual.subjectRef);
  });
});
