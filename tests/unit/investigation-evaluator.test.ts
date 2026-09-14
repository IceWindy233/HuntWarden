import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateInvestigation, parseInvestigationEvaluationManifest, type InvestigationEvaluationManifest } from "../../src/evaluation/investigation-evaluator.js";
import type { InvestigationSession } from "../../src/investigation/types.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = []; const stores: RuntimeStore[] = [];
afterEach(async () => { for (const store of stores.splice(0)) store.close(); await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

async function seed(caseId: string, malicious: boolean, adjudicate = malicious, existingStore?: RuntimeStore, identity?: { commit: string; helperSha256: string }) {
  let store = existingStore;
  if (!store) {
    const directory = await mkdtemp(join(tmpdir(), `huntwarden-eval-${caseId}-`)); directories.push(directory);
    store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
  }
  const task = testTask(); task.taskId = `TASK-${caseId}`; task.protocolVersion = 2; task.checks = ["linux_intrusion_triage"]; store.createTask(task);
  const now = new Date().toISOString();
  const epoch: ScanEpoch = { epochId: `EPOCH-${caseId}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: now, ...(identity ? { controllerCommit: identity.commit, controllerTreeClean: true, helperSha256: identity.helperSha256 } : {}) };
  store.createScanEpoch(epoch); task.activeEpochId = epoch.epochId; store.saveTask(task);
  const session: InvestigationSession = { sessionId: `ISESS-${caseId}`, taskId: task.taskId, epochId: epoch.epochId, engineVersion: "1.0.0", playbookRegistryDigest: "a".repeat(64), ruleRegistryDigest: "b".repeat(64), authorizationVersion: "AUTH", executionStatus: "STOPPED", investigationStatus: malicious ? "CLOSED_WITH_FINDINGS" : "CLOSED_NO_OBSERVED_FINDING", revision: 0, createdAt: now, updatedAt: now };
  store.createInvestigationSession(session);
  const path = malicious ? "/tmp/payload" : "/usr/bin/updater";
  const fact = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `RUN-${caseId}`, source: { kind: "SYSTEM", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint, requestId: `RUN-${caseId}`, collector: { name: "enumerate", version: "3.0.0" }, observations: [{ namespace: "process", identity: { bootId: "boot", pid: malicious ? 41 : 42, startTicks: "1" }, fields: { bootId: "boot", pid: malicious ? 41 : 42, startTicks: "1", exe: path }, observedAt: now, consistency: "POINT_IN_TIME" }], edges: [], gaps: [], wireDigest: (malicious ? "a" : "b").repeat(64) }).facts[0]!;
  store.putInvestigationObligation({ obligationId: `OBL-${caseId}`, taskId: task.taskId, epochId: epoch.epochId, obligationKind: "PRESERVE_EXECUTABLE_EVIDENCE", dedupeKey: `PRESERVE:${caseId}`, subjectRefs: [fact.subjectRef], required: true, status: "SATISFIED", resultRefs: [fact.factId, ...(malicious ? [`EV-${caseId}`] : [])], gapRefs: [], createdAt: now, updatedAt: now });
  if (malicious) store.putEvidence({ evidenceId: `EV-${caseId}`, taskId: task.taskId, host: task.target.host, type: "collected_object", source: path, sha256: "c".repeat(64), tool: "collect", collectedAt: now, metadata: { epochId: epoch.epochId, subjectRef: fact.subjectRef, complete: true, integrityStatus: "VERIFIED", range: { start: 0, length: 7, complete: true }, artifactSize: 7, artifactDigest: "c".repeat(64) } });
  if (malicious && adjudicate) store.putAssessment({ assessmentId: `ASM-${caseId}`, taskId: task.taskId, epochId: epoch.epochId, authorType: "RULE", category: "linux_intrusion_triage", subjectRef: fact.subjectRef, scope: "SUBJECT", verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.8, rationale: "临时目录执行候选", evidenceRefs: [], factRefs: [fact.factId], queryRefs: [], createdAt: now });
  return { store, task, epoch };
}

describe("自主调查端到端评测", () => {
  it("分层计算发现、保全、义务闭合、良性误报和 Wilson 区间", async () => {
    const malicious = await seed("M", true); const benign = await seed("B", false);
    // 两个 case 必须位于同一 RuntimeStore；把良性 fixture 写入恶意 fixture 的库。
    const benignTask = benign.store.getTask(benign.task.taskId)!;
    const benignEpoch = benign.store.getScanEpoch(benign.task.taskId, benign.epoch.epochId)!;
    const sourceFact = benign.store.listFacts(benign.task.taskId, benign.epoch.epochId)[0]!;
    malicious.store.createTask(benignTask); malicious.store.createScanEpoch(benignEpoch); malicious.store.createInvestigationSession(benign.store.getInvestigationSession(benign.task.taskId, benign.epoch.epochId)!);
    const copied = malicious.store.commitFactBatch({ taskId: benignTask.taskId, epochId: benignEpoch.epochId, sourceRunId: "RUN-B-COPY", source: sourceFact.source, targetFingerprint: benignTask.target.hostFingerprint, requestId: "RUN-B-COPY", collector: sourceFact.collector, observations: [{ namespace: "process", identity: sourceFact.privatePayload, fields: sourceFact.privatePayload, observedAt: sourceFact.observedAt, consistency: sourceFact.consistency }], edges: [], gaps: [], wireDigest: "d".repeat(64) }).facts[0]!;
    malicious.store.putInvestigationObligation({ ...benign.store.listInvestigationObligations(benignTask.taskId, benignEpoch.epochId)[0]!, resultRefs: [copied.factId] });
    const ruleAt = sourceFact.observedAt;
    const humanAt = new Date(Date.parse(ruleAt) + 1_000).toISOString();
    malicious.store.putAssessment({ assessmentId: "ASM-B-RULE", taskId: benignTask.taskId, epochId: benignEpoch.epochId, authorType: "RULE", category: "linux_intrusion_triage", subjectRef: copied.subjectRef, scope: "SUBJECT", verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.7, rationale: "规则候选", evidenceRefs: [], factRefs: [copied.factId], queryRefs: [], createdAt: ruleAt });
    malicious.store.putAssessment({ assessmentId: "ASM-B-HUMAN", taskId: benignTask.taskId, epochId: benignEpoch.epochId, authorType: "HUMAN", category: "linux_intrusion_triage", subjectRef: copied.subjectRef, scope: "SUBJECT", verdict: "BENIGN", severity: "INFO", confidence: 1, rationale: "人工裁定", evidenceRefs: [], factRefs: [copied.factId], queryRefs: [], createdAt: humanAt });
    malicious.store.putAssessmentRelation({ relationId: "AREL-B-HUMAN", taskId: benignTask.taskId, epochId: benignEpoch.epochId, kind: "ADJUDICATES", fromAssessmentId: "ASM-B-HUMAN", toAssessmentId: "ASM-B-RULE", createdAt: new Date(Date.parse(humanAt) + 1_000).toISOString() });
    const manifest = parseInvestigationEvaluationManifest({ schemaVersion: 2, suiteId: "unit", environment: {
      targetOs: "fixture", architecture: process.arch, transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2,
      manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
      ruleRegistryVersion: "2.2.0", playbookRegistryVersion: "1.1.0", commit: "abcdef0", budgetProfile: "UNIT",
    }, cases: [
      { caseId: "malicious", taskId: malicious.task.taskId, disposition: "MALICIOUS", entryMode: "ZERO_IOC", runKind: "FIRST", expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/tmp/payload", evidenceRequired: true }] },
      { caseId: "benign", taskId: benignTask.taskId, disposition: "BENIGN", entryMode: "SINGLE_LEAD", runKind: "FIRST", expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/usr/bin/updater" }] },
    ], thresholds: { minDiscoveryRecall: 1, minEvidencePreservation: 1, minObligationClosure: 1, maxBenignFalsePositive: 0, minAutonomousCompletion: 1 } });
    const result = evaluateInvestigation(malicious.store, manifest);
    expect(result.status).toBe("PASS");
    expect(result.metrics.collectionRecall).toMatchObject({ numerator: 2, denominator: 2, rate: 1, confidence95: { high: 1 } });
    expect(result.metrics.discoveryRecall).toMatchObject({ numerator: 1, denominator: 1, rate: 1, confidence95: { high: 1 } });
    expect(result.metrics.evidencePreservation.rate).toBe(1);
    expect(result.metrics.benignFalsePositive.rate).toBe(0);
    expect(result.metrics.autonomousCompletion.rate).toBe(1);
    expect(result.environment.manifestVersion).toBe("3.0.0");
    expect(result.cases.flatMap((item) => item.failureAttributions)).toEqual([]);
  });

  it("恶意样本已采集但缺少真值主体风险结论时发布发现率失败", async () => {
    const fixture = await seed("MISSING-ADJUDICATION", true, false);
    const manifest = parseInvestigationEvaluationManifest({ schemaVersion: 2, suiteId: "missing-adjudication", environment: {
      targetOs: "fixture", architecture: process.arch, transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2,
      manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
      ruleRegistryVersion: "2.2.0", playbookRegistryVersion: "1.3.1", commit: "abcdef0", budgetProfile: "UNIT",
    }, cases: [{ caseId: "malicious", taskId: fixture.task.taskId, disposition: "MALICIOUS", entryMode: "ZERO_IOC", runKind: "FIRST", expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/tmp/payload", evidenceRequired: true }] }],
    thresholds: { minCollectionRecall: 1, minDiscoveryRecall: 1, minEvidencePreservation: 1, minObligationClosure: 1, maxBenignFalsePositive: 0 } });

    const result = evaluateInvestigation(fixture.store, manifest);
    expect(result.status).toBe("FAIL");
    expect(result.metrics.collectionRecall.rate).toBe(1);
    expect(result.metrics.discoveryRecall.rate).toBe(0);
    expect(result.cases[0]?.failureAttributions).toContain("ADJUDICATION_MISSING");
  });

  it("拒绝覆盖首次运行以及没有具体缺口真值的受限样本", () => {
    const base = { schemaVersion: 2, suiteId: "invalid", environment: {
      targetOs: "fixture", architecture: "arm64", transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2,
      manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
      ruleRegistryVersion: "2.2.0", playbookRegistryVersion: "1.1.0", commit: "abcdef0", budgetProfile: "UNIT",
    }, thresholds: { minDiscoveryRecall: 1, minEvidencePreservation: 1, minObligationClosure: 1, maxBenignFalsePositive: 0 } };
    expect(() => parseInvestigationEvaluationManifest({ ...base, cases: [{ caseId: "limited", taskId: "TASK-L", disposition: "LIMITED", entryMode: "ZERO_IOC", runKind: "FIRST", expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/tmp/a" }] }] })).toThrow(/expectedGapCodes/);
    expect(() => parseInvestigationEvaluationManifest({ ...base, cases: [{ caseId: "retry", taskId: "TASK-R", disposition: "MALICIOUS", entryMode: "ZERO_IOC", runKind: "RETRY", retryOfCaseId: "missing", expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/tmp/a" }] }] })).toThrow(/首次运行/);
  });

  it("发布阈值只计算 FIRST，RETRY 使用相同真值并单独报告", async () => {
    const first = await seed("FIRST", true);
    const retry = await seed("RETRY", false);
    const retryTask = retry.store.getTask(retry.task.taskId)!;
    const retryEpoch = retry.store.getScanEpoch(retry.task.taskId, retry.epoch.epochId)!;
    const retryFact = retry.store.listFacts(retry.task.taskId, retry.epoch.epochId)[0]!;
    first.store.createTask(retryTask);
    first.store.createScanEpoch(retryEpoch);
    first.store.createInvestigationSession(retry.store.getInvestigationSession(retry.task.taskId, retry.epoch.epochId)!);
    const copied = first.store.commitFactBatch({
      taskId: retryTask.taskId, epochId: retryEpoch.epochId, sourceRunId: "RUN-RETRY-COPY", source: retryFact.source,
      targetFingerprint: retryTask.target.hostFingerprint, requestId: "RUN-RETRY-COPY", collector: retryFact.collector,
      observations: [{ namespace: "process", identity: retryFact.privatePayload, fields: retryFact.privatePayload, observedAt: retryFact.observedAt, consistency: retryFact.consistency }],
      edges: [], gaps: [], wireDigest: "e".repeat(64),
    }).facts[0]!;
    first.store.putInvestigationObligation({ ...retry.store.listInvestigationObligations(retryTask.taskId, retryEpoch.epochId)[0]!, resultRefs: [copied.factId] });

    const environment = {
      targetOs: "fixture", architecture: process.arch, transport: "SSH" as const, applicationVersion: "0.2.0", protocolVersion: 2 as const,
      manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
      ruleRegistryVersion: "2.3.0", playbookRegistryVersion: "1.3.0", commit: "abcdef0", budgetProfile: "UNIT",
    };
    const truth = { disposition: "MALICIOUS" as const, entryMode: "ZERO_IOC" as const, expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: "/tmp/payload", evidenceRequired: true }] };
    const manifest = parseInvestigationEvaluationManifest({
      schemaVersion: 2, suiteId: "first-versus-retry", environment,
      cases: [
        { ...truth, caseId: "first", taskId: first.task.taskId, runKind: "FIRST" },
        { ...truth, caseId: "retry", taskId: retryTask.taskId, runKind: "RETRY", retryOfCaseId: "first" },
      ],
      thresholds: { minDiscoveryRecall: 1, minEvidencePreservation: 1, minObligationClosure: 1, maxBenignFalsePositive: 0, minAutonomousCompletion: 1 },
    });
    const result = evaluateInvestigation(first.store, manifest);
    expect(result.population).toMatchObject({ firstRunCases: 1, retryCases: 1, maliciousFirstRunCases: 1 });
    expect(result.metrics.discoveryRecall.rate).toBe(1);
    expect(result.thresholdResults.find((item) => item.metric === "discoveryRecall")?.pass).toBe(true);
    expect(result.retryMetrics?.discoveryRecall.rate).toBe(0);
    expect(result.retryMetrics?.evidencePreservation.rate).toBe(0);
  });

  it("BLIND_RELEASE 强制冻结摘要、角色隔离、答案隔离和最低首跑总体", () => {
    const caseDefinition = (index: number, disposition: "MALICIOUS" | "BENIGN" | "LIMITED") => ({
      caseId: `${disposition.toLowerCase()}-${index}`, taskId: `TASK-${disposition}-${index}`, disposition,
      entryMode: index % 2 === 0 ? "ZERO_IOC" : "SINGLE_LEAD", runKind: "FIRST",
      expectedCategories: ["linux_intrusion_triage"], expectedFacts: [{ namespace: "process", field: "exe", value: `/fixture/${disposition}/${index}`, ...(disposition === "MALICIOUS" ? { evidenceRequired: true } : {}) }],
      ...(disposition === "LIMITED" ? { expectedGapCodes: ["FIXTURE_UNAVAILABLE"] } : {}),
    });
    const cases = [
      ...Array.from({ length: 100 }, (_, index) => caseDefinition(index, "MALICIOUS")),
      ...Array.from({ length: 100 }, (_, index) => caseDefinition(index, "BENIGN")),
      caseDefinition(0, "LIMITED"),
    ];
    const blind = {
      schemaVersion: 2, suiteId: "blind-release", evaluationMode: "BLIND_RELEASE",
      truthSet: {
        archiveSha256: "d".repeat(64), frozenAt: "2026-09-07T00:00:00.000Z", curator: "independent-curator", runner: "release-runner", independentFromTuning: true,
        isolation: { targetAuthorizationContainsTruth: false, helperReceivesTruth: false, modelReceivesTruth: false },
      },
      environment: {
        targetOs: "frozen-matrix", architecture: "x86_64", transport: "SSH", applicationVersion: "0.2.0", protocolVersion: 2,
        manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0",
        ruleRegistryVersion: "2.3.0", playbookRegistryVersion: "1.3.0", commit: "a".repeat(40), budgetProfile: "STANDARD",
      },
      cases,
      thresholds: { minCollectionRecall: 0.95, minDiscoveryRecall: 0.95, minEvidencePreservation: 0.95, minObligationClosure: 1, maxBenignFalsePositive: 0.05 },
    };
    expect(parseInvestigationEvaluationManifest(blind).evaluationMode).toBe("BLIND_RELEASE");
    const { truthSet: _truthSet, ...withoutTruth } = blind;
    expect(() => parseInvestigationEvaluationManifest(withoutTruth)).toThrow(/冻结真值集/);
    expect(() => parseInvestigationEvaluationManifest({ ...blind, truthSet: { ...blind.truthSet, runner: blind.truthSet.curator } })).toThrow(/不能同时担任/);
    expect(() => parseInvestigationEvaluationManifest({ ...blind, cases: cases.slice(1) })).toThrow(/malicious=99/);
    expect(() => parseInvestigationEvaluationManifest({ ...blind, thresholds: { ...blind.thresholds, minDiscoveryRecall: 0.94 } })).toThrow(/阈值/);
    expect(() => parseInvestigationEvaluationManifest({ ...blind, environment: { ...blind.environment, commit: "abcdef0" } })).toThrow(/完整提交摘要/);
  });

  it("正式评分核对数据库全部 Epoch，不能以账本或选定旧 Epoch 掩盖身份漂移", async () => {
    const identity = { commit: "a".repeat(40), helperSha256: "b".repeat(64) };
    const startedAt = new Date().toISOString();
    let store: RuntimeStore | undefined;
    const cases: InvestigationEvaluationManifest["cases"] = [];
    for (let index = 0; index < 201; index += 1) {
      const disposition = index < 100 ? "MALICIOUS" : index < 200 ? "BENIGN" : "LIMITED";
      const value = await seed(`BLIND-${index}`, disposition === "MALICIOUS", true, store, identity);
      store = value.store;
      if (disposition === "LIMITED") {
        const session = store.getInvestigationSession(value.task.taskId, value.epoch.epochId)!;
        store.updateInvestigationSession({ ...session, investigationStatus: "LIMITED", revision: session.revision + 1 }, session.revision);
        const obligation = store.listInvestigationObligations(value.task.taskId, value.epoch.epochId)[0]!;
        store.updateInvestigationObligation({ ...obligation, gapRefs: ["FIXTURE_UNAVAILABLE"] }, obligation.status);
      }
      store.finishScanEpoch(value.task.taskId, value.epoch.epochId, "COMPLETED", { commit: identity.commit, clean: true });
      cases.push({ caseId: `case-${index}`, taskId: value.task.taskId, epochId: value.epoch.epochId, disposition, entryMode: "ZERO_IOC", runKind: "FIRST", expectedCategories: ["linux_intrusion_triage"],
        expectedFacts: [{ namespace: "process", field: "exe", value: disposition === "MALICIOUS" ? "/tmp/payload" : "/usr/bin/updater", ...(disposition === "MALICIOUS" ? { evidenceRequired: true } : {}) }],
        ...(disposition === "LIMITED" ? { expectedGapCodes: ["FIXTURE_UNAVAILABLE"] } : {}) });
    }
    const manifest = parseInvestigationEvaluationManifest({ schemaVersion: 2, suiteId: "actual-epoch-identity", evaluationMode: "BLIND_RELEASE",
      truthSet: { archiveSha256: "d".repeat(64), frozenAt: "2026-09-07T00:00:00.000Z", curator: "curator", runner: "runner", independentFromTuning: true,
        isolation: { targetAuthorizationContainsTruth: false, helperReceivesTruth: false, modelReceivesTruth: false } },
      environment: { targetOs: "fixture", architecture: "arm64", transport: "SSH", applicationVersion: "0.3.0", protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", investigationEngineVersion: "1.0.0", ruleRegistryVersion: "2.3.0", playbookRegistryVersion: "1.3.1", commit: identity.commit, budgetProfile: "STANDARD" },
      cases, thresholds: { minCollectionRecall: 0.95, minDiscoveryRecall: 0.95, minEvidencePreservation: 0.95, minObligationClosure: 1, maxBenignFalsePositive: 0.05, minLimitedRecognition: 1 } });
    const runRecord = { schemaVersion: 1, suiteId: manifest.suiteId, evaluationMode: "BLIND_RELEASE", ...identity, clean: true, startedAt, finishedAt: new Date().toISOString(), state: "FINISHED", plannedCases: cases.length,
      cases: cases.map((item) => ({ caseId: item.caseId, taskId: item.taskId, epochId: item.epochId, runKind: item.runKind, state: "FINISHED" })) };
    const archivedTruth = { ...manifest, cases: manifest.cases.map(({ taskId: _taskId, epochId: _epochId, ...definition }) => definition) };
    const qualification = { run: runRecord, archivedTruth, archiveSha256: manifest.truthSet!.archiveSha256 };
    expect(() => evaluateInvestigation(store!, manifest)).toThrow();
    const valid = evaluateInvestigation(store!, manifest, qualification);
    expect(valid.status, JSON.stringify({ failures: valid.qualificationFailures, thresholds: valid.thresholdResults })).toBe("PASS");
    expect(() => evaluateInvestigation(store!, manifest, { ...qualification, run: { ...runRecord, evaluationMode: "DEVELOPMENT" } })).toThrow();

    const first = store!.getScanEpoch(cases[0]!.taskId, cases[0]!.epochId!)!;
    store!.createScanEpoch({ ...first, epochId: "EPOCH-DRIFTED", helperSha256: "f".repeat(64), controllerTreeCleanAtFinish: false });
    const failed = evaluateInvestigation(store!, manifest, qualification);
    expect(failed.status).toBe("FAIL");
    expect(failed.population.firstRunCases).toBe(201);
    expect(failed.qualificationFailures).toEqual(expect.arrayContaining([
      "case-0/EPOCH-DRIFTED: HELPER_SHA256_MISMATCH", "case-0/EPOCH-DRIFTED: CONTROLLER_FINISH_TREE_NOT_CLEAN",
    ]));
  });
});
