import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import type { CheckCategory } from "../domain/types.js";
import { NAMESPACE_NAMES, type FactRecord, type ScanEpoch } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import { projectEffectiveAssessments } from "../assessments/projection.js";
import { digestObject } from "../common/json.js";

const categories = ["webshell", "java_memory_shell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"] as const;
const ExpectedFactSchema = Type.Object({
  namespace: Type.Enum(NAMESPACE_NAMES),
  field: Type.String({ minLength: 1, maxLength: 128 }),
  value: Type.Union([Type.String({ maxLength: 4096 }), Type.Number(), Type.Boolean()]),
  evidenceRequired: Type.Optional(Type.Boolean()),
}, { additionalProperties: false });
const ExpectedEndpointSchema = Type.Object({
  namespace: Type.Enum(NAMESPACE_NAMES),
  field: Type.String({ minLength: 1, maxLength: 128 }),
  value: Type.Union([Type.String({ maxLength: 4096 }), Type.Number(), Type.Boolean()]),
}, { additionalProperties: false });
const EnvironmentSchema = Type.Object({
  targetOs: Type.String({ minLength: 1, maxLength: 256 }),
  architecture: Type.String({ minLength: 1, maxLength: 64 }),
  transport: Type.Literal("SSH"),
  provider: Type.Optional(Type.String({ minLength: 1, maxLength: 256 })),
  applicationVersion: Type.String({ minLength: 1, maxLength: 64 }),
  protocolVersion: Type.Literal(2),
  manifestVersion: Type.String({ minLength: 1, maxLength: 64 }),
  helperVersion: Type.String({ minLength: 1, maxLength: 64 }),
  investigationEngineVersion: Type.String({ minLength: 1, maxLength: 64 }),
  ruleRegistryVersion: Type.String({ minLength: 1, maxLength: 64 }),
  playbookRegistryVersion: Type.String({ minLength: 1, maxLength: 64 }),
  commit: Type.String({ minLength: 7, maxLength: 64, pattern: "^[a-f0-9]+$" }),
  budgetProfile: Type.String({ minLength: 1, maxLength: 64 }),
}, { additionalProperties: false });

export const InvestigationEvaluationManifestSchema = Type.Object({
  schemaVersion: Type.Literal(2),
  suiteId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
  evaluationMode: Type.Optional(Type.Union([Type.Literal("DEVELOPMENT"), Type.Literal("BLIND_RELEASE")])),
  truthSet: Type.Optional(Type.Object({
    archiveSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
    frozenAt: Type.String({ minLength: 20, maxLength: 64 }),
    curator: Type.String({ minLength: 1, maxLength: 128 }),
    runner: Type.String({ minLength: 1, maxLength: 128 }),
    independentFromTuning: Type.Literal(true),
    isolation: Type.Object({
      targetAuthorizationContainsTruth: Type.Literal(false),
      helperReceivesTruth: Type.Literal(false),
      modelReceivesTruth: Type.Literal(false),
    }, { additionalProperties: false }),
  }, { additionalProperties: false })),
  environment: EnvironmentSchema,
  cases: Type.Array(Type.Object({
    caseId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
    taskId: Type.String({ minLength: 1, maxLength: 128 }),
    epochId: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })),
    disposition: Type.Union([Type.Literal("MALICIOUS"), Type.Literal("BENIGN"), Type.Literal("LIMITED")]),
    entryMode: Type.Union([Type.Literal("ZERO_IOC"), Type.Literal("SINGLE_LEAD")]),
    runKind: Type.Union([Type.Literal("FIRST"), Type.Literal("RETRY")]),
    retryOfCaseId: Type.Optional(Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" })),
    expectedCategories: Type.Array(Type.Enum(categories), { minItems: 1, maxItems: 5, uniqueItems: true }),
    expectedFacts: Type.Array(ExpectedFactSchema, { minItems: 1, maxItems: 100 }),
    expectedRelations: Type.Optional(Type.Array(Type.Object({
      relation: Type.String({ minLength: 1, maxLength: 128 }),
      from: ExpectedEndpointSchema,
      to: ExpectedEndpointSchema,
      derivation: Type.Optional(Type.Union([Type.Literal("OBSERVED"), Type.Literal("DERIVED"), Type.Literal("INFERRED")])),
    }, { additionalProperties: false }), { maxItems: 100 })),
    expectedGapCodes: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 128 }), { minItems: 1, maxItems: 100, uniqueItems: true })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: 500 }),
  thresholds: Type.Object({
    minDiscoveryRecall: Type.Number({ minimum: 0, maximum: 1 }),
    minCollectionRecall: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    minEvidencePreservation: Type.Number({ minimum: 0, maximum: 1 }),
    minObligationClosure: Type.Number({ minimum: 0, maximum: 1 }),
    maxBenignFalsePositive: Type.Number({ minimum: 0, maximum: 1 }),
    minRelationshipRecall: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    minLimitedRecognition: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    minAutonomousCompletion: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
  }, { additionalProperties: false }),
}, { additionalProperties: false });

export type InvestigationEvaluationManifest = Static<typeof InvestigationEvaluationManifestSchema>;
export const InvestigationEvaluationTruthSchema = Type.Object({
  ...InvestigationEvaluationManifestSchema.properties,
  cases: Type.Array(Type.Omit(InvestigationEvaluationManifestSchema.properties.cases.items, ["taskId", "epochId"]), { minItems: 1, maxItems: 500 }),
}, { additionalProperties: false });
const ArchivedInvestigationTruthSchema = Type.Object({
  ...InvestigationEvaluationTruthSchema.properties,
  truthSet: Type.Optional(Type.Object({
    ...InvestigationEvaluationManifestSchema.properties.truthSet.properties,
    archiveSha256: Type.Optional(Type.String({ pattern: "^[a-f0-9]{64}$" })),
  }, { additionalProperties: false })),
}, { additionalProperties: false });

export function verifyInvestigationTruthArchive(truth: unknown, archivedTruth: unknown, archiveSha256: string): void {
  if (!Value.Check(InvestigationEvaluationTruthSchema, truth) || !truth.truthSet) throw new Error("正式评分真值必须使用无 Task/Epoch 的严格 schema v2");
  if (!/^[a-f0-9]{64}$/.test(archiveSha256) || truth.truthSet.archiveSha256 !== archiveSha256) throw new Error("独立真值归档 SHA-256 不一致");
  if (!Value.Check(ArchivedInvestigationTruthSchema, archivedTruth) || !archivedTruth.truthSet) throw new Error("归档 truth.json 必须使用无 Task/Epoch 的严格真值 schema");
  if (archivedTruth.truthSet.archiveSha256 !== undefined && archivedTruth.truthSet.archiveSha256 !== archiveSha256) throw new Error("归档 truth.json 的 SHA-256 声明不一致");
  const boundTruth = { ...archivedTruth, truthSet: { ...archivedTruth.truthSet, archiveSha256 } };
  if (digestObject(truth) !== digestObject(boundTruth)) throw new Error("真值清单内容与归档 truth.json 不一致");
}

export const InvestigationRunRecordSchema = Type.Object({
  schemaVersion: Type.Literal(1), suiteId: Type.String(), evaluationMode: Type.Union([Type.Literal("DEVELOPMENT"), Type.Literal("BLIND_RELEASE")]),
  commit: Type.String({ pattern: "^[a-f0-9]{40}$" }), clean: Type.Boolean(), helperSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  startedAt: Type.String(), finishedAt: Type.String(), state: Type.Union([Type.Literal("FINISHED"), Type.Literal("FAILED")]),
  plannedCases: Type.Integer({ minimum: 1, maximum: 500 }),
  cases: Type.Array(Type.Object({
    caseId: Type.String(), runKind: Type.Union([Type.Literal("FIRST"), Type.Literal("RETRY")]), retryOfCaseId: Type.Optional(Type.String()),
    state: Type.Union([Type.Literal("STARTED"), Type.Literal("FINISHED"), Type.Literal("FAILED")]),
    taskId: Type.Optional(Type.String()), epochId: Type.Optional(Type.String()),
  })),
});
export type InvestigationRunRecord = Static<typeof InvestigationRunRecordSchema>;
export interface InvestigationEvaluationQualification { run: unknown; archivedTruth: unknown; archiveSha256: string }
export interface InvestigationEpochIdentity {
  epochId: string;
  controllerCommit: string | null;
  controllerTreeClean: boolean | null;
  controllerCommitAtFinish: string | null;
  controllerTreeCleanAtFinish: boolean | null;
  helperSha256: string | null;
}

export function investigationEpochIdentity(epoch: ScanEpoch): InvestigationEpochIdentity {
  return {
    epochId: epoch.epochId,
    controllerCommit: epoch.controllerCommit ?? null, controllerTreeClean: epoch.controllerTreeClean ?? null,
    controllerCommitAtFinish: epoch.controllerCommitAtFinish ?? null, controllerTreeCleanAtFinish: epoch.controllerTreeCleanAtFinish ?? null,
    helperSha256: epoch.helperSha256 ?? null,
  };
}

export function investigationEpochIdentityFailures(epoch: ScanEpoch, identity: { commit: string; helperSha256: string }): string[] {
  const failures: string[] = [];
  if (epoch.controllerCommit !== identity.commit) failures.push("CONTROLLER_COMMIT_MISMATCH");
  if (epoch.controllerTreeClean !== true) failures.push("CONTROLLER_TREE_NOT_CLEAN");
  if (epoch.controllerCommitAtFinish !== identity.commit) failures.push("CONTROLLER_FINISH_COMMIT_MISMATCH");
  if (epoch.controllerTreeCleanAtFinish !== true) failures.push("CONTROLLER_FINISH_TREE_NOT_CLEAN");
  if (epoch.helperSha256 !== identity.helperSha256) failures.push("HELPER_SHA256_MISMATCH");
  return failures;
}
export type FailureAttribution = "COLLECTION_MISSING" | "INVESTIGATION_NOT_REACHED" | "ADJUDICATION_MISSING" | "PRESERVATION_FAILED" | "OBLIGATION_INCOMPLETE" | "EXPECTED_LIMIT_NOT_RECORDED";
export interface RateMetric { numerator: number; denominator: number; rate: number | null; confidence95: { low: number; high: number } | null }
export interface InvestigationCaseEvaluation {
  caseId: string;
  taskId: string;
  epochId: string;
  epochs: InvestigationEpochIdentity[];
  disposition: "MALICIOUS" | "BENIGN" | "LIMITED";
  runKind: "FIRST" | "RETRY";
  retryOfCaseId?: string;
  discoveredLabels: number;
  expectedLabels: number;
  preservedLabels: number;
  expectedPreservationLabels: number;
  matchedRelations: number;
  expectedRelations: number;
  riskyCategories: CheckCategory[];
  openRequiredObligationIds: string[];
  autonomousExecutedActions: number;
  completionStatus: string;
  observedGapCodes: string[];
  autonomouslyCompleted: boolean;
  durationMs: number | null;
  actionAttempts: Array<{ attemptId: string; actionId: string; attempt: number; status: string; error?: string; startedAt: string; finishedAt?: string }>;
  failureAttributions: FailureAttribution[];
}

export interface InvestigationEvaluationResult {
  schemaVersion: 2;
  suiteId: string;
  evaluationMode: "DEVELOPMENT" | "BLIND_RELEASE";
  truthSet?: InvestigationEvaluationManifest["truthSet"];
  evaluatedAt: string;
  environment: Static<typeof EnvironmentSchema>;
  runIdentity?: Pick<InvestigationRunRecord, "evaluationMode" | "commit" | "clean" | "helperSha256" | "startedAt" | "finishedAt">;
  qualificationFailures: string[];
  status: "PASS" | "FAIL";
  population: { firstRunCases: number; retryCases: number; maliciousFirstRunCases: number; benignFirstRunCases: number; limitedFirstRunCases: number };
  metrics: InvestigationMetricSet;
  retryMetrics: InvestigationMetricSet | null;
  thresholdResults: Array<{ metric: keyof InvestigationEvaluationResult["metrics"]; comparator: ">=" | "<="; expected: number; actual: number | null; pass: boolean }>;
  cases: InvestigationCaseEvaluation[];
}

export interface InvestigationMetricSet { collectionRecall: RateMetric; discoveryRecall: RateMetric; evidencePreservation: RateMetric; obligationClosure: RateMetric; benignFalsePositive: RateMetric; relationshipRecall: RateMetric; limitedRecognition: RateMetric; autonomousCompletion: RateMetric }

interface MetricAccumulator {
  caseCount: number;
  collected: number;
  collectionExpected: number;
  maliciousDiscovered: number;
  maliciousCases: number;
  preserved: number;
  preservationExpected: number;
  closedObligations: number;
  obligations: number;
  benignFalsePositive: number;
  benignCases: number;
  matchedRelations: number;
  expectedRelations: number;
  recognizedLimits: number;
  limitedCases: number;
  autonomousCompleted: number;
}

export function parseInvestigationEvaluationManifest(input: unknown): InvestigationEvaluationManifest {
  const errors = [...Value.Errors(InvestigationEvaluationManifestSchema, input)];
  if (errors.length > 0) throw new Error(`调查评测清单无效:\n${errors.map((item) => `${item.instancePath || "/"}: ${item.message}`).join("\n")}`);
  const value = structuredClone(input) as InvestigationEvaluationManifest;
  const caseIds = new Set<string>(); const taskIds = new Set<string>();
  for (const item of value.cases) {
    if (caseIds.has(item.caseId)) throw new Error(`重复 caseId: ${item.caseId}`);
    if (taskIds.has(item.taskId)) throw new Error(`重复 taskId: ${item.taskId}`);
    caseIds.add(item.caseId); taskIds.add(item.taskId);
    if (item.runKind === "FIRST" && item.retryOfCaseId) throw new Error(`首次运行不能设置 retryOfCaseId: ${item.caseId}`);
    if (item.disposition === "LIMITED" && (!item.expectedGapCodes || item.expectedGapCodes.length === 0)) throw new Error(`受限 case 必须声明 expectedGapCodes: ${item.caseId}`);
  }
  const casesById = new Map(value.cases.map((item) => [item.caseId, item]));
  for (const item of value.cases) {
    if (item.runKind !== "RETRY") continue;
    const first = item.retryOfCaseId ? casesById.get(item.retryOfCaseId) : undefined;
    if (first?.runKind !== "FIRST") throw new Error(`重试 case 必须引用同清单首次运行: ${item.caseId}`);
    if (first.disposition !== item.disposition || first.entryMode !== item.entryMode
      || JSON.stringify(first.expectedCategories) !== JSON.stringify(item.expectedCategories)
      || JSON.stringify(first.expectedFacts) !== JSON.stringify(item.expectedFacts)
      || JSON.stringify(first.expectedRelations ?? []) !== JSON.stringify(item.expectedRelations ?? [])
      || JSON.stringify(first.expectedGapCodes ?? []) !== JSON.stringify(item.expectedGapCodes ?? [])) {
      throw new Error(`重试 case 必须保留首次运行的真值定义: ${item.caseId}`);
    }
  }
  if ((value.evaluationMode ?? "DEVELOPMENT") === "BLIND_RELEASE") validateBlindRelease(value);
  return value;
}

export function evaluateInvestigation(store: RuntimeStore, manifest: InvestigationEvaluationManifest, qualification?: InvestigationEvaluationQualification): InvestigationEvaluationResult {
  manifest = parseInvestigationEvaluationManifest(manifest);
  const run = manifest.evaluationMode === "BLIND_RELEASE" ? validateBlindRun(manifest, qualification) : undefined;
  const qualificationFailures: string[] = [];
  const cases: InvestigationCaseEvaluation[] = [];
  const firstRun = emptyAccumulator();
  const retries = emptyAccumulator();
  for (const definition of manifest.cases) {
    const task = store.getTask(definition.taskId);
    if (task?.protocolVersion !== 2) throw new Error(`评测 case 引用未知 v2 task: ${definition.caseId}`);
    const epochId = definition.epochId ?? task.activeEpochId;
    if (!epochId) throw new Error(`评测 case 缺少 epoch: ${definition.caseId}`);
    const epochs = store.listScanEpochs(task.taskId);
    if (!epochs.some((epoch) => epoch.epochId === epochId)) throw new Error(`评测 case 引用未知 epoch: ${definition.caseId}`);
    if (run) {
      for (const epoch of epochs) {
        qualificationFailures.push(...investigationEpochIdentityFailures(epoch, run).map((failure) => `${definition.caseId}/${epoch.epochId}: ${failure}`));
        const startedAt = Date.parse(epoch.startedAt); const finishedAt = Date.parse(epoch.finishedAt ?? "");
        if (epoch.status === "RUNNING" || !Number.isFinite(startedAt) || !Number.isFinite(finishedAt)
          || startedAt < Date.parse(run.startedAt) || finishedAt < startedAt || finishedAt > Date.parse(run.finishedAt)) {
          qualificationFailures.push(`${definition.caseId}/${epoch.epochId}: EPOCH_OUTSIDE_FROZEN_RUN`);
        }
      }
    }
    const facts = store.listFacts(task.taskId, epochId);
    const evidence = store.listEvidence(task.taskId);
    const assessments = store.listAssessments(task.taskId, epochId);
    const assessmentsById = new Map(assessments.map((item) => [item.assessmentId, item]));
    const effectiveAssessments = projectEffectiveAssessments(assessments, store.listAssessmentRelations(task.taskId, epochId));
    const investigationObligations = store.listInvestigationObligations(task.taskId, epochId);
    const attempts = store.listInvestigationActionAttempts(task.taskId, epochId);
    const edges = store.listEdges(task.taskId, epochId);
    const provenance = new Map(store.listRelationProvenance(task.taskId, epochId).map((item) => [item.edgeRef, item]));
    const actionsById = new Map(store.listInvestigationActions(task.taskId, epochId).map((item) => [item.actionId, item]));
    const session = store.getInvestigationSession(task.taskId, epochId);
    const matchedFacts: FactRecord[][] = definition.expectedFacts.map((matcher) => facts.filter((fact) => fact.namespace === matcher.namespace && fieldValue(fact.privatePayload, matcher.field) === matcher.value));
    const caseDiscovered = matchedFacts.filter((items) => items.length > 0).length;
    const requiredEvidence = definition.expectedFacts.map((item, index) => ({ item, facts: matchedFacts[index]! })).filter(({ item }) => item.evidenceRequired === true);
    const casePreserved = requiredEvidence.filter(({ facts: matching }) => matching.some((fact) => evidence.some((item) => item.metadata?.subjectRef === fact.subjectRef && item.metadata.complete === true && item.metadata.integrityStatus === "VERIFIED" && item.metadata.epochId === epochId))).length;
    const caseMatchedRelations = (definition.expectedRelations ?? []).filter((expectedRelation) => {
      const fromRefs = new Set(facts.filter((fact) => fact.namespace === expectedRelation.from.namespace && fieldValue(fact.privatePayload, expectedRelation.from.field) === expectedRelation.from.value).map((fact) => fact.subjectRef));
      const toRefs = new Set(facts.filter((fact) => fact.namespace === expectedRelation.to.namespace && fieldValue(fact.privatePayload, expectedRelation.to.field) === expectedRelation.to.value).map((fact) => fact.subjectRef));
      return edges.some((edge) => edge.relation === expectedRelation.relation && fromRefs.has(edge.fromRef) && toRefs.has(edge.toRef)
        && (!expectedRelation.derivation || provenance.get(edge.edgeId)?.derivation === expectedRelation.derivation));
    }).length;
    const accumulator = definition.runKind === "FIRST" ? firstRun : retries;
    accumulator.caseCount += 1;
    accumulator.collectionExpected += definition.expectedFacts.length; accumulator.collected += caseDiscovered;
    accumulator.preservationExpected += requiredEvidence.length; accumulator.preserved += casePreserved;
    accumulator.expectedRelations += definition.expectedRelations?.length ?? 0; accumulator.matchedRelations += caseMatchedRelations;
    accumulator.obligations += investigationObligations.filter((item) => item.required).length;
    accumulator.closedObligations += investigationObligations.filter((item) => item.required && ["SATISFIED", "LIMITED", "CANCELLED"].includes(item.status)).length;
    const riskProjections = effectiveAssessments.filter((item) => ["SUSPICIOUS", "HIGHLY_SUSPICIOUS", "CONFIRMED_MALICIOUS", "CONFLICT"].includes(item.conclusion));
    const riskyCategories = [...new Set(riskProjections.map((item) => item.category))];
    const matchedFactIds = new Set(matchedFacts.flat().map((fact) => fact.factId));
    const matchedSubjectRefs = new Set(matchedFacts.flat().map((fact) => fact.subjectRef));
    const maliciousDiscovered = definition.disposition === "MALICIOUS" && riskProjections.some((projection) => projection.scope === "SUBJECT"
      && projection.subjectRef !== undefined && matchedSubjectRefs.has(projection.subjectRef)
      && definition.expectedCategories.includes(projection.category as typeof definition.expectedCategories[number])
      && projection.effectiveAssessmentIds.some((assessmentId) => {
        const assessment = assessmentsById.get(assessmentId);
        return assessment !== undefined && assessment.subjectRef === projection.subjectRef && assessment.factRefs.some((factRef) => matchedFactIds.has(factRef));
      }));
    if (definition.disposition === "MALICIOUS") { accumulator.maliciousCases += 1; if (maliciousDiscovered) accumulator.maliciousDiscovered += 1; }
    if (definition.disposition === "BENIGN") { accumulator.benignCases += 1; if (riskyCategories.length > 0) accumulator.benignFalsePositive += 1; }
    const openRequiredObligationIds = investigationObligations.filter((item) => item.required && ["OPEN", "QUEUED"].includes(item.status)).map((item) => item.obligationId);
    const observedGapCodes = [...new Set([
      ...investigationObligations.flatMap((item) => item.gapRefs),
      ...store.listInvestigationGaps(task.taskId, epochId).flatMap((item) => [item.code, item.reasonCode]),
      ...store.listCoverageRuns(task.taskId, epochId).flatMap((item) => item.missingCriteria.map((criterion) => criterion.reasonCode)),
      ...store.listDiscoveryCheckpoints(task.taskId, epochId).filter((item) => ["LIMITED", "FAILED"].includes(item.status)).map((item) => item.remainingDescription ?? item.status),
    ])].sort();
    const failureAttributions = new Set<FailureAttribution>();
    if (caseDiscovered < definition.expectedFacts.length) failureAttributions.add("COLLECTION_MISSING");
    const reachedRefs = new Set(investigationObligations.flatMap((item) => item.resultRefs));
    if (matchedFacts.some((items) => items.length > 0 && !items.some((fact) => reachedRefs.has(fact.factId)))) failureAttributions.add("INVESTIGATION_NOT_REACHED");
    if (definition.disposition === "MALICIOUS" && !maliciousDiscovered) failureAttributions.add("ADJUDICATION_MISSING");
    if (casePreserved < requiredEvidence.length) failureAttributions.add("PRESERVATION_FAILED");
    if (openRequiredObligationIds.length > 0) failureAttributions.add("OBLIGATION_INCOMPLETE");
    const completionStatus = session?.investigationStatus ?? "NOT_STARTED";
    const limitRecognized = definition.disposition !== "LIMITED" || (["LIMITED", "CANCELLED"].includes(completionStatus) && (definition.expectedGapCodes ?? []).every((code) => observedGapCodes.includes(code)));
    if (definition.disposition === "LIMITED") { accumulator.limitedCases += 1; if (limitRecognized) accumulator.recognizedLimits += 1; }
    if (!limitRecognized) failureAttributions.add("EXPECTED_LIMIT_NOT_RECORDED");
    const autonomouslyClosed = session?.executionStatus === "STOPPED" && ["CLOSED_WITH_FINDINGS", "CLOSED_NO_OBSERVED_FINDING", "LIMITED"].includes(completionStatus) && openRequiredObligationIds.length === 0;
    if (autonomouslyClosed) accumulator.autonomousCompleted += 1;
    const timestamps = [session?.createdAt, session?.updatedAt, ...attempts.flatMap((attempt) => [attempt.startedAt, attempt.finishedAt])].filter((value): value is string => Boolean(value)).map(Date.parse).filter(Number.isFinite);
    const durationMs = timestamps.length >= 2 ? Math.max(...timestamps) - Math.min(...timestamps) : null;
    cases.push({ caseId: definition.caseId, taskId: task.taskId, epochId, epochs: epochs.map(investigationEpochIdentity), disposition: definition.disposition, runKind: definition.runKind, ...(definition.retryOfCaseId ? { retryOfCaseId: definition.retryOfCaseId } : {}), discoveredLabels: caseDiscovered, expectedLabels: definition.expectedFacts.length, preservedLabels: casePreserved, expectedPreservationLabels: requiredEvidence.length, matchedRelations: caseMatchedRelations, expectedRelations: definition.expectedRelations?.length ?? 0, riskyCategories, openRequiredObligationIds, autonomousExecutedActions: attempts.filter((attempt) => ["DISCOVERY", "PLAYBOOK", "MODEL"].includes(actionsById.get(attempt.actionId)?.requestedBy ?? "")).length, completionStatus, observedGapCodes, autonomouslyCompleted: autonomouslyClosed, durationMs, actionAttempts: attempts.map((attempt) => ({ attemptId: attempt.attemptId, actionId: attempt.actionId, attempt: attempt.attempt, status: attempt.status, ...(attempt.error ? { error: attempt.error } : {}), startedAt: attempt.startedAt, ...(attempt.finishedAt ? { finishedAt: attempt.finishedAt } : {}) })), failureAttributions: [...failureAttributions] });
  }
  const metrics = metricSet(firstRun);
  const retryMetrics = retries.caseCount > 0 ? metricSet(retries) : null;
  const thresholdResults: InvestigationEvaluationResult["thresholdResults"] = [
    compare("collectionRecall", ">=", manifest.thresholds.minCollectionRecall ?? manifest.thresholds.minDiscoveryRecall, metrics.collectionRecall.rate),
    compare("discoveryRecall", ">=", manifest.thresholds.minDiscoveryRecall, metrics.discoveryRecall.rate),
    compare("evidencePreservation", ">=", manifest.thresholds.minEvidencePreservation, metrics.evidencePreservation.rate),
    compare("obligationClosure", ">=", manifest.thresholds.minObligationClosure, metrics.obligationClosure.rate),
    compare("benignFalsePositive", "<=", manifest.thresholds.maxBenignFalsePositive, metrics.benignFalsePositive.rate),
  ];
  if (manifest.thresholds.minRelationshipRecall !== undefined) thresholdResults.push(compare("relationshipRecall", ">=", manifest.thresholds.minRelationshipRecall, metrics.relationshipRecall.rate));
  if (manifest.thresholds.minLimitedRecognition !== undefined) thresholdResults.push(compare("limitedRecognition", ">=", manifest.thresholds.minLimitedRecognition, metrics.limitedRecognition.rate));
  if (manifest.thresholds.minAutonomousCompletion !== undefined) thresholdResults.push(compare("autonomousCompletion", ">=", manifest.thresholds.minAutonomousCompletion, metrics.autonomousCompletion.rate));
  const firstCases = manifest.cases.filter((item) => item.runKind === "FIRST");
  return {
    schemaVersion: 2,
    suiteId: manifest.suiteId,
    evaluationMode: manifest.evaluationMode ?? "DEVELOPMENT",
    ...(manifest.truthSet ? { truthSet: manifest.truthSet } : {}),
    environment: manifest.environment,
    ...(run ? { runIdentity: { evaluationMode: run.evaluationMode, commit: run.commit, clean: run.clean, helperSha256: run.helperSha256, startedAt: run.startedAt, finishedAt: run.finishedAt } } : {}),
    qualificationFailures,
    population: {
      firstRunCases: firstCases.length,
      retryCases: retries.caseCount,
      maliciousFirstRunCases: firstCases.filter((item) => item.disposition === "MALICIOUS").length,
      benignFirstRunCases: firstCases.filter((item) => item.disposition === "BENIGN").length,
      limitedFirstRunCases: firstCases.filter((item) => item.disposition === "LIMITED").length,
    },
    evaluatedAt: new Date().toISOString(),
    status: qualificationFailures.length === 0 && thresholdResults.every((item) => item.pass) ? "PASS" : "FAIL",
    metrics,
    retryMetrics,
    thresholdResults,
    cases,
  };
}

function validateBlindRun(manifest: InvestigationEvaluationManifest, qualification: InvestigationEvaluationQualification | undefined): InvestigationRunRecord {
  if (!qualification || !Value.Check(InvestigationRunRecordSchema, qualification.run)) throw new Error("BLIND_RELEASE 必须提供包含 Helper 摘要的完整 schema v1 运行账本和真值归档");
  const run = qualification.run;
  if (run.evaluationMode !== "BLIND_RELEASE" || !run.clean || run.commit !== manifest.environment.commit || run.suiteId !== manifest.suiteId) throw new Error("BLIND_RELEASE 运行模式、干净提交或套件不一致；DEVELOPMENT 不能提升为正式资格");
  const startedAt = Date.parse(run.startedAt); const finishedAt = Date.parse(run.finishedAt);
  if (!Number.isFinite(startedAt) || !Number.isFinite(finishedAt) || finishedAt < startedAt || Date.parse(manifest.truthSet!.frozenAt) > startedAt) throw new Error("BLIND_RELEASE 真值必须在完整运行时间区间前冻结");
  if (run.plannedCases !== manifest.cases.length || run.cases.length !== run.plannedCases) throw new Error("BLIND_RELEASE 必须保留完整 FIRST/RETRY 运行分母");
  const runCases = new Map(run.cases.map((item) => [item.caseId, item]));
  if (runCases.size !== run.cases.length) throw new Error("BLIND_RELEASE 运行账本包含重复 caseId");
  for (const definition of manifest.cases) {
    const actual = runCases.get(definition.caseId);
    if (!actual?.taskId || !actual.epochId || actual.taskId !== definition.taskId || actual.epochId !== definition.epochId
      || actual.runKind !== definition.runKind || actual.retryOfCaseId !== definition.retryOfCaseId) throw new Error(`BLIND_RELEASE 案例与实际运行账本不一致: ${definition.caseId}`);
  }
  const truth = { ...manifest, cases: manifest.cases.map(({ taskId: _taskId, epochId: _epochId, ...definition }) => definition) };
  verifyInvestigationTruthArchive(truth, qualification.archivedTruth, qualification.archiveSha256);
  return run;
}

function validateBlindRelease(value: InvestigationEvaluationManifest): void {
  if (!value.truthSet) throw new Error("BLIND_RELEASE 必须声明冻结真值集、独立角色和答案隔离");
  if (value.truthSet.curator.trim().toLowerCase() === value.truthSet.runner.trim().toLowerCase()) throw new Error("BLIND_RELEASE 的真值集维护者不能同时担任运行者");
  if (!Number.isFinite(Date.parse(value.truthSet.frozenAt))) throw new Error("BLIND_RELEASE 的 frozenAt 必须是有效时间");
  const first = value.cases.filter((item) => item.runKind === "FIRST");
  const malicious = first.filter((item) => item.disposition === "MALICIOUS").length;
  const benign = first.filter((item) => item.disposition === "BENIGN").length;
  const limited = first.filter((item) => item.disposition === "LIMITED").length;
  if (malicious < 100 || benign < 100 || limited < 1) throw new Error(`BLIND_RELEASE 首跑样本不足: malicious=${malicious}, benign=${benign}, limited=${limited}`);
  if ((value.thresholds.minCollectionRecall ?? 0) < 0.95 || value.thresholds.minDiscoveryRecall < 0.95 || value.thresholds.minEvidencePreservation < 0.95 || value.thresholds.maxBenignFalsePositive > 0.05) {
    throw new Error("BLIND_RELEASE 阈值不得低于采集率/恶意发现率/保全率 95% 或放宽良性误报率 5%");
  }
  if (!/^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(value.environment.commit) || /^0+$/.test(value.environment.commit)) throw new Error("BLIND_RELEASE 必须绑定非零完整提交摘要");
}

function emptyAccumulator(): MetricAccumulator {
  return { caseCount: 0, collected: 0, collectionExpected: 0, maliciousDiscovered: 0, maliciousCases: 0, preserved: 0, preservationExpected: 0, closedObligations: 0, obligations: 0, benignFalsePositive: 0, benignCases: 0, matchedRelations: 0, expectedRelations: 0, recognizedLimits: 0, limitedCases: 0, autonomousCompleted: 0 };
}

function metricSet(values: MetricAccumulator): InvestigationMetricSet {
  return {
    collectionRecall: metric(values.collected, values.collectionExpected),
    discoveryRecall: metric(values.maliciousDiscovered, values.maliciousCases),
    evidencePreservation: metric(values.preserved, values.preservationExpected),
    obligationClosure: metric(values.closedObligations, values.obligations),
    benignFalsePositive: metric(values.benignFalsePositive, values.benignCases),
    relationshipRecall: metric(values.matchedRelations, values.expectedRelations),
    limitedRecognition: metric(values.recognizedLimits, values.limitedCases),
    autonomousCompletion: metric(values.autonomousCompleted, values.caseCount),
  };
}

function metric(numerator: number, denominator: number): RateMetric {
  if (denominator === 0) return { numerator, denominator, rate: null, confidence95: null };
  const rate = numerator / denominator;
  return { numerator, denominator, rate, confidence95: wilson(numerator, denominator) };
}

function wilson(successes: number, total: number): { low: number; high: number } {
  const z = 1.959963984540054; const p = successes / total; const z2 = z * z;
  const center = (p + z2 / (2 * total)) / (1 + z2 / total);
  const margin = z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total) / (1 + z2 / total);
  return { low: Math.max(0, center - margin), high: Math.min(1, center + margin) };
}

function compare(metricName: keyof InvestigationEvaluationResult["metrics"], comparator: ">=" | "<=", expected: number, actual: number | null) {
  return { metric: metricName, comparator, expected, actual, pass: actual !== null && (comparator === ">=" ? actual >= expected : actual <= expected) };
}

function fieldValue(value: Record<string, unknown>, path: string): unknown {
  let current: unknown = value;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}
