import { randomUUID } from "node:crypto";
import type { Assessment } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { CompletionSnapshot, InvestigationStatus } from "./types.js";
import { projectEffectiveAssessments } from "../assessments/projection.js";

const riskVerdicts = new Set<Assessment["verdict"]>(["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"]);
const terminalActions = new Set(["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"]);
const evidenceObligation = /(?:^|_)(?:EVIDENCE|CAPTURE|PRESERVE|PRESERVATION)(?:_|$)/;

export interface CompletionEvaluation {
  canClose: boolean;
  status: InvestigationStatus;
  reasons: string[];
  openRequiredObligationIds: string[];
  limitedObligationIds: string[];
  runningActionIds: string[];
  findingAssessmentIds: string[];
}

export class InvestigationCompletionValidator {
  constructor(private readonly store: RuntimeStore) {}

  evaluate(taskId: string, epochId: string): CompletionEvaluation {
    const obligations = this.store.listInvestigationObligations(taskId, epochId);
    const actions = this.store.listInvestigationActions(taskId, epochId);
    const checkpoints = this.store.listDiscoveryCheckpoints(taskId, epochId);
    const assessments = this.store.listAssessments(taskId, epochId);
    const effective = projectEffectiveAssessments(assessments, this.store.listAssessmentRelations(taskId, epochId));
    const evidence = new Map(this.store.listEvidence(taskId).map((item) => [item.evidenceId, item]));
    const edges = this.store.listEdges(taskId, epochId);
    const trustedEdges = new Set(this.store.listRelationProvenance(taskId, epochId)
      .filter((item) => item.derivation === "OBSERVED" || item.derivation === "DERIVED")
      .map((item) => item.edgeRef));
    const reasons: string[] = [];
    const requiredObligationIds = new Set(obligations.filter((item) => item.required).map((item) => item.obligationId));
    const runningActionIds = actions.filter((item) => !terminalActions.has(item.status)).map((item) => item.actionId);
    const openRequiredObligationIds = obligations.filter((item) => item.required && ["OPEN", "QUEUED"].includes(item.status)).map((item) => item.obligationId);
    const limited = new Set(obligations.filter((item) => item.required && ["LIMITED", "CANCELLED"].includes(item.status)).map((item) => item.obligationId));
    for (const obligation of obligations.filter((item) => item.required && item.status === "SATISFIED" && evidenceObligation.test(item.obligationKind))) {
      const valid = obligation.resultRefs.some((ref) => {
        const item = evidence.get(ref);
        if (item?.metadata?.complete !== true || item.metadata.epochId !== epochId) return false;
        const evidenceSubjects = [item.metadata.subjectRef, item.metadata.artifactSubjectRef].filter((value): value is string => typeof value === "string");
        if (evidenceSubjects.some((ref) => obligation.subjectRefs.includes(ref))) return true;
        return edges.some((edge) => trustedEdges.has(edge.edgeId)
          && evidenceSubjects.some((ref) => edge.fromRef === ref || edge.toRef === ref)
          && obligation.subjectRefs.some((ref) => edge.fromRef === ref || edge.toRef === ref));
      });
      if (!valid) limited.add(obligation.obligationId);
    }
    const limitedObligationIds = [...limited];
    const unfinishedDiscovery = checkpoints.filter((item) => item.status === "RUNNING");
    const limitedDiscovery = checkpoints.filter((item) => ["LIMITED", "FAILED"].includes(item.status));
    const findingAssessmentIds = effective.filter((item) => riskVerdicts.has(item.conclusion as Assessment["verdict"])).flatMap((item) => item.effectiveAssessmentIds);
    const unresolvedConflicts = effective.filter((item) => item.conclusion === "CONFLICT");
    if (runningActionIds.length > 0) reasons.push("仍有未终止 Action");
    if (openRequiredObligationIds.length > 0) reasons.push("仍有未完成 required obligation");
    if (unfinishedDiscovery.length > 0) reasons.push("发现范围尚未处理完");
    if (obligations.length === 0) reasons.push("尚未建立调查义务");
    if (unresolvedConflicts.length > 0) reasons.push("存在未裁定的 Assessment 冲突");
    const canClose = runningActionIds.length === 0 && openRequiredObligationIds.length === 0 && unfinishedDiscovery.length === 0 && obligations.length > 0;
    const failedRequiredAction = actions.some((item) => ["FAILED", "BLOCKED", "CANCELLED"].includes(item.status)
      && item.obligationIds.some((obligationId) => requiredObligationIds.has(obligationId)));
    let status: InvestigationStatus = "OPEN";
    if (canClose && (limitedObligationIds.length > 0 || limitedDiscovery.length > 0 || unresolvedConflicts.length > 0 || failedRequiredAction)) status = "LIMITED";
    else if (canClose && findingAssessmentIds.length > 0) status = "CLOSED_WITH_FINDINGS";
    else if (canClose) {
      const coverage = this.store.listCoverageRuns(taskId, epochId);
      const categoriesConcluded = coverage.length > 0 && coverage.every((run) => run.status === "COMPLETE")
        && coverage.every((run) => run.applicability === "NOT_APPLICABLE"
          || effective.some((item) => item.category === run.category && item.scope === "OBSERVED_CATEGORY" && item.conclusion === "NO_OBSERVED_FINDING"));
      status = categoriesConcluded ? "CLOSED_NO_OBSERVED_FINDING" : "LIMITED";
      if (!categoriesConcluded) reasons.push("Coverage 或无发现结论不足以支持全范围闭合");
    }
    return { canClose, status, reasons, openRequiredObligationIds, limitedObligationIds, runningActionIds, findingAssessmentIds };
  }

  freeze(taskId: string, epochId: string): CompletionSnapshot {
    this.materializeDeterministicCategoryConclusions(taskId, epochId);
    const evaluation = this.evaluate(taskId, epochId);
    if (!evaluation.canClose) throw new Error(`调查不能结束：${evaluation.reasons.join("；")}`);
    const snapshot: CompletionSnapshot = {
      snapshotRef: `CSNAP-${randomUUID()}`,
      taskId,
      epochId,
      investigationStatus: evaluation.status,
      maxEventSeq: this.store.maxInvestigationEventSeq(taskId, epochId),
      openRequiredObligationIds: evaluation.openRequiredObligationIds,
      runningActionIds: evaluation.runningActionIds,
      limitedObligationIds: evaluation.limitedObligationIds,
      findingAssessmentIds: evaluation.findingAssessmentIds,
      createdAt: new Date().toISOString(),
    };
    this.store.putCompletionSnapshot(snapshot);
    const session = this.store.getInvestigationSession(taskId, epochId);
    if (session) this.store.updateInvestigationSession({ ...session, investigationStatus: snapshot.investigationStatus, executionStatus: "STOPPED", completionSnapshotRef: snapshot.snapshotRef, revision: session.revision + 1, updatedAt: snapshot.createdAt }, session.revision);
    return snapshot;
  }

  /**
   * Model review remains visible as a separate status, but it is not required for the
   * controller to describe the deterministic scope it completed.  Create this narrow
   * conclusion only at freeze time, after no later Action can invalidate it.
   */
  private materializeDeterministicCategoryConclusions(taskId: string, epochId: string): void {
    const obligations = this.store.listInvestigationObligations(taskId, epochId);
    if (obligations.length === 0 || obligations.some((item) => item.required && item.status !== "SATISFIED")) return;
    if (this.store.listInvestigationActions(taskId, epochId).some((item) => item.status !== "SUCCEEDED" && item.status !== "PARTIAL")) return;
    if (this.store.listDiscoveryCheckpoints(taskId, epochId).some((item) => item.status !== "COMPLETE")) return;

    const assessments = this.store.listAssessments(taskId, epochId);
    const effective = projectEffectiveAssessments(assessments, this.store.listAssessmentRelations(taskId, epochId));
    for (const run of this.store.listCoverageRuns(taskId, epochId)) {
      if (run.status !== "COMPLETE" || run.applicability !== "APPLICABLE") continue;
      if (effective.some((item) => item.category === run.category && (
        item.scope === "OBSERVED_CATEGORY"
        || riskVerdicts.has(item.conclusion as Assessment["verdict"])
        || item.conclusion === "CONFLICT"
      ))) continue;
      this.store.putAssessment({
        assessmentId: `ASM-${randomUUID()}`,
        taskId,
        epochId,
        authorType: "SYSTEM",
        category: run.category,
        scope: "OBSERVED_CATEGORY",
        verdict: "NO_OBSERVED_FINDING",
        severity: "INFO",
        confidence: 1,
        rationale: `确定性完成校验：Coverage ${run.coverageId} 完整，所有 required obligation 已满足，发现检查点与 Action 均已终止，当前观察范围内无有效风险结论。`,
        evidenceRefs: [],
        factRefs: [],
        queryRefs: [],
        createdAt: new Date().toISOString(),
      });
    }
  }

  freezeWithLimits(taskId: string, epochId: string, reason: string): CompletionSnapshot {
    const existingSession = this.store.getInvestigationSession(taskId, epochId);
    if (existingSession?.completionSnapshotRef) {
      const existing = this.store.getCompletionSnapshot(taskId, epochId, existingSession.completionSnapshotRef);
      if (existing) return existing;
    }
    for (const action of this.store.listInvestigationActions(taskId, epochId)) {
      if (action.status === "READY") this.store.blockReadyInvestigationAction(action.actionId, reason);
    }
    for (const obligation of this.store.listInvestigationObligations(taskId, epochId)) {
      if (!["OPEN", "QUEUED"].includes(obligation.status)) continue;
      this.store.updateInvestigationObligation({
        ...obligation,
        status: "LIMITED",
        gapRefs: [...new Set([...obligation.gapRefs, reason])],
        updatedAt: new Date().toISOString(),
      }, obligation.status);
    }
    return this.freeze(taskId, epochId);
  }

  freezeCancelled(taskId: string, epochId: string, reason: string): CompletionSnapshot {
    const existingSession = this.store.getInvestigationSession(taskId, epochId);
    if (existingSession?.completionSnapshotRef) {
      const existing = this.store.getCompletionSnapshot(taskId, epochId, existingSession.completionSnapshotRef);
      if (existing) return existing;
    }
    for (const action of this.store.listInvestigationActions(taskId, epochId)) {
      if (action.status === "READY") this.store.blockReadyInvestigationAction(action.actionId, reason);
      else if (action.status === "RUNNING") this.store.finishInvestigationAction(action.actionId, action.revision, "BLOCKED", action.resultRefs ?? [], `取消时远端结果未知：${reason}`);
    }
    for (const obligation of this.store.listInvestigationObligations(taskId, epochId)) {
      if (!["OPEN", "QUEUED"].includes(obligation.status)) continue;
      this.store.updateInvestigationObligation({ ...obligation, status: "CANCELLED", gapRefs: [...new Set([...obligation.gapRefs, reason])], updatedAt: new Date().toISOString() }, obligation.status);
    }
    const now = new Date().toISOString();
    const assessments = this.store.listAssessments(taskId, epochId);
    const effective = projectEffectiveAssessments(assessments, this.store.listAssessmentRelations(taskId, epochId));
    const snapshot: CompletionSnapshot = {
      snapshotRef: `CSNAP-${randomUUID()}`, taskId, epochId, investigationStatus: "CANCELLED",
      maxEventSeq: this.store.maxInvestigationEventSeq(taskId, epochId), openRequiredObligationIds: [], runningActionIds: [],
      limitedObligationIds: this.store.listInvestigationObligations(taskId, epochId).filter((item) => item.required && ["LIMITED", "CANCELLED"].includes(item.status)).map((item) => item.obligationId),
      findingAssessmentIds: effective.filter((item) => riskVerdicts.has(item.conclusion as Assessment["verdict"])).flatMap((item) => item.effectiveAssessmentIds), createdAt: now,
    };
    this.store.putCompletionSnapshot(snapshot);
    const session = this.store.getInvestigationSession(taskId, epochId);
    if (session) this.store.updateInvestigationSession({ ...session, investigationStatus: "CANCELLED", executionStatus: "STOPPED", completionSnapshotRef: snapshot.snapshotRef, revision: session.revision + 1, updatedAt: now }, session.revision);
    return snapshot;
  }
}
