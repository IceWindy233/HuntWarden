import { randomUUID } from "node:crypto";
import { digestObject } from "../common/json.js";
import type { InvestigationAction, InvestigationLead, InvestigationObligation, InvestigationSession } from "../investigation/types.js";
import type { FactRecord, NamespaceName } from "../protocol-v2/types.js";
import { MAX_ACTIVE_INVESTIGATION_ACTIONS, type RuntimeStore } from "../storage/runtime-store.js";
import { isPublicThreatIntelIp } from "../threat-intel/network-ioc.js";

const EXECUTABLE_COLLECT_BYTES = 10 * 1_024 * 1_024;

export interface DiscoveryPlanResult {
  leadIds: string[];
  obligationIds: string[];
  actionIds: string[];
}

export class VolatileDiscoveryPlanner {
  constructor(private readonly store: RuntimeStore) {}

  plan(taskId: string, epochId: string, session: InvestigationSession): DiscoveryPlanResult {
    const task = this.store.getTask(taskId);
    if (!task?.checks.includes("linux_intrusion_triage")) return { leadIds: [], obligationIds: [], actionIds: [] };
    const facts = this.store.listFacts(taskId, epochId);
    const processFacts = latestBySubject(facts.filter((fact) => fact.namespace === "process"));
    const socketFacts = latestBySubject(facts.filter((fact) => fact.namespace === "socket"));
    const processByPid = new Map<number, FactRecord>();
    for (const fact of processFacts) if (typeof fact.privatePayload.pid === "number") processByPid.set(fact.privatePayload.pid, fact);
    const candidates: Array<{ subject: FactRecord; triggerFacts: FactRecord[]; trigger: string; priority: number }> = [];
    for (const socket of socketFacts) {
      const address = socket.privatePayload.remoteAddress;
      if (typeof address !== "string" || !isPublicThreatIntelIp(address)) continue;
      const process = typeof socket.privatePayload.pid === "number" ? processByPid.get(socket.privatePayload.pid) : undefined;
      candidates.push({ subject: process ?? socket, triggerFacts: process ? [socket, process] : [socket], trigger: "EXTERNAL_CONNECTION", priority: process ? 100 : 90 });
    }
    for (const process of processFacts) {
      const path = String(process.privatePayload.exe ?? "");
      const command = String(process.privatePayload.command ?? "");
      const unusual = /(?:^|\/)(?:tmp|dev\/shm|var\/tmp)\//.test(path) || /\(deleted\)/.test(path)
        || /(?:^|\s|["'])\/(?:tmp|dev\/shm|var\/tmp)\//.test(command)
        || /(?:^|\s)(?:curl|wget|nc|ncat|socat)\b/.test(command);
      if (unusual && !candidates.some((item) => item.subject.subjectRef === process.subjectRef)) candidates.push({ subject: process, triggerFacts: [process], trigger: "UNUSUAL_EXECUTION", priority: 80 });
    }

    const leadIds: string[] = [];
    const obligationIds: string[] = [];
    const actionIds: string[] = [];
    const plannedOperations = new Map<string, Set<string>>();
    const existingActions = this.store.listInvestigationActions(taskId, epochId);
    let availableSlots = MAX_ACTIVE_INVESTIGATION_ACTIONS - existingActions.filter((action) => ["READY", "RUNNING"].includes(action.status)).length;
    for (const action of existingActions) {
      if (action.requestedBy !== "DISCOVERY") continue;
      for (const subjectRef of action.subjectRefs) {
        const operations = plannedOperations.get(subjectRef) ?? new Set<string>();
        operations.add(`${action.operationRef}:${action.argsDigest}`);
        plannedOperations.set(subjectRef, operations);
      }
    }
    const missingOperationCount = (candidate: { subject: FactRecord }) => this.operationsFor(candidate)
      .filter((operation) => !plannedOperations.get(candidate.subject.subjectRef)?.has(`${operation.operationRef}:${digestObject(operation.args)}`)).length;
    const pendingCandidates = candidates.filter((candidate) => missingOperationCount(candidate) > 0);
    for (const candidate of pendingCandidates.slice(0, 100)) {
      const missingActions = missingOperationCount(candidate);
      if (missingActions > availableSlots) continue;
      availableSlots -= missingActions;
      const lead = this.putLead(candidate, taskId, epochId);
      leadIds.push(lead.leadId);
      const planned = this.planSubject(candidate, lead, session);
      obligationIds.push(...planned.obligationIds);
      actionIds.push(...planned.actionIds);
    }

    const now = new Date().toISOString();
    const coverage = this.store.listCoverageRuns(taskId, epochId).find((item) => item.category === "linux_intrusion_triage");
    const candidateLimitReached = pendingCandidates.length > leadIds.length;
    const discoveryStatus: InvestigationObligation["status"] = !coverage ? "OPEN" : coverage.status === "COMPLETE" && !candidateLimitReached ? "SATISFIED" : "LIMITED";
    let discovery = this.store.putInvestigationObligation({
      obligationId: `OBL-${randomUUID()}`,
      taskId,
      epochId,
      obligationKind: "VOLATILE_DISCOVERY_SCOPE",
      dedupeKey: "VOLATILE_DISCOVERY_SCOPE",
      subjectRefs: [],
      required: true,
      status: discoveryStatus,
      resultRefs: facts.filter((fact) => fact.namespace === "process" || fact.namespace === "socket").map((fact) => fact.factId),
      gapRefs: [...(coverage?.missingCriteria.map((item) => item.reasonCode) ?? ["COVERAGE_NOT_RECORDED"]), ...(candidateLimitReached ? ["CANDIDATE_QUEUE_LIMIT"] : [])],
      createdAt: now,
      updatedAt: now,
    });
    const scopeResults = facts.filter((fact) => fact.namespace === "process" || fact.namespace === "socket").map((fact) => fact.factId);
    const scopeGaps = [...(coverage?.missingCriteria.map((item) => item.reasonCode) ?? ["COVERAGE_NOT_RECORDED"]), ...(candidateLimitReached ? ["CANDIDATE_QUEUE_LIMIT"] : [])];
    // 范围义务是当前发现状态的聚合投影；队列排空后可解除暂时限制，新缺口也必须重新打开。
    if (discovery.status !== discoveryStatus || digestObject(discovery.resultRefs) !== digestObject(scopeResults) || digestObject(discovery.gapRefs) !== digestObject(scopeGaps)) {
      const previous = discovery.status;
      discovery = { ...discovery, status: discoveryStatus, resultRefs: scopeResults, gapRefs: scopeGaps, updatedAt: now };
      this.store.updateInvestigationObligation(discovery, previous);
    }
    obligationIds.push(discovery.obligationId);
    this.store.putDiscoveryCheckpoint({
      checkpointId: `DCP-${randomUUID()}`,
      taskId,
      epochId,
      namespace: "process",
      requestDigest: digestObject({ planner: "volatile-discovery@1.0.0", namespaces: ["process", "socket"] }),
      status: discoveryStatus === "SATISFIED" ? "COMPLETE" : discoveryStatus === "OPEN" ? "RUNNING" : "LIMITED",
      scannedCount: processFacts.length + socketFacts.length,
      matchedCount: candidates.length,
      returnedCount: leadIds.length,
      ...(candidateLimitReached ? { remainingDescription: `${pendingCandidates.length - leadIds.length} 个候选因批次或活动队列容量待后续处理` } : {}),
      createdAt: now,
      updatedAt: now,
    });
    return { leadIds, obligationIds: [...new Set(obligationIds)], actionIds: [...new Set(actionIds)] };
  }

  private putLead(candidate: { subject: FactRecord; triggerFacts: FactRecord[]; trigger: string; priority: number }, taskId: string, epochId: string): InvestigationLead {
    const now = new Date().toISOString();
    // process/socket 的稳定身份在 Epoch 内已经区分 PID 复用和 socket inode；后续
    // project 只是补齐字段，不能因此把同一线索再次排入整条易失调查链。
    const observationRound = `SUBJECT:${candidate.subject.subjectRef}`;
    return this.store.putInvestigationLead({
      leadId: `LEAD-${randomUUID()}`,
      taskId,
      epochId,
      subjectRef: candidate.subject.subjectRef,
      triggerKind: candidate.trigger,
      triggerVersion: "1.0.0",
      triggerFactRefs: candidate.triggerFacts.map((fact) => fact.factId),
      observationRound,
      priority: candidate.priority,
      status: "OPEN",
      createdAt: now,
      updatedAt: now,
    });
  }

  private operationsFor(candidate: { subject: FactRecord }) {
    return candidate.subject.namespace === "process"
      ? [
          { obligationKind: "VERIFY_PROCESS_IDENTITY", operationRef: "project", args: { ref: candidate.subject.subjectRef, fields: ["pid", "startTicks", "exe", "exeDeleted", "exeInode", "exeSha256", "command", "launcherPath", "namespaces", "cgroups", "mapsSummary"] }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "PRESERVE_EXECUTABLE_EVIDENCE", operationRef: "collect", args: { ref: candidate.subject.subjectRef, maxBytes: EXECUTABLE_COLLECT_BYTES, purpose: "AUTONOMOUS_VOLATILE_PRESERVATION" }, replayPolicy: "RESUME_OR_RECOLLECT" as const },
          { obligationKind: "TRACE_PROCESS_EXECUTABLE", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "executable", limit: 20 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "TRACE_PROCESS_COMMAND_FILES", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "command_file", limit: 100 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "TRACE_PROCESS_PARENT", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "parent", limit: 20 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "TRACE_PROCESS_CONNECTIONS", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "connects", limit: 500 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "TRACE_PROCESS_STARTUP", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "started_by", limit: 100 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "TRACE_PROCESS_OPEN_FILES", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "opens", limit: 500 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "CHECK_PROCESS_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "process", subjectRef: candidate.subject.subjectRef, limit: 100 }, replayPolicy: "SAFE_REOBSERVE" as const },
        ]
      : [
          { obligationKind: "BIND_SOCKET_OWNER", operationRef: "relate", args: { ref: candidate.subject.subjectRef, relation: "owned_by", limit: 20 }, replayPolicy: "SAFE_REOBSERVE" as const },
          { obligationKind: "CHECK_SOCKET_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "socket", subjectRef: candidate.subject.subjectRef, limit: 100 }, replayPolicy: "SAFE_REOBSERVE" as const },
        ];
  }

  private planSubject(candidate: { subject: FactRecord; triggerFacts: FactRecord[]; trigger: string; priority: number }, lead: InvestigationLead, session: InvestigationSession): { obligationIds: string[]; actionIds: string[] } {
    const operations = this.operationsFor(candidate);
    const obligationIds: string[] = [];
    const actionIds: string[] = [];
    for (const [index, operation] of operations.entries()) {
      const now = new Date().toISOString();
      const obligation = this.store.putInvestigationObligation({
        obligationId: `OBL-${randomUUID()}`,
        taskId: lead.taskId,
        epochId: lead.epochId,
        obligationKind: operation.obligationKind,
        dedupeKey: `${operation.obligationKind}:${lead.subjectRef}`,
        subjectRefs: [lead.subjectRef],
        required: operation.obligationKind !== "CHECK_PROCESS_COUNTEREVIDENCE" && operation.obligationKind !== "CHECK_SOCKET_COUNTEREVIDENCE",
        status: "QUEUED",
        resultRefs: [],
        gapRefs: [],
        createdAt: now,
        updatedAt: now,
      });
      obligationIds.push(obligation.obligationId);
      const argsDigest = digestObject(operation.args);
      const value: InvestigationAction = {
        actionId: `IACT-${randomUUID()}`,
        taskId: lead.taskId,
        epochId: lead.epochId,
        kind: operation.operationRef === "query_facts" ? "LOCAL_QUERY" : "REMOTE_PRIMITIVE",
        requestedBy: "DISCOVERY",
        obligationIds: [obligation.obligationId],
        subjectRefs: [lead.subjectRef],
        entityVersionRefs: this.store.listEntityVersions(lead.taskId, lead.epochId, lead.subjectRef).slice(-1).map((item) => item.versionRef),
        operationRef: operation.operationRef,
        replayPolicy: operation.replayPolicy,
        args: operation.args,
        argsDigest,
        dependsOn: [],
        authorizationVersion: session.authorizationVersion,
        observationRound: lead.observationRound,
        idempotencyKey: digestObject({ taskId: lead.taskId, epochId: lead.epochId, operationRef: operation.operationRef, subjectRef: lead.subjectRef, argsDigest, observationRound: lead.observationRound }),
        priority: lead.priority - index,
        status: "READY",
        revision: 0,
        createdAt: now,
        updatedAt: now,
      };
      const stored = this.store.putInvestigationAction(value);
      actionIds.push(stored.actionId);
    }
    return { obligationIds, actionIds };
  }
}

function latestBySubject(facts: FactRecord[]): FactRecord[] {
  const values = new Map<string, FactRecord>();
  for (const fact of facts) {
    const previous = values.get(fact.subjectRef);
    if (!previous || previous.factSeq < fact.factSeq) values.set(fact.subjectRef, fact);
  }
  return [...values.values()];
}

export const VOLATILE_DISCOVERY_NAMESPACES: readonly NamespaceName[] = ["process", "socket"];
