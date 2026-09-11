import { randomUUID } from "node:crypto";
import { digestObject } from "../common/json.js";
import type { CheckCategory } from "../domain/types.js";
import type { InvestigationAction, InvestigationHypothesis, InvestigationSession } from "../investigation/types.js";
import type { FactRecord } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import { projectEffectiveAssessments } from "../assessments/projection.js";
import { isUsableJavaClassIdentifier } from "../investigation/java-class-identity.js";

export const PLAYBOOK_REGISTRY_VERSION = "1.3.1";

const MAX_COLLECT_BYTES = 104_857_600;
const DEFAULT_EXECUTABLE_COLLECT_BYTES = 10 * 1_024 * 1_024;
export const PLAYBOOK_CANDIDATE_BATCH_SIZE = 200;

export const PLAYBOOK_DEFINITIONS = Object.freeze([
  { id: "process-egress", version: "1.3.1", categories: ["linux_intrusion_triage"] },
  { id: "web-execution-chain", version: "1.3.0", categories: ["webshell"] },
  { id: "account-trust-persistence", version: "1.3.0", categories: ["backdoor_account", "linux_persistence"] },
  { id: "java-runtime-bytecode", version: "1.3.0", categories: ["java_memory_shell"] },
] as const);

export interface PlaybookPlanResult {
  hypothesisIds: string[];
  obligationIds: string[];
  actionIds: string[];
}

interface PlannedOperation {
  obligationKind: string;
  operationRef: string;
  args: Record<string, unknown>;
  required: boolean;
  replayPolicy?: InvestigationAction["replayPolicy"];
  priority: number;
}

export class InvestigationPlaybookPlanner {
  constructor(private readonly store: RuntimeStore) {}

  plan(taskId: string, epochId: string, session: InvestigationSession): PlaybookPlanResult {
    const task = this.store.getTask(taskId);
    if (!task) throw new Error(`未知任务 ${taskId}`);
    const facts = this.store.listFacts(taskId, epochId);
    const assessments = this.store.listAssessments(taskId, epochId);
    const effectiveRiskIds = new Set(projectEffectiveAssessments(assessments, this.store.listAssessmentRelations(taskId, epochId))
      .filter((item) => ["SUSPICIOUS", "HIGHLY_SUSPICIOUS", "CONFIRMED_MALICIOUS"].includes(item.conclusion))
      .flatMap((item) => item.effectiveAssessmentIds));
    const riskAssessments = assessments
      .filter((assessment) => assessment.subjectRef && effectiveRiskIds.has(assessment.assessmentId));
    const riskSubjects = new Set(riskAssessments.map((assessment) => assessment.subjectRef!));
    const riskCategories = new Map<string, Set<CheckCategory>>();
    for (const assessment of riskAssessments) {
      const categories = riskCategories.get(assessment.subjectRef!) ?? new Set<CheckCategory>();
      categories.add(assessment.category); riskCategories.set(assessment.subjectRef!, categories);
    }
    const edges = this.store.listEdges(taskId, epochId);
    const checkpointKey = "PLAYBOOK_CANDIDATES:1";
    const checkpoint = this.store.listDiscoveryCheckpoints(taskId, epochId)
      .find((item) => item.namespace === "task_ioc" && item.requestDigest === checkpointKey);
    const processedFactSeq = checkpoint?.scannedCount ?? 0;
    const plannedRiskSubjects = new Set(this.store.listInvestigationHypotheses(taskId, epochId)
      .filter((item) => item.proposedBy === "PLAYBOOK")
      .map((item) => item.subjectRef));
    const latestFacts = latestBySubject(facts);
    const candidates = latestFacts.filter((fact) => (fact.factSeq > processedFactSeq || (riskSubjects.has(fact.subjectRef) && !plannedRiskSubjects.has(fact.subjectRef)))
      && isPlaybookCandidate(fact, riskSubjects.has(fact.subjectRef), edges))
      .sort((left, right) => left.factSeq - right.factSeq);
    const selected = candidates.slice(0, PLAYBOOK_CANDIDATE_BATCH_SIZE);
    const result: PlaybookPlanResult = { hypothesisIds: [], obligationIds: [], actionIds: [] };

    for (const fact of selected) {
      for (const category of categoriesForFact(fact, task.checks, edges, riskCategories.get(fact.subjectRef))) {
        const operations = operationsForFact(fact, category, edges);
        if (operations.length === 0) continue;
        const hypothesis = this.ensureHypothesis(taskId, epochId, fact, category);
        result.hypothesisIds.push(hypothesis.hypothesisId);
        for (const operation of operations) {
          const planned = this.putOperation(session, hypothesis, fact, operation);
          result.obligationIds.push(planned.obligationId);
          result.actionIds.push(planned.actionId);
        }
      }
    }
    const processedFactSeqAfterBatch = selected.at(-1)?.factSeq ?? Math.max(processedFactSeq, ...latestFacts.map((fact) => fact.factSeq), 0);
    const remaining = candidates.length - selected.length;
    const checkpointNow = new Date().toISOString();
    this.store.putDiscoveryCheckpoint({
      checkpointId: checkpoint?.checkpointId ?? `DCHK-${randomUUID()}`, taskId, epochId, namespace: "task_ioc",
      requestDigest: checkpointKey, status: remaining > 0 ? "RUNNING" : "COMPLETE",
      sourceGeneration: String(this.store.maxInvestigationEventSeq(taskId, epochId)), ...(remaining > 0 ? { cursorRef: String(processedFactSeqAfterBatch) } : {}),
      scannedCount: processedFactSeqAfterBatch, matchedCount: (checkpoint?.matchedCount ?? 0) + selected.length, returnedCount: (checkpoint?.returnedCount ?? 0) + selected.length,
      ...(remaining > 0 ? { remainingDescription: `${remaining} 个 Playbook 候选待处理` } : {}),
      createdAt: checkpoint?.createdAt ?? checkpointNow, updatedAt: checkpointNow,
    });

    for (const category of task.checks) {
      const now = new Date().toISOString();
      const coverage = this.store.listCoverageRuns(taskId, epochId).find((item) => item.category === category);
      const desiredStatus = !coverage ? "OPEN" as const : coverage.status === "COMPLETE" ? "SATISFIED" as const : "LIMITED" as const;
      let obligation = this.store.putInvestigationObligation({
        obligationId: `OBL-${randomUUID()}`, taskId, epochId,
        obligationKind: `CATEGORY_SCOPE_${category.toUpperCase()}`,
        dedupeKey: `CATEGORY_SCOPE:${category}`,
        subjectRefs: [], required: true,
        status: desiredStatus,
        resultRefs: coverage ? [coverage.coverageId] : [],
        gapRefs: coverage?.missingCriteria.map((item) => item.reasonCode) ?? ["COVERAGE_NOT_RECORDED"],
        createdAt: now, updatedAt: now,
      });
      if (obligation.status !== desiredStatus && ["OPEN", "QUEUED"].includes(obligation.status)) {
        const previous = obligation.status;
        obligation = { ...obligation, status: desiredStatus, resultRefs: coverage ? [coverage.coverageId] : obligation.resultRefs, gapRefs: coverage?.missingCriteria.map((item) => item.reasonCode) ?? obligation.gapRefs, updatedAt: now };
        this.store.updateInvestigationObligation(obligation, previous);
      }
      result.obligationIds.push(obligation.obligationId);
    }
    return {
      hypothesisIds: [...new Set(result.hypothesisIds)],
      obligationIds: [...new Set(result.obligationIds)],
      actionIds: [...new Set(result.actionIds)],
    };
  }

  private ensureHypothesis(taskId: string, epochId: string, fact: FactRecord, category: CheckCategory): InvestigationHypothesis {
    const claim = claimFor(category, fact.namespace);
    const existing = this.store.listInvestigationHypotheses(taskId, epochId)
      .find((item) => item.subjectRef === fact.subjectRef && item.claim === claim && item.proposedBy === "PLAYBOOK");
    if (existing) return existing;
    const now = new Date().toISOString();
    const hypothesis: InvestigationHypothesis = {
      hypothesisId: `HYP-${randomUUID()}`, taskId, epochId, subjectRef: fact.subjectRef, claim,
      proposedBy: "PLAYBOOK", supportRefs: [fact.factId], counterEvidenceRefs: [],
      alternativeExplanations: benignAlternatives(category), status: "OPEN", revision: 0,
      createdAt: now, updatedAt: now,
    };
    this.store.putInvestigationHypothesis(hypothesis);
    return hypothesis;
  }

  private putOperation(session: InvestigationSession, hypothesis: InvestigationHypothesis, fact: FactRecord, operation: PlannedOperation): { obligationId: string; actionId: string } {
    const now = new Date().toISOString();
    const dedupeKey = `${operation.obligationKind}:${hypothesis.subjectRef}`;
    const obligation = this.store.putInvestigationObligation({
      obligationId: `OBL-${randomUUID()}`, taskId: hypothesis.taskId, epochId: hypothesis.epochId,
      hypothesisId: hypothesis.hypothesisId, obligationKind: operation.obligationKind, dedupeKey,
      subjectRefs: [hypothesis.subjectRef], required: operation.required, status: "QUEUED",
      resultRefs: [], gapRefs: [], createdAt: now, updatedAt: now,
    });
    const argsDigest = digestObject(operation.args);
    // ObjectRef 已由 namespace 稳定身份约束；project/match/verify/collect 只会给同一对象
    // 增补字段并形成新的 EntityVersion。若把版本引用作为轮次，这些动作会互相触发并反复
    // 排队直至耗尽预算。真正换对象会获得新的 ObjectRef，因此 Epoch 内按主体去重。
    const observationRound = `SUBJECT:${fact.subjectRef}`;
    const action = this.store.putInvestigationAction({
      actionId: `IACT-${randomUUID()}`, taskId: hypothesis.taskId, epochId: hypothesis.epochId,
      kind: operation.operationRef === "query_facts" ? "LOCAL_QUERY" : operation.operationRef === "resolve_derived_objects" ? "DERIVE" : "REMOTE_PRIMITIVE",
      requestedBy: "PLAYBOOK", obligationIds: [obligation.obligationId],
      subjectRefs: [hypothesis.subjectRef],
      entityVersionRefs: this.store.listEntityVersions(hypothesis.taskId, hypothesis.epochId, fact.subjectRef).slice(-1).map((item) => item.versionRef),
      operationRef: operation.operationRef, replayPolicy: operation.replayPolicy ?? "SAFE_REOBSERVE",
      args: operation.args, argsDigest, dependsOn: [], authorizationVersion: session.authorizationVersion,
      observationRound,
      // 幂等键描述实际动作，而不是哪个规划器提出了动作。这样易失发现器和
      // Playbook 在同一观察轮提出相同读取时只执行一次；语义变化会体现在 argsDigest。
      idempotencyKey: digestObject({ taskId: hypothesis.taskId, epochId: hypothesis.epochId, operationRef: operation.operationRef, subjectRef: hypothesis.subjectRef, argsDigest, observationRound }),
      priority: operation.priority, status: "READY", revision: 0, createdAt: now, updatedAt: now,
    });
    return { obligationId: obligation.obligationId, actionId: action.actionId };
  }
}

function categoriesForFact(fact: FactRecord, checks: readonly CheckCategory[], edges: readonly { fromRef: string; toRef: string; relation: string }[], riskCategories?: ReadonlySet<CheckCategory>): CheckCategory[] {
  const allowed = new Set(checks);
  const categories = new Set([...(riskCategories ?? [])].filter((category) => allowed.has(category)));
  if (fact.namespace === "file" && allowed.has("webshell") && (riskCategories?.has("webshell") || isWebCandidate(fact))) categories.add("webshell");
  if (fact.namespace === "file" && allowed.has("linux_persistence") && edges.some((edge) => edge.toRef === fact.subjectRef && ["executes", "referenced_by_persistence"].includes(edge.relation))) categories.add("linux_persistence");
  if (fact.namespace === "file" && allowed.has("linux_intrusion_triage") && edges.some((edge) => edge.toRef === fact.subjectRef && ["executable", "command_file", "executes"].includes(edge.relation))) categories.add("linux_intrusion_triage");
  if (fact.namespace === "file" && allowed.has("backdoor_account") && edges.some((edge) => edge.toRef === fact.subjectRef && edge.relation === "references")) categories.add("backdoor_account");
  if (["account", "ssh_key", "delegation_rule", "ssh_trust_config"].includes(fact.namespace) && allowed.has("backdoor_account")) categories.add("backdoor_account");
  if (["cron_entry", "unit", "persistence"].includes(fact.namespace) && allowed.has("linux_persistence")) categories.add("linux_persistence");
  if (["cron_entry", "unit", "persistence"].includes(fact.namespace) && allowed.has("linux_intrusion_triage") && edges.some((edge) => edge.toRef === fact.subjectRef && edge.relation === "started_by")) categories.add("linux_intrusion_triage");
  if (["jvm", "java_component", "class"].includes(fact.namespace) && allowed.has("java_memory_shell")) categories.add("java_memory_shell");
  if (["process", "socket", "exec_event"].includes(fact.namespace) && allowed.has("linux_intrusion_triage")) categories.add("linux_intrusion_triage");
  return [...categories];
}

function isPlaybookCandidate(fact: FactRecord, hasRiskAssessment: boolean, edges: readonly { fromRef: string; toRef: string; relation: string }[]): boolean {
  if (hasRiskAssessment) return true;
  if (fact.namespace === "file") return isWebCandidate(fact) || edges.some((edge) => edge.toRef === fact.subjectRef && ["executable", "command_file", "executes", "references"].includes(edge.relation));
  if (["cron_entry", "unit", "persistence"].includes(fact.namespace)) return edges.some((edge) => edge.toRef === fact.subjectRef && edge.relation === "started_by");
  if (fact.namespace === "socket") {
    const address = fact.privatePayload.remoteAddress;
    return typeof address === "string" && !/^(?:127\.|10\.|192\.168\.|169\.254\.|0\.|::1$|fc|fd|fe80)/i.test(address);
  }
  if (fact.namespace === "process") {
    const exe = String(fact.privatePayload.exe ?? "");
    const command = String(fact.privatePayload.command ?? "");
    return fact.privatePayload.exeDeleted === true || /(?:^|\/)(?:tmp|dev\/shm|var\/tmp)\//.test(exe)
      || /(?:^|\s|["'])\/(?:tmp|dev\/shm|var\/tmp)\//.test(command)
      || /(?:^|\s)(?:curl|wget|nc|ncat|socat)\b/.test(command);
  }
  return false;
}

function operationsForFact(fact: FactRecord, category: CheckCategory, edges: readonly { fromRef: string; toRef: string; relation: string }[]): PlannedOperation[] {
  if (fact.namespace === "file" && category === "webshell") {
    const yaraHit = typeof fact.privatePayload.content === "string" && fact.privatePayload.content.startsWith("YARA_MATCH:");
    return yaraHit ? [
      { obligationKind: "WEB_PRESERVE_CANDIDATE", operationRef: "collect", args: { ref: fact.subjectRef, maxBytes: collectBytesForFact(fact), purpose: "WEB_CANDIDATE_PRESERVATION" }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 96 },
      { obligationKind: "WEB_VERIFY_FILE_VERSION", operationRef: "project", args: { ref: fact.subjectRef, fields: ["path", "size", "mtime", "sha256", "contentClass"] }, required: true, priority: 92 },
      { obligationKind: "WEB_PACKAGE_COUNTERCHECK", operationRef: "verify", args: { ref: fact.subjectRef, baseline: "package_db" }, required: false, priority: 78 },
      { obligationKind: "WEB_TRACE_REQUESTS", operationRef: "relate", args: { ref: fact.subjectRef, relation: "requested_in", limit: 500 }, required: false, priority: 84 },
      { obligationKind: "WEB_TRACE_WORKER", operationRef: "relate", args: { ref: fact.subjectRef, relation: "opened_by", limit: 100 }, required: false, priority: 82 },
      { obligationKind: "WEB_TRACE_PERSISTENCE", operationRef: "relate", args: { ref: fact.subjectRef, relation: "referenced_by_persistence", limit: 100 }, required: false, priority: 76 },
      { obligationKind: "WEB_QUERY_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "file", subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 68 },
    ] : [
      { obligationKind: "WEB_MATCH_BUILTIN_RULESET", operationRef: "match", args: { refs: [fact.subjectRef], matcher: { engine: "yara", ruleSetRef: "RULESET-WEBSHELL-BUILTIN-2" }, maxHits: 20, includeContext: false }, required: true, priority: 94 },
      { obligationKind: "WEB_TRACE_REQUESTS", operationRef: "relate", args: { ref: fact.subjectRef, relation: "requested_in", limit: 500 }, required: false, priority: 76 },
      { obligationKind: "WEB_TRACE_WORKER", operationRef: "relate", args: { ref: fact.subjectRef, relation: "opened_by", limit: 100 }, required: false, priority: 74 },
      { obligationKind: "WEB_TRACE_PERSISTENCE", operationRef: "relate", args: { ref: fact.subjectRef, relation: "referenced_by_persistence", limit: 100 }, required: false, priority: 70 },
    ];
  }
  if (fact.namespace === "file" && category === "linux_persistence") return [
    { obligationKind: "PERSISTENCE_VERIFY_TARGET_FILE", operationRef: "project", args: { ref: fact.subjectRef, fields: ["path", "size", "mtime", "sha256", "contentClass"] }, required: true, priority: 84 },
    { obligationKind: "PERSISTENCE_BASELINE_TARGET_FILE", operationRef: "verify", args: { ref: fact.subjectRef, baseline: "package_db" }, required: false, priority: 72 },
    { obligationKind: "PERSISTENCE_PRESERVE_TARGET_FILE", operationRef: "collect", args: { ref: fact.subjectRef, maxBytes: collectBytesForFact(fact), purpose: "PERSISTENCE_TARGET_PRESERVATION" }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 88 },
  ];
  if (fact.namespace === "file" && category === "linux_intrusion_triage") return [
    { obligationKind: "PROCESS_FILE_VERIFY_VERSION", operationRef: "project", args: { ref: fact.subjectRef, fields: ["path", "size", "mtime", "sha256", "contentClass"] }, required: true, priority: 86 },
    { obligationKind: "PROCESS_FILE_PACKAGE_COUNTERCHECK", operationRef: "verify", args: { ref: fact.subjectRef, baseline: "package_db" }, required: false, priority: 76 },
    { obligationKind: "PROCESS_FILE_PRESERVE", operationRef: "collect", args: { ref: fact.subjectRef, maxBytes: collectBytesForFact(fact), purpose: "PROCESS_RELATED_FILE_PRESERVATION" }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 92 },
    { obligationKind: "PROCESS_FILE_TRACE_PERSISTENCE", operationRef: "relate", args: { ref: fact.subjectRef, relation: "referenced_by_persistence", limit: 100 }, required: true, priority: 82 },
    { obligationKind: "PROCESS_FILE_TRACE_OPENERS", operationRef: "relate", args: { ref: fact.subjectRef, relation: "opened_by", limit: 100 }, required: false, priority: 68 },
    { obligationKind: "PROCESS_FILE_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "file", subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 60 },
  ];
  if (fact.namespace === "file" && category === "backdoor_account") return [
    { obligationKind: "ACCOUNT_VERIFY_TRUST_FILE", operationRef: "project", args: { ref: fact.subjectRef, fields: ["path", "size", "mtime", "sha256", "contentClass"] }, required: true, priority: 86 },
    { obligationKind: "ACCOUNT_PRESERVE_TRUST_FILE", operationRef: "collect", args: { ref: fact.subjectRef, maxBytes: collectBytesForFact(fact), purpose: "SSH_TRUST_EVIDENCE" }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 90 },
    { obligationKind: "ACCOUNT_TRUST_FILE_PACKAGE_COUNTERCHECK", operationRef: "verify", args: { ref: fact.subjectRef, baseline: "package_db" }, required: false, priority: 70 },
    { obligationKind: "ACCOUNT_TRUST_FILE_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "file", subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 60 },
  ];
  if (fact.namespace === "account") return [
    { obligationKind: "ACCOUNT_VERIFY_CURRENT_STATE", operationRef: "project", args: { ref: fact.subjectRef, fields: ["uid", "username", "gid", "home", "shell", "groups", "locked"] }, required: true, priority: 80 },
    { obligationKind: "ACCOUNT_TRACE_KEYS", operationRef: "relate", args: { ref: fact.subjectRef, relation: "authorized_key", limit: 100 }, required: true, priority: 75 },
    { obligationKind: "ACCOUNT_TRACE_LOGIN", operationRef: "relate", args: { ref: fact.subjectRef, relation: "login_event", limit: 100 }, required: false, priority: 70 },
  ];
  if (fact.namespace === "ssh_key") return [
    { obligationKind: "ACCOUNT_BIND_KEY_OWNER", operationRef: "relate", args: { ref: fact.subjectRef, relation: "owned_by", limit: 20 }, required: true, priority: 82 },
    { obligationKind: "ACCOUNT_REVIEW_KEY_SOURCE", operationRef: "query_facts", args: { view: "facts", namespace: "ssh_key", subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 68 },
  ];
  if (fact.namespace === "delegation_rule" || fact.namespace === "ssh_trust_config") return [
    { obligationKind: "ACCOUNT_VERIFY_EFFECTIVE_TRUST", operationRef: "project", args: { ref: fact.subjectRef, fields: Object.keys(fact.modelPayload).slice(0, 20) }, required: true, priority: 80 },
    ...(fact.namespace === "ssh_trust_config" && ["authorizedkeysfile", "trustedusercakeys", "authorizedprincipalsfile"].includes(String(fact.privatePayload.directive))
      ? [{ obligationKind: "ACCOUNT_TRACE_TRUST_FILE", operationRef: "relate", args: { ref: fact.subjectRef, relation: "references", limit: 20 }, required: false, priority: 76 } satisfies PlannedOperation]
      : []),
    { obligationKind: "ACCOUNT_REVIEW_TRUST_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: fact.namespace, subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 66 },
  ];
  if (["cron_entry", "unit", "persistence"].includes(fact.namespace)) return [
    { obligationKind: "PERSISTENCE_VERIFY_SOURCE", operationRef: "project", args: { ref: fact.subjectRef, fields: Object.keys(fact.modelPayload).slice(0, 20) }, required: true, priority: 82 },
    { obligationKind: "PERSISTENCE_TRACE_EXECUTION", operationRef: "relate", args: { ref: fact.subjectRef, relation: "executes", limit: 100 }, required: true, priority: 76 },
    { obligationKind: "PERSISTENCE_QUERY_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: fact.namespace, subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 65 },
  ];
  if (fact.namespace === "jvm") return [
    { obligationKind: "JAVA_INVENTORY_RUNTIME", operationRef: "probe", args: { ref: fact.subjectRef, probeKind: "jvm.tomcat.inventory", parameters: {} }, required: true, priority: 85 },
  ];
  if (fact.namespace === "java_component") {
    const jvmRef = edges.find((edge) => edge.toRef === fact.subjectRef && edge.relation === "hosts_component")?.fromRef;
    const className = fact.privatePayload.className;
    const classLoaderId = fact.privatePayload.classLoaderId;
    return jvmRef && isUsableJavaClassIdentifier(className) && isUsableJavaClassIdentifier(classLoaderId) ? [
      { obligationKind: "JAVA_INSPECT_EXACT_CLASS", operationRef: "probe", args: { ref: jvmRef, probeKind: "jvm.class.inspect", parameters: { className, classLoaderId } }, required: true, priority: 88 },
      { obligationKind: "JAVA_PRESERVE_BYTECODE", operationRef: "probe", args: { ref: jvmRef, probeKind: "jvm.class.dump", parameters: { className, classLoaderId } }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 92 },
    ] : [];
  }
  if (fact.namespace === "class") return [
    { obligationKind: "JAVA_QUERY_CLASS_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: "class", subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 68 },
  ];
  if (fact.namespace === "socket") return [
    { obligationKind: "BIND_SOCKET_OWNER", operationRef: "relate", args: { ref: fact.subjectRef, relation: "owned_by", limit: 20 }, required: true, priority: 92 },
    { obligationKind: "PROCESS_EGRESS_DERIVE_OWNER", operationRef: "resolve_derived_objects", args: { resolverRef: "socket.owner_by_pid@1.0.0", sourceFactRef: fact.factId }, required: false, priority: 74 },
    { obligationKind: "PROCESS_EGRESS_LOCAL_REVIEW", operationRef: "query_facts", args: { view: "facts", namespace: fact.namespace, subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 58 },
  ];
  if (fact.namespace === "process") return [
    { obligationKind: "VERIFY_PROCESS_IDENTITY", operationRef: "project", args: { ref: fact.subjectRef, fields: ["pid", "startTicks", "exe", "exeDeleted", "exeInode", "exeSha256", "command", "launcherPath", "namespaces", "cgroups", "mapsSummary"] }, required: true, priority: 98 },
    { obligationKind: "PRESERVE_EXECUTABLE_EVIDENCE", operationRef: "collect", args: { ref: fact.subjectRef, maxBytes: collectBytesForFact(fact), purpose: "AUTONOMOUS_VOLATILE_PRESERVATION" }, required: true, replayPolicy: "RESUME_OR_RECOLLECT", priority: 97 },
    { obligationKind: "TRACE_PROCESS_EXECUTABLE", operationRef: "relate", args: { ref: fact.subjectRef, relation: "executable", limit: 20 }, required: true, priority: 94 },
    { obligationKind: "TRACE_PROCESS_COMMAND_FILES", operationRef: "relate", args: { ref: fact.subjectRef, relation: "command_file", limit: 100 }, required: true, priority: 92 },
    { obligationKind: "TRACE_PROCESS_PARENT", operationRef: "relate", args: { ref: fact.subjectRef, relation: "parent", limit: 20 }, required: true, priority: 90 },
    { obligationKind: "TRACE_PROCESS_CONNECTIONS", operationRef: "relate", args: { ref: fact.subjectRef, relation: "connects", limit: 500 }, required: true, priority: 88 },
    { obligationKind: "TRACE_PROCESS_OPEN_FILES", operationRef: "relate", args: { ref: fact.subjectRef, relation: "opens", limit: 500 }, required: false, priority: 84 },
    { obligationKind: "TRACE_PROCESS_STARTUP", operationRef: "relate", args: { ref: fact.subjectRef, relation: "started_by", limit: 100 }, required: true, priority: 86 },
    { obligationKind: "PROCESS_EGRESS_DERIVE_PARENT", operationRef: "resolve_derived_objects", args: { resolverRef: "process.parent_by_ppid@1.0.0", sourceFactRef: fact.factId }, required: false, priority: 72 },
    { obligationKind: "CHECK_PROCESS_COUNTEREVIDENCE", operationRef: "query_facts", args: { view: "facts", namespace: fact.namespace, subjectRef: fact.subjectRef, limit: 100 }, required: false, priority: 58 },
  ];
  return [];
}

/**
 * 稳定 file Fact 已含采集时 size，按实际字节预留即可；统一预留 100 MiB 会让默认 64 MiB
 * discovery 账户中的任何 collect 在执行前必然失败。process 的 /proc/<pid>/exe 无独立 size
 * 字段，使用 10 MiB 上限，超大可执行文件会明确形成采集限制而不会吞掉整场预算。
 */
function collectBytesForFact(fact: FactRecord): number {
  const size = fact.privatePayload.size;
  if (fact.namespace === "file" && typeof size === "number" && Number.isSafeInteger(size) && size >= 0) {
    return Math.min(MAX_COLLECT_BYTES, Math.max(1, size));
  }
  return DEFAULT_EXECUTABLE_COLLECT_BYTES;
}

function claimFor(category: CheckCategory, namespace: string): string {
  const claims: Record<CheckCategory, string> = {
    webshell: `${namespace} 对象可能属于 Web 执行链，需要验证版本、来源与访问/进程关系`,
    java_memory_shell: `${namespace} 运行态对象可能包含未授权动态组件，需要精确 ClassLoader 与字节码验证`,
    backdoor_account: `${namespace} 对象可能扩大账户信任边界，需要验证有效配置、密钥与会话`,
    linux_persistence: `${namespace} 对象可能建立持久化执行，需要验证有效来源与真实执行目标`,
    linux_intrusion_triage: `${namespace} 对象可能属于异常外连或执行链，需要验证身份和良性解释`,
  };
  return claims[category];
}

function benignAlternatives(category: CheckCategory): string[] {
  if (category === "webshell") return ["正常 CMS 或部署产物", "已授权运维脚本"];
  if (category === "java_memory_shell") return ["框架动态代理或 APM 增强", "正常热部署组件"];
  if (category === "backdoor_account") return ["已审批管理员账户或自动化密钥轮换"];
  if (category === "linux_persistence") return ["系统包或配置管理下发的启动项"];
  return ["正常服务外连", "已安装软件的维护或更新行为"];
}

function latestBySubject(facts: readonly FactRecord[]): FactRecord[] {
  const latest = new Map<string, FactRecord>();
  for (const fact of facts) if (!latest.has(fact.subjectRef) || latest.get(fact.subjectRef)!.factSeq < fact.factSeq) latest.set(fact.subjectRef, fact);
  return [...latest.values()];
}

function isWebCandidate(fact: FactRecord): boolean {
  if (fact.namespace !== "file" || fact.source.kind !== "PRESET" || fact.source.presetId !== "webshell-baseline") return false;
  const path = fact.privatePayload.path;
  return typeof path === "string" && (/(?:^|\/)\.user\.ini$/i.test(path) || /\.(?:php\d*|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py)$/i.test(path));
}
