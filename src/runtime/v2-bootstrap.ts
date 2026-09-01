import { randomUUID } from "node:crypto";
import type { ApprovalService } from "../agent/approval-service.js";
import type { AppConfig } from "../config/schema.js";
import { digestObject } from "../common/json.js";
import type { TaskContext } from "../domain/types.js";
import type { EvidenceStore } from "../evidence/evidence-store.js";
import type { ProtocolV2Executor } from "../executor/protocol-v2-executor.js";
import { gateCapabilities } from "../protocol-v2/capability.js";
import { MANIFEST_VERSION, type ScanEpoch, type TaskGrant, type WireCost, type WireObservation } from "../protocol-v2/types.js";
import { PresetExecutorV2 } from "../presets/executor.js";
import { DeterministicRuleEngineV2 } from "../rules/deterministic-rule-engine-v2.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { ThreatIntelClient } from "../threat-intel/types.js";
import { createV2SecurityTools } from "../tools/v2/tools.js";
import { INITIAL_GRANT_POLICY } from "../protocol-v2/policy.js";

export interface V2BootstrapResult {
  epoch: ScanEpoch;
  tools: ReturnType<typeof createV2SecurityTools>;
  presetContext: string;
}

export async function bootstrapProtocolV2(input: {
  task: TaskContext;
  config: AppConfig;
  store: RuntimeStore;
  executor: ProtocolV2Executor;
  evidence: EvidenceStore;
  approvals: ApprovalService;
  checkpoint?: (name: string) => void;
  threatIntel?: ThreatIntelClient;
  signal?: AbortSignal;
}): Promise<V2BootstrapResult> {
  const { task, store, executor, config } = input;
  if (task.protocolVersion !== 2) throw new Error("v1 历史任务只读，不能进入 v2 bootstrap");
  const capabilities = await executor.getCapabilitiesV2(input.signal);
  ensureCategoryGrants(task, store);
  ensureInitialProbeGrants(task, store, capabilities.probes);
  const effective = gateCapabilities(capabilities, store.listTaskGrants(task.taskId));
  const epoch: ScanEpoch = {
    epochId: `EPOCH-${randomUUID()}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
    protocolVersion: 2, manifestVersion: MANIFEST_VERSION, helperVersion: capabilities.helper.version,
    reason: task.activeEpochId ? "RESCAN" : "INITIAL", status: "RUNNING", startedAt: new Date().toISOString(),
  };
  store.createScanEpoch(epoch);
  task.activeEpochId = epoch.epochId;
  store.initializeBudget(task.taskId, epoch.epochId, "PRESET", scaleRemoteBudget(task, config.protocolV2.remoteBudget.preset));
  store.initializeBudget(task.taskId, epoch.epochId, "MODEL", scaleRemoteBudget(task, config.protocolV2.remoteBudget.model));
  initializeUsageCounters(task, epoch, store, config);
  store.appendAudit({ taskId: task.taskId, event: "protocol_v2_capability_negotiated", level: effective.protocolAnomalies.length > 0 ? "warn" : "info", data: {
    epochId: epoch.epochId, protocolVersion: 2, manifestVersion: MANIFEST_VERSION, helperVersion: capabilities.helper.version,
    namespaces: Object.keys(effective.namespaces), anomalies: effective.protocolAnomalies,
  } });
  materializeTaskIocs(task, epoch, store);
  const base = { task, epoch, config, store, executor, evidence: input.evidence, capabilities: effective, approvals: input.approvals, ...(input.checkpoint ? { checkpoint: input.checkpoint } : {}), ...(input.threatIntel ? { threatIntel: input.threatIntel } : {}) };
  const preset = await new PresetExecutorV2(base).run(input.signal);
  const ruleAssessments = new DeterministicRuleEngineV2(store).evaluate(task.taskId, epoch.epochId, preset.presetRunId);
  const tools = createV2SecurityTools({ ...base, budgetOwner: "MODEL" });
  const presetContext = `${preset.promptContext}\n${JSON.stringify({ ruleAssessmentIds: ruleAssessments.map((item) => item.assessmentId), instruction: "规则结论不可覆盖；请通过 query_facts 复核并追加模型 Assessment。" })}`;
  return { epoch, tools, presetContext };
}

export async function restoreProtocolV2(input: {
  task: TaskContext;
  config: AppConfig;
  store: RuntimeStore;
  executor: ProtocolV2Executor;
  evidence: EvidenceStore;
  approvals: ApprovalService;
  checkpoint?: (name: string) => void;
  threatIntel?: ThreatIntelClient;
  signal?: AbortSignal;
}): Promise<V2BootstrapResult> {
  const epochId = input.task.activeEpochId;
  const epoch = epochId ? input.store.getScanEpoch(input.task.taskId, epochId) : undefined;
  if (input.task.protocolVersion !== 2 || !epoch) throw new Error("v2 任务没有可恢复的 epoch");
  const capabilities = await input.executor.getCapabilitiesV2(input.signal);
  initializeUsageCounters(input.task, epoch, input.store, input.config);
  const effective = gateCapabilities(capabilities, input.store.listTaskGrants(input.task.taskId));
  const base = { task: input.task, epoch, config: input.config, store: input.store, executor: input.executor, evidence: input.evidence, capabilities: effective, approvals: input.approvals, ...(input.checkpoint ? { checkpoint: input.checkpoint } : {}), ...(input.threatIntel ? { threatIntel: input.threatIntel } : {}) };
  return {
    epoch,
    tools: createV2SecurityTools({ ...base, budgetOwner: "MODEL" }),
    presetContext: JSON.stringify({ recovery: true, epochId, instruction: "继续同一 epoch；使用 query_facts 恢复事实，不把 SAFE_REOBSERVE 误解为状态未变化。" }),
  };
}

function initializeUsageCounters(task: TaskContext, epoch: ScanEpoch, store: RuntimeStore, config: AppConfig): void {
  const factor = profileFactor(task);
  store.initializeUsageCounter(task.taskId, epoch.epochId, "LOCAL_QUERY_CALLS", scale(config.protocolV2.localQueryBudget.calls, factor, 1));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "LOCAL_QUERY_ROWS", scale(config.protocolV2.localQueryBudget.rows, factor, 1));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "LOCAL_QUERY_WALL_MS", scale(config.protocolV2.localQueryBudget.wallTimeMs, factor, 1_000));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES", scale(config.protocolV2.dataPolicy.modelContentBytes, factor, 1_024));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "EVIDENCE_BYTES", scale(config.protocolV2.dataPolicy.evidenceBytes, factor, 1_024));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "GRANT_REQUESTS", config.protocolV2.grants.maxRequests);
  store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_CALLS", scale(config.protocolV2.externalIntelBudget.calls, factor, 1));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_IOCS", scale(config.protocolV2.externalIntelBudget.iocs, factor, 1));
  store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_WALL_MS", scale(config.protocolV2.externalIntelBudget.wallTimeMs, factor, 1_000));
}

function profileFactor(task: TaskContext): number {
  return task.profile === "QUICK" ? 0.25 : task.profile === "DEEP" ? 1 : 0.5;
}

function scale(value: number, factor: number, minimum: number): number {
  return Math.max(minimum, Math.floor(value * factor));
}

function scaleRemoteBudget(task: TaskContext, budget: WireCost): WireCost {
  const factor = profileFactor(task);
  return {
    remoteCalls: scale(budget.remoteCalls, factor, 1), nodes: scale(budget.nodes, factor, 1),
    bytes: scale(budget.bytes, factor, 1_024), wallTimeMs: scale(budget.wallTimeMs, factor, 1_000),
    probeCalls: budget.probeCalls === 0 ? 0 : scale(budget.probeCalls ?? 0, factor, 1),
  };
}

function ensureCategoryGrants(task: TaskContext, store: RuntimeStore): void {
  const existing = new Set(store.listTaskGrants(task.taskId).filter((grant) => grant.kind === "CATEGORY").map((grant) => grant.binding.category));
  for (const category of task.checks) {
    if (existing.has(category)) continue;
    const grant: TaskGrant = {
      grantId: `GRANT-${randomUUID()}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
      kind: "CATEGORY", status: "ACTIVE", binding: { category }, createdAt: new Date().toISOString(),
    };
    store.putTaskGrant(grant);
  }
}

function ensureInitialProbeGrants(task: TaskContext, store: RuntimeStore, advertised: readonly string[]): void {
  const allowed = task.checks.flatMap((category) => INITIAL_GRANT_POLICY.probesByCategory[category] ?? []);
  if (allowed.length === 0) return;
  const existing = new Set(store.listTaskGrants(task.taskId).filter((grant) => grant.kind === "PROBE" && grant.status === "ACTIVE").map((grant) => grant.binding.probeKind));
  for (const probeKind of advertised.filter((value) => allowed.includes(value))) {
    if (existing.has(probeKind)) continue;
    store.putTaskGrant({ grantId: `GRANT-${randomUUID()}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
      kind: "PROBE", status: "ACTIVE", binding: { category: "java_memory_shell", probeKind }, createdAt: new Date().toISOString() });
  }
}

function materializeTaskIocs(task: TaskContext, epoch: ScanEpoch, store: RuntimeStore): void {
  const observations: WireObservation[] = [];
  for (const [kind, values] of Object.entries(task.iocs ?? {})) for (const value of values) observations.push({
    namespace: "task_ioc", identity: { kind, valueDigest: digestObject(value) },
    fields: { kind, valueDigest: digestObject(value), value, suppliedAt: task.createdAt },
    observedAt: task.createdAt, consistency: "POINT_IN_TIME",
  });
  if (observations.length === 0) return;
  store.commitFactBatch({
    taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `SYSTEM-IOC-${task.taskId}`, source: { kind: "SYSTEM" },
    targetFingerprint: task.target.hostFingerprint, requestId: `SYSTEM-IOC-${task.taskId}`,
    collector: { name: "task_ioc_materializer", version: "2.0.0" }, observations, edges: [], gaps: [], wireDigest: digestObject(observations),
  });
}
