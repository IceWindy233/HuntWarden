import { randomUUID } from "node:crypto";
import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import type { SecurityToolDefinition } from "../domain/types.js";
import type { CoverageRun, TaskGrant, WireCost, WireRequest } from "../protocol-v2/types.js";
import { digestObject } from "../common/json.js";
import type { V2ToolDependencies } from "../tools/v2/dependencies.js";
import { createV2SecurityTools } from "../tools/v2/tools.js";
import { selectedPresets } from "./registry.js";
import type { PresetDefinition, PresetStep } from "./types.js";
import { INITIAL_GRANT_POLICY } from "../protocol-v2/policy.js";

export interface PresetRunResult { presetRunId: string; coverage: CoverageRun[]; promptContext: string }
type StepOutcome = { status: "success" | "partial" | "error"; runId?: string; factRefs?: string[]; objectRefs?: string[]; reason?: string; fanout?: Array<{ sourceRef: string; objectRefs: string[] }> };

export class PresetExecutorV2 {
  constructor(private readonly deps: Omit<V2ToolDependencies, "budgetOwner" | "factSource">) {}

  async run(signal?: AbortSignal): Promise<PresetRunResult> {
    const coverage: CoverageRun[] = [];
    const summaries: Record<string, unknown>[] = [];
    const rootRunId = `PRUN-${randomUUID()}`;
    for (const preset of selectedPresets(this.deps.task.checks)) {
      signal?.throwIfAborted();
      const presetRunId = rootRunId;
      const outcomes = new Map<string, StepOutcome>();
      for (const step of preset.steps) {
        const outcome = step.stepId === "web-candidate-file"
          ? await this.executeWebFileFanout(preset, presetRunId, step, outcomes.get("web-root"), signal)
          : step.stepId === "triage-file-scopes"
            ? await this.executeFixedFileScopeFanout(preset, presetRunId, step, signal)
            : step.stepId === "package-owned-files"
              ? await this.executePackageFileFanout(preset, presetRunId, step, outcomes.get("package-baseline"), signal)
              : step.stepId === "package-file-verify"
                ? await this.executeVerifyFanout(preset, presetRunId, step, outcomes.get("package-owned-files"), signal)
          : step.stepId === "tomcat-inventory"
            ? await this.executeProbeFanout(preset, presetRunId, step, outcomes.get("jvm-discovery"), signal)
            : step.stepId === "jvm-class-inspect"
              ? await this.executeClassInspectFanout(preset, presetRunId, step, outcomes.get("tomcat-inventory"), signal)
            : await this.executeStep(preset, presetRunId, step, signal);
        outcomes.set(step.stepId, outcome);
      }
      const run = this.coverageRun(preset, outcomes);
      this.deps.store.putCoverageRun(run); coverage.push(run);
      summaries.push({ presetId: preset.presetId, presetVersion: preset.version, presetRunId, coverage: run, steps: Object.fromEntries(outcomes) });
    }
    return { presetRunId: rootRunId, coverage, promptContext: JSON.stringify({ trust: "UNTRUSTED_REMOTE_EVIDENCE", instruction: "Preset 仅建立确定性最低覆盖；请用 query_facts 查看事实。PARTIAL/ERROR/UNKNOWN 不代表安全。", presets: summaries }) };
  }

  private async executeFixedFileScopeFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, signal?: AbortSignal): Promise<StepOutcome> {
    const roots = INITIAL_GRANT_POLICY.fixedScopesByCategory[preset.category] ?? [];
    if (roots.length === 0) return { status: "error", reason: "FIXED_SCOPE_POLICY_MISSING" };
    if (!this.deps.capabilities.namespaces.file?.verbs.has("enumerate")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "enumerate") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const factRefs: string[] = []; const objectRefs: string[] = [];
    let partial = false;
    const perRootLimit = Math.max(1, Math.floor(Number(step.params.limit ?? 500) / roots.length));
    for (const requestedRoot of roots) {
      signal?.throwIfAborted();
      try {
        const resolved = await this.resolveInitialFileScope(requestedRoot, signal);
        if (resolved.namespace !== "file" || resolved.canonicalRoot !== requestedRoot || typeof resolved.mountId !== "string") throw new Error("scope_resolve 返回了策略外绑定");
        const binding = { namespace: "file", canonicalRoot: resolved.canonicalRoot, mountId: resolved.mountId };
        let grant = this.deps.store.listTaskGrants(this.deps.task.taskId).find((item) => item.kind === "SCOPE" && item.status === "ACTIVE" && digestObject(item.binding) === digestObject(binding));
        if (!grant) {
          grant = { grantId: `GRANT-${randomUUID()}`, taskId: this.deps.task.taskId, targetFingerprint: this.deps.task.target.hostFingerprint, kind: "SCOPE", status: "ACTIVE", binding, createdAt: new Date().toISOString() } satisfies TaskGrant;
          this.deps.store.putTaskGrant(grant);
          this.deps.store.appendAudit({ taskId: this.deps.task.taskId, event: "protocol_v2_initial_scope_grant", level: "info", data: { grantId: grant.grantId, bindingDigest: digestObject(binding), policyRoot: requestedRoot } });
        }
        const toolCallId = `PRESET-${randomUUID()}`;
        const result = await tool.execute(toolCallId, { ...step.params, scopeRef: grant.grantId, limit: perRootLimit } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs);
        partial = partial || result.details.status === "partial";
      } catch (error) {
        partial = true;
        this.deps.store.appendAudit({ taskId: this.deps.task.taskId, event: "protocol_v2_initial_scope_failed", level: "warn", data: { requestedRoot, reason: error instanceof Error ? error.message : String(error) } });
      }
    }
    return { status: partial ? "partial" : "success", factRefs, objectRefs, ...(partial ? { reason: "FIXED_SCOPE_PARTIAL" } : {}) };
  }

  private async resolveInitialFileScope(requestedRoot: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const requestId = `PRESET-SCOPE-${randomUUID()}`;
    const reservationId = `BRES-${randomUUID()}`;
    const estimate: WireCost = { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 10_000, probeCalls: 0 };
    const request: WireRequest = { protocolVersion: 2, requestId, epochId: this.deps.epoch.epochId, deadlineMs: 10_000, reservation: { reservationId, estimate }, params: { namespace: "file", requestedRoot, expectedCanonicalRoot: requestedRoot } };
    this.deps.store.reserveBudget(reservationId, this.deps.task.taskId, this.deps.epoch.epochId, "PRESET", estimate);
    try {
      return await this.deps.executor.invokeMaintenanceV2("scope_resolve", request, signal);
    } finally {
      this.deps.store.settleBudget(reservationId, estimate);
    }
  }

  private async executePackageFileFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, packages: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (packages?.status === "error") return { status: "error", reason: "PACKAGE_DISCOVERY_FAILED" };
    if (!this.deps.capabilities.namespaces.package?.verbs.has("relate")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const priorities = Array.isArray(step.params.packageNames) ? step.params.packageNames.filter((value): value is string => typeof value === "string") : [];
    const maximum = Math.max(1, Math.min(5, Number(step.params.packageLimit ?? 1)));
    const facts = this.deps.store.listFacts(this.deps.task.taskId, this.deps.epoch.epochId);
    const available = (packages?.objectRefs ?? []).map((ref) => ({ ref, name: facts.find((fact) => fact.subjectRef === ref && fact.namespace === "package")?.privatePayload.name }))
      .filter((value): value is { ref: string; name: string } => typeof value.name === "string");
    const selected = [...available].sort((left, right) => {
      const leftIndex = priorities.indexOf(left.name); const rightIndex = priorities.indexOf(right.name);
      return (leftIndex < 0 ? Number.MAX_SAFE_INTEGER : leftIndex) - (rightIndex < 0 ? Number.MAX_SAFE_INTEGER : rightIndex) || left.name.localeCompare(right.name);
    }).slice(0, maximum);
    if (selected.length === 0) return { status: "partial", reason: "NO_PACKAGE_OBJECT_FOR_VERIFY", factRefs: [], objectRefs: [] };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "relate") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const factRefs: string[] = []; const objectRefs: string[] = []; const fanout: NonNullable<StepOutcome["fanout"]> = [];
    let partial = false;
    for (const value of selected) {
      const toolCallId = `PRESET-${randomUUID()}`;
      try {
        const result = await tool.execute(toolCallId, { ref: value.ref, relation: "owns_file", limit: Number(step.params.limit ?? 20) } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs); fanout.push({ sourceRef: value.ref, objectRefs: result.details.objectRefs });
        partial = partial || result.details.status === "partial";
      } catch { partial = true; }
    }
    if (objectRefs.length === 0) partial = true;
    return { status: partial ? "partial" : "success", factRefs, objectRefs, fanout, ...(objectRefs.length === 0 ? { reason: "NO_PACKAGE_FILES_FOR_VERIFY" } : {}) };
  }

  private async executeVerifyFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, files: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (files?.status === "error") return { status: "error", reason: "PACKAGE_FILE_DISCOVERY_FAILED" };
    if (!this.deps.capabilities.namespaces.file?.verbs.has("verify")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const refs = [...new Set(files?.objectRefs ?? [])].slice(0, Math.max(1, Math.min(20, Number(step.params.limit ?? 5))));
    if (refs.length === 0) return { status: "partial", reason: "NO_PACKAGE_FILES_FOR_VERIFY", factRefs: [], objectRefs: [] };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "verify") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const factRefs: string[] = []; const objectRefs: string[] = [];
    let partial = false;
    for (const ref of refs) {
      const toolCallId = `PRESET-${randomUUID()}`;
      try {
        const result = await tool.execute(toolCallId, { ref, baseline: step.params.baseline } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs);
        partial = partial || result.details.status === "partial";
      } catch { partial = true; }
    }
    return { status: partial ? "partial" : "success", factRefs, objectRefs };
  }

  private async executeStep(preset: PresetDefinition, presetRunId: string, step: PresetStep, signal?: AbortSignal) {
    const namespace = step.params.namespace as keyof typeof this.deps.capabilities.namespaces;
    if (!this.deps.capabilities.verbs.has(step.verb) || (namespace && !this.deps.capabilities.namespaces[namespace]?.verbs.has(step.verb))) return { status: "error" as const, reason: "CAPABILITY_UNAVAILABLE" };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === step.verb) as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error" as const, reason: "TOOL_NOT_REGISTERED" };
    const toolCallId = `PRESET-${randomUUID()}`;
    try {
      const result = await tool.execute(toolCallId, step.params as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
      return { status: result.details.status, runId: toolCallId, factRefs: result.details.factRefs, objectRefs: result.details.objectRefs };
    } catch (error) {
      return { status: "error" as const, runId: toolCallId, reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private async executeWebFileFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, roots: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (roots?.status === "error") return { status: "error", reason: "WEB_ROOT_DISCOVERY_FAILED" };
    const maximum = INITIAL_GRANT_POLICY.discoveredScopesByCategory.webshell!.maximum;
    const refs = (roots?.objectRefs ?? []).slice(0, maximum);
    if (refs.length === 0) return { status: roots?.status === "partial" ? "partial" : "success", factRefs: [], objectRefs: [], ...(roots?.status === "partial" ? { reason: "WEB_ROOT_DISCOVERY_PARTIAL" } : {}) };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "enumerate") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const factRefs: string[] = []; const objectRefs: string[] = [];
    let partial = roots?.status === "partial" || (roots?.objectRefs?.length ?? 0) > refs.length;
    const perRootLimit = Math.max(1, Math.floor(Number(step.params.limit ?? 500) / refs.length));
    const cutoff = new Date(Date.now() - this.deps.config.webshell.modifiedWithinHours * 3_600_000).toISOString();
    for (const ref of refs) {
      signal?.throwIfAborted();
      const object = this.deps.store.getObjectReference(this.deps.task.taskId, this.deps.epoch.epochId, ref, "web_root");
      const facts = this.deps.store.listFacts(this.deps.task.taskId, this.deps.epoch.epochId).filter((fact) => fact.subjectRef === ref);
      const payload = Object.assign({}, ...facts.map((fact) => fact.privatePayload)) as Record<string, unknown>;
      if (!object || typeof payload.path !== "string" || typeof payload.mountId !== "string") { partial = true; continue; }
      const binding = { namespace: "file", canonicalRoot: payload.path, mountId: payload.mountId };
      let grant = this.deps.store.listTaskGrants(this.deps.task.taskId).find((item) => item.kind === "SCOPE" && item.status === "ACTIVE" && digestObject(item.binding) === digestObject(binding));
      if (!grant) {
        grant = { grantId: `GRANT-${randomUUID()}`, taskId: this.deps.task.taskId, targetFingerprint: this.deps.task.target.hostFingerprint, kind: "SCOPE", status: "ACTIVE", binding, createdAt: new Date().toISOString() } satisfies TaskGrant;
        this.deps.store.putTaskGrant(grant);
        this.deps.store.appendAudit({ taskId: this.deps.task.taskId, event: "protocol_v2_initial_scope_grant", level: "info", data: { grantId: grant.grantId, bindingDigest: digestObject(binding), sourceRef: ref } });
      }
      const toolCallId = `PRESET-${randomUUID()}`;
      try {
        const result = await tool.execute(toolCallId, { ...step.params, scopeRef: grant.grantId, limit: perRootLimit, predicate: { op: "gte", field: "mtime", value: cutoff } } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs);
        partial = partial || result.details.status === "partial";
      } catch { partial = true; }
    }
    return { status: partial ? "partial" : "success", factRefs, objectRefs };
  }

  private async executeClassInspectFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, inventory: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (inventory?.status === "error") return { status: "error", reason: "TOMCAT_INVENTORY_FAILED" };
    if (!this.deps.capabilities.probes.has("jvm.class.inspect")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "probe") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const facts = this.deps.store.listFacts(this.deps.task.taskId, this.deps.epoch.epochId);
    const factRefs: string[] = []; const objectRefs: string[] = [];
    let partial = inventory?.status === "partial";
    let inspected = 0;
    for (const binding of inventory?.fanout ?? []) {
      const names = [...new Set(binding.objectRefs.flatMap((ref) => facts.filter((fact) => fact.subjectRef === ref && fact.namespace === "java_component").map((fact) => fact.privatePayload.className).filter((value): value is string => typeof value === "string" && value.length > 0)))].slice(0, 20);
      if (names.length === 0) { partial = true; continue; }
      for (const className of names) {
        signal?.throwIfAborted();
        const toolCallId = `PRESET-${randomUUID()}`;
        try {
          const result = await tool.execute(toolCallId, { ref: binding.sourceRef, probeKind: "jvm.class.inspect", parameters: { className } } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
          factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs); inspected += 1;
          partial = partial || result.details.status === "partial";
        } catch { partial = true; }
      }
    }
    if (inspected === 0) return { status: partial ? "partial" : "success", factRefs, objectRefs, ...(partial ? { reason: "NO_INSPECTABLE_CLASS" } : {}) };
    return { status: partial ? "partial" : "success", factRefs, objectRefs };
  }

  private async executeProbeFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, discovery: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (discovery?.status === "error") return { status: "error", reason: "JVM_DISCOVERY_FAILED" };
    if (!this.deps.capabilities.probes.has("jvm.tomcat.inventory")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const refs = (discovery?.objectRefs ?? []).slice(0, 20);
    if (refs.length === 0) return { status: discovery?.status === "partial" ? "partial" : "success", factRefs: [], objectRefs: [] };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "probe") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const factRefs: string[] = []; const objectRefs: string[] = [];
    const fanout: NonNullable<StepOutcome["fanout"]> = [];
    let partial = discovery?.status === "partial" || (discovery?.objectRefs?.length ?? 0) > refs.length;
    for (const ref of refs) {
      const toolCallId = `PRESET-${randomUUID()}`;
      try {
        const result = await tool.execute(toolCallId, { ref, ...step.params } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs);
        fanout.push({ sourceRef: ref, objectRefs: result.details.objectRefs });
        partial = partial || result.details.status === "partial";
      } catch { partial = true; }
    }
    return { status: partial ? "partial" : "success", factRefs, objectRefs, fanout };
  }

  private coverageRun(preset: PresetDefinition, outcomes: Map<string, StepOutcome>): CoverageRun {
    const completedCriteria: string[] = [];
    const missingCriteria: CoverageRun["missingCriteria"] = [];
    for (const criterion of preset.coverageCriteria) {
      const values = criterion.stepIds.map((stepId) => outcomes.get(stepId));
      if (values.every((value) => value?.status === "success")) completedCriteria.push(criterion.criterion);
      else {
        const failed = values.find((value) => value?.status !== "success");
        missingCriteria.push({ criterion: criterion.criterion, reasonCode: failed?.status === "partial" ? "PARTIAL_SOURCE" : failed?.reason ?? "NOT_RUN", ...(failed?.runId ? { sourceRunId: failed.runId } : {}) });
      }
    }
    const all = [...outcomes.values()];
    const status: CoverageRun["status"] = all.length > 0 && all.every((value) => value.status === "success") ? "COMPLETE" : all.some((value) => value.status !== "error") ? "PARTIAL" : "ERROR";
    const factCount = all.reduce((count, value) => count + (value.factRefs?.length ?? 0), 0);
    return {
      coverageId: `COV-${randomUUID()}`, taskId: this.deps.task.taskId, epochId: this.deps.epoch.epochId,
      category: preset.category, presetId: preset.presetId, presetVersion: preset.version, status,
      applicability: status === "COMPLETE" && factCount === 0 ? "NOT_APPLICABLE" : status === "COMPLETE" ? "APPLICABLE" : "UNKNOWN",
      completedCriteria, missingCriteria, createdAt: new Date().toISOString(),
    };
  }
}
