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
import { selectJavaClassInspectionTargets } from "../investigation/java-class-identity.js";

export interface PresetRunResult { presetRunId: string; coverage: CoverageRun[]; promptContext: string }
type StepOutcome = { status: "success" | "partial" | "error"; runId?: string; factRefs?: string[]; objectRefs?: string[]; reason?: string; fanout?: Array<{ sourceRef: string; objectRefs: string[] }> };
const PRESET_MAX_PAGES = 100;

export class PresetExecutorV2 {
  private rootRunId?: string;
  private readonly seededOutcomes = new Map<string, Map<string, StepOutcome>>();

  constructor(
    private readonly deps: Omit<V2ToolDependencies, "budgetOwner" | "factSource">,
    private readonly afterPageCommitted?: () => Promise<void>,
  ) {}

  async runVolatilePrelude(signal?: AbortSignal): Promise<{ presetRunId: string; stepIds: string[] }> {
    this.rootRunId ??= `PRUN-${randomUUID()}`;
    const preset = selectedPresets(this.deps.task.checks).find((item) => item.presetId === "linux-triage-baseline");
    if (!preset) return { presetRunId: this.rootRunId, stepIds: [] };
    const outcomes = this.seededOutcomes.get(preset.presetId) ?? new Map<string, StepOutcome>();
    const stepIds = ["process-snapshot", "socket-snapshot"];
    for (const stepId of stepIds) {
      const step = preset.steps.find((item) => item.stepId === stepId);
      if (!step || outcomes.has(stepId)) continue;
      signal?.throwIfAborted();
      outcomes.set(stepId, await this.executeStep(preset, this.rootRunId, step, signal));
    }
    this.seededOutcomes.set(preset.presetId, outcomes);
    return { presetRunId: this.rootRunId, stepIds: [...outcomes.keys()] };
  }

  async run(signal?: AbortSignal): Promise<PresetRunResult> {
    const coverage: CoverageRun[] = [];
    const summaries: Record<string, unknown>[] = [];
    if (!this.rootRunId) this.rootRunId = `PRUN-${randomUUID()}`;
    const rootRunId = this.rootRunId;
    for (const preset of selectedPresets(this.deps.task.checks)) {
      signal?.throwIfAborted();
      const presetRunId = rootRunId;
      const outcomes = new Map(this.seededOutcomes.get(preset.presetId) ?? []);
      for (const step of preset.steps) {
        if (outcomes.has(step.stepId)) continue;
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
            : step.stepId === "jvm-class-bytecode"
              ? await this.executeClassDumpFanout(preset, presetRunId, step, outcomes.get("jvm-class-inspect"), signal)
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
        const result = await this.executePaged(tool, { ...step.params, scopeRef: grant.grantId, limit: perRootLimit }, signal);
        factRefs.push(...(result.factRefs ?? [])); objectRefs.push(...(result.objectRefs ?? []));
        partial = partial || result.status === "partial";
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
      try {
        const result = await this.executePaged(tool, { ref: value.ref, relation: "owns_file", limit: Number(step.params.limit ?? 20) }, signal);
        factRefs.push(...(result.factRefs ?? [])); objectRefs.push(...(result.objectRefs ?? [])); fanout.push({ sourceRef: value.ref, objectRefs: result.objectRefs ?? [] });
        partial = partial || result.status === "partial";
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
      try {
        const toolCallId = `PRESET-${randomUUID()}`;
        const args = { ref, baseline: step.params.baseline };
        const reused = this.findReusableInvestigationResult("verify", args);
        const result = reused ?? await tool.execute(toolCallId, args as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
        if (reused) this.deps.store.appendAudit({ taskId: this.deps.task.taskId, event: "preset_reused_investigation_primitive", level: "info", data: { presetId: preset.presetId, stepId: step.stepId, tool: "verify", argsDigest: digestObject(args) } });
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
    try {
      const params = step.verb === "enumerate" && step.params.sinceHours !== undefined && this.deps.task.timeWindowHours !== undefined
        ? { ...step.params, sinceHours: this.deps.task.timeWindowHours }
        : step.params;
      return await this.executePaged(tool, params, signal);
    } catch (error) {
      return { status: "error" as const, reason: error instanceof Error ? error.message : String(error) };
    }
  }

  private async executePaged(tool: SecurityToolDefinition, baseParams: Record<string, unknown>, signal?: AbortSignal): Promise<StepOutcome> {
    const factRefs: string[] = [];
    const objectRefs: string[] = [];
    let partial = false;
    let cursorRef: string | undefined;
    let firstRunId: string | undefined;
    for (let page = 0; page < PRESET_MAX_PAGES; page += 1) {
      signal?.throwIfAborted();
      const toolCallId = `PRESET-${randomUUID()}`;
      firstRunId ??= toolCallId;
      try {
        const result = await tool.execute(toolCallId, { ...baseParams, ...(cursorRef ? { cursorRef } : {}) } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[]; cursorRef?: string }>;
        factRefs.push(...result.details.factRefs);
        objectRefs.push(...result.details.objectRefs);
        partial = partial || result.details.status === "partial";
        // 每个远程页已经作为独立 FactBatch 原子提交。此时立即唤醒持久化调度器，
        // 让首屏的易失对象先建 Lead 和保全动作，而不等待大型枚举耗尽 Cursor。
        await this.afterPageCommitted?.();
        cursorRef = result.details.cursorRef;
        if (!cursorRef) return { status: partial ? "partial" : "success", runId: firstRunId!, factRefs, objectRefs };
      } catch (error) {
        if (!cursorRef && factRefs.length === 0) throw error;
        const reason = error instanceof Error ? error.message : String(error);
        this.limitDiscoveryCheckpoint(cursorRef, `Preset 分页中断：${reason}`);
        return { status: "partial", runId: firstRunId!, factRefs, objectRefs, reason };
      }
    }
    this.limitDiscoveryCheckpoint(cursorRef, `Preset 分页达到 ${PRESET_MAX_PAGES} 页上限`);
    return { status: "partial", runId: firstRunId!, factRefs, objectRefs, reason: "PRESET_PAGE_LIMIT" };
  }

  private limitDiscoveryCheckpoint(cursorRef: string | undefined, reason: string): void {
    if (!cursorRef) return;
    const checkpoint = this.deps.store.listDiscoveryCheckpoints(this.deps.task.taskId, this.deps.epoch.epochId)
      .find((item) => item.cursorRef === cursorRef);
    if (!checkpoint) return;
    this.deps.store.putDiscoveryCheckpoint({ ...checkpoint, status: "LIMITED", remainingDescription: reason, updatedAt: new Date().toISOString() });
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
      try {
        // 深度取证的首轮 Web 候选必须覆盖整个站点。mtime 仅可用于后续排序或增量优化，
        // 不能把任务日志时间窗变成文件排除条件，否则回改时间戳和长期驻留脚本会被漏掉。
        const result = await this.executePaged(tool, { ...step.params, scopeRef: grant.grantId, limit: perRootLimit }, signal);
        factRefs.push(...(result.factRefs ?? [])); objectRefs.push(...(result.objectRefs ?? []));
        partial = partial || result.status === "partial";
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
    const fanout: NonNullable<StepOutcome["fanout"]> = [];
    let partial = inventory?.status === "partial";
    let inspected = 0;
    for (const binding of inventory?.fanout ?? []) {
      const boundObjectRefs: string[] = [];
      const selected = selectJavaClassInspectionTargets(facts, binding.objectRefs, 20);
      const classes = selected.targets;
      partial = partial || selected.incomplete;
      if (classes.length === 0) { partial = true; continue; }
      for (const { className, classLoaderId } of classes) {
        signal?.throwIfAborted();
        const toolCallId = `PRESET-${randomUUID()}`;
        try {
          const result = await tool.execute(toolCallId, { ref: binding.sourceRef, probeKind: "jvm.class.inspect", parameters: { className, classLoaderId } } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }>;
          factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs); inspected += 1;
          boundObjectRefs.push(...result.details.objectRefs);
          partial = partial || result.details.status === "partial";
        } catch { partial = true; }
      }
      if (boundObjectRefs.length > 0) fanout.push({ sourceRef: binding.sourceRef, objectRefs: [...new Set(boundObjectRefs)] });
    }
    if (inspected === 0) return { status: partial ? "partial" : "success", factRefs, objectRefs, ...(partial ? { reason: "NO_INSPECTABLE_CLASS" } : {}) };
    return { status: partial ? "partial" : "success", factRefs, objectRefs, fanout };
  }

  private async executeClassDumpFanout(preset: PresetDefinition, presetRunId: string, step: PresetStep, inspected: StepOutcome | undefined, signal?: AbortSignal): Promise<StepOutcome> {
    if (inspected?.status === "error") return { status: "error", reason: "CLASS_INSPECTION_FAILED" };
    if (!this.deps.capabilities.probes.has("jvm.class.dump")) return { status: "error", reason: "CAPABILITY_UNAVAILABLE" };
    const tools = createV2SecurityTools({ ...this.deps, budgetOwner: "PRESET", factSource: { kind: "PRESET", presetRunId, presetId: preset.presetId, presetVersion: preset.version, stepId: step.stepId } });
    const tool = tools.find((item) => item.name === "probe") as SecurityToolDefinition | undefined;
    if (!tool) return { status: "error", reason: "TOOL_NOT_REGISTERED" };
    const facts = this.deps.store.listFacts(this.deps.task.taskId, this.deps.epoch.epochId);
    const factRefs: string[] = []; const objectRefs: string[] = [];
    let partial = inspected?.status === "partial";
    let captured = 0;
    for (const binding of inspected?.fanout ?? []) {
      const classes = binding.objectRefs.flatMap((ref) => facts.filter((fact) => fact.subjectRef === ref && fact.namespace === "class").slice(-1)).slice(0, 20);
      for (const fact of classes) {
        const className = fact.privatePayload.className;
        const classLoaderId = fact.privatePayload.loaderId;
        if (typeof className !== "string" || typeof classLoaderId !== "string") { partial = true; continue; }
        signal?.throwIfAborted();
        try {
          const result = await tool.execute(`PRESET-${randomUUID()}`, { ref: binding.sourceRef, probeKind: "jvm.class.dump", parameters: { className, classLoaderId } } as never, signal) as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[]; evidenceRefs: string[] }>;
          factRefs.push(...result.details.factRefs); objectRefs.push(...result.details.objectRefs);
          captured += result.details.evidenceRefs.length;
          partial = partial || result.details.status === "partial" || result.details.evidenceRefs.length === 0;
        } catch { partial = true; }
      }
    }
    if (captured === 0 && (inspected?.objectRefs?.length ?? 0) > 0) partial = true;
    return { status: partial ? "partial" : "success", factRefs, objectRefs, ...(captured === 0 && partial ? { reason: "NO_CLASS_BYTECODE_EVIDENCE" } : {}) };
  }

  private findReusableInvestigationResult(toolName: string, args: Record<string, unknown>): AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }> | undefined {
    const argsDigest = digestObject(args);
    const run = this.deps.store.listToolRuns(this.deps.task.taskId, 100_000).find((item) => item.epochId === this.deps.epoch.epochId
      && item.status === "SUCCEEDED" && item.toolCallId.startsWith("ACT-") && item.toolName === toolName
      && digestObject(item.args) === argsDigest && item.result !== undefined);
    return run?.result as AgentToolResult<{ status: "success" | "partial"; factRefs: string[]; objectRefs: string[] }> | undefined;
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
