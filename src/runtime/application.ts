import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { Models, Model, Api } from "@earendil-works/pi-ai";
import { ApprovalService } from "../agent/approval-service.js";
import type { AppConfig } from "../config/schema.js";
import { createId } from "../common/ids.js";
import { InvalidArgumentError } from "../common/errors.js";
import type { AgentStreamUpdate, CheckCategory, InvestigationIocs, ReportRecord, ScanProfile, TargetConfig, TaskContext, TaskMode } from "../domain/types.js";
import { validateTargetConfig } from "../domain/validation.js";
import { EvidenceStore } from "../evidence/evidence-store.js";
import { SSHExecutor } from "../executor/ssh-executor.js";
import { ReportService } from "../report/report-service.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { ThreatIntelClient } from "../threat-intel/types.js";
import { SecurityAgentRuntime } from "./security-agent-runtime.js";
import { bootstrapProtocolV2, restoreProtocolV2 } from "./v2-bootstrap.js";
import type { Assessment, AssessmentVerdict, TaskGrant, WireRequest } from "../protocol-v2/types.js";
import { createKnownHashDataSet, parseKnownHashSetImport, summarizeKnownHashDataSet, type KnownHashDataSetSummary } from "../datasets/known-hash-registry.js";

export class Application extends EventEmitter {
  readonly approvals: ApprovalService;
  readonly reports: ReportService;
  private runtime?: SecurityAgentRuntime;
  private runtimeTaskId?: string;
  private executor?: SSHExecutor;
  private closePromise: Promise<void> | undefined;
  private presetContext = "";

  constructor(
    readonly config: AppConfig,
    readonly store: RuntimeStore,
    private readonly models: Models,
    private readonly model: Model<Api>,
    private readonly checkpoint?: (name: string) => void,
    private readonly threatIntel?: ThreatIntelClient,
  ) {
    super();
    this.approvals = new ApprovalService(store);
    this.reports = new ReportService(config.storage.baseDir, store, config.llmData.maxTextBytes, checkpoint);
    this.approvals.on("requested", (ticket) => this.emit("approval_requested", ticket));
    this.approvals.on("decided", (ticket) => this.emit("changed", ticket.taskId));
  }

  createTask(input: { request: string; mode: TaskMode; checks?: CheckCategory[]; profile?: ScanProfile; timeWindowHours?: number; iocs?: InvestigationIocs; target: TargetConfig }): TaskContext {
    validateTargetConfig(input.target);
    if (!input.request.trim() || input.request.length > 20_000) throw new InvalidArgumentError("调查请求不能为空且不能超过 20000 字符");
    if (!(["SCAN", "REMEDIATE"] as const).includes(input.mode)) throw new InvalidArgumentError("任务模式必须是 SCAN 或 REMEDIATE");
    if (this.store.hasActiveTask()) throw new Error("已有活动任务；首期只允许单任务运行");
    const now = new Date().toISOString();
    const task: TaskContext = {
      taskId: createId("task"), request: input.request, target: input.target, mode: input.mode,
      status: "CREATED", modelProvider: this.config.model.provider, modelId: this.config.model.model,
      promptVersion: this.config.agent.promptVersion,
      checks: input.checks ?? ["webshell", "java_memory_shell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"],
      ...(input.profile ? { profile: input.profile } : {}),
      ...(input.timeWindowHours !== undefined ? { timeWindowHours: input.timeWindowHours } : {}),
      ...(input.iocs && Object.keys(input.iocs).length > 0 ? { iocs: structuredClone(input.iocs) } : {}),
      createdAt: now, updatedAt: now, turnCount: 0, toolCallCount: 0, protocolVersion: 2,
    };
    this.store.createTask(task);
    this.store.appendAudit({
      taskId: task.taskId,
      event: "task_created",
      level: "info",
      data: {
        host: task.target.host,
        mode: task.mode,
        checks: task.checks,
        profile: task.profile ?? "LEGACY_DEFAULT",
        timeWindowHours: task.timeWindowHours,
        iocCounts: Object.fromEntries(Object.entries(task.iocs ?? {}).map(([kind, values]) => [kind, values.length])),
      },
    });
    this.emit("changed", task.taskId);
    return task;
  }

  importKnownHashDataSet(value: unknown): KnownHashDataSetSummary {
    const prepared = createKnownHashDataSet(parseKnownHashSetImport(value));
    const stored = this.store.putKnownHashDataSet(prepared);
    this.store.appendAudit({ event: "protocol_v2_known_hash_dataset_imported", level: "info", data: {
      dataSetRef: stored.dataSetRef, name: stored.name, version: stored.version, digest: stored.digest, entryCount: stored.sha256.length,
    } });
    return summarizeKnownHashDataSet(stored);
  }

  listKnownHashDataSets(): KnownHashDataSetSummary[] { return this.store.listKnownHashDataSets(); }

  runtimeFor(task: TaskContext): SecurityAgentRuntime {
    if (this.runtime && this.runtimeTaskId === task.taskId) return this.runtime;
    throw new InvalidArgumentError("任务运行时尚未完成 v2 capability/epoch 初始化；请使用 startTask、recoverTask 或 steerTask");
  }

  private async ensureRuntimeFor(task: TaskContext, restore = false): Promise<SecurityAgentRuntime> {
    if (this.runtime && this.runtimeTaskId === task.taskId) return this.runtime;
    if (this.runtime) {
      this.runtime.abort();
      void this.executor?.close();
    }
    this.executor = new SSHExecutor(task.target, this.config.executor.helperPath, this.config.executor.timeoutSeconds * 1000);
    const evidence = new EvidenceStore(this.config.storage.baseDir, this.store, this.checkpoint);
    if (task.protocolVersion !== 2) throw new InvalidArgumentError("v1 历史任务只读，不允许恢复执行或重新调查");
    const session = restore
      ? await restoreProtocolV2({ task, config: this.config, store: this.store, executor: this.executor, evidence, approvals: this.approvals, ...(this.checkpoint ? { checkpoint: this.checkpoint } : {}), ...(this.threatIntel ? { threatIntel: this.threatIntel } : {}) })
      : await bootstrapProtocolV2({ task, config: this.config, store: this.store, executor: this.executor, evidence, approvals: this.approvals, ...(this.checkpoint ? { checkpoint: this.checkpoint } : {}), ...(this.threatIntel ? { threatIntel: this.threatIntel } : {}) });
    this.presetContext = session.presetContext;
    this.runtime = new SecurityAgentRuntime({ task, config: this.config, store: this.store, executor: this.executor, approvals: this.approvals, tools: session.tools, models: this.models, model: this.model, protocolV2: { epochId: session.epoch.epochId }, ...(this.checkpoint ? { checkpoint: this.checkpoint } : {}) });
    this.runtime.on("event", (event: { type: string }) => {
      if (event.type !== "message_update") this.emit("changed", task.taskId);
    });
    this.runtime.on("stream", (update: AgentStreamUpdate) => this.emit("stream", update));
    this.runtimeTaskId = task.taskId;
    return this.runtime;
  }

  async close(): Promise<void> {
    if (!this.closePromise) this.closePromise = this.closeOnce();
    await this.closePromise;
  }

  private async closeOnce(): Promise<void> {
    this.runtime?.abort();
    await this.runtime?.agent.waitForIdle().catch(() => undefined);
    await this.executor?.close();
    this.store.close();
  }

  async startTask(taskId: string): Promise<void> {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    const runtime = await this.ensureRuntimeFor(task);
    await runtime.prompt(`${task.request}\n\n<preset-v2>\n${this.presetContext}\n</preset-v2>`);
    this.finishActiveEpoch(task.taskId);
    this.emit("changed", taskId);
  }

  async recoverTask(taskId: string): Promise<void> {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (!task.interruption?.recoveryRequired) throw new InvalidArgumentError("任务没有需要处理的中断状态");
    const runtime = await this.ensureRuntimeFor(task, true);
    if (task.interruption.previousStatus === "REPORTING") await this.reports.generate(this.requireTask(taskId), runtime);
    else await runtime.recover();
    this.finishActiveEpoch(task.taskId);
    this.emit("changed", taskId);
  }

  async steerTask(taskId: string, text: string): Promise<void> {
    const normalized = text.trim();
    if (!normalized || normalized.length > 20_000) throw new InvalidArgumentError("Steering 输入不能为空且不能超过 20000 字符");
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    await (await this.ensureRuntimeFor(task, true)).steer(normalized);
    this.emit("changed", taskId);
  }

  abortTask(taskId: string): void {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (this.runtimeTaskId === taskId) this.runtime?.abort();
    task.status = "ABORTED";
    if (task.protocolVersion === 2 && task.activeEpochId) this.store.finishScanEpoch(task.taskId, task.activeEpochId, "ABORTED");
    this.store.saveTask(task);
    this.store.appendAudit({ taskId, event: "task_aborted_by_analyst", level: "warn", data: {} });
    this.emit("changed", taskId);
  }

  archiveTask(taskId: string): TaskContext {
    const task = this.requireTask(taskId);
    if (task.archivedAt) return task;
    if (["RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"].includes(task.status)) {
      throw new InvalidArgumentError("活动任务不能归档，请等待任务结束或先终止任务");
    }
    if (task.interruption?.recoveryRequired) throw new InvalidArgumentError("待恢复任务不能归档，请先完成恢复或明确终止恢复流程");
    task.archivedAt = new Date().toISOString();
    this.store.saveTask(task);
    this.store.appendAudit({ taskId, event: "task_archived", level: "info", data: { archivedAt: task.archivedAt } });
    this.emit("changed", taskId);
    return task;
  }

  restoreTask(taskId: string): TaskContext {
    const task = this.requireTask(taskId);
    if (!task.archivedAt) return task;
    const archivedAt = task.archivedAt;
    delete task.archivedAt;
    this.store.saveTask(task);
    this.store.appendAudit({ taskId, event: "task_restored_from_archive", level: "info", data: { archivedAt } });
    this.emit("changed", taskId);
    return task;
  }

  decideApproval(approvalId: string, approved: boolean): void {
    const ticket = this.approvals.decide(approvalId, approved);
    this.emit("changed", ticket.taskId);
  }

  async decideGrantRequest(requestId: string, approved: boolean): Promise<void> {
    const request = this.store.getGrantRequest(requestId);
    if (request?.status !== "PENDING") throw new InvalidArgumentError("Grant Request 不存在或已结束");
    const task = this.requireTask(request.taskId);
    if (request.targetFingerprint !== task.target.hostFingerprint || task.protocolVersion !== 2 || !task.activeEpochId) throw new InvalidArgumentError("Grant Request 与当前 task/target/epoch 不匹配");
    if (!approved) {
      this.store.updateGrantRequest(requestId, "DENIED");
      this.store.putInvestigationGap({ gapId: `IGAP-${randomUUID()}`, taskId: task.taskId, epochId: task.activeEpochId, code: "GRANT_DENIED", reasonCode: request.kind, createdAt: new Date().toISOString() });
      this.store.appendAudit({ taskId: task.taskId, event: "protocol_v2_grant_denied", level: "info", data: { requestId, kind: request.kind, bindingDigest: request.bindingDigest } });
      this.emit("changed", task.taskId);
      return;
    }
    let binding = structuredClone(request.binding);
    if (request.kind === "SCOPE") {
      if (request.binding.namespace !== "file" || typeof request.binding.requestedRoot !== "string") throw new InvalidArgumentError("Scope Request binding 不完整");
      if (!this.executor) throw new InvalidArgumentError("Scope 批准需要当前任务的 v2 目标连接");
      const wire: WireRequest = {
        protocolVersion: 2, requestId: `${requestId}:RESOLVE`, epochId: task.activeEpochId, deadlineMs: 10_000,
        reservation: { reservationId: `${requestId}:RESOLVE`, estimate: { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 10_000, probeCalls: 0 } },
        params: { namespace: "file", requestedRoot: request.binding.requestedRoot, expectedCanonicalRoot: request.binding.requestedRoot },
      };
      binding = await this.executor.invokeMaintenanceV2("scope_resolve", wire);
    }
    const grant: TaskGrant = {
      grantId: `GRANT-${randomUUID()}`, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
      kind: request.kind, status: "ACTIVE", binding, createdAt: new Date().toISOString(),
    };
    this.store.putTaskGrant(grant);
    this.store.updateGrantRequest(requestId, "APPROVED");
    this.store.appendAudit({ taskId: task.taskId, event: "protocol_v2_grant_activated", level: "warn", data: { requestId, grantId: grant.grantId, kind: grant.kind, bindingDigest: request.bindingDigest } });
    this.emit("changed", task.taskId);
  }

  recordHumanAssessment(input: { taskId: string; targetAssessmentId: string; verdict: AssessmentVerdict; rationale: string }): Assessment {
    const task = this.requireTask(input.taskId);
    if (task.protocolVersion !== 2 || !task.activeEpochId) throw new InvalidArgumentError("只有活动的 v2 epoch 可以记录 HUMAN Assessment");
    const target = this.store.listAssessments(task.taskId, task.activeEpochId).find((item) => item.assessmentId === input.targetAssessmentId);
    if (!target) throw new InvalidArgumentError("目标 Assessment 不存在或不属于当前 epoch");
    const assessment: Assessment = {
      assessmentId: `ASM-${randomUUID()}`, taskId: task.taskId, epochId: task.activeEpochId, authorType: "HUMAN",
      category: target.category, ...(target.subjectRef ? { subjectRef: target.subjectRef } : {}), scope: target.scope,
      verdict: input.verdict, severity: severityForHumanVerdict(input.verdict, target.severity), confidence: 1,
      rationale: input.rationale, evidenceRefs: [...target.evidenceRefs], factRefs: [...target.factRefs], queryRefs: [...target.queryRefs], createdAt: new Date().toISOString(),
    };
    this.store.putAssessment(assessment);
    this.store.putAssessmentRelation({ relationId: `AREL-${randomUUID()}`, taskId: task.taskId, epochId: task.activeEpochId, kind: "ADJUDICATES", fromAssessmentId: assessment.assessmentId, toAssessmentId: target.assessmentId, createdAt: new Date().toISOString() });
    this.store.appendAudit({ taskId: task.taskId, event: "protocol_v2_human_assessment_recorded", level: "warn", data: { assessmentId: assessment.assessmentId, targetAssessmentId: target.assessmentId, verdict: assessment.verdict } });
    this.emit("changed", task.taskId);
    return assessment;
  }

  revokeTaskGrant(taskId: string, grantId: string, reason: string): TaskGrant {
    const task = this.requireTask(taskId);
    if (task.protocolVersion !== 2) throw new InvalidArgumentError("只有 v2 任务具有可撤销 Grant");
    const grant = this.store.listTaskGrants(taskId).find((item) => item.grantId === grantId);
    if (!grant || grant.targetFingerprint !== task.target.hostFingerprint) throw new InvalidArgumentError("Task Grant 不存在或目标不匹配");
    const revoked = this.store.revokeTaskGrant(taskId, grantId, reason);
    this.store.appendAudit({ taskId, event: "protocol_v2_grant_revoked", level: "warn", data: { grantId, kind: revoked.kind, reason: revoked.revocationReason } });
    this.emit("changed", taskId);
    return revoked;
  }

  async generateReport(taskId: string): Promise<ReportRecord> {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (["CREATED", "RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"].includes(task.status)) {
      throw new InvalidArgumentError("调查尚未结束，不能生成报告");
    }
    if (task.interruption?.recoveryRequired) throw new InvalidArgumentError("任务需要先完成恢复，才能生成报告");
    this.store.appendAudit({ taskId, event: "report_generation_requested_by_analyst", level: "info", data: { existingVersions: this.store.listReports(taskId).length } });
    if (task.protocolVersion !== 2) throw new InvalidArgumentError("v1 历史任务只读，仅可查看已生成报告");
    const report = await this.reports.generate(task, await this.ensureRuntimeFor(task, true));
    this.emit("changed", taskId);
    return report;
  }

  async inferLabFingerprint(knownHostsPath = this.config.executor.knownHostsPath, port?: number): Promise<string> {
    const text = await readFile(knownHostsPath, "utf8");
    const match = port
      ? text.match(new RegExp(`# (SHA256:[A-Za-z0-9+/]+) port=${port}(?:\\s|$)`))
      : text.match(/SHA256:[A-Za-z0-9+/]+/);
    if (!match) throw new Error("known_hosts 中没有 SHA256 指纹注释");
    return match[1] ?? match[0];
  }

  private requireTask(taskId: string): TaskContext {
    const task = this.store.getTask(taskId);
    if (!task) throw new InvalidArgumentError(`任务不存在: ${taskId}`);
    return task;
  }

  private assertNotArchived(task: TaskContext): void {
    if (task.archivedAt) throw new InvalidArgumentError("已归档任务为只读，请先恢复归档");
  }

  private finishActiveEpoch(taskId: string): void {
    const task = this.requireTask(taskId);
    if (task.protocolVersion !== 2 || !task.activeEpochId) return;
    const epoch = this.store.getScanEpoch(taskId, task.activeEpochId);
    if (epoch?.status !== "RUNNING") return;
    const coverage = this.store.listCoverageRuns(taskId, task.activeEpochId);
    const partial = coverage.length !== task.checks.length || coverage.some((run) => run.status !== "COMPLETE" || run.applicability === "UNKNOWN");
    this.store.finishScanEpoch(taskId, task.activeEpochId, partial ? "PARTIAL" : "COMPLETED");
  }
}

function severityForHumanVerdict(verdict: AssessmentVerdict, fallback: Assessment["severity"]): Assessment["severity"] {
  if (verdict === "CONFIRMED_MALICIOUS") return fallback === "CRITICAL" ? "CRITICAL" : "HIGH";
  if (verdict === "HIGHLY_SUSPICIOUS") return fallback === "CRITICAL" || fallback === "HIGH" ? fallback : "HIGH";
  if (verdict === "SUSPICIOUS") return fallback === "INFO" || fallback === "LOW" ? "MEDIUM" : fallback;
  return "INFO";
}
