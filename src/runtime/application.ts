import { EventEmitter } from "node:events";
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
import { createSecurityTools } from "../tools/index.js";
import type { ThreatIntelClient } from "../threat-intel/types.js";
import { SecurityAgentRuntime } from "./security-agent-runtime.js";

export class Application extends EventEmitter {
  readonly approvals: ApprovalService;
  readonly reports: ReportService;
  private runtime?: SecurityAgentRuntime;
  private runtimeTaskId?: string;
  private executor?: SSHExecutor;
  private closePromise: Promise<void> | undefined;

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
      coverage: {},
      createdAt: now, updatedAt: now, turnCount: 0, toolCallCount: 0,
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

  runtimeFor(task: TaskContext): SecurityAgentRuntime {
    if (this.runtime && this.runtimeTaskId === task.taskId) return this.runtime;
    if (this.runtime) {
      this.runtime.abort();
      void this.executor?.close();
    }
    this.executor = new SSHExecutor(task.target, this.config.executor.helperPath, this.config.executor.timeoutSeconds * 1000);
    const evidence = new EvidenceStore(this.config.storage.baseDir, this.store, this.checkpoint);
    const deps = {
      task, config: this.config, store: this.store, evidence, executor: this.executor, approvals: this.approvals,
      ...(this.checkpoint ? { checkpoint: this.checkpoint } : {}),
      ...(this.threatIntel ? { threatIntel: this.threatIntel } : {}),
    };
    const tools = createSecurityTools(deps);
    this.runtime = new SecurityAgentRuntime({ task, config: this.config, store: this.store, executor: this.executor, approvals: this.approvals, tools, models: this.models, model: this.model, ...(this.checkpoint ? { checkpoint: this.checkpoint } : {}) });
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
    const runtime = this.runtimeFor(task);
    await runtime.prompt(task.request);
    this.emit("changed", taskId);
  }

  async recoverTask(taskId: string): Promise<void> {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (!task.interruption?.recoveryRequired) throw new InvalidArgumentError("任务没有需要处理的中断状态");
    const runtime = this.runtimeFor(task);
    if (task.interruption.previousStatus === "REPORTING") await this.reports.generate(this.requireTask(taskId), runtime);
    else await runtime.recover();
    this.emit("changed", taskId);
  }

  async steerTask(taskId: string, text: string): Promise<void> {
    const normalized = text.trim();
    if (!normalized || normalized.length > 20_000) throw new InvalidArgumentError("Steering 输入不能为空且不能超过 20000 字符");
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    await this.runtimeFor(task).steer(normalized);
    this.emit("changed", taskId);
  }

  abortTask(taskId: string): void {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (this.runtimeTaskId === taskId) this.runtime?.abort();
    task.status = "ABORTED";
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

  async generateReport(taskId: string): Promise<ReportRecord> {
    const task = this.requireTask(taskId);
    this.assertNotArchived(task);
    if (["CREATED", "RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"].includes(task.status)) {
      throw new InvalidArgumentError("调查尚未结束，不能生成报告");
    }
    if (task.interruption?.recoveryRequired) throw new InvalidArgumentError("任务需要先完成恢复，才能生成报告");
    this.store.appendAudit({ taskId, event: "report_generation_requested_by_analyst", level: "info", data: { existingVersions: this.store.listReports(taskId).length } });
    const report = await this.reports.generate(task, this.runtimeFor(task));
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
}
