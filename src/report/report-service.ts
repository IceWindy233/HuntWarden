import { createHash } from "node:crypto";
import { access, chmod, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { encodeWithinBudget } from "../agent/data-sanitizer.js";
import { createId } from "../common/ids.js";
import type { ReportGenerationMode, ReportRecord, TaskContext } from "../domain/types.js";
import type { SecurityAgentRuntime } from "../runtime/security-agent-runtime.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { Assessment, CoverageRun, InvestigationGap } from "../protocol-v2/types.js";

interface ReportProjectionV2 {
  task: { taskId: string; epochId: string; target: string; mode: string; checks: string[]; request: string };
  coverage: CoverageRun[];
  assessments: Assessment[];
  investigationGaps: InvestigationGap[];
  evidence: Record<string, unknown>[];
  actions: Record<string, unknown>[];
  recovery: Record<string, unknown>[];
  modelState: Array<{ category: string; state: "CONCLUDED" | "NOT_CONCLUDED" }>;
}

export interface ReportValidation { valid: boolean; errors: string[] }

export class ReportService {
  constructor(
    private readonly baseDir: string,
    private readonly store: RuntimeStore,
    private readonly maxLlmBytes = 65_536,
    private readonly checkpoint?: (name: string) => void,
  ) {}

  validate(taskId: string, markdown: string): ReportValidation {
    const task = this.store.getTask(taskId);
    // v1 任务不再有可校验的结构化结论平面：既不生成新报告，也不参与投影校验。
    if (task?.protocolVersion !== 2 || !task.activeEpochId) {
      return { valid: false, errors: ["任务没有可校验的 v2 Epoch：v1 历史任务只保留已生成的报告文件"] };
    }
    return this.validateV2(this.projectionV2(task), markdown);
  }

  async generate(task: TaskContext, runtime: SecurityAgentRuntime): Promise<ReportRecord> {
    const current = this.store.getTask(task.taskId) ?? task;
    if (current.protocolVersion !== 2 || !current.activeEpochId) throw new Error("v1 历史任务只读，不能生成新的调查报告");
    current.status = "REPORTING";
    this.store.saveTask(current);
    this.checkpoint?.("reporting_started");
    const projection = this.projectionV2(current);
    const context = this.reportContextV2(projection);
    let markdown = "";
    let generationMode: ReportGenerationMode = "MODEL";
    const validationErrors: string[] = [];
    if (context.incomplete) {
      // 强制字段本身超预算：模型无论如何都无法引用被截掉的 Assessment/Action ID，两轮往返注定失败。
      validationErrors.push("结构化报告上下文超出模型文本预算，已直接使用确定性模板");
      markdown = this.fallbackV2(projection);
      generationMode = "FALLBACK";
    }

    try {
      if (generationMode === "MODEL") {
        await runtime.promptWithoutTools(`分析师已确认当前调查结果并请求生成报告。禁止继续调用远程调查或处置工具。请严格依据以下结构化上下文生成完整中文 Markdown 报告，保留所有 Coverage/Assessment/InvestigationGap/Evidence/Action ID、审批与恢复状态，以及 PARTIAL/ERROR/NOT_RUN/UNKNOWN 对应的 INCOMPLETE 呈现，不得发明引用。\n\n${context.text}`);
        markdown = runtime.lastAssistantText();
        let validation = this.validate(current.taskId, markdown);
        if (!validation.valid) {
          validationErrors.push(...validation.errors);
          await runtime.promptWithoutTools(`上一版报告校验失败：${validation.errors.join("；")}。请仅修复报告，不调用工具、不新增事实。`);
          markdown = runtime.lastAssistantText();
          validation = this.validate(current.taskId, markdown);
          generationMode = "REPAIRED";
          if (!validation.valid) validationErrors.push(...validation.errors);
        }
        if (!validation.valid) {
          markdown = this.fallbackV2(projection);
          generationMode = "FALLBACK";
        }
      }
    } catch (error) {
      validationErrors.push(`模型报告生成失败: ${error instanceof Error ? error.message : String(error)}`);
      markdown = this.fallbackV2(projection);
      generationMode = "FALLBACK";
    }

    const fallbackValidation = this.validate(current.taskId, markdown);
    if (!fallbackValidation.valid) {
      const message = `确定性报告校验失败: ${fallbackValidation.errors.join("；")}`;
      current.status = "FAILED";
      this.store.saveTask(current);
      this.store.appendAudit({ taskId: current.taskId, event: "report_generation_failed", level: "error", data: { error: message } });
      throw new Error(message);
    }
    try {
      await this.importLegacy(current.taskId);
      const reportDir = join(this.baseDir, "reports", current.taskId);
      await mkdir(reportDir, { recursive: true, mode: 0o700 });
      await chmod(reportDir, 0o700);
      await this.importOrphanVersions(current.taskId, reportDir);
      const version = (this.store.latestReport(current.taskId)?.version ?? 0) + 1;
      const path = join(reportDir, `v${String(version).padStart(4, "0")}.md`);
      await writeFile(path, markdown, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await chmod(path, 0o600);
      const report: ReportRecord = {
        reportId: createId("report"), taskId: current.taskId, version, path,
        sha256: createHash("sha256").update(markdown).digest("hex"), generationMode,
        validationErrors: [...new Set(validationErrors)], createdAt: new Date().toISOString(),
      };
      this.store.putReport(report);
      current.status = "COMPLETED";
      if (current.interruption) current.interruption.recoveryRequired = false;
      this.store.saveTask(current);
      this.store.appendAudit({ taskId: current.taskId, event: "report_generated", level: "info", data: { reportId: report.reportId, version, path, generationMode } });
      return report;
    } catch (error) {
      current.status = "FAILED";
      this.store.saveTask(current);
      this.store.appendAudit({ taskId: current.taskId, event: "report_generation_failed", level: "error", data: { error: error instanceof Error ? error.message : String(error) } });
      throw error;
    }
  }

  async list(taskId: string): Promise<ReportRecord[]> {
    await this.importLegacy(taskId);
    await this.importOrphanVersions(taskId, join(this.baseDir, "reports", taskId));
    return this.store.listReports(taskId);
  }

  async read(taskId: string, reportId?: string): Promise<{ report: ReportRecord; markdown: string } | undefined> {
    await this.importLegacy(taskId);
    const report = reportId ? this.store.getReport(taskId, reportId) : this.store.latestReport(taskId);
    if (!report) return undefined;
    return { report, markdown: await readFile(report.path, "utf8") };
  }

  private async importLegacy(taskId: string): Promise<void> {
    if (this.store.listReports(taskId).length > 0) return;
    const path = join(this.baseDir, "reports", `${taskId}.md`);
    try { await access(path); } catch { return; }
    const markdown = await readFile(path, "utf8");
    this.store.putReport({
      reportId: createId("report"), taskId, version: 1, path,
      sha256: createHash("sha256").update(markdown).digest("hex"),
      generationMode: "LEGACY", validationErrors: [], createdAt: new Date().toISOString(),
    });
  }

  private async importOrphanVersions(taskId: string, reportDir: string): Promise<void> {
    let entries: string[];
    try { entries = await readdir(reportDir); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    const known = new Set(this.store.listReports(taskId).map((item) => item.version));
    for (const name of entries.sort()) {
      const match = name.match(/^v(\d{4,})\.md$/);
      if (!match) continue;
      const version = Number(match[1]);
      if (!Number.isSafeInteger(version) || version < 1 || known.has(version)) continue;
      const path = join(reportDir, name);
      const [markdown, info] = await Promise.all([readFile(path, "utf8"), stat(path)]);
      this.store.putReport({
        reportId: createId("report"), taskId, version, path,
        sha256: createHash("sha256").update(markdown).digest("hex"), generationMode: "LEGACY",
        validationErrors: ["检测到报告文件已落盘但版本记录未提交，恢复时补记"], createdAt: info.mtime.toISOString(),
      });
      known.add(version);
    }
  }

  private projectionV2(task: TaskContext): ReportProjectionV2 {
    const epochId = task.activeEpochId;
    if (!epochId) throw new Error("v2 报告缺少 active epoch");
    const coverage = task.checks.map((category) => this.store.listCoverageRuns(task.taskId, epochId)
      .filter((run) => run.category === category).at(-1))
      .filter((run): run is CoverageRun => run !== undefined);
    const assessments = this.store.listAssessments(task.taskId, epochId);
    const modelState = task.checks.map((category) => ({
      category,
      state: assessments.some((assessment) => assessment.authorType === "MODEL" && assessment.category === category && assessment.scope === "OBSERVED_CATEGORY")
        ? "CONCLUDED" as const : "NOT_CONCLUDED" as const,
    }));
    return Object.freeze({
      task: { taskId: task.taskId, epochId, target: task.target.host, mode: task.mode, checks: task.checks, request: task.request },
      coverage, assessments, investigationGaps: this.store.listInvestigationGaps(task.taskId, epochId),
      evidence: this.store.listEvidence(task.taskId).map(({ storagePath: _private, ...item }) => item as unknown as Record<string, unknown>),
      actions: [...this.store.listApprovals(task.taskId), ...this.store.listActionReceipts(task.taskId)] as unknown as Record<string, unknown>[],
      recovery: this.store.listAudit(task.taskId)
        .filter((item) => item.event.includes("recover") || item.event.includes("interrupt"))
        .map(({ eventId: _eventId, taskId: _taskId, ...item }) => item as unknown as Record<string, unknown>),
      modelState,
    });
  }

  private validateV2(projection: ReportProjectionV2, markdown: string): ReportValidation {
    const errors: string[] = [];
    const allowed = {
      assessment: new Set(projection.assessments.map((item) => item.assessmentId)),
      coverage: new Set(projection.coverage.map((item) => item.coverageId)),
      gap: new Set(projection.investigationGaps.map((item) => item.gapId)),
      evidence: new Set(projection.evidence.map((item) => String(item.evidenceId ?? "")).filter(Boolean)),
      action: new Set(projection.actions.map((item) => String(item.actionId ?? "")).filter(Boolean)),
    };
    for (const id of markdown.match(/\bASM-[0-9a-f-]{36}/gi) ?? []) if (!allowed.assessment.has(id)) errors.push(`未知 Assessment 引用: ${id}`);
    for (const id of markdown.match(/\bCOV-[0-9a-f-]{36}/gi) ?? []) if (!allowed.coverage.has(id)) errors.push(`未知 Coverage 引用: ${id}`);
    for (const id of markdown.match(/\bIGAP-[0-9a-f-]{36}/gi) ?? []) if (!allowed.gap.has(id)) errors.push(`未知 InvestigationGap 引用: ${id}`);
    for (const id of markdown.match(/\bEV-[0-9a-f-]{36}/gi) ?? []) if (!allowed.evidence.has(id)) errors.push(`未知 Evidence 引用: ${id}`);
    for (const id of markdown.match(/\bACT-[0-9a-f-]{36}/gi) ?? []) if (!allowed.action.has(id)) errors.push(`未知 Action 引用: ${id}`);
    if (!markdown.includes(projection.task.epochId)) errors.push(`报告未展示 Epoch: ${projection.task.epochId}`);
    for (const category of projection.task.checks) {
      const run = projection.coverage.find((item) => item.category === category);
      if (!run) { errors.push(`缺少 CoverageRun: ${category}`); continue; }
      if (!markdown.includes(run.coverageId)) errors.push(`报告未展示 Coverage ID: ${run.coverageId}`);
      if (!markdown.includes(run.status) || !markdown.includes(run.applicability)) errors.push(`报告未展示 Coverage 状态: ${category}/${run.status}/${run.applicability}`);
      const model = projection.modelState.find((item) => item.category === category)!;
      if (!markdown.includes(`MODEL: ${model.state}`)) errors.push(`报告未展示模型状态: ${category}/MODEL: ${model.state}`);
    }
    for (const assessment of projection.assessments) {
      if (!markdown.includes(assessment.assessmentId)) errors.push(`报告未展示 Assessment: ${assessment.assessmentId}`);
      if (!markdown.includes(assessment.verdict)) errors.push(`报告未展示 Assessment verdict: ${assessment.assessmentId}/${assessment.verdict}`);
    }
    for (const gap of projection.investigationGaps) if (!markdown.includes(gap.gapId) || !markdown.includes(gap.code)) errors.push(`报告未展示 InvestigationGap: ${gap.gapId}/${gap.code}`);
    for (const action of projection.actions) {
      const id = String(action.actionId ?? ""); const status = String(action.status ?? "");
      if (id && (!markdown.includes(id) || !markdown.includes(status))) errors.push(`报告未展示动作: ${id}/${status}`);
    }
    if (projection.coverage.some((run) => run.status !== "COMPLETE" || run.applicability === "UNKNOWN") && !markdown.includes("INCOMPLETE")) errors.push("不完整 Coverage 必须显示 INCOMPLETE");
    return { valid: errors.length === 0, errors: [...new Set(errors)] };
  }

  private reportContextV2(projection: ReportProjectionV2): { text: string; incomplete: boolean; truncated: boolean } {
    const required = { task: projection.task, coverage: projection.coverage, assessments: projection.assessments, investigationGaps: projection.investigationGaps, actions: projection.actions, modelState: projection.modelState };
    const full = encodeWithinBudget(projection.evidence.length, (keep) => ({
      ...required, evidence: projection.evidence.slice(0, keep), ...(keep < projection.evidence.length ? { evidenceOmitted: projection.evidence.length - keep } : {}),
      recovery: projection.recovery,
      instruction: "Coverage、RULE、MODEL、HUMAN 必须并列；UNKNOWN/PARTIAL/ERROR/NOT_RUN 固定写 INCOMPLETE；MODEL 状态按给定值逐类原样写为 MODEL: CONCLUDED 或 MODEL: NOT_CONCLUDED。",
    }), this.maxLlmBytes);
    return { text: full.text, incomplete: full.overBudget, truncated: full.truncated };
  }

  private fallbackV2(projection: ReportProjectionV2): string {
    const lines = [
      "# HuntWarden v2 主机取证报告", "", "## 任务与 Epoch", "",
      `- 任务：${projection.task.taskId}`, `- Epoch：${projection.task.epochId}`, `- 目标：${projection.task.target}`, `- 模式：${projection.task.mode}`, `- 请求：${projection.task.request}`, "",
      "## Coverage 与模型状态", "",
    ];
    for (const category of projection.task.checks) {
      const run = projection.coverage.find((item) => item.category === category);
      const model = projection.modelState.find((item) => item.category === category)!;
      if (!run) { lines.push(`- ${category}: NOT_RUN / UNKNOWN / INCOMPLETE；MODEL: ${model.state}`); continue; }
      const unsafe = run.status !== "COMPLETE" || run.applicability === "UNKNOWN" ? " / INCOMPLETE" : "";
      lines.push(`- ${category}: ${run.coverageId} / ${run.status} / ${run.applicability}${unsafe}；MODEL: ${model.state}`);
    }
    lines.push("", "## Assessment Ledger", "");
    if (projection.assessments.length === 0) lines.push("- 尚无 RULE / MODEL / HUMAN Assessment；不得推断为无风险。");
    for (const item of projection.assessments) lines.push(`- ${item.assessmentId}: ${item.authorType} / ${item.category} / ${item.verdict} / ${item.severity} / subject ${item.subjectRef ?? "OBSERVED_CATEGORY"} / Facts ${item.factRefs.join(", ") || "无"} / Evidence ${item.evidenceRefs.join(", ") || "无"}\n  ${item.rationale}`);
    lines.push("", "## Investigation Gaps", "");
    if (projection.investigationGaps.length === 0) lines.push("- 无模型调查限制记录。");
    for (const gap of projection.investigationGaps) lines.push(`- ${gap.gapId}: ${gap.code} / ${gap.reasonCode} / ${gap.category ?? "task"}`);
    lines.push("", "## Evidence", "");
    for (const item of projection.evidence) lines.push(`- ${String(item.evidenceId)}: ${String(item.type)} / SHA-256 ${String(item.sha256 ?? "N/A")}`);
    lines.push("", "## 审批、动作与恢复", "");
    if (projection.actions.length === 0) lines.push("- 无写操作。");
    for (const item of projection.actions) lines.push(`- ${String(item.actionId)}: ${String(item.status)}`);
    if (projection.recovery.length === 0) lines.push("- 未发生恢复流程。");
    for (const item of projection.recovery) lines.push(`- ${JSON.stringify(item)}`);
    lines.push("", "## 固定限制", "", "Coverage 完整性与风险判断正交；不完整、未调查和不适用均不等于安全。", "");
    return lines.join("\n");
  }
}
