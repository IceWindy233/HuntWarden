import { createHash } from "node:crypto";
import { access, chmod, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import { createId } from "../common/ids.js";
import type { ReportGenerationMode, ReportRecord, TaskContext } from "../domain/types.js";
import type { SecurityAgentRuntime } from "../runtime/security-agent-runtime.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

export interface ReportValidation { valid: boolean; errors: string[] }

export class ReportService {
  constructor(
    private readonly baseDir: string,
    private readonly store: RuntimeStore,
    private readonly maxLlmBytes = 65_536,
    private readonly checkpoint?: (name: string) => void,
  ) {}

  validate(taskId: string, markdown: string): ReportValidation {
    const findings = new Set(this.store.listFindings(taskId).map((item) => item.findingId));
    const evidence = new Set(this.store.listEvidence(taskId).map((item) => item.evidenceId));
    const actions = new Map(this.store.listActionReceipts(taskId).map((item) => [item.actionId, item.status]));
    const approvals = this.store.listApprovals(taskId);
    const errors: string[] = [];
    for (const id of markdown.match(/FIND-[0-9a-f-]{36}/g) ?? []) if (!findings.has(id)) errors.push(`未知 Finding 引用: ${id}`);
    for (const id of markdown.match(/EV-[0-9a-f-]{36}/g) ?? []) if (!evidence.has(id)) errors.push(`未知 Evidence 引用: ${id}`);
    for (const id of markdown.match(/ACT-[0-9a-f-]{36}/g) ?? []) {
      if (!actions.has(id) && !approvals.some((item) => item.actionId === id)) errors.push(`未知 Action 引用: ${id}`);
    }
    const task = this.store.getTask(taskId);
    for (const category of task?.checks ?? []) {
      const status = task?.coverage[category];
      if (!status) errors.push(`检测类别缺少结构化结论: ${category}`);
      else if (!markdown.includes(status)) errors.push(`报告未展示 ${category} 的状态 ${status}`);
    }
    for (const [actionId, status] of actions) {
      if (!markdown.includes(actionId)) errors.push(`报告未展示远程动作: ${actionId}`);
      if (!markdown.includes(status)) errors.push(`报告未展示动作状态: ${actionId}/${status}`);
    }
    for (const approval of approvals) {
      if (!markdown.includes(approval.actionId)) errors.push(`报告未展示审批动作: ${approval.actionId}`);
      if (!markdown.includes(approval.status)) errors.push(`报告未展示审批状态: ${approval.actionId}/${approval.status}`);
    }
    if (task?.interruption && !markdown.includes("恢复")) errors.push("报告未展示任务恢复信息");
    return { valid: errors.length === 0, errors: [...new Set(errors)] };
  }

  async generate(task: TaskContext, runtime: SecurityAgentRuntime): Promise<ReportRecord> {
    let current = this.store.getTask(task.taskId) ?? task;
    this.ensureCoverageFindings(current);
    current = this.store.getTask(task.taskId) ?? current;
    current.status = "REPORTING";
    this.store.saveTask(current);
    this.checkpoint?.("reporting_started");
    const context = this.reportContext(current);
    let markdown = "";
    let generationMode: ReportGenerationMode = "MODEL";
    const validationErrors: string[] = [];

    try {
      await runtime.promptWithoutTools(`分析师已确认当前调查结果并请求生成报告。禁止继续调用远程调查或处置工具。请严格依据以下结构化上下文生成完整中文 Markdown 报告，保留所有 Finding/Evidence/Action ID、审批与恢复状态以及 ERROR/NOT_CHECKED，不得发明引用。\n\n${context}`);
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
        markdown = this.fallback(current);
        generationMode = "FALLBACK";
      }
    } catch (error) {
      validationErrors.push(`模型报告生成失败: ${error instanceof Error ? error.message : String(error)}`);
      markdown = this.fallback(current);
      generationMode = "FALLBACK";
    }

    const fallbackValidation = this.validate(current.taskId, markdown);
    if (!fallbackValidation.valid) throw new Error(`确定性报告校验失败: ${fallbackValidation.errors.join("；")}`);
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

  private ensureCoverageFindings(task: TaskContext): void {
    for (const category of task.checks) {
      if (task.coverage[category]) continue;
      this.store.putFinding({
        findingId: createId("finding"), taskId: task.taskId, host: task.target.host,
        category, severity: "INFO", confidence: 1, status: "NOT_CHECKED",
        title: `${category} 未完成检测`,
        summary: "调查在该检测项形成有效工具结论前结束；NOT_CHECKED 不代表目标安全。",
        evidenceRefs: [], recommendation: "补齐目标条件或调查预算后重新执行该检测项。",
        createdAt: new Date().toISOString(), toolCallId: `report-coverage:${task.taskId}:${category}`,
      });
    }
  }

  private reportContext(task: TaskContext): string {
    return sanitizeForLlm(JSON.stringify({
      task: { taskId: task.taskId, target: task.target.host, request: task.request, mode: task.mode, checks: task.checks, coverage: task.coverage, interruption: task.interruption },
      findings: this.store.listFindings(task.taskId),
      evidence: this.store.listEvidence(task.taskId).map(({ storagePath: _private, ...item }) => item),
      approvals: this.store.listApprovals(task.taskId),
      actionReceipts: this.store.listActionReceipts(task.taskId),
      audit: this.store.listAudit(task.taskId).filter((item) => ["task_interrupted_detected", "recovery_started", "recovery_completed", "tool_failed"].includes(item.event)),
    }), this.maxLlmBytes).text;
  }

  private fallback(task: TaskContext): string {
    const findings = this.store.listFindings(task.taskId);
    const evidence = this.store.listEvidence(task.taskId);
    const approvals = this.store.listApprovals(task.taskId);
    const receipts = this.store.listActionReceipts(task.taskId);
    const recovery = this.store.listAudit(task.taskId).filter((item) => item.event.includes("recover") || item.event.includes("interrupt"));
    const lines = [
      "# HuntWarden 主机安全专项检测报告", "", "## 任务信息", "",
      `- 任务：${task.taskId}`, `- 目标：${task.target.host}`, `- 模式：${task.mode}`, `- 请求：${task.request}`, "",
      "## 检测覆盖", "", ...task.checks.map((category) => `- ${category}: ${task.coverage[category] ?? "NOT_CHECKED"}`), "",
      "## Findings", "",
    ];
    for (const finding of findings) {
      lines.push(`### ${finding.findingId} ${finding.title}`, "", `- 类别：${finding.category}`, `- 状态：${finding.status}`, `- 严重度：${finding.severity}`, `- 置信度：${finding.confidence}`, `- 证据：${finding.evidenceRefs.join(", ") || "无"}`, "", finding.summary, "");
    }
    lines.push("## Evidence", "");
    for (const item of evidence) lines.push(`- ${item.evidenceId}: ${item.type} / ${item.source} / SHA-256 ${item.sha256 ?? "N/A"}`);
    lines.push("", "## 审批与处置", "");
    if (approvals.length === 0) lines.push("- 未请求写操作审批");
    for (const item of approvals) lines.push(`- ${item.actionId}: ${item.tool} / 审批 ${item.status}`);
    for (const item of receipts) lines.push(`- ${item.actionId}: ${item.tool} / 远程回执 ${item.status}`);
    lines.push("", "## 恢复信息", "");
    if (recovery.length === 0) lines.push("- 本任务未发生恢复流程");
    for (const item of recovery) lines.push(`- ${item.createdAt} ${item.event}: ${JSON.stringify(item.data)}`);
    lines.push("", "## 限制", "", "本报告由结构化存储回退模板生成；ERROR 和 NOT_CHECKED 不代表目标安全。", "");
    return lines.join("\n");
  }
}
