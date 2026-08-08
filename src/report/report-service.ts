import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import { createId } from "../common/ids.js";
import type { TaskContext } from "../domain/types.js";
import type { SecurityAgentRuntime } from "../runtime/security-agent-runtime.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

export interface ReportValidation { valid: boolean; errors: string[] }

export class ReportService {
  constructor(private readonly baseDir: string, private readonly store: RuntimeStore, private readonly maxLlmBytes = 65_536) {}

  validate(taskId: string, markdown: string): ReportValidation {
    const findings = new Set(this.store.listFindings(taskId).map((item) => item.findingId));
    const evidence = new Set(this.store.listEvidence(taskId).map((item) => item.evidenceId));
    const errors: string[] = [];
    for (const id of markdown.match(/FIND-[0-9a-f-]{36}/g) ?? []) if (!findings.has(id)) errors.push(`未知 Finding 引用: ${id}`);
    for (const id of markdown.match(/EV-[0-9a-f-]{36}/g) ?? []) if (!evidence.has(id)) errors.push(`未知 Evidence 引用: ${id}`);
    const task = this.store.getTask(taskId);
    for (const category of task?.checks ?? []) {
      const status = task?.coverage[category];
      if (!status) errors.push(`检测类别缺少结构化结论: ${category}`);
      else if (!markdown.includes(status)) errors.push(`报告未展示 ${category} 的状态 ${status}`);
    }
    return { valid: errors.length === 0, errors: [...new Set(errors)] };
  }

  async generate(task: TaskContext, runtime: SecurityAgentRuntime): Promise<string> {
    let current = this.store.getTask(task.taskId) ?? task;
    this.ensureCoverageFindings(current);
    current = this.store.getTask(task.taskId) ?? current;
    current.status = "REPORTING";
    this.store.saveTask(current);
    const context = this.reportContext(current);
    await runtime.promptWithoutTools(`调查阶段结束。禁止继续调用远程调查或处置工具。请严格依据以下结构化上下文生成完整中文 Markdown 报告，保留所有 Finding/Evidence ID 和 ERROR/NOT_CHECKED，不得发明引用。\n\n${context}`);
    let markdown = runtime.lastAssistantText();
    let validation = this.validate(current.taskId, markdown);
    if (!validation.valid) {
      await runtime.promptWithoutTools(`上一版报告校验失败：${validation.errors.join("；")}。请仅修复报告，不调用工具、不新增事实。`);
      markdown = runtime.lastAssistantText();
      validation = this.validate(current.taskId, markdown);
    }
    if (!validation.valid) markdown = this.fallback(current);
    const reportDir = join(this.baseDir, "reports");
    await mkdir(reportDir, { recursive: true, mode: 0o700 });
    await chmod(reportDir, 0o700);
    const path = join(reportDir, `${current.taskId}.md`);
    await writeFile(path, markdown, { encoding: "utf8", mode: 0o600 });
    await chmod(path, 0o600);
    current.status = "COMPLETED";
    this.store.saveTask(current);
    this.store.appendAudit({ taskId: current.taskId, event: "report_generated", level: "info", data: { path, fallback: !validation.valid } });
    return path;
  }

  private ensureCoverageFindings(task: TaskContext): void {
    for (const category of task.checks) {
      if (task.coverage[category]) continue;
      this.store.putFinding({
        findingId: createId("finding"),
        taskId: task.taskId,
        host: task.target.host,
        category,
        severity: "INFO",
        confidence: 1,
        status: "NOT_CHECKED",
        title: `${category} 未完成检测`,
        summary: "调查在该检测项形成有效工具结论前结束；NOT_CHECKED 不代表目标安全。",
        evidenceRefs: [],
        recommendation: "补齐目标条件或调查预算后重新执行该检测项。",
        createdAt: new Date().toISOString(),
        toolCallId: `report-coverage:${task.taskId}:${category}`,
      });
    }
  }

  private reportContext(task: TaskContext): string {
    return sanitizeForLlm(JSON.stringify({
      task: { taskId: task.taskId, target: task.target.host, request: task.request, mode: task.mode, checks: task.checks, coverage: task.coverage },
      findings: this.store.listFindings(task.taskId),
      evidence: this.store.listEvidence(task.taskId).map(({ storagePath: _private, ...item }) => item),
      audit: this.store.listAudit(task.taskId).filter((item) => ["file_quarantined", "account_disabled", "tool_failed"].includes(item.event)),
    }), this.maxLlmBytes).text;
  }

  private fallback(task: TaskContext): string {
    const findings = this.store.listFindings(task.taskId);
    const evidence = this.store.listEvidence(task.taskId);
    const lines = [
      "# 主机安全专项检测报告", "", "## 任务信息", "",
      `- 任务：${task.taskId}`, `- 目标：${task.target.host}`, `- 模式：${task.mode}`, `- 请求：${task.request}`, "",
      "## 风险摘要", "",
      ...task.checks.map((category) => `- ${category}: ${task.coverage[category] ?? "NOT_CHECKED"}`), "",
      "## Findings", "",
    ];
    for (const finding of findings) {
      lines.push(`### ${finding.findingId} ${finding.title}`, "", `- 类别：${finding.category}`, `- 状态：${finding.status}`, `- 严重度：${finding.severity}`, `- 置信度：${finding.confidence}`, `- 证据：${finding.evidenceRefs.join(", ") || "无"}`, "", finding.summary, "");
    }
    lines.push("## Evidence", "");
    for (const item of evidence) lines.push(`- ${item.evidenceId}: ${item.type} / ${item.source} / SHA-256 ${item.sha256 ?? "N/A"}`);
    lines.push("", "## 限制", "", "本报告由结构化存储回退模板生成；ERROR 和 NOT_CHECKED 不代表目标安全。", "");
    return lines.join("\n");
  }
}
