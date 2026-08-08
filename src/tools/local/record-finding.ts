import { Type } from "typebox";
import { createId } from "../../common/ids.js";
import type { Finding, SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";

const statuses = ["CONFIRMED", "HIGHLY_SUSPICIOUS", "SUSPICIOUS", "NO_FINDING", "NOT_CHECKED", "ERROR"] as const;
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function createRecordFindingTool(deps: ToolDependencies): SecurityToolDefinition {
  return createSecurityTool(deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes, {
    name: "record_finding", label: "记录安全发现",
    description: "把已经由工具事实支持的结论保存为结构化 Finding。每个检测类别结束前必须调用；ERROR/NOT_CHECKED 也必须明确记录。高风险结论必须引用 Evidence ID。",
    parameters: Type.Object({
      category: Type.Union([Type.Literal("webshell"), Type.Literal("java_memory_shell"), Type.Literal("backdoor_account"), Type.Literal("linux_persistence")]),
      severity: Type.Union(severities.map((value) => Type.Literal(value))),
      confidence: Type.Number({ minimum: 0, maximum: 1 }),
      status: Type.Union(statuses.map((value) => Type.Literal(value))),
      title: Type.String({ minLength: 1, maxLength: 200 }),
      summary: Type.String({ minLength: 1, maxLength: 8000 }),
      evidenceRefs: Type.Array(Type.String({ pattern: "^EV-" }), { maxItems: 100 }),
      recommendation: Type.Optional(Type.String({ maxLength: 8000 })),
    }, { additionalProperties: false }),
    risk: "LOCAL", replayPolicy: "SAFE", timeoutMs: 10_000, auditEvent: "finding_created", executionMode: "sequential",
    run: async (toolCallId, params): Promise<SecurityToolResult> => {
      for (const evidenceId of params.evidenceRefs) {
        if (!deps.store.getEvidence(deps.task.taskId, evidenceId)) throw new Error(`Finding 引用了不存在或跨任务的 Evidence: ${evidenceId}`);
      }
      if (["CONFIRMED", "HIGHLY_SUSPICIOUS"].includes(params.status) && params.evidenceRefs.length === 0) {
        throw new Error("CONFIRMED/HIGHLY_SUSPICIOUS 必须至少引用一个 Evidence");
      }
      const finding: Finding = {
        findingId: createId("finding"), taskId: deps.task.taskId, host: deps.task.target.host,
        category: params.category, severity: params.severity, confidence: params.confidence,
        status: params.status, title: params.title, summary: params.summary,
        evidenceRefs: params.evidenceRefs, createdAt: new Date().toISOString(), toolCallId,
        ...(params.recommendation ? { recommendation: params.recommendation } : {}),
      };
      const saved = deps.store.putFinding(finding);
      return { status: "success", summary: { findingId: saved.findingId, category: saved.category, status: saved.status }, items: [saved], artifactRefs: [saved.findingId], warnings: [] };
    },
  });
}
