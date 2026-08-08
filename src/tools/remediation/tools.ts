import { Type } from "typebox";
import { SecurityError } from "../../common/errors.js";
import type { AccountRefShape } from "./types.js";
import type { ActionReceipt, SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { requireReference } from "../reference-utils.js";

function failedReceiptStatus(error: unknown): "FAILED" | "UNKNOWN" {
  return error instanceof SecurityError && ["RECOVERY_UNCERTAIN", "TOOL_TIMEOUT", "TARGET_UNAVAILABLE"].includes(error.code)
    ? "UNKNOWN"
    : "FAILED";
}

export function createRemediationTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  return [
    createSecurityTool(...common, {
      name: "quarantine_file", label: "隔离可疑文件",
      description: "在明确逐动作批准后，按 Evidence 的原路径和哈希原子隔离文件。参数只接受已采集 evidenceRef。",
      parameters: Type.Object({ evidenceRef: Type.String({ pattern: "^EV-" }) }, { additionalProperties: false }),
      risk: "WRITE", replayPolicy: "NEVER", timeoutMs: 60_000, auditEvent: "file_quarantined", executionMode: "sequential",
      run: async (_toolCallId, params, signal): Promise<SecurityToolResult> => {
        const ticket = deps.approvals.consume(deps.task, "quarantine_file", params);
        if (!ticket) throw new SecurityError("APPROVAL_REQUIRED", "缺少与本次参数完全匹配的一次性授权票据");
        const evidence = deps.store.getEvidence(deps.task.taskId, params.evidenceRef);
        if (!evidence?.sha256 || evidence.type !== "file") throw new SecurityError("EVIDENCE_COLLECTION", "Evidence 不是可隔离文件或缺少哈希");
        const started: ActionReceipt = { actionId: ticket.actionId, taskId: deps.task.taskId, tool: "quarantine_file", targetFingerprint: deps.task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString() };
        deps.store.putActionReceipt(started);
        let result: Record<string, unknown>;
        try {
          result = await deps.executor.invoke({ operation: "quarantine_file", params: { actionId: ticket.actionId, path: evidence.source, expectedSha256: evidence.sha256, quarantineRoot: deps.config.remediation.quarantineRoot }, actionId: ticket.actionId }, signal);
          deps.checkpoint?.("remote_write_succeeded_before_local_receipt");
        } catch (error) {
          deps.store.putActionReceipt({ ...started, status: failedReceiptStatus(error), result: { error: error instanceof Error ? error.message : String(error) }, finishedAt: new Date().toISOString() });
          throw error;
        }
        const receipt: ActionReceipt = { ...started, status: result.status === "SUCCEEDED" ? "SUCCEEDED" : "FAILED", result, finishedAt: new Date().toISOString() };
        deps.store.putActionReceipt(receipt);
        if (receipt.status !== "SUCCEEDED") throw new SecurityError("EVIDENCE_COLLECTION", "隔离未成功，请人工检查", { actionId: ticket.actionId, result });
        return { status: "success", summary: receipt, items: [result], artifactRefs: [params.evidenceRef], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "disable_account", label: "禁用可疑账户",
      description: "在明确逐动作批准后锁定并过期 accountRef 对应账户。root 和当前 SSH 执行账户永久禁止。",
      parameters: Type.Object({ accountRef: Type.String({ pattern: "^ACCT-" }) }, { additionalProperties: false }),
      risk: "WRITE", replayPolicy: "NEVER", timeoutMs: 60_000, auditEvent: "account_disabled", executionMode: "sequential",
      run: async (_toolCallId, params, signal): Promise<SecurityToolResult> => {
        const ticket = deps.approvals.consume(deps.task, "disable_account", params);
        if (!ticket) throw new SecurityError("APPROVAL_REQUIRED", "缺少与本次参数完全匹配的一次性授权票据");
        const account = requireReference<AccountRefShape>(deps.store, deps.task.taskId, params.accountRef, "account");
        const started: ActionReceipt = { actionId: ticket.actionId, taskId: deps.task.taskId, tool: "disable_account", targetFingerprint: deps.task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString() };
        deps.store.putActionReceipt(started);
        let result: Record<string, unknown>;
        try {
          result = await deps.executor.invoke({ operation: "disable_account", params: { actionId: ticket.actionId, username: account.value.username, executorUsername: deps.task.target.username }, actionId: ticket.actionId }, signal);
          deps.checkpoint?.("remote_write_succeeded_before_local_receipt");
        } catch (error) {
          deps.store.putActionReceipt({ ...started, status: failedReceiptStatus(error), result: { error: error instanceof Error ? error.message : String(error) }, finishedAt: new Date().toISOString() });
          throw error;
        }
        const receipt: ActionReceipt = { ...started, status: result.status === "SUCCEEDED" ? "SUCCEEDED" : "FAILED", result, finishedAt: new Date().toISOString() };
        deps.store.putActionReceipt(receipt);
        if (receipt.status !== "SUCCEEDED") throw new SecurityError("PERMISSION_DENIED", "账户禁用未成功，请人工检查", { actionId: ticket.actionId, result });
        return { status: "success", summary: receipt, items: [result], artifactRefs: [params.accountRef], warnings: [] };
      },
    }),
  ];
}
