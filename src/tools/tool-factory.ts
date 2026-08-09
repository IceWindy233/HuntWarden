import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import type { Static, TSchema } from "typebox";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import { SecurityError } from "../common/errors.js";
import type { SecurityToolDefinition } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import { withHostOperationTimeout } from "../executor/timeout-context.js";

export interface SecurityToolMeta<TParameters extends TSchema, TDetails> {
  name: string;
  label: string;
  description: string;
  parameters: TParameters;
  risk: SecurityToolDefinition["risk"];
  replayPolicy: SecurityToolDefinition["replayPolicy"];
  timeoutMs: number;
  auditEvent: string;
  executionMode?: "parallel" | "sequential";
  run: (
    toolCallId: string,
    params: Static<TParameters>,
    signal?: AbortSignal,
    onUpdate?: (result: AgentToolResult<TDetails>) => void,
  ) => Promise<TDetails>;
}

export function createSecurityTool<TParameters extends TSchema, TDetails>(
  store: RuntimeStore,
  taskId: string,
  maxLlmBytes: number,
  meta: SecurityToolMeta<TParameters, TDetails>,
): SecurityToolDefinition<TParameters, TDetails> {
  const tool: SecurityToolDefinition<TParameters, TDetails> = {
    name: meta.name,
    label: meta.label,
    description: meta.description,
    parameters: meta.parameters,
    risk: meta.risk,
    replayPolicy: meta.replayPolicy,
    timeoutMs: meta.timeoutMs,
    auditEvent: meta.auditEvent,
    ...(meta.executionMode ? { executionMode: meta.executionMode } : {}),
    execute: async (toolCallId, params, signal, onUpdate) => {
      const existing = store.getToolRun(toolCallId);
      if (existing?.status === "SUCCEEDED" && existing.result) {
        return existing.result as AgentToolResult<TDetails>;
      }
      store.startToolRun({
        toolCallId,
        taskId,
        toolName: meta.name,
        risk: meta.risk,
        replayPolicy: meta.replayPolicy,
        args: params,
      });
      store.appendAudit({ taskId, event: "tool_started", level: "info", data: { toolCallId, tool: meta.name, risk: meta.risk } });
      try {
        onUpdate?.({ content: [{ type: "text", text: `${meta.label} 正在执行` }], details: {} as TDetails });
        const details = await withHostOperationTimeout(meta.timeoutMs, async () => await meta.run(toolCallId, params, signal, onUpdate));
        const sanitized = sanitizeForLlm(JSON.stringify(details), maxLlmBytes);
        const result: AgentToolResult<TDetails> = {
          content: [{ type: "text", text: sanitized.text }],
          details,
        };
        store.finishToolRun(toolCallId, "SUCCEEDED", result);
        store.appendAudit({ taskId, event: meta.auditEvent, level: "info", data: { toolCallId, tool: meta.name, truncated: sanitized.truncated } });
        return result;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        store.finishToolRun(toolCallId, "FAILED", undefined, message);
        store.appendAudit({ taskId, event: "tool_failed", level: "error", data: { toolCallId, tool: meta.name, error: message } });
        if (error instanceof SecurityError) throw error;
        throw new SecurityError("UNSUPPORTED_ENVIRONMENT", message, { tool: meta.name }, error instanceof Error ? { cause: error } : undefined);
      }
    },
  };
  return tool;
}
