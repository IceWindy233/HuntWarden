import { EventEmitter } from "node:events";
import type { AgentEvent, AgentMessage, AgentToolResult } from "@earendil-works/pi-agent-core";
import { Agent } from "@earendil-works/pi-agent-core";
import type { Api, Model, Models, ToolResultMessage } from "@earendil-works/pi-ai";
import type { ApprovalService } from "../agent/approval-service.js";
import { buildSystemPrompt } from "../agent/system-prompt.js";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import type { AppConfig } from "../config/schema.js";
import type { AgentStreamUpdate, SecurityToolDefinition, TaskContext } from "../domain/types.js";
import type { HostExecutor } from "../executor/operations.js";
import type { RuntimeStore, ToolRunRecord } from "../storage/runtime-store.js";
import { finalizeUnresolvedChecks, ScanPlanner } from "../checks/scan-planner.js";

export interface SecurityAgentRuntimeOptions {
  task: TaskContext;
  config: AppConfig;
  store: RuntimeStore;
  executor: HostExecutor;
  approvals: ApprovalService;
  tools: SecurityToolDefinition[];
  models: Models;
  model: Model<Api>;
  checkpoint?: (name: string) => void;
  scanPlanner?: ScanPlanner | false;
}

export class SecurityAgentRuntime extends EventEmitter {
  readonly agent: Agent;
  private readonly pendingInputByTimestamp = new Map<number, string>();
  private activeStream: { streamId: string; timestamp: number } | undefined;
  private streamSequence = 0;
  private readonly scanPlanner: ScanPlanner | undefined;
  private scanAbortController: AbortController | undefined;

  constructor(private readonly options: SecurityAgentRuntimeOptions) {
    super();
    const { task, config, tools, models, model, store } = options;
    this.agent = new Agent({
      initialState: {
        systemPrompt: buildSystemPrompt(task),
        model,
        thinkingLevel: config.model.thinkingLevel,
        tools,
        messages: store.loadMessages(task.taskId),
      },
      streamFn: models.streamSimple.bind(models),
      toolExecution: "parallel",
      steeringMode: "one-at-a-time",
      followUpMode: "one-at-a-time",
      beforeToolCall: async ({ toolCall, args }, signal) => await this.beforeToolCall(toolCall.id, toolCall.name, args, signal),
      shouldStopAfterTurn: async () => {
        const current = this.options.store.getTask(task.taskId) ?? task;
        return current.turnCount >= config.agent.maxTurns || current.toolCallCount >= config.agent.maxToolCalls;
      },
    });
    this.agent.subscribe(async (event) => { this.persistEvent(event); });
    this.scanPlanner = options.scanPlanner === false
      ? undefined
      : options.scanPlanner ?? (tools.some((tool) => tool.name === "get_host_info")
        ? new ScanPlanner({ task, store, tools, maxLlmBytes: config.llmData.maxTextBytes, accountChecks: config.account })
        : undefined);
  }

  async prompt(text: string): Promise<void> {
    await this.runPrompt(text, "RUNNING", false);
  }

  async promptWithoutTools(text: string): Promise<void> {
    await this.runPrompt(text, "REPORTING", true);
  }

  private async runPrompt(text: string, status: "RUNNING" | "REPORTING", withoutTools: boolean): Promise<void> {
    this.ensureSingleActive();
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    task.status = status;
    this.options.store.saveTask(task);
    const originalTools = this.agent.state.tools;
    if (withoutTools) this.agent.state.tools = [];
    this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_started" : "agent_started", level: "info", data: {} });
    try {
      let prompt = text;
      if (!withoutTools && this.scanPlanner) {
        this.scanAbortController = new AbortController();
        const scan = await this.scanPlanner.run(this.scanAbortController.signal);
        this.agent.state.tools = originalTools.filter((tool) => !scan.minimumToolNames.has(tool.name));
        prompt = `${text}\n\n<deterministic-minimum-scan>\n${scan.promptContext}\n</deterministic-minimum-scan>`;
      }
      await this.agent.prompt(prompt);
      const lastAssistant = [...this.agent.state.messages].reverse().find((message) => message.role === "assistant");
      if (lastAssistant?.role === "assistant" && lastAssistant.stopReason === "error") {
        throw new Error(lastAssistant.errorMessage || "模型 Provider 调用失败");
      }
      if (!withoutTools && this.scanPlanner) {
        finalizeUnresolvedChecks(this.options.store, task.taskId, "NOT_CHECKED", "模型未为该类别固化 Finding，最低只读入口虽已执行，但尚不足以得出安全结论。", "model-missing");
      }
      this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_finished" : "agent_run_finished", level: "info", data: {} });
      if (!withoutTools) {
        const completed = this.options.store.getTask(task.taskId) ?? task;
        completed.status = "COMPLETED";
        this.options.store.saveTask(completed);
      }
    } catch (error) {
      const aborted = Boolean(this.agent.signal?.aborted || this.scanAbortController?.signal.aborted);
      if (!withoutTools && this.scanPlanner) {
        finalizeUnresolvedChecks(
          this.options.store,
          task.taskId,
          aborted ? "NOT_CHECKED" : "ERROR",
          aborted ? "调查在形成完整结论前被中止。" : `模型 Provider 在最低只读覆盖后失败：${error instanceof Error ? error.message : String(error)}`,
          aborted ? "agent-aborted" : "provider-failed",
        );
        this.options.store.appendAudit({
          taskId: task.taskId,
          event: aborted ? "deterministic_scan_aborted" : "provider_failed_after_minimum_scan",
          level: aborted ? "warn" : "error",
          data: { error: error instanceof Error ? error.message : String(error) },
        });
      }
      const failed = this.options.store.getTask(task.taskId) ?? task;
      failed.status = aborted ? "ABORTED" : "FAILED";
      this.options.store.saveTask(failed);
      throw error;
    } finally {
      this.scanAbortController = undefined;
      this.agent.state.tools = originalTools;
    }
  }

  async steer(text: string): Promise<void> {
    const message: AgentMessage = { role: "user", content: text, timestamp: Date.now() };
    const inputId = this.options.store.enqueueInput(this.options.task.taskId, message);
    this.pendingInputByTimestamp.set(message.timestamp, inputId);
    this.agent.steer(message);
  }

  async recover(): Promise<void> {
    this.ensureSingleActive();
    this.options.task.status = "RECOVERING";
    this.options.store.saveTask(this.options.task);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "recovery_started", level: "warn", data: {} });
    for (const queued of this.options.store.listPendingInputs(this.options.task.taskId)) {
      const timestamp = "timestamp" in queued.message ? queued.message.timestamp : Date.now();
      this.pendingInputByTimestamp.set(timestamp, queued.inputId);
      this.agent.steer(queued.message);
    }
    for (const record of this.options.store.listIncompleteToolRuns(this.options.task.taskId)) {
      await this.recoverToolRun(record);
    }
    this.options.task.status = "RUNNING";
    this.options.store.saveTask(this.options.task);
    const messages = this.agent.state.messages;
    const last = messages.at(-1);
    if (last?.role === "user" || last?.role === "toolResult") await this.agent.continue();
    const completed = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    completed.status = "COMPLETED";
    if (completed.interruption) completed.interruption.recoveryRequired = false;
    this.options.store.saveTask(completed);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "recovery_completed", level: "info", data: {} });
  }

  abort(): void { this.scanAbortController?.abort(new Error("调查被分析师中止")); this.agent.abort(); }

  lastAssistantText(): string {
    const message = [...this.agent.state.messages].reverse().find((item) => item.role === "assistant");
    if (!message || message.role !== "assistant") return "";
    return message.content.filter((item) => item.type === "text").map((item) => item.text).join("");
  }

  private ensureSingleActive(): void {
    if (this.options.store.hasActiveTask(this.options.task.taskId)) {
      throw new Error("已有其他运行中的任务；首期只允许单任务运行");
    }
  }

  private async beforeToolCall(toolCallId: string, toolName: string, args: unknown, signal?: AbortSignal) {
    const tool = this.options.tools.find((item) => item.name === toolName);
    if (!tool) return { block: true, reason: `未注册工具: ${toolName}` };
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    task.toolCallCount += 1;
    if (task.toolCallCount > this.options.config.agent.maxToolCalls) {
      this.options.store.saveTask(task);
      return { block: true, reason: "已达到最大 Tool Call 预算" };
    }
    this.options.store.saveTask(task);
    this.options.store.startToolRun({ toolCallId, taskId: task.taskId, toolName, risk: tool.risk, replayPolicy: tool.replayPolicy, args });
    this.options.checkpoint?.("tool_started");
    if (tool.risk !== "WRITE") return undefined;
    if (task.mode !== "REMEDIATE") {
      this.options.store.finishToolRun(toolCallId, "BLOCKED", undefined, "SCAN 模式禁止写操作");
      return { block: true, reason: "当前任务为 SCAN 模式，写操作被阻断" };
    }
    if (!this.options.config.remediation.allowedTools.includes(toolName as "quarantine_file" | "disable_account")) {
      return { block: true, reason: "写工具不在配置白名单" };
    }
    let approved = this.options.store.findApproval(task.taskId, toolName, this.options.approvals.getArgsDigest(args));
    if (!approved) {
      const ticket = this.options.approvals.request(task, toolName, args);
      this.options.checkpoint?.("approval_waiting");
      const decision = await this.options.approvals.waitForDecision(ticket, signal);
      if (decision.status !== "APPROVED") {
        this.options.store.finishToolRun(toolCallId, "BLOCKED", undefined, "用户拒绝授权");
        return { block: true, reason: "分析师拒绝了本次写操作" };
      }
      approved = decision;
    }
    return undefined;
  }

  private persistEvent(event: AgentEvent): void {
    const type = event.type;
    if (type === "message_start" && event.message.role === "assistant") {
      this.activeStream = {
        streamId: `${this.options.task.taskId}:${event.message.timestamp}:${++this.streamSequence}`,
        timestamp: event.message.timestamp,
      };
      this.emitStream({ phase: "start" });
    }
    if (type === "message_update") {
      this.options.checkpoint?.("model_streaming");
      if (event.assistantMessageEvent.type === "text_delta" && event.assistantMessageEvent.delta) {
        if (!this.activeStream) {
          this.activeStream = {
            streamId: `${this.options.task.taskId}:${event.message.timestamp}:${++this.streamSequence}`,
            timestamp: event.message.timestamp,
          };
          this.emitStream({ phase: "start" });
        }
        this.emitStream({ phase: "delta", delta: event.assistantMessageEvent.delta });
      }
      return;
    }
    if (type === "message_end" && event.message && typeof event.message === "object") {
      const message = event.message as AgentMessage;
      this.options.store.appendMessage(this.options.task.taskId, message);
      if (message.role === "user") {
        const inputId = this.pendingInputByTimestamp.get(message.timestamp);
        if (inputId) { this.options.store.markInputDelivered(inputId); this.pendingInputByTimestamp.delete(message.timestamp); }
        this.options.checkpoint?.("model_response_after_user_persisted");
      }
      if (message.role === "assistant") {
        const stopReason = "stopReason" in message ? message.stopReason : "stop";
        this.emitStream({ phase: stopReason === "error" || stopReason === "aborted" ? "error" : "end" });
        this.activeStream = undefined;
      }
    }
    if (type === "turn_end") {
      const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
      task.turnCount += 1;
      this.options.store.saveTask(task);
    }
    if (type === "tool_execution_end") {
      const toolCallId = String(event.toolCallId ?? "");
      const run = toolCallId ? this.options.store.getToolRun(toolCallId) : undefined;
      if (run?.status === "STARTED" && event.result) {
        const isError = Boolean(event.isError);
        this.options.store.finishToolRun(toolCallId, isError ? "FAILED" : "SUCCEEDED", event.result, isError ? "Pi tool execution error" : undefined);
      }
    }
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: type, level: type.includes("failed") ? "error" : "debug", data: {} });
    this.emit("event", { taskId: this.options.task.taskId, type });
  }

  private emitStream(input: { phase: AgentStreamUpdate["phase"]; delta?: string }): void {
    if (!this.activeStream) return;
    const update: AgentStreamUpdate = {
      taskId: this.options.task.taskId,
      streamId: this.activeStream.streamId,
      phase: input.phase,
      timestamp: this.activeStream.timestamp,
      ...(input.delta === undefined ? {} : { delta: input.delta }),
    };
    this.emit("stream", update);
  }

  private async recoverToolRun(record: ToolRunRecord): Promise<void> {
    const tool = this.options.tools.find((item) => item.name === record.toolName);
    if (!tool) {
      this.appendRecoveredToolResult(record, { content: [{ type: "text", text: "恢复失败：工具已不可用" }], details: {} }, true);
      return;
    }
    if (record.replayPolicy === "SAFE") {
      try {
        const result = await tool.execute(record.toolCallId, record.args as never, undefined);
        this.appendRecoveredToolResult(record, result, false);
      } catch (error) {
        this.appendRecoveredToolResult(record, { content: [{ type: "text", text: `恢复重放失败: ${error instanceof Error ? error.message : String(error)}` }], details: {} }, true);
      }
      return;
    }

    const previousApproval = this.options.store.findLatestApproval(
      record.taskId,
      record.toolName,
      this.options.approvals.getArgsDigest(record.args),
    );
    const actionId = previousApproval?.actionId;
    if (actionId) {
      try {
        const remote = await this.options.executor.invoke({ operation: "get_action_receipt", params: { actionId }, actionId });
        if (remote.status === "SUCCEEDED" || remote.status === "FAILED") {
          const local = this.options.store.getActionReceipt(actionId);
          this.options.store.putActionReceipt({
            actionId,
            taskId: record.taskId,
            tool: record.toolName,
            targetFingerprint: this.options.task.target.hostFingerprint,
            status: remote.status,
            result: remote,
            startedAt: local?.startedAt ?? previousApproval.createdAt,
            finishedAt: typeof remote.finishedAt === "string" ? remote.finishedAt : new Date().toISOString(),
          });
          const result: AgentToolResult<unknown> = { content: [{ type: "text", text: sanitizeForLlm(JSON.stringify(remote), this.options.config.llmData.maxTextBytes).text }], details: remote };
          this.appendRecoveredToolResult(record, result, remote.status === "FAILED");
          return;
        }
      } catch (error) {
        this.options.store.appendAudit({
          taskId: record.taskId,
          event: "action_receipt_query_failed",
          level: "warn",
          data: { actionId, error: error instanceof Error ? error.message : String(error) },
        });
      }
    }
    const ticket = this.options.approvals.request(
      this.options.task,
      record.toolName,
      record.args,
      `恢复确认：先前动作 ${actionId ?? "未知"} 状态未知，重新批准可能再次执行`,
    );
    const decision = await this.options.approvals.waitForDecision(ticket);
    if (decision.status !== "APPROVED") {
      this.appendRecoveredToolResult(record, { content: [{ type: "text", text: "恢复时写操作状态未知，分析师拒绝重新执行" }], details: {} }, true);
      return;
    }
    try {
      const result = await tool.execute(record.toolCallId, record.args as never, undefined);
      this.appendRecoveredToolResult(record, result, false);
    } catch (error) {
      this.appendRecoveredToolResult(record, { content: [{ type: "text", text: `重新批准后的执行失败: ${error instanceof Error ? error.message : String(error)}` }], details: {} }, true);
    }
  }

  private appendRecoveredToolResult(record: ToolRunRecord, result: AgentToolResult<unknown>, isError: boolean): void {
    this.options.store.finishToolRun(record.toolCallId, isError ? "FAILED" : "SUCCEEDED", result, isError ? "recovery failed" : undefined);
    const message: ToolResultMessage = {
      role: "toolResult", toolCallId: record.toolCallId, toolName: record.toolName,
      content: result.content, details: result.details, isError, timestamp: Date.now(),
    };
    this.options.store.appendMessage(record.taskId, message);
    this.agent.state.messages = [...this.agent.state.messages, message];
  }
}
