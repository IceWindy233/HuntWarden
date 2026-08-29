import { EventEmitter } from "node:events";
import type { AgentEvent, AgentMessage, AgentToolResult } from "@earendil-works/pi-agent-core";
import { Agent } from "@earendil-works/pi-agent-core";
import type { Api, Model, Models, ToolResultMessage } from "@earendil-works/pi-ai";
import type { ApprovalService } from "../agent/approval-service.js";
import { buildSystemPrompt } from "../agent/system-prompt.js";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import type { AppConfig } from "../config/schema.js";
import { digestObject } from "../common/json.js";
import type { AgentStreamUpdate, SecurityToolDefinition, TaskContext } from "../domain/types.js";
import type { ProtocolV2Executor } from "../executor/protocol-v2-executor.js";
import type { RuntimeStore, ToolRunRecord } from "../storage/runtime-store.js";
import { randomUUID } from "node:crypto";

/** 小于该体量的工具结果不值得淘汰：存根本身也要占位，压缩收益接近零。 */
const EVICTION_MIN_BYTES = 2_048;

export interface SecurityAgentRuntimeOptions {
  task: TaskContext;
  config: AppConfig;
  store: RuntimeStore;
  executor: ProtocolV2Executor;
  approvals: ApprovalService;
  tools: SecurityToolDefinition[];
  models: Models;
  model: Model<Api>;
  checkpoint?: (name: string) => void;
  protocolV2: { epochId: string };
}

export class SecurityAgentRuntime extends EventEmitter {
  readonly agent: Agent;
  private readonly pendingInputByTimestamp = new Map<number, string>();
  private activeStream: { streamId: string; timestamp: number } | undefined;
  private streamSequence = 0;
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
      // 调查循环此前不传重试策略：一次 429 或网络抖动就让 stopReason 变成 error，任务 FAILED，
      // 所有未固化类别被标成 ERROR。有界重试把可恢复的 Provider 抖动与真正的目标环境受限区分开。
      streamFn: (streamModel, context, options) => models.streamSimple(streamModel, context, {
        ...options,
        maxRetries: config.agent.providerMaxRetries,
        timeoutMs: config.agent.providerTimeoutSeconds * 1_000,
      }),
      transformContext: async (messages) => this.evictStaleToolResults(messages),
      // 远程预算按最坏成本先预留、响应后结算。并行工具会把多个 60 秒
      // wallTime 估算同时计入 reserved，QUICK 的 225 秒账户因此在第 4 个
      // 并发调用上产生虚假的 BUDGET_EXHAUSTED。顺序执行既保持预算
      // fail-close，也让下一次预留基于前一次已结算的实际成本。
      toolExecution: "sequential",
      steeringMode: "one-at-a-time",
      followUpMode: "one-at-a-time",
      beforeToolCall: async ({ toolCall, args }, signal) => await this.beforeToolCall(toolCall.id, toolCall.name, args, signal),
      shouldStopAfterTurn: async () => {
        const current = this.options.store.getTask(task.taskId) ?? task;
        return current.turnCount >= config.agent.maxTurns;
      },
    });
    this.agent.subscribe(async (event) => { this.persistEvent(event); });
  }

  /**
   * 把过旧的工具结果文本换成存根，只作用于发给 Provider 的上下文。
   *
   * 存在理由：本运行时用的是低层 `Agent`，没有 compaction，历史消息又是从 SQLite 全量回放的，
   * 上下文只增不减。单条满额工具结果约 16k token，长调查必然撞窗口，届时输出预算被夹到极小、
   * 或 Provider 直接报错，任务 FAILED 且未固化类别全被标 ERROR。
   *
   * 淘汰是**无损**的：v2 事实已落入 Model Fact Plane，可按 sourceRunId 用
   * `query_facts` 回取。持久化的 `messages` 不受影响，恢复与审计看到的仍是原文。
   */
  private async evictStaleToolResults(messages: AgentMessage[]): Promise<AgentMessage[]> {
    const retainTurns = this.options.config.agent.contextRetainTurns;
    let assistantTurns = 0;
    const output: AgentMessage[] = [];
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index];
      if (message === undefined) continue;
      if (message.role === "assistant") assistantTurns += 1;
      // `>=`：走过 retainTurns 个 assistant 消息之后的工具结果才淘汰，因此恰好保留最近
      // retainTurns 个回合的原文，而不是 retainTurns + 1 个。
      output.push(assistantTurns >= retainTurns ? this.stubToolResult(message) : message);
    }
    return output.reverse();
  }

  /** 只压缩体量大且成功的工具结果：错误结果本身很短，且失败原因是后续判断的依据。 */
  private stubToolResult(message: AgentMessage): AgentMessage {
    if (message.role !== "toolResult" || message.isError) return message;
    const text = message.content.filter((item) => item.type === "text").map((item) => item.text).join("");
    if (Buffer.byteLength(text, "utf8") <= EVICTION_MIN_BYTES) return message;
    return {
      ...message,
      content: [{
        type: "text",
        text: `[上下文缓存已淘汰：${message.toolName} / runId=${message.toolCallId} / ${Buffer.byteLength(text, "utf8")} 字节。事实仍在 Model Fact Plane；请用 query_facts 按 sourceRunId 查询。]`,
      }],
    };
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
    if (withoutTools) this.agent.state.tools = originalTools.filter((tool) => tool.name === "query_facts" || tool.name === "get_assessment_projection");
    this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_started" : "agent_started", level: "info", data: {} });
    try {
      await this.agent.prompt(text);
      const lastAssistant = [...this.agent.state.messages].reverse().find((message) => message.role === "assistant");
      if (lastAssistant?.role === "assistant" && lastAssistant.stopReason === "error") {
        throw new Error(lastAssistant.errorMessage || "模型 Provider 调用失败");
      }
      if (!withoutTools) this.finalizeV2ModelGaps("NORMAL_SKIP");
      this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_finished" : "agent_run_finished", level: "info", data: {} });
      if (!withoutTools) {
        const completed = this.options.store.getTask(task.taskId) ?? task;
        completed.status = "COMPLETED";
        this.options.store.saveTask(completed);
      }
    } catch (error) {
      const aborted = Boolean(this.agent.signal?.aborted);
      if (!withoutTools) this.finalizeV2ModelGaps(aborted ? "ANALYST_ABORT" : "PROVIDER_FAILURE");
      const failed = this.options.store.getTask(task.taskId) ?? task;
      failed.status = aborted ? "ABORTED" : "FAILED";
      this.options.store.saveTask(failed);
      throw error;
    } finally {
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
    // 存在状态未知的写动作时，绝不能把任务归档为已完成：`recoveryRequired` 是分析师进入
    // 恢复入口的唯一信号，清零它等于把撕裂的隔离/锁定动作静默归档。见 9.0。
    const unresolved = this.options.store.listActionReceipts(this.options.task.taskId)
      .filter((receipt) => receipt.status === "UNKNOWN");
    if (unresolved.length > 0) {
      completed.status = "ABORTED";
      completed.interruption = {
        previousStatus: completed.interruption?.previousStatus ?? "RECOVERING",
        reason: "PROCESS_INTERRUPTED",
        detectedAt: completed.interruption?.detectedAt ?? new Date().toISOString(),
        recoveryRequired: true,
      };
      this.options.store.saveTask(completed);
      this.options.store.appendAudit({
        taskId: this.options.task.taskId,
        event: "recovery_requires_manual_confirmation",
        level: "warn",
        data: {
          unknownActionIds: unresolved.map((receipt) => receipt.actionId),
          detail: `${unresolved.length} 个写动作状态未知，需人工确认目标端实际状态`,
        },
      });
      return;
    }
    completed.status = "COMPLETED";
    if (completed.interruption) completed.interruption.recoveryRequired = false;
    this.options.store.saveTask(completed);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "recovery_completed", level: "info", data: {} });
  }

  abort(): void { this.agent.abort(); }

  lastAssistantText(): string {
    const message = [...this.agent.state.messages].reverse().find((item) => item.role === "assistant");
    if (message?.role !== "assistant") return "";
    return message.content.filter((item) => item.type === "text").map((item) => item.text).join("");
  }

  private ensureSingleActive(): void {
    if (this.options.store.hasActiveTask(this.options.task.taskId)) {
      throw new Error("已有其他运行中的任务；首期只允许单任务运行");
    }
  }

  private async beforeToolCall(toolCallId: string, toolName: string, args: unknown, signal?: AbortSignal) {
    const tool = this.options.tools.find((item) => item.name === toolName);
    if (!tool) {
      this.options.store.appendAudit({
        taskId: this.options.task.taskId,
        event: "model_invalid_tool_call",
        level: "warn",
        data: { reason: "UNREGISTERED_TOOL", toolNameDigest: digestObject(toolName) },
      });
      return { block: true, reason: `未注册工具: ${toolName}` };
    }
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    task.toolCallCount += 1;
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
    if (["SAFE", "SAFE_REOBSERVE", "LOCAL_REPLAY", "IDEMPOTENT_LOCAL", "RESUME_OR_RECOLLECT"].includes(record.replayPolicy)) {
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
        const remote = await this.options.executor.invokeMaintenanceV2("get_action_receipt", {
          protocolVersion: 2, requestId: `${actionId}:RECOVERY`, epochId: this.options.task.activeEpochId ?? "RECOVERY",
          deadlineMs: 10_000, reservation: { reservationId: `${actionId}:RECOVERY`, estimate: { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 10_000, probeCalls: 0 } },
          params: { actionId },
        });
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
        // 远端回执为 STARTED/UNKNOWN 时，本地必须落 UNKNOWN：这是 9.0 的撕裂窗口，
        // 「动作从未开始」与「动作可能已半执行」在存储上必须可区分，否则报告与 GUI 读不出不确定性。
        const local = this.options.store.getActionReceipt(actionId);
        this.options.store.putActionReceipt({
          actionId,
          taskId: record.taskId,
          tool: record.toolName,
          targetFingerprint: this.options.task.target.hostFingerprint,
          status: "UNKNOWN",
          result: remote,
          startedAt: local?.startedAt ?? previousApproval.createdAt,
        });
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

  private finalizeV2ModelGaps(reasonCode: string): void {
    const epochId = this.options.protocolV2.epochId;
    const concluded = new Set(this.options.store.listAssessments(this.options.task.taskId, epochId)
      .filter((assessment) => assessment.authorType === "MODEL" && assessment.scope === "OBSERVED_CATEGORY")
      .map((assessment) => assessment.category));
    const existing = new Set(this.options.store.listInvestigationGaps(this.options.task.taskId, epochId)
      .filter((gap) => gap.code === "MODEL_DID_NOT_INVESTIGATE")
      .map((gap) => gap.category));
    for (const category of this.options.task.checks) {
      if (concluded.has(category) || existing.has(category)) continue;
      this.options.store.putInvestigationGap({
        gapId: `IGAP-${randomUUID()}`, taskId: this.options.task.taskId, epochId, category,
        code: "MODEL_DID_NOT_INVESTIGATE", reasonCode, createdAt: new Date().toISOString(),
      });
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
