import { EventEmitter } from "node:events";
import type { AgentEvent, AgentMessage, AgentToolResult } from "@earendil-works/pi-agent-core";
import { Agent } from "@earendil-works/pi-agent-core";
import type { Api, Model, Models, ToolResultMessage } from "@earendil-works/pi-ai";
import type { ApprovalService } from "../agent/approval-service.js";
import { buildSystemPrompt } from "../agent/system-prompt.js";
import { createObservedProviderFetch, providerRequestSignal } from "../agent/provider-observer.js";
import { sanitizeForLlm, serializeToolResultForLlm } from "../agent/data-sanitizer.js";
import type { AppConfig } from "../config/schema.js";
import { digestObject } from "../common/json.js";
import type { AgentStreamUpdate, SecurityToolDefinition, TaskContext } from "../domain/types.js";
import type { ProtocolV2Executor } from "../executor/protocol-v2-executor.js";
import type { RuntimeStore, ToolRunRecord } from "../storage/runtime-store.js";
import { randomUUID } from "node:crypto";
import { InvestigationCompletionValidator } from "../investigation/completion-validator.js";

/** 小于该体量的工具结果不值得淘汰：存根本身也要占位，压缩收益接近零。 */
const EVICTION_MIN_BYTES = 2_048;
/**
 * 模型窗口是 token 单位，而工具结果预算是 UTF-8 字节。按 1 byte/token 换算会比常见
 * 英文 JSON 的 3-4 bytes/token 更保守，也覆盖大量转义、短标识符导致的高 token 密度。
 */
const PROVIDER_CONTEXT_BYTES_PER_TOKEN = 1;
const PROVIDER_CONTEXT_MIN_RESERVE_TOKENS = 8_192;
const PROVIDER_CONTEXT_MAX_RESERVE_TOKENS = 32_768;
const PROVIDER_CONTEXT_RESERVE_RATIO = 0.125;
const MIN_BATCH_RESULT_BYTES = 1_024;

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
  private pauseRequested = false;
  constructor(private readonly options: SecurityAgentRuntimeOptions) {
    super();
    const { task, config, tools, models, model, store } = options;
    const providerFetch = createObservedProviderFetch((attempt) => {
      store.appendAudit({
        taskId: task.taskId,
        event: "model_provider_http_attempt",
        level: attempt.status !== undefined && attempt.status < 400 ? "debug" : "warn",
        data: { epochId: options.protocolV2.epochId, provider: model.provider, model: model.id, ...attempt },
      });
    });
    this.agent = new Agent({
      initialState: {
        systemPrompt: buildSystemPrompt(task),
        model,
        thinkingLevel: config.model.thinkingLevel,
        tools,
        messages: store.loadMessages(task.taskId, options.protocolV2.epochId),
      },
      // 调查循环此前不传重试策略：一次 429 或网络抖动就让 stopReason 变成 error，任务 FAILED，
      // 所有未固化类别被标成 ERROR。有界重试把可恢复的 Provider 抖动与真正的目标环境受限区分开。
      streamFn: (streamModel, context, options) => {
        store.appendAudit({
          taskId: task.taskId,
          event: "model_provider_context",
          level: "debug",
          data: {
            epochId: this.options.protocolV2.epochId,
            provider: model.provider,
            model: model.id,
            messages: context.messages.length,
            serializedBytes: Buffer.byteLength(JSON.stringify(context), "utf8"),
          },
        });
        return models.streamSimple(streamModel, context, {
          ...options,
          maxRetries: config.agent.providerMaxRetries,
          timeoutMs: config.agent.providerTimeoutSeconds * 1_000,
          signal: providerRequestSignal(config.agent.providerTimeoutSeconds * 1_000, options?.signal),
          fetch: providerFetch,
        });
      },
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
   * 把过旧的工具结果文本换成存根，并约束同一批工具结果的总量；只作用于发给 Provider 的上下文。
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
    let agedResults = 0;
    const reversed: AgentMessage[] = [];
    for (let index = messages.length - 1; index >= 0; index -= 1) {
      const message = messages[index];
      if (message === undefined) continue;
      if (message.role === "assistant") assistantTurns += 1;
      // `>=`：走过 retainTurns 个 assistant 消息之后的工具结果才淘汰，因此恰好保留最近
      // retainTurns 个回合的原文，而不是 retainTurns + 1 个。
      const next = assistantTurns >= retainTurns ? this.stubToolResult(message) : message;
      if (next !== message) agedResults += 1;
      reversed.push(next);
    }
    const turnBounded = reversed.reverse();
    const toolBudgetBytes = this.providerToolResultBudgetBytes();
    const originalToolBytes = turnBounded.reduce((sum, message) => sum + this.toolResultTextBytes(message), 0);
    const resizable = turnBounded.flatMap((message, index) => {
      if (message.role !== "toolResult" || message.isError || message.details === undefined) return [];
      const bytes = this.toolResultTextBytes(message);
      return bytes > EVICTION_MIN_BYTES ? [{ index, bytes }] : [];
    });
    const resizableBytes = resizable.reduce((sum, item) => sum + item.bytes, 0);
    const fixedBytes = originalToolBytes - resizableBytes;
    const availableBytes = Math.max(0, toolBudgetBytes - fixedBytes);
    const fairCap = originalToolBytes > toolBudgetBytes && resizable.length > 0
      ? this.fairPerResultCap(resizable.map((item) => item.bytes), availableBytes)
      : Number.POSITIVE_INFINITY;
    const resizedIndexes = new Set<number>();
    const output = turnBounded.map((message, index) => {
      let next = message;
      const entry = resizable.find((item) => item.index === index);
      if (entry && entry.bytes > fairCap) {
        next = this.resizeToolResult(message, fairCap);
        resizedIndexes.add(index);
      }
      return this.withoutToolDetails(next);
    });
    const outputToolBytes = output.reduce((sum, message) => sum + this.toolResultTextBytes(message), 0);
    this.options.store.appendAudit({
      taskId: this.options.task.taskId,
      event: "model_context_compacted",
      level: "debug",
      data: {
        epochId: this.options.protocolV2.epochId,
        messages: messages.length,
        retainTurns,
        toolBudgetBytes,
        originalToolBytes,
        outputToolBytes,
        agedResults,
        batchResizedResults: resizedIndexes.size,
      },
    });
    return output;
  }

  /** 为 system prompt、Tool Schema、普通消息和 Provider 封装预留窗口，再给工具正文分配保守预算。 */
  private providerToolResultBudgetBytes(): number {
    const inputTokens = Math.max(0, this.options.model.contextWindow - this.options.model.maxTokens);
    const reserveTokens = Math.min(
      PROVIDER_CONTEXT_MAX_RESERVE_TOKENS,
      Math.max(PROVIDER_CONTEXT_MIN_RESERVE_TOKENS, Math.ceil(this.options.model.contextWindow * PROVIDER_CONTEXT_RESERVE_RATIO)),
    );
    return Math.max(
      MIN_BATCH_RESULT_BYTES,
      Math.floor(Math.max(0, inputTokens - reserveTokens) * PROVIDER_CONTEXT_BYTES_PER_TOKEN),
    );
  }

  /** 水位分配：小结果保持完整，大结果获得相同上限，未使用的份额自动回流给大结果。 */
  private fairPerResultCap(sizes: number[], budget: number): number {
    if (sizes.length === 0 || budget <= 0) return 0;
    let low = 0;
    let high = Math.max(...sizes);
    let best = 0;
    while (low <= high) {
      const middle = (low + high) >> 1;
      const used = sizes.reduce((sum, size) => sum + Math.min(size, middle), 0);
      if (used <= budget) {
        best = middle;
        low = middle + 1;
      } else {
        high = middle - 1;
      }
    }
    return best;
  }

  private resizeToolResult(message: AgentMessage, maxBytes: number): AgentMessage {
    if (message.role !== "toolResult" || message.details === undefined) return message;
    const encoded = serializeToolResultForLlm(message.details, Math.max(MIN_BATCH_RESULT_BYTES, maxBytes));
    if (encoded.outputBytes > maxBytes) {
      return {
        ...message,
        content: [{ type: "text", text: "[工具结果受 Provider 总上下文预算限制；请缩小条件或分页查询。]" }],
      };
    }
    return { ...message, content: [{ type: "text", text: encoded.text }] };
  }

  /** details 用于本地审计；Provider 只需要脱敏且有界的 content。 */
  private withoutToolDetails(message: AgentMessage): AgentMessage {
    if (message.role !== "toolResult") return message;
    const { details: _details, ...wireMessage } = message;
    return wireMessage;
  }

  private toolResultTextBytes(message: AgentMessage): number {
    if (message.role !== "toolResult") return 0;
    return Buffer.byteLength(message.content.filter((item) => item.type === "text").map((item) => item.text).join(""), "utf8");
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
    if (withoutTools) this.agent.state.tools = originalTools.filter((tool) => tool.name === "query_facts" || tool.name === "query_investigation" || tool.name === "get_assessment_projection");
    this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_started" : "agent_started", level: "info", data: {} });
    try {
      await this.agent.prompt(text);
      if (!withoutTools && this.pauseRequested) { this.markPaused(); return; }
      const lastAssistant = [...this.agent.state.messages].reverse().find((message) => message.role === "assistant");
      if (lastAssistant?.role === "assistant" && (lastAssistant.stopReason === "error" || lastAssistant.stopReason === "aborted")) {
        throw new Error(lastAssistant.errorMessage || (lastAssistant.stopReason === "aborted" ? "模型 Provider 流在完成前中止" : "模型 Provider 调用失败"));
      }
      this.requireMeaningfulAssistant(lastAssistant);
      if (!withoutTools) {
        await this.reconcileTerminalAssessment();
        const reconciledAssistant = [...this.agent.state.messages].reverse().find((message) => message.role === "assistant");
        if (reconciledAssistant?.role === "assistant" && (reconciledAssistant.stopReason === "error" || reconciledAssistant.stopReason === "aborted")) {
          throw new Error(reconciledAssistant.errorMessage || "模型终态协调失败");
        }
        this.requireMeaningfulAssistant(reconciledAssistant);
        this.finalizeV2ModelGaps("NORMAL_SKIP");
        this.completeInvestigation("MODEL_STOPPED_WITH_OPEN_WORK");
      }
      this.options.store.appendAudit({ taskId: task.taskId, event: withoutTools ? "report_model_finished" : "agent_run_finished", level: "info", data: {} });
      if (!withoutTools) {
        const completed = this.options.store.getTask(task.taskId) ?? task;
        completed.status = "COMPLETED";
        this.options.store.saveTask(completed);
      }
    } catch (error) {
      const aborted = Boolean(this.agent.signal?.aborted);
      if (!withoutTools && this.pauseRequested) { this.markPaused(); return; }
      if (!withoutTools) {
        this.finalizeV2ModelGaps(aborted ? "ANALYST_ABORT" : "PROVIDER_FAILURE");
        if (aborted) this.cancelInvestigation("ANALYST_ABORT");
        else this.completeInvestigationAfterFailure("PROVIDER_FAILURE");
      }
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
    const inputId = this.options.store.enqueueInput(this.options.task.taskId, message, this.options.protocolV2.epochId);
    this.pendingInputByTimestamp.set(message.timestamp, inputId);
    this.agent.steer(message);
  }

  async recover(): Promise<void> {
    this.ensureSingleActive();
    this.options.task.status = "RECOVERING";
    this.options.store.saveTask(this.options.task);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "recovery_started", level: "warn", data: { epochId: this.options.protocolV2.epochId } });
    for (const queued of this.options.store.listPendingInputs(this.options.task.taskId, this.options.protocolV2.epochId)) {
      const timestamp = "timestamp" in queued.message ? queued.message.timestamp : Date.now();
      this.pendingInputByTimestamp.set(timestamp, queued.inputId);
      this.agent.steer(queued.message);
    }
    const incomplete = this.options.store.listIncompleteToolRuns(this.options.task.taskId);
    const unbound = incomplete.filter((record) => record.epochId !== this.options.protocolV2.epochId);
    if (unbound.length > 0) {
      this.options.store.appendAudit({
        taskId: this.options.task.taskId,
        event: "recovery_unbound_tool_runs",
        level: "error",
        data: { epochId: this.options.protocolV2.epochId, count: unbound.length, toolRunDigests: unbound.map((record) => digestObject(record.toolCallId)) },
      });
      this.options.task.status = "ABORTED";
      this.options.task.interruption = {
        previousStatus: "RECOVERING", reason: "PROCESS_INTERRUPTED", detectedAt: new Date().toISOString(), recoveryRequired: true,
      };
      this.options.store.saveTask(this.options.task);
      throw new Error("存在未绑定当前 Epoch 的未完成 ToolRun，拒绝自动恢复");
    }
    for (const record of incomplete) {
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
      .filter((receipt) => receipt.epochId === this.options.protocolV2.epochId && receipt.status === "UNKNOWN");
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
          epochId: this.options.protocolV2.epochId,
          unknownActionIds: unresolved.map((receipt) => receipt.actionId),
          detail: `${unresolved.length} 个写动作状态未知，需人工确认目标端实际状态`,
        },
      });
      return;
    }
    completed.status = "COMPLETED";
    this.finalizeV2ModelGaps("RECOVERY_SKIP");
    this.completeInvestigation("RECOVERY_STOPPED_WITH_OPEN_WORK");
    if (completed.interruption) completed.interruption.recoveryRequired = false;
    this.options.store.saveTask(completed);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "recovery_completed", level: "info", data: { epochId: this.options.protocolV2.epochId } });
  }

  pause(): void {
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    if (!["RUNNING", "WAITING_APPROVAL", "RECOVERING"].includes(task.status)) throw new Error("只有运行中的调查可以暂停");
    this.pauseRequested = true;
    this.markPaused();
    this.agent.abort();
  }

  async resume(): Promise<void> {
    this.ensureSingleActive();
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    const session = this.options.store.getInvestigationSession(task.taskId, this.options.protocolV2.epochId);
    if (task.status !== "PAUSED" || session?.executionStatus !== "PAUSED") throw new Error("任务没有处于可继续的暂停状态");
    this.pauseRequested = false;
    this.options.store.updateInvestigationSession({ ...session, executionStatus: "RUNNING", revision: session.revision + 1, updatedAt: new Date().toISOString() }, session.revision);
    task.status = "RUNNING";
    this.options.store.saveTask(task);
    this.options.store.appendAudit({ taskId: task.taskId, event: "investigation_resumed", level: "info", data: {} });
    try {
      await this.agent.continue();
      if (this.pauseRequested) { this.markPaused(); return; }
      const lastAssistant = [...this.agent.state.messages].reverse().find((message) => message.role === "assistant");
      if (lastAssistant?.role === "assistant" && (lastAssistant.stopReason === "error" || lastAssistant.stopReason === "aborted")) {
        throw new Error(lastAssistant.errorMessage || (lastAssistant.stopReason === "aborted" ? "模型 Provider 流在完成前中止" : "模型 Provider 调用失败"));
      }
      this.requireMeaningfulAssistant(lastAssistant);
      this.finalizeV2ModelGaps("NORMAL_SKIP");
      this.completeInvestigation("MODEL_STOPPED_WITH_OPEN_WORK");
      const completed = this.options.store.getTask(task.taskId) ?? task;
      completed.status = "COMPLETED";
      this.options.store.saveTask(completed);
      this.options.store.appendAudit({ taskId: task.taskId, event: "agent_run_finished", level: "info", data: { resumed: true } });
    } catch (error) {
      if (this.pauseRequested) { this.markPaused(); return; }
      const aborted = Boolean(this.agent.signal?.aborted);
      this.finalizeV2ModelGaps(aborted ? "ANALYST_ABORT" : "PROVIDER_FAILURE");
      if (aborted) this.cancelInvestigation("ANALYST_ABORT"); else this.completeInvestigationAfterFailure("PROVIDER_FAILURE");
      const failed = this.options.store.getTask(task.taskId) ?? task;
      failed.status = aborted ? "ABORTED" : "FAILED";
      this.options.store.saveTask(failed);
      throw error;
    }
  }

  abort(): void { this.agent.abort(); }

  lastAssistantText(): string {
    const message = [...this.agent.state.messages].reverse().find((item) => item.role === "assistant");
    if (message?.role !== "assistant") return "";
    return message.content.filter((item) => item.type === "text").map((item) => item.text).join("");
  }

  /**
   * Provider 以 stop 正常结束却没有文本或工具调用时，不能把这次请求当成模型已审查。
   * assistant 原消息已经由 persistEvent 保存，后续 Provider failure 路径会把未审查类别
   * 固化成 MODEL_DID_NOT_INVESTIGATE，因而既保留首跑轨迹，也不会丢掉确定性调查结果。
   */
  private requireMeaningfulAssistant(message: AgentMessage | undefined): void {
    const meaningful = message?.role === "assistant" && message.content.some((item) =>
      item.type === "toolCall" || (item.type === "text" && item.text.trim().length > 0));
    if (meaningful) return;
    this.options.store.appendAudit({
      taskId: this.options.task.taskId,
      event: "model_empty_response",
      level: "warn",
      data: { provider: this.options.model.provider, model: this.options.model.id },
    });
    throw new Error("模型 Provider 返回空 assistant 响应");
  }

  private ensureSingleActive(): void {
    if (this.options.store.hasActiveTask(this.options.task.taskId)) {
      throw new Error("已有其他运行中的任务；首期只允许单任务运行");
    }
  }

  private markPaused(): void {
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    const session = this.options.store.getInvestigationSession(task.taskId, this.options.protocolV2.epochId);
    let transitioned = false;
    if (session && session.executionStatus !== "PAUSED" && session.executionStatus !== "STOPPED") {
      this.options.store.updateInvestigationSession({ ...session, executionStatus: "PAUSED", revision: session.revision + 1, updatedAt: new Date().toISOString() }, session.revision);
      transitioned = true;
    }
    if (task.status !== "PAUSED") { task.status = "PAUSED"; this.options.store.saveTask(task); transitioned = true; }
    if (transitioned) this.options.store.appendAudit({ taskId: task.taskId, event: "investigation_paused", level: "info", data: {} });
  }

  private async beforeToolCall(toolCallId: string, toolName: string, args: unknown, signal?: AbortSignal) {
    const tool = this.options.tools.find((item) => item.name === toolName);
    if (!tool) {
      this.options.store.appendAudit({
        taskId: this.options.task.taskId,
        event: "model_invalid_tool_call",
        level: "warn",
        data: { epochId: this.options.protocolV2.epochId, reason: "UNREGISTERED_TOOL", toolNameDigest: digestObject(toolName) },
      });
      return { block: true, reason: `未注册工具: ${toolName}` };
    }
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    task.toolCallCount += 1;
    this.options.store.saveTask(task);
    const run = this.options.store.startToolRun({ toolCallId, taskId: task.taskId, epochId: this.options.protocolV2.epochId, toolName, risk: tool.risk, replayPolicy: tool.replayPolicy, args });
    if (run.status !== "STARTED") {
      this.options.store.appendAudit({
        taskId: task.taskId,
        event: "model_invalid_tool_call",
        level: "warn",
        data: { epochId: this.options.protocolV2.epochId, reason: "TERMINAL_TOOL_CALL_ID_REUSED", toolCallIdDigest: digestObject(toolCallId) },
      });
      return { block: true, reason: "ToolCall ID 已经进入终态，不能再次执行" };
    }
    this.options.checkpoint?.("tool_started");
    if (tool.risk !== "WRITE") return undefined;
    if (task.mode !== "REMEDIATE") {
      this.options.store.finishToolRun(toolCallId, "BLOCKED", undefined, "SCAN 模式禁止写操作");
      return { block: true, reason: "当前任务为 SCAN 模式，写操作被阻断" };
    }
    if (!this.options.config.remediation.allowedTools.includes(toolName as "quarantine_file" | "disable_account")) {
      return { block: true, reason: "写工具不在配置白名单" };
    }
    let approved = this.options.store.findApproval(task.taskId, toolName, this.options.approvals.getArgsDigest(args), this.options.protocolV2.epochId);
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
      this.options.store.appendMessage(this.options.task.taskId, message, this.options.protocolV2.epochId);
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
      const run = toolCallId
        ? this.options.store.getToolRunForScope(this.options.task.taskId, this.options.protocolV2.epochId, toolCallId)
        : undefined;
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
    const recordEpochId = record.epochId;
    if (!recordEpochId || recordEpochId !== this.options.protocolV2.epochId) throw new Error("ToolRun 未绑定当前 Epoch");
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
      recordEpochId,
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
            epochId: recordEpochId,
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
          epochId: recordEpochId,
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
          data: { epochId: recordEpochId, actionId, error: error instanceof Error ? error.message : String(error) },
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

  /**
   * 模型常在动作已经闭合后仍沿用调查中期的 INCONCLUSIVE，或者在文字里指出具体风险却没有
   * 写 SUBJECT Assessment。此时证据平面完整，但账本无法形成 CLOSED_* 终态。只给一次额外
   * 模型回合，让它通过正式的 Assessment 工具完成裁定；控制端不替模型猜测风险或改写结论。
   */
  private async reconcileTerminalAssessment(): Promise<void> {
    const validator = new InvestigationCompletionValidator(this.options.store);
    const before = validator.evaluate(this.options.task.taskId, this.options.protocolV2.epochId);
    if (!before.canClose || before.status !== "LIMITED" || before.limitedObligationIds.length > 0 || before.runningActionIds.length > 0) return;
    const task = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
    if (task.turnCount >= this.options.config.agent.maxTurns) return;
    this.options.store.appendAudit({
      taskId: task.taskId,
      event: "model_terminal_reconciliation_started",
      level: "info",
      data: { epochId: this.options.protocolV2.epochId, reasons: before.reasons },
    });
    await this.agent.prompt(`调查执行面已经闭合，但终态校验仍为 LIMITED：${before.reasons.join("；") || "模型 Assessment 尚未形成终态"}。

请执行一次最终证据裁定，不再扩大枚举范围：
1. 先用 get_assessment_projection 和 query_investigation 核对当前有效结论、已完成动作与缺口。
2. 若任何具体对象或事件仍构成可疑信号，必须用 record_assessment 写 SUBJECT 级 SUSPICIOUS/HIGHLY_SUSPICIOUS，并绑定该事实已有的 subjectRef；对应类别保持或裁定为 INCONCLUSIVE。不能只在文字中描述风险。
3. 若动作结果已排除中期疑点，Coverage 为 COMPLETE，且没有影响结论的真实采集缺口，则用 adjudicate_assessment 针对当前类别 Assessment 写 NO_OBSERVED_FINDING。不得仅因时间、缓存截断或没有逐页阅读全部已固化事实而判 INCONCLUSIVE。
4. 不得把真实 PARTIAL/ERROR/UNKNOWN、未满足义务或未决冲突改写为安全。完成必要的 Assessment Tool Call 后直接给出终态摘要。`);
    const after = validator.evaluate(this.options.task.taskId, this.options.protocolV2.epochId);
    this.options.store.appendAudit({
      taskId: task.taskId,
      event: "model_terminal_reconciliation_finished",
      level: after.status === "LIMITED" ? "warn" : "info",
      data: { epochId: this.options.protocolV2.epochId, beforeStatus: before.status, afterStatus: after.status, reasons: after.reasons },
    });
  }

  private completeInvestigation(reason: string): void {
    if (!this.options.store.getInvestigationSession(this.options.task.taskId, this.options.protocolV2.epochId)) return;
    const snapshot = new InvestigationCompletionValidator(this.options.store)
      .freezeWithLimits(this.options.task.taskId, this.options.protocolV2.epochId, reason);
    this.options.store.appendAudit({
      taskId: this.options.task.taskId,
      event: "investigation_completion_frozen",
      level: snapshot.investigationStatus === "LIMITED" ? "warn" : "info",
      data: { snapshotRef: snapshot.snapshotRef, investigationStatus: snapshot.investigationStatus, maxEventSeq: snapshot.maxEventSeq },
    });
  }

  /** Provider 的原始错误是首要失败轨迹；完成快照自身异常必须留审计，但不能覆盖它。 */
  private completeInvestigationAfterFailure(reason: string): void {
    try {
      this.completeInvestigation(reason);
    } catch (error) {
      this.options.store.appendAudit({
        taskId: this.options.task.taskId,
        event: "investigation_completion_after_provider_failure_failed",
        level: "error",
        data: { reason, error: error instanceof Error ? error.message : String(error) },
      });
    }
  }

  private cancelInvestigation(reason: string): void {
    if (!this.options.store.getInvestigationSession(this.options.task.taskId, this.options.protocolV2.epochId)) return;
    const snapshot = new InvestigationCompletionValidator(this.options.store)
      .freezeCancelled(this.options.task.taskId, this.options.protocolV2.epochId, reason);
    this.options.store.appendAudit({ taskId: this.options.task.taskId, event: "investigation_cancelled", level: "warn", data: { snapshotRef: snapshot.snapshotRef, maxEventSeq: snapshot.maxEventSeq } });
  }

  private appendRecoveredToolResult(record: ToolRunRecord, result: AgentToolResult<unknown>, isError: boolean): void {
    this.options.store.finishToolRun(record.toolCallId, isError ? "FAILED" : "SUCCEEDED", result, isError ? "recovery failed" : undefined);
    const message: ToolResultMessage = {
      role: "toolResult", toolCallId: record.toolCallId, toolName: record.toolName,
      content: result.content, details: result.details, isError, timestamp: Date.now(),
    };
    this.options.store.appendMessage(record.taskId, message, record.epochId);
    this.agent.state.messages = [...this.agent.state.messages, message];
  }
}
