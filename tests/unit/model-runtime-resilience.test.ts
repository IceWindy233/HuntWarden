import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createModels, type Context, type ToolResultMessage } from "@earendil-works/pi-ai";
import { fauxAssistantMessage, fauxProvider } from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { digestObject } from "../../src/common/json.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import type { InvestigationSession } from "../../src/investigation/types.js";
import type { HelperCapabilitiesV2, ScanEpoch } from "../../src/protocol-v2/types.js";
import { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { selectModelVisibleTools } from "../../src/runtime/security-agent-runtime.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import type { SecurityToolDefinition } from "../../src/domain/types.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
const stores: RuntimeStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

const capabilities: HelperCapabilitiesV2 = {
  protocolVersion: 2,
  manifestVersion: "3.0.0",
  helper: { name: "helper", version: "3.0.0" },
  namespaces: {},
  matchers: [],
  probes: [],
  verbs: [],
  limits: { maxObjects: 100, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
};

async function fixture(withObligation = true) {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-model-runtime-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  stores.push(store);
  const task = testTask();
  task.protocolVersion = 2;
  task.activeEpochId = "EPOCH-00000000-0000-4000-8000-000000000091";
  store.createTask(task);
  const now = new Date().toISOString();
  const epoch: ScanEpoch = {
    epochId: task.activeEpochId,
    taskId: task.taskId,
    targetFingerprint: task.target.hostFingerprint,
    protocolVersion: 2,
    manifestVersion: "3.0.0",
    helperVersion: "3.0.0",
    reason: "INITIAL",
    status: "RUNNING",
    startedAt: now,
  };
  store.createScanEpoch(epoch);
  const session: InvestigationSession = {
    sessionId: "ISESS-00000000-0000-4000-8000-000000000091",
    taskId: task.taskId,
    epochId: epoch.epochId,
    engineVersion: "1.0.0",
    playbookRegistryDigest: "a".repeat(64),
    ruleRegistryDigest: "b".repeat(64),
    authorizationVersion: "AUTH-1",
    executionStatus: "RUNNING",
    investigationStatus: "OPEN",
    revision: 0,
    createdAt: now,
    updatedAt: now,
  };
  store.createInvestigationSession(session);
  if (withObligation) store.putInvestigationObligation({
    obligationId: "OBL-00000000-0000-4000-8000-000000000091",
    taskId: task.taskId,
    epochId: epoch.epochId,
    obligationKind: "MODEL_REVIEW",
    dedupeKey: "MODEL_REVIEW:backdoor_account",
    subjectRefs: [],
    required: true,
    status: "OPEN",
    resultRefs: [],
    gapRefs: [],
    createdAt: now,
    updatedAt: now,
  });
  const config = testConfig(directory);
  config.agent.providerMaxRetries = 4;
  config.agent.providerTimeoutSeconds = 17;
  const models = createModels();
  const faux = fauxProvider({ tokensPerSecond: 0 });
  models.setProvider(faux.provider);
  const runtime = new SecurityAgentRuntime({
    task,
    config,
    store,
    executor: new FakeProtocolV2Executor(capabilities, () => { throw new Error("模型降级测试不得调用远端原语"); }),
    approvals: new ApprovalService(store),
    tools: [],
    models,
    model: faux.getModel(),
    protocolV2: { epochId: epoch.epochId },
  });
  return { store, task, epoch, config, faux, runtime };
}

describe("模型运行时故障降级", () => {
  it("模型只能通过持久化提案调度八个远端原语", () => {
    const names = [
      "enumerate", "project", "read", "match", "relate", "verify", "collect", "probe",
      "query_facts", "propose_hypothesis", "propose_actions", "record_assessment",
    ];
    const tools = names.map((name) => ({ name })) as SecurityToolDefinition[];
    expect(selectModelVisibleTools(tools).map((tool) => tool.name)).toEqual([
      "query_facts", "propose_hypothesis", "propose_actions", "record_assessment",
    ]);
  });

  it("空 assistant 保留原响应并按 Provider failure 固化调查缺口", async () => {
    const { store, task, epoch, faux, runtime } = await fixture();
    faux.setResponses([fauxAssistantMessage([])]);

    await expect(runtime.prompt("审查当前调查")).rejects.toThrow(/空 assistant/);

    expect(store.getTask(task.taskId)?.status).toBe("FAILED");
    expect(store.loadMessages(task.taskId).some((message) => message.role === "assistant" && message.content.length === 0)).toBe(true);
    expect(store.listAudit(task.taskId).some((event) => event.event === "model_empty_response")).toBe(true);
    expect(store.listInvestigationGaps(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "MODEL_DID_NOT_INVESTIGATE", reasonCode: "PROVIDER_FAILURE" }),
    ]));
    expect(store.getInvestigationSession(task.taskId, epoch.epochId)?.investigationStatus).toBe("LIMITED");
  });

  it("完成快照自身异常不会覆盖 Provider 的首要失败", async () => {
    const { store, task, faux, runtime } = await fixture(false);
    faux.setResponses([fauxAssistantMessage([])]);

    await expect(runtime.prompt("审查当前调查")).rejects.toThrow(/空 assistant/);

    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "investigation_completion_after_provider_failure_failed" }),
    ]));
  });

  it("把有界重试与流式硬超时传给 Provider", async () => {
    const { store, task, faux, runtime } = await fixture();
    let observed: { maxRetries: number | undefined; timeoutMs: number | undefined } | undefined;
    faux.setResponses([(_context, options) => {
      observed = { maxRetries: options?.maxRetries, timeoutMs: options?.timeoutMs };
      return fauxAssistantMessage("已完成模型审查。");
    }]);

    await runtime.prompt("审查当前调查");

    expect(observed).toEqual({ maxRetries: 4, timeoutMs: 17_000 });
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
  });

  it("按模型窗口公平压缩同一回合的批量工具结果并移除本地 details", async () => {
    const { store, task, faux, runtime } = await fixture();
    let observed: Context | undefined;
    faux.setResponses([((context) => {
      observed = context;
      return fauxAssistantMessage("已完成模型审查。");
    })]);
    const timestamp = Date.now();
    const results: ToolResultMessage[] = Array.from({ length: 13 }, (_, index) => {
      const details = {
        status: "success",
        summary: { offset: 0, returned: 120, total: 120 },
        items: Array.from({ length: 120 }, (_item, itemIndex) => ({ index: itemIndex, value: `${index}:${"x".repeat(1024)}` })),
        warnings: [],
      };
      return {
        role: "toolResult",
        toolCallId: `call-${index}`,
        toolName: "query_facts",
        content: [{ type: "text", text: JSON.stringify(details) }],
        details,
        isError: false,
        timestamp,
      };
    });
    runtime.agent.state.messages = results;

    await runtime.prompt("继续调查");

    const sentResults = observed?.messages.filter((message): message is ToolResultMessage => message.role === "toolResult") ?? [];
    expect(sentResults).toHaveLength(13);
    const sentBytes = sentResults.reduce((sum, message) => sum + Buffer.byteLength(message.content[0]?.type === "text" ? message.content[0].text : "", "utf8"), 0);
    expect(sentBytes).toBeLessThanOrEqual(95_616);
    expect(sentResults.every((message) => message.details === undefined)).toBe(true);
    expect(sentResults.every((message) => JSON.parse(message.content[0]?.type === "text" ? message.content[0].text : "null").status === "partial")).toBe(true);
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({
        event: "model_context_compacted",
        data: expect.objectContaining({ batchResizedResults: 13, toolBudgetBytes: 95_616 }),
      }),
      expect.objectContaining({ event: "model_provider_context" }),
    ]));
  });

  it("执行面已闭合时依次协调缺失里程碑与非终态 Assessment", async () => {
    const { store, task, epoch, faux, runtime } = await fixture();
    const obligation = store.listInvestigationObligations(task.taskId, epoch.epochId)[0]!;
    store.updateInvestigationObligation({
      ...obligation,
      status: "SATISFIED",
      updatedAt: new Date().toISOString(),
    }, "OPEN");
    let providerCalls = 0;
    faux.setResponses([
      () => { providerCalls += 1; return fauxAssistantMessage("调查正文已完成。"); },
      () => { providerCalls += 1; return fauxAssistantMessage("已复核模型调查里程碑。"); },
      () => { providerCalls += 1; return fauxAssistantMessage("已完成终态证据裁定。"); },
    ]);

    await runtime.prompt("审查当前调查");

    expect(providerCalls).toBe(3);
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({
        event: "model_milestone_reconciliation_started",
        data: expect.objectContaining({
          missing: expect.objectContaining({ hypothesis: true, action: true, assessmentCategories: task.checks }),
        }),
      }),
      expect.objectContaining({
        event: "model_milestone_reconciliation_finished",
        level: "warn",
        data: expect.objectContaining({ complete: false }),
      }),
      expect.objectContaining({ event: "model_terminal_reconciliation_started" }),
      expect.objectContaining({
        event: "model_terminal_reconciliation_finished",
        data: expect.objectContaining({ beforeStatus: "LIMITED", afterStatus: "LIMITED" }),
      }),
    ]));
  });

  it("第 5 轮调查仍缺里程碑时只追加一次控制端提醒", async () => {
    const { store, task, faux, runtime } = await fixture();
    const current = store.getTask(task.taskId)!;
    current.turnCount = 4;
    store.saveTask(current);
    let providerCalls = 0;
    let secondContext: Context | undefined;
    faux.setResponses([
      () => { providerCalls += 1; return fauxAssistantMessage("继续分页读取事实。"); },
      (context) => { providerCalls += 1; secondContext = context; return fauxAssistantMessage("已按控制端要求检查里程碑。"); },
    ]);

    await runtime.prompt("继续调查");

    expect(providerCalls).toBe(2);
    expect(secondContext?.messages).toEqual(expect.arrayContaining([
      expect.objectContaining({ role: "user", content: expect.stringContaining("控制端第 5 轮里程碑检查") }),
    ]));
    expect(store.listAudit(task.taskId).filter((event) => event.event === "model_milestone_nudge_queued")).toEqual([
      expect.objectContaining({ data: expect.objectContaining({ turnCount: 5 }) }),
    ]);
    expect(store.listPendingInputs(task.taskId)).toHaveLength(0);
  });

  it("暂停后继续仍执行里程碑与终态协调", async () => {
    const { store, task, epoch, faux, runtime } = await fixture();
    const obligation = store.listInvestigationObligations(task.taskId, epoch.epochId)[0]!;
    store.updateInvestigationObligation({ ...obligation, status: "SATISFIED", updatedAt: new Date().toISOString() }, "OPEN");
    const session = store.getInvestigationSession(task.taskId, epoch.epochId)!;
    store.updateInvestigationSession({ ...session, executionStatus: "PAUSED", revision: 1, updatedAt: new Date().toISOString() }, 0);
    const current = store.getTask(task.taskId)!;
    current.status = "PAUSED";
    store.saveTask(current);
    runtime.agent.state.messages = [{ role: "user", content: "从暂停点继续", timestamp: Date.now() }];
    let providerCalls = 0;
    faux.setResponses([
      () => { providerCalls += 1; return fauxAssistantMessage("已继续调查。"); },
      () => { providerCalls += 1; return fauxAssistantMessage("已协调里程碑。"); },
      () => { providerCalls += 1; return fauxAssistantMessage("已协调终态。"); },
    ]);

    await runtime.resume();

    expect(providerCalls).toBe(3);
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "model_milestone_reconciliation_started" }),
      expect.objectContaining({ event: "model_terminal_reconciliation_started" }),
    ]));
  });

  it("执行面闭合后在主循环中主动要求终态裁定", async () => {
    const { store, task, epoch, config, faux, runtime } = await fixture();
    task.checks = ["backdoor_account"];
    task.turnCount = 5;
    store.saveTask(task);
    config.agent.maxTurns = 7;
    const now = new Date().toISOString();
    const fact = store.commitFactBatch({
      taskId: task.taskId,
      epochId: epoch.epochId,
      sourceRunId: "MODEL-TERMINAL-FACT",
      source: { kind: "SYSTEM" },
      targetFingerprint: task.target.hostFingerprint,
      requestId: "MODEL-TERMINAL-FACT",
      collector: { name: "enumerate", version: "2.0.0" },
      observations: [{
        namespace: "process",
        identity: { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "d".repeat(64) },
        fields: { bootId: "boot", pid: 42, startTicks: "10", exeInode: "20", exeSha256: "d".repeat(64) },
        observedAt: now,
        consistency: "OBJECT_STABLE",
      }],
      edges: [],
      gaps: [],
      wireDigest: "c".repeat(64),
    }).facts[0]!;
    store.putInvestigationHypothesis({
      hypothesisId: "HYP-MODEL-TERMINAL", taskId: task.taskId, epochId: epoch.epochId, subjectRef: fact.subjectRef,
      claim: "测试终态提醒", proposedBy: "MODEL", supportRefs: [fact.factId], counterEvidenceRefs: [],
      alternativeExplanations: ["良性进程"], status: "SUPPORTED", revision: 0, createdAt: now, updatedAt: now,
    });
    const obligation = store.listInvestigationObligations(task.taskId, epoch.epochId)[0]!;
    store.updateInvestigationObligation({ ...obligation, status: "SATISFIED", updatedAt: now }, "OPEN");
    const actionArgs = { ref: fact.subjectRef, fields: ["pid"] };
    store.putInvestigationAction({
      actionId: "ACTION-MODEL-TERMINAL", taskId: task.taskId, epochId: epoch.epochId, kind: "LOCAL_QUERY", requestedBy: "MODEL",
      obligationIds: [obligation.obligationId], subjectRefs: [fact.subjectRef], entityVersionRefs: [], operationRef: "query_facts",
      replayPolicy: "SAFE_REOBSERVE", args: actionArgs, argsDigest: digestObject(actionArgs), dependsOn: [], authorizationVersion: "AUTH-1",
      observationRound: "ROUND-1", idempotencyKey: `${task.taskId}:${epoch.epochId}:terminal-test`, priority: 10,
      status: "SUCCEEDED", revision: 0, createdAt: now, updatedAt: now,
    });
    store.putAssessment({
      assessmentId: "ASM-MODEL-TERMINAL", taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL",
      category: "backdoor_account", scope: "OBSERVED_CATEGORY", verdict: "INCONCLUSIVE", severity: "INFO", confidence: 0.7,
      rationale: "等待终态裁定", evidenceRefs: [], factRefs: [fact.factId], queryRefs: [], createdAt: now,
    });
    let providerCalls = 0;
    let secondContext: Context | undefined;
    faux.setResponses([
      () => { providerCalls += 1; return fauxAssistantMessage("继续查询。"); },
      (context) => { providerCalls += 1; secondContext = context; return fauxAssistantMessage("执行终态裁定。"); },
    ]);

    await runtime.prompt("继续调查");

    expect(providerCalls).toBe(2);
    expect(secondContext?.messages).toEqual(expect.arrayContaining([
      expect.objectContaining({ role: "user", content: expect.stringContaining("控制端终态检查") }),
    ]));
    expect(store.listAudit(task.taskId).filter((event) => event.event === "model_terminal_nudge_queued")).toHaveLength(1);
    expect(store.listPendingInputs(task.taskId)).toHaveLength(0);
  });

  it("把带部分文本的非完整 aborted 流按 Provider failure 固化而不误报完成", async () => {
    const { store, task, epoch, faux, runtime } = await fixture();
    faux.setResponses([{ ...fauxAssistantMessage("partial before stall"), stopReason: "aborted" }]);

    await expect(runtime.prompt("审查当前调查")).rejects.toThrow(/Provider 流在完成前中止/);

    expect(store.getTask(task.taskId)?.status).toBe("FAILED");
    expect(store.listInvestigationGaps(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "MODEL_DID_NOT_INVESTIGATE", reasonCode: "PROVIDER_FAILURE" }),
    ]));
    expect(store.getInvestigationSession(task.taskId, epoch.epochId)?.investigationStatus).toBe("LIMITED");
  });

  it("HTTP 200 后的 terminated 流中断仅续接一次并保留失败消息", async () => {
    const { store, task, faux, runtime } = await fixture();
    let providerCalls = 0;
    faux.setResponses([
      () => {
        providerCalls += 1;
        return { ...fauxAssistantMessage("中断前的部分正文"), stopReason: "error", errorMessage: "terminated" };
      },
      () => {
        providerCalls += 1;
        return fauxAssistantMessage("续接后完成调查。");
      },
    ]);

    await runtime.prompt("审查当前调查");

    expect(providerCalls).toBe(2);
    expect(store.loadMessages(task.taskId).filter((message) => message.role === "assistant")).toEqual(expect.arrayContaining([
      expect.objectContaining({ stopReason: "error", errorMessage: "terminated" }),
      expect.objectContaining({ stopReason: "stop" }),
    ]));
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "model_provider_stream_retry_started", level: "warn" }),
      expect.objectContaining({ event: "model_provider_stream_retry_finished", level: "info", data: expect.objectContaining({ stopReason: "stop" }) }),
    ]));
  });
});
