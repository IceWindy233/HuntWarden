import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createModels } from "@earendil-works/pi-ai";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { ApprovalTicket, CheckCategory, SecurityToolDefinition, TaskContext, TaskMode } from "../../src/domain/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import type { ToolDependencies } from "../../src/tools/dependencies.js";
import { createSecurityTools } from "../../src/tools/index.js";
import { createReference } from "../../src/tools/reference-utils.js";
import { testConfig, testTask } from "../helpers.js";

/**
 * 崩溃恢复不变量。全部使用 FakeExecutor + RuntimeStore + ApprovalService，
 * 不依赖 Docker、Electron 或真实 SSH，因此可以进入必跑 CI。
 * 覆盖 tests/integration/agent-loop.test.ts:235,265 未触达的分支：
 * 真实写工具、远端回执 UNKNOWN、远端回执 STARTED 的撕裂窗口、以及重复恢复。
 */

const directories: string[] = [];
const stores: RuntimeStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function openStore(prefix: string): Promise<{ directory: string; store: RuntimeStore }> {
  const directory = await mkdtemp(join(tmpdir(), prefix));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  stores.push(store);
  return { directory, store };
}

function recoveryTask(mode: TaskMode, checks: CheckCategory[]): TaskContext {
  const task = testTask(mode);
  task.checks = checks;
  return task;
}

function buildDeps(input: {
  directory: string;
  store: RuntimeStore;
  task: TaskContext;
  executor: FakeExecutor;
  approvals: ApprovalService;
}): ToolDependencies {
  return {
    task: input.task,
    config: testConfig(input.directory),
    store: input.store,
    executor: input.executor,
    approvals: input.approvals,
    evidence: new EvidenceStore(input.directory, input.store),
  };
}

function requireTool(tools: SecurityToolDefinition[], name: string): SecurityToolDefinition {
  const tool = tools.find((item) => item.name === name);
  if (!tool) throw new Error(`测试期望注册工具 ${name}`);
  return tool;
}

/**
 * 恢复期间的重新审批必须延后一个微任务再决定：`request` 同步 emit `requested`，
 * 而 `waitForDecision` 在 `request` 返回之后才注册 `decided` 监听。
 * 在 emit 回调里同步 decide 会让通知早于监听注册，恢复流程将永远等不到决定。
 * 这里不涉及墙钟等待，微任务在 `waitForDecision` 注册监听后立即执行。
 */
function collectAndDenyApprovals(approvals: ApprovalService): ApprovalTicket[] {
  const requested: ApprovalTicket[] = [];
  approvals.on("requested", (ticket: ApprovalTicket) => {
    requested.push(ticket);
    queueMicrotask(() => approvals.decide(ticket.approvalId, false));
  });
  return requested;
}

function fauxRuntime(input: {
  task: TaskContext;
  deps: ToolDependencies;
  store: RuntimeStore;
  executor: FakeExecutor;
  approvals: ApprovalService;
  tools: SecurityToolDefinition[];
  replies: string[];
}): SecurityAgentRuntime {
  const faux = fauxProvider({ tokensPerSecond: 0 });
  const models = createModels();
  models.setProvider(faux.provider);
  faux.setResponses(input.replies.map((text) => fauxAssistantMessage(text)));
  return new SecurityAgentRuntime({
    task: input.task, config: input.deps.config, store: input.store, executor: input.executor,
    approvals: input.approvals, tools: input.tools, models, model: faux.getModel(), scanPlanner: false,
  });
}

const webStackOutput = { processes: [], configPaths: [], binaries: {}, partial: false, warnings: [] };

describe("崩溃恢复不变量", () => {
  it("SAFE 工具按原 toolCallId 恢复一次，重复恢复不再产生远端调用", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-safe-");
    const task = recoveryTask("SCAN", ["webshell"]);
    store.createTask(task);
    const executor = new FakeExecutor({ inventory_web_stacks: () => webStackOutput });
    const approvals = new ApprovalService(store);
    const deps = buildDeps({ directory, store, task, executor, approvals });
    const tools = createSecurityTools(deps);

    // 崩溃点：模型已发出 Tool Call，tool_run 落到 STARTED，远端调用尚未落地。
    const call = fauxToolCall("inventory_web_stacks", {}, { id: "call-recover-inventory" });
    store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
    store.startToolRun({
      toolCallId: call.id, taskId: task.taskId, toolName: call.name,
      risk: "READ", replayPolicy: "SAFE", args: {},
    });
    const runtime = fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["恢复后继续调查。", "无待恢复工具。"] });

    await runtime.recover();

    expect(executor.calls.filter((item) => item.operation === "inventory_web_stacks")).toHaveLength(1);
    expect(store.getToolRun(call.id)?.status).toBe("SUCCEEDED");
    expect(store.listIncompleteToolRuns(task.taskId)).toEqual([]);
    const results = store.loadMessages(task.taskId).filter((message) => message.role === "toolResult");
    expect(results.map((message) => message.role === "toolResult" && message.toolCallId)).toEqual([call.id]);
    const evidenceId = store.listEvidence(task.taskId)[0]?.evidenceId;
    expect(store.listEvidence(task.taskId)).toHaveLength(1);

    // 恢复过程中再次崩溃：第二次恢复没有未完成的 tool_run，不得再打一次远端。
    await runtime.recover();
    expect(executor.calls.filter((item) => item.operation === "inventory_web_stacks")).toHaveLength(1);
    expect(store.listEvidence(task.taskId).map((item) => item.evidenceId)).toEqual([evidenceId]);
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
  });

  it("NEVER 写工具恢复时先查远端回执，SUCCEEDED 则补记且不重放写入", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-succeeded-");
    const task = recoveryTask("REMEDIATE", ["backdoor_account"]);
    store.createTask(task);
    const accountRef = createReference(store, task.taskId, "account", "account", { username: "backdoor" }).ref;
    const args = { accountRef };
    const approvals = new ApprovalService(store);
    const ticket = approvals.request(task, "disable_account", args);
    approvals.decide(ticket.approvalId, true);
    approvals.consume(task, "disable_account", args);
    // 崩溃点：意图回执已落盘，远端动作已经执行，本地还没确认。
    store.putActionReceipt({
      actionId: ticket.actionId, taskId: task.taskId, tool: "disable_account",
      targetFingerprint: task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString(),
    });
    const executor = new FakeExecutor({
      get_action_receipt: () => ({ actionId: ticket.actionId, status: "SUCCEEDED", finishedAt: "2026-08-19T00:00:00.000Z", locked: true }),
      disable_account: () => { throw new Error("恢复不得重放写操作"); },
    });
    const deps = buildDeps({ directory, store, task, executor, approvals });
    const tools = createSecurityTools(deps);
    const call = fauxToolCall("disable_account", args, { id: "call-recover-disable" });
    store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
    store.startToolRun({
      toolCallId: call.id, taskId: task.taskId, toolName: call.name,
      risk: "WRITE", replayPolicy: "NEVER", args,
    });
    const reRequested = collectAndDenyApprovals(approvals);

    await fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["已按远端回执恢复。"] }).recover();

    expect(executor.calls.map((item) => item.operation)).toEqual(["get_action_receipt"]);
    expect(reRequested).toEqual([]);
    expect(store.getToolRun(call.id)?.status).toBe("SUCCEEDED");
    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("SUCCEEDED");
    // 回执按 actionId 覆盖写，恢复不得让同一动作被计成两次。
    expect(store.listActionReceipts(task.taskId)).toHaveLength(1);
    expect(store.listApprovals(task.taskId).map((item) => item.status)).toEqual(["CONSUMED"]);
    expect(store.listAudit(task.taskId).filter((item) => item.event === "write_tool_requested")).toHaveLength(1);
    expect(store.listAudit(task.taskId).filter((item) => item.event === "account_disabled")).toEqual([]);
  });

  it("NEVER 写工具远端回执 UNKNOWN 时不自动重放，必须重新审批", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-unknown-");
    const task = recoveryTask("REMEDIATE", ["webshell"]);
    store.createTask(task);
    const approvals = new ApprovalService(store);
    const executor = new FakeExecutor({
      get_action_receipt: () => ({ status: "UNKNOWN" }),
      quarantine_file: () => { throw new Error("恢复不得自动重放写操作"); },
    });
    const deps = buildDeps({ directory, store, task, executor, approvals });
    const evidenceId = deps.evidence.putStructured({
      taskId: task.taskId, host: task.target.host, type: "file",
      source: "/var/www/html/shell.php", tool: "collect_file", sha256: "a".repeat(64),
    }).evidenceId;
    const args = { evidenceRef: evidenceId };
    const ticket = approvals.request(task, "quarantine_file", args);
    approvals.decide(ticket.approvalId, true);
    approvals.consume(task, "quarantine_file", args);
    // 崩溃点：意图回执已落盘，远端只能回答「不知道写入是否发生」。
    store.putActionReceipt({
      actionId: ticket.actionId, taskId: task.taskId, tool: "quarantine_file",
      targetFingerprint: task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString(),
    });
    const tools = createSecurityTools(deps);
    const call = fauxToolCall("quarantine_file", args, { id: "call-recover-unknown" });
    store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
    store.startToolRun({
      toolCallId: call.id, taskId: task.taskId, toolName: call.name,
      risk: "WRITE", replayPolicy: "NEVER", args,
    });
    const reRequested = collectAndDenyApprovals(approvals);

    await fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["状态未知，等待人工确认。"] }).recover();

    expect(executor.calls.map((item) => item.operation)).toEqual(["get_action_receipt"]);
    expect(reRequested).toHaveLength(1);
    expect(reRequested[0]?.actionSummary).toContain("恢复确认");
    expect(reRequested[0]?.actionSummary).toContain(ticket.actionId);
    expect(reRequested[0]?.actionId).not.toBe(ticket.actionId);
    expect(store.getToolRun(call.id)?.status).toBe("FAILED");
    expect(store.listActionReceipts(task.taskId).map((item) => item.actionId)).toEqual([ticket.actionId]);
    expect(store.listAudit(task.taskId).filter((item) => item.event === "file_quarantined")).toEqual([]);
  });

  it("远端回执停在 STARTED 的撕裂窗口不自动重放，改为要求重新审批", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-torn-");
    const { task, ticket, executor, approvals, tools, deps, call } = await tornWindowFixture(directory, store);
    const reRequested = collectAndDenyApprovals(approvals);

    await fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["撕裂窗口未确认。"] }).recover();

    expect(executor.calls.map((item) => item.operation)).toEqual(["get_action_receipt"]);
    expect(reRequested).toHaveLength(1);
    expect(store.getToolRun(call.id)?.status).toBe("FAILED");
    expect(store.listAudit(task.taskId).filter((item) => item.event === "file_quarantined")).toEqual([]);
    expect(store.listActionReceipts(task.taskId).map((item) => item.actionId)).toEqual([ticket.actionId]);
  });

  /**
   * 已知缺陷（预期失败）：docs/TODO_PLAN_REAL_WORLD.md 9.0 第二条记录的撕裂窗口。
   * `quarantine_file` 在 src/tools/remediation/tools.ts:28-29 先落盘 STARTED 回执再执行远端写；
   * 崩溃后 src/runtime/security-agent-runtime.ts:304 只处理 SUCCEEDED / FAILED，
   * 远端回执仍是 STARTED 时既不更新本地回执也不标记不确定，本地回执永远停在 STARTED，
   * 与「动作从未开始」无法区分。domain 层已有 ActionReceiptStatus="UNKNOWN" 表达这一状态。
   */
  it("远端回执停在 STARTED 时本地 Action Receipt 必须标记为 UNKNOWN 供人工确认", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-torn-receipt-");
    const { task, ticket, executor, approvals, tools, deps } = await tornWindowFixture(directory, store);
    collectAndDenyApprovals(approvals);

    await fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["撕裂窗口未确认。"] }).recover();

    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("UNKNOWN");
  });

  /**
   * 已知缺陷（预期失败）：同一撕裂窗口的第二个后果。
   * src/runtime/security-agent-runtime.ts:158-161 在恢复结束时无条件把任务置为 COMPLETED
   * 并清掉 interruption.recoveryRequired，即使分析师刚刚拒绝了重新执行、目标端是否已被写入仍然未知。
   * 结果是「需要人工确认」这一唯一信号被恢复流程自己抹掉。
   */
  it("撕裂窗口未确认时任务不得被置为 COMPLETED，recoveryRequired 不得清零", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-torn-task-");
    const { task, executor, approvals, tools, deps } = await tornWindowFixture(directory, store);
    collectAndDenyApprovals(approvals);

    await fauxRuntime({ task, deps, store, executor, approvals, tools, replies: ["撕裂窗口未确认。"] }).recover();

    expect(store.getTask(task.taskId)?.interruption?.recoveryRequired).toBe(true);
    expect(store.getTask(task.taskId)?.status).not.toBe("COMPLETED");
  });

  it("恢复后 Finding 与 Evidence 不重复写入", async () => {
    const { directory, store } = await openStore("huntwarden-recovery-dedupe-");
    const task = recoveryTask("SCAN", ["webshell"]);
    store.createTask(task);
    const executor = new FakeExecutor({ inventory_web_stacks: () => webStackOutput });
    const approvals = new ApprovalService(store);
    const deps = buildDeps({ directory, store, task, executor, approvals });
    const tools = createSecurityTools(deps);

    // 崩溃前两个工具都已经产生领域记录。
    await requireTool(tools, "inventory_web_stacks").execute("call-crash-inventory", {}, undefined);
    const evidenceId = store.listEvidence(task.taskId)[0]?.evidenceId;
    const findingArgs = {
      category: "webshell", severity: "HIGH", confidence: 0.9, status: "SUSPICIOUS",
      title: "崩溃前已固化的结论", summary: "恢复重放不得重复写入。", evidenceRefs: [evidenceId],
    };
    await requireTool(tools, "record_finding").execute("call-crash-finding", findingArgs, undefined);
    const findingId = store.listFindings(task.taskId)[0]?.findingId;
    expect(store.listFindings(task.taskId)).toHaveLength(1);

    // 崩溃点：副作用已落盘，tool_run 的收尾未提交。
    for (const toolCallId of ["call-crash-inventory", "call-crash-finding"]) {
      store.finishToolRun(toolCallId, "STARTED");
    }
    store.appendMessage(task.taskId, fauxAssistantMessage(
      fauxToolCall("record_finding", findingArgs, { id: "call-crash-finding" }), { stopReason: "toolUse" },
    ));
    expect(store.listIncompleteToolRuns(task.taskId)).toHaveLength(2);
    expect(store.getTask(task.taskId)?.coverage.webshell).toBe("SUSPICIOUS");

    // 进程重启：与 src/runtime/application.ts:120 一致，任务上下文从 SQLite 重新加载。
    const restored = store.getTask(task.taskId);
    if (!restored) throw new Error("测试期望重启后仍能读回任务");
    const restoredDeps = buildDeps({ directory, store, task: restored, executor, approvals });
    await fauxRuntime({
      task: restored, deps: restoredDeps, store, executor, approvals,
      tools: createSecurityTools(restoredDeps), replies: ["恢复完成。"],
    }).recover();

    expect(store.listFindings(task.taskId).map((item) => item.findingId)).toEqual([findingId]);
    expect(store.listEvidence(task.taskId).map((item) => item.evidenceId)).toEqual([evidenceId]);
    expect(store.getTask(task.taskId)?.coverage.webshell).toBe("SUSPICIOUS");
    expect(store.listIncompleteToolRuns(task.taskId)).toEqual([]);
    expect(store.listToolRuns(task.taskId).map((item) => item.toolCallId).sort())
      .toEqual(["call-crash-finding", "call-crash-inventory"]);
  });
});

/** 崩溃发生在 `quarantine_file` 远端写入途中：本地与远端回执都停在 STARTED。 */
async function tornWindowFixture(directory: string, store: RuntimeStore): Promise<{
  task: TaskContext;
  ticket: ApprovalTicket;
  executor: FakeExecutor;
  approvals: ApprovalService;
  tools: SecurityToolDefinition[];
  deps: ToolDependencies;
  call: { id: string; name: string };
}> {
  const seed = recoveryTask("REMEDIATE", ["webshell"]);
  store.createTask(seed);
  const approvals = new ApprovalService(store);
  const seedDeps = buildDeps({ directory, store, task: seed, executor: new FakeExecutor(), approvals });
  const evidenceId = seedDeps.evidence.putStructured({
    taskId: seed.taskId, host: seed.target.host, type: "file",
    source: "/var/www/html/shell.php", tool: "collect_file", sha256: "a".repeat(64),
  }).evidenceId;
  const args = { evidenceRef: evidenceId };
  const ticket = approvals.request(seed, "quarantine_file", args);
  approvals.decide(ticket.approvalId, true);
  approvals.consume(seed, "quarantine_file", args);
  store.putActionReceipt({
    actionId: ticket.actionId, taskId: seed.taskId, tool: "quarantine_file",
    targetFingerprint: seed.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString(),
  });
  const call = fauxToolCall("quarantine_file", args, { id: "call-recover-torn" });
  store.appendMessage(seed.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
  store.startToolRun({
    toolCallId: call.id, taskId: seed.taskId, toolName: call.name,
    risk: "WRITE", replayPolicy: "NEVER", args,
  });
  const interrupted = store.reconcileInterruptedTasks()[0];
  if (!interrupted) throw new Error("测试期望进程重启对账识别出被中断的任务");
  const executor = new FakeExecutor({
    get_action_receipt: () => ({ actionId: ticket.actionId, status: "STARTED" }),
    quarantine_file: () => { throw new Error("撕裂窗口不得自动重放写操作"); },
  });
  const deps = buildDeps({ directory, store, task: interrupted, executor, approvals });
  return { task: interrupted, ticket, executor, approvals, tools: createSecurityTools(deps), deps, call };
}
