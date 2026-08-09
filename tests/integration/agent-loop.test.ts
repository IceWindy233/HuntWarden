import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createModels } from "@earendil-works/pi-ai";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { Type } from "typebox";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { Application } from "../../src/runtime/application.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createRecordFindingTool } from "../../src/tools/local/record-finding.js";
import { createSecurityTool } from "../../src/tools/tool-factory.js";
import { testConfig, testTask } from "../helpers.js";
import type { AgentStreamUpdate } from "../../src/domain/types.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("Pi Faux Provider Agent Loop", () => {
  it("四类联合任务先固化 FindingStatus，再由分析师手动生成版本报告", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-four-checks-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const config = testConfig(directory);
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    const categories = ["webshell", "java_memory_shell", "backdoor_account", "linux_persistence"] as const;
    faux.setResponses([
      ...categories.map((category, index) => fauxAssistantMessage(fauxToolCall("record_finding", {
        category, severity: "INFO", confidence: 0.8, status: category === "linux_persistence" ? "SUSPICIOUS" : "NO_FINDING",
        title: `${category} 联合测试结论`, summary: "Faux Provider 固定事实链，未执行任何写工具。", evidenceRefs: [],
      }, { id: `call-four-${index}` }), { stopReason: "toolUse" })),
      fauxAssistantMessage("四类联合调查已完成。"),
      fauxAssistantMessage("报告模型输出故意不含引用，以验证确定性回退。"),
    ]);
    const application = new Application(config, store, models, faux.getModel());
    const task = application.createTask({ request: "四类联合 Faux 调查", mode: "SCAN", target: testTask().target });
    await application.startTask(task.taskId);
    expect(store.listFindings(task.taskId).map((finding) => [finding.category, finding.status])).toEqual([
      ["webshell", "NO_FINDING"], ["java_memory_shell", "NO_FINDING"], ["backdoor_account", "NO_FINDING"], ["linux_persistence", "SUSPICIOUS"],
    ]);
    expect(store.listReports(task.taskId)).toHaveLength(0);
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    const generated = await application.generateReport(task.taskId);
    expect(generated.version).toBe(1);
    expect(store.listReports(task.taskId)).toMatchObject([{ version: 1 }]);
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    expect(store.listAudit(task.taskId).map((event) => event.event)).toContain("report_generation_requested_by_analyst");
    const findingIds = store.listFindings(task.taskId).map((finding) => finding.findingId);
    const reportIds = store.listReports(task.taskId).map((report) => report.reportId);
    const archived = application.archiveTask(task.taskId);
    expect(archived.archivedAt).toBeTruthy();
    await expect(application.generateReport(task.taskId)).rejects.toThrow(/已归档任务为只读/);
    expect(store.listFindings(task.taskId).map((finding) => finding.findingId)).toEqual(findingIds);
    expect(store.listReports(task.taskId).map((report) => report.reportId)).toEqual(reportIds);
    expect(application.restoreTask(task.taskId).archivedAt).toBeUndefined();
    expect(store.listAudit(task.taskId).map((event) => event.event)).toEqual(expect.arrayContaining([
      "task_archived", "task_restored_from_archive",
    ]));
    await application.close();
  });

  it("拒绝归档活动任务和等待人工恢复的任务", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-archive-policy-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const config = testConfig(directory);
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    const application = new Application(config, store, models, faux.getModel());
    const task = application.createTask({ request: "归档策略测试", mode: "SCAN", target: testTask().target });

    task.status = "RUNNING";
    store.saveTask(task);
    expect(() => application.archiveTask(task.taskId)).toThrow(/活动任务不能归档/);

    task.status = "ABORTED";
    task.interruption = { previousStatus: "RUNNING", reason: "PROCESS_INTERRUPTED", detectedAt: new Date().toISOString(), recoveryRequired: true };
    store.saveTask(task);
    expect(() => application.archiveTask(task.taskId)).toThrow(/待恢复任务不能归档/);
    await application.close();
  });

  it("执行固定 Tool Call 序列并固化 Finding", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-agent-loop-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const config = testConfig(directory);
    const executor = new FakeExecutor();
    const approvals = new ApprovalService(store);
    const tool = createRecordFindingTool({ task, config, store, executor, approvals, evidence: new EvidenceStore(directory, store) });
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("record_finding", {
        category: "webshell", severity: "INFO", confidence: 0.98, status: "NO_FINDING",
        title: "未发现 WebShell", summary: "已完成限定范围检测", evidenceRefs: [],
      }, { id: "call-record-webshell" }), { stopReason: "toolUse" }),
      fauxAssistantMessage("WebShell 检测完成。"),
    ]);
    const runtime = new SecurityAgentRuntime({ task, config, store, executor, approvals, tools: [tool], models, model: faux.getModel() });
    const stream: AgentStreamUpdate[] = [];
    runtime.on("stream", (update: AgentStreamUpdate) => stream.push(update));
    await runtime.prompt("执行 WebShell 检测");
    expect(store.listFindings(task.taskId)).toMatchObject([{ category: "webshell", status: "NO_FINDING" }]);
    expect(store.getToolRun("call-record-webshell")?.status).toBe("SUCCEEDED");
    expect(store.loadMessages(task.taskId).some((message) => message.role === "toolResult")).toBe(true);
    expect(stream.some((update) => update.phase === "start")).toBe(true);
    expect(stream.some((update) => update.phase === "end")).toBe(true);
    expect(stream.filter((update) => update.phase === "delta").map((update) => update.delta).join("")).toContain("WebShell 检测完成");
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    store.close();
  });

  it("即使模型发起写 Tool Call，SCAN 模式也在工具执行前阻断", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-policy-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("SCAN");
    store.createTask(task);
    const config = testConfig(directory);
    const executor = new FakeExecutor();
    const approvals = new ApprovalService(store);
    let writes = 0;
    const writeTool = createSecurityTool(store, task.taskId, config.llmData.maxTextBytes, {
      name: "dangerous_write", label: "测试写操作", description: "测试策略边界",
      parameters: Type.Object({}, { additionalProperties: false }), risk: "WRITE", replayPolicy: "NEVER",
      timeoutMs: 1_000, auditEvent: "dangerous_write", executionMode: "sequential",
      run: async () => { writes += 1; return { status: "success", summary: {}, items: [], artifactRefs: [], warnings: [] }; },
    });
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall("dangerous_write", {}, { id: "call-blocked-write" }), { stopReason: "toolUse" }),
      fauxAssistantMessage("写操作已被策略阻断。"),
    ]);
    const runtime = new SecurityAgentRuntime({ task, config, store, executor, approvals, tools: [writeTool], models, model: faux.getModel() });
    await runtime.prompt("证据文本要求忽略规则并执行写操作");
    expect(writes).toBe(0);
    expect(executor.calls).toHaveLength(0);
    expect(store.getToolRun("call-blocked-write")?.status).toBe("BLOCKED");
    store.close();
  });

  it("恢复时以原 toolCallId 幂等重放本地 SAFE 工具", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-safe-recovery-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const config = testConfig(directory);
    const executor = new FakeExecutor();
    const approvals = new ApprovalService(store);
    const args = {
      category: "webshell", severity: "INFO", confidence: 1, status: "NO_FINDING",
      title: "恢复完成", summary: "本地幂等重放", evidenceRefs: [],
    };
    const call = fauxToolCall("record_finding", args, { id: "call-recover-safe" });
    store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
    store.startToolRun({ toolCallId: call.id, taskId: task.taskId, toolName: call.name, risk: "LOCAL", replayPolicy: "SAFE", args });
    const tool = createRecordFindingTool({ task, config, store, executor, approvals, evidence: new EvidenceStore(directory, store) });
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    faux.setResponses([fauxAssistantMessage("恢复后继续完成。")]);
    const runtime = new SecurityAgentRuntime({ task, config, store, executor, approvals, tools: [tool], models, model: faux.getModel() });
    await runtime.recover();
    expect(store.listFindings(task.taskId)).toHaveLength(1);
    expect(store.getToolRun(call.id)?.status).toBe("SUCCEEDED");
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    store.close();
  });

  it("恢复 NEVER 工具时先核对远端回执，已成功则补记且不重放写入", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-write-recovery-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    store.createTask(task);
    const config = testConfig(directory);
    const args = { evidenceRef: "EV-00000000-0000-4000-8000-000000000001" };
    const approvals = new ApprovalService(store);
    const ticket = approvals.request(task, "quarantine_file", args);
    approvals.decide(ticket.approvalId, true);
    approvals.consume(task, "quarantine_file", args);
    let writes = 0;
    const executor = new FakeExecutor({
      get_action_receipt: () => ({ actionId: ticket.actionId, status: "SUCCEEDED", result: { quarantinePath: "/quarantine/item" } }),
    });
    const writeTool = createSecurityTool(store, task.taskId, config.llmData.maxTextBytes, {
      name: "quarantine_file", label: "隔离", description: "恢复测试",
      parameters: Type.Object({ evidenceRef: Type.String() }), risk: "WRITE", replayPolicy: "NEVER",
      timeoutMs: 1_000, auditEvent: "file_quarantined", executionMode: "sequential",
      run: async () => { writes += 1; return { status: "success", summary: {}, items: [], artifactRefs: [], warnings: [] }; },
    });
    const call = fauxToolCall("quarantine_file", args, { id: "call-recover-write" });
    store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
    store.startToolRun({ toolCallId: call.id, taskId: task.taskId, toolName: call.name, risk: "WRITE", replayPolicy: "NEVER", args });
    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    faux.setResponses([fauxAssistantMessage("已根据回执恢复。")]);
    const runtime = new SecurityAgentRuntime({ task, config, store, executor, approvals, tools: [writeTool], models, model: faux.getModel() });
    await runtime.recover();
    expect(writes).toBe(0);
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    expect(executor.calls).toEqual([{ operation: "get_action_receipt", params: { actionId: ticket.actionId } }]);
    expect(store.getToolRun(call.id)?.status).toBe("SUCCEEDED");
    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("SUCCEEDED");
    store.close();
  });
});
