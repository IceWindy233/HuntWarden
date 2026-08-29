import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createModels } from "@earendil-works/pi-ai";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { ApprovalTicket } from "../../src/domain/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { gateCapabilities } from "../../src/protocol-v2/capability.js";
import type { HelperCapabilitiesV2, ScanEpoch, TaskGrant } from "../../src/protocol-v2/types.js";
import { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createV2SecurityTools } from "../../src/tools/v2/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
const stores: RuntimeStore[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

const helper: HelperCapabilitiesV2 = {
  protocolVersion: 2, manifestVersion: "2.0.0", helper: { name: "helper", version: "2.0.0" },
  namespaces: { account: { fields: ["uid", "username", "gid", "home", "shell", "locked"], relations: [], verbs: ["enumerate"] } },
  matchers: [], probes: [], verbs: ["enumerate"],
  limits: { maxObjects: 100, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
};

async function fixture(remoteStatus: "SUCCEEDED" | "STARTED" | "UNKNOWN") {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-recovery-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  stores.push(store);
  const task = testTask("REMEDIATE");
  task.protocolVersion = 2;
  task.checks = ["backdoor_account"];
  task.activeEpochId = "EPOCH-00000000-0000-4000-8000-000000000031";
  store.createTask(task);
  const epoch: ScanEpoch = { epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "2.0.0", helperVersion: "2.0.0", reason: "RECOVERY_REOBSERVE", status: "RUNNING", startedAt: new Date().toISOString() };
  store.createScanEpoch(epoch);
  const grant: TaskGrant = { grantId: "GRANT-RECOVERY", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "backdoor_account" }, createdAt: new Date().toISOString() };
  store.putTaskGrant(grant);
  const fact = store.commitFactBatch({
    taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "ACCOUNT-RECOVERY", source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
    requestId: "ACCOUNT-RECOVERY", collector: { name: "enumerate", version: "2.0.0" },
    observations: [{ namespace: "account", identity: { uid: 1337, username: "backdoor" }, fields: { uid: 1337, username: "backdoor", gid: 1337, home: "/home/backdoor", shell: "/bin/bash", locked: false }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
    edges: [], gaps: [], wireDigest: "3".repeat(64),
  }).facts[0]!;
  const args = { accountRef: fact.subjectRef };
  const approvals = new ApprovalService(store);
  const ticket = approvals.request(task, "disable_account", args);
  approvals.decide(ticket.approvalId, true);
  approvals.consume(task, "disable_account", args);
  store.putActionReceipt({ actionId: ticket.actionId, taskId: task.taskId, tool: "disable_account", targetFingerprint: task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString() });
  const call = fauxToolCall("disable_account", args, { id: "WRITE-RECOVERY-31" });
  store.appendMessage(task.taskId, fauxAssistantMessage(call, { stopReason: "toolUse" }));
  store.startToolRun({ toolCallId: call.id, taskId: task.taskId, toolName: call.name, risk: "WRITE", replayPolicy: "NEVER", args });

  const executor = new FakeProtocolV2Executor(helper, async () => { throw new Error("恢复不得调用取证原语"); }, {}, async (verb) => {
    if (verb !== "get_action_receipt") throw new Error("恢复不得自动重放写操作");
    return { actionId: ticket.actionId, status: remoteStatus, ...(remoteStatus === "SUCCEEDED" ? { finishedAt: new Date().toISOString(), locked: true } : {}) };
  });
  const tools = createV2SecurityTools({ task, epoch, config: testConfig(directory), store, executor, approvals, evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, [grant]), budgetOwner: "MODEL" });
  const faux = fauxProvider({ tokensPerSecond: 0 });
  faux.setResponses([fauxAssistantMessage("恢复流程完成。")]);
  const models = createModels();
  models.setProvider(faux.provider);
  const runtime = new SecurityAgentRuntime({ task, config: testConfig(directory), store, executor, approvals, tools, models, model: faux.getModel(), protocolV2: { epochId: epoch.epochId } });
  return { store, task, approvals, ticket, call, executor, runtime };
}

function denyRecoveryApproval(approvals: ApprovalService): ApprovalTicket[] {
  const requested: ApprovalTicket[] = [];
  approvals.on("requested", (ticket: ApprovalTicket) => {
    requested.push(ticket);
    queueMicrotask(() => approvals.decide(ticket.approvalId, false));
  });
  return requested;
}

describe("v2 崩溃恢复不变量", () => {
  it("INV-23：远端回执已成功时只补记结果，不重放写动作", async () => {
    const { store, ticket, call, executor, runtime, approvals } = await fixture("SUCCEEDED");
    const requested = denyRecoveryApproval(approvals);
    await runtime.recover();

    expect(executor.maintenanceCalls.map((entry) => entry.verb)).toEqual(["get_action_receipt"]);
    expect(requested).toHaveLength(0);
    expect(store.getToolRun(call.id)?.status).toBe("SUCCEEDED");
    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("SUCCEEDED");
    expect(store.listActionReceipts(ticket.taskId)).toHaveLength(1);
  });

  it.each(["STARTED", "UNKNOWN"] as const)("INV-23：远端回执为 %s 时标记 UNKNOWN、要求重新审批且不得完成任务", async (status) => {
    const { store, task, approvals, ticket, call, executor, runtime } = await fixture(status);
    const requested = denyRecoveryApproval(approvals);
    await runtime.recover();

    expect(executor.maintenanceCalls.map((entry) => entry.verb)).toEqual(["get_action_receipt"]);
    expect(requested).toHaveLength(1);
    expect(requested[0]?.actionSummary).toContain("恢复确认");
    expect(store.getToolRun(call.id)?.status).toBe("FAILED");
    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("UNKNOWN");
    expect(store.getTask(task.taskId)).toMatchObject({ status: "ABORTED", interruption: { recoveryRequired: true } });
  });
});
