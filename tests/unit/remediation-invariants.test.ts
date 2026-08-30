import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { gateCapabilities } from "../../src/protocol-v2/capability.js";
import type { HelperCapabilitiesV2, ScanEpoch, TaskGrant, WireRequest } from "../../src/protocol-v2/types.js";
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
  protocolVersion: 2, manifestVersion: "2.1.0", helper: { name: "helper", version: "2.1.0" },
  namespaces: {
    file: { fields: ["mountId", "device", "inode", "path", "size", "sha256"], relations: [], verbs: ["enumerate", "collect"] },
    account: { fields: ["uid", "username", "gid", "home", "shell", "locked"], relations: [], verbs: ["enumerate"] },
  },
  matchers: [], probes: [], verbs: ["enumerate", "collect"],
  limits: { maxObjects: 100, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
};

async function fixture(check: "webshell" | "backdoor_account") {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-write-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  stores.push(store);
  const task = testTask("REMEDIATE");
  task.protocolVersion = 2;
  task.checks = [check];
  task.activeEpochId = "EPOCH-00000000-0000-4000-8000-000000000021";
  store.createTask(task);
  const epoch: ScanEpoch = {
    epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
    protocolVersion: 2, manifestVersion: "2.1.0", helperVersion: "2.1.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString(),
  };
  store.createScanEpoch(epoch);
  const grant: TaskGrant = {
    grantId: "GRANT-WRITE", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint,
    kind: "CATEGORY", status: "ACTIVE", binding: { category: check }, createdAt: new Date().toISOString(),
  };
  store.putTaskGrant(grant);
  const maintenance: Array<{ verb: string; request: WireRequest }> = [];
  const executor = new FakeProtocolV2Executor(helper, async () => { throw new Error("写操作测试不应调用取证原语"); }, {}, async (verb, request) => {
    maintenance.push({ verb, request: structuredClone(request) });
    return { status: "SUCCEEDED", actionId: (request.params.action as { actionId: string }).actionId };
  });
  const approvals = new ApprovalService(store);
  const tools = createV2SecurityTools({
    task, epoch, config: testConfig(directory), store, executor, approvals,
    evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, [grant]), budgetOwner: "MODEL",
  });
  return { store, task, epoch, approvals, tools, maintenance };
}

function requireTool<T extends { name: string }>(tools: T[], name: string): T {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`缺少测试工具 ${name}`);
  return tool;
}

function putFileSubject(store: RuntimeStore, taskId: string, epochId: string) {
  return store.commitFactBatch({
    taskId, epochId, sourceRunId: "FILE-OBSERVE", source: { kind: "MODEL" },
    targetFingerprint: testTask().target.hostFingerprint, requestId: "FILE-OBSERVE", collector: { name: "enumerate", version: "2.0.0" },
    observations: [{ namespace: "file", identity: { mountId: "1", device: "8:1", inode: "42" }, fields: { mountId: "1", device: "8:1", inode: "42", path: "/srv/www/shell.php", kind: "regular", size: 128, mode: 420, uid: 33, gid: 33, mtime: new Date().toISOString(), sha256: "a".repeat(64) }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
    edges: [], gaps: [], wireDigest: "a".repeat(64),
  }).facts[0]!;
}

describe("v2 写操作不变量", () => {
  it("INV-21/INV-22：精确审批只消费一次，并发送绑定后的 v2 写 Envelope", async () => {
    const { store, task, epoch, approvals, tools, maintenance } = await fixture("webshell");
    const file = putFileSubject(store, task.taskId, epoch.epochId);
    const evidenceRef = "EV-00000000-0000-4000-8000-000000000021";
    store.putEvidence({ evidenceId: evidenceRef, taskId: task.taskId, host: task.target.host, type: "collected_object", source: "/srv/www/shell.php", sha256: "a".repeat(64), collectedAt: new Date().toISOString(), tool: "collect", toolCallId: "COLLECT-21", metadata: { epochId: epoch.epochId, subjectRef: file.subjectRef, complete: true } });
    const args = { evidenceRef };
    const approval = approvals.request(task, "quarantine_file", args);
    approvals.decide(approval.approvalId, true);
    store.startToolRun({ toolCallId: "WRITE-21", taskId: task.taskId, toolName: "quarantine_file", risk: "WRITE", replayPolicy: "NEVER", args });
    await requireTool(tools, "quarantine_file").execute("WRITE-21", args);

    expect(maintenance).toHaveLength(1);
    expect(maintenance[0]).toMatchObject({ verb: "quarantine_file", request: { protocolVersion: 2, epochId: epoch.epochId, params: { authorization: { mode: "REMEDIATE", tool: "quarantine_file", actionId: approval.actionId } } } });
    expect(store.getActionReceipt(approval.actionId)?.status).toBe("SUCCEEDED");
    expect(store.listApprovals(task.taskId)[0]?.status).toBe("CONSUMED");
    await expect(requireTool(tools, "quarantine_file").execute("WRITE-22", args)).rejects.toMatchObject({ code: "APPROVAL_REQUIRED" });
    expect(maintenance).toHaveLength(1);
  });

  it("审批与参数摘要精确绑定，不能替换 Evidence 引用", async () => {
    const { store, task, epoch, approvals, tools, maintenance } = await fixture("webshell");
    const file = putFileSubject(store, task.taskId, epoch.epochId);
    for (const suffix of ["022", "023"]) store.putEvidence({ evidenceId: `EV-00000000-0000-4000-8000-000000000${suffix}`, taskId: task.taskId, host: task.target.host, type: "collected_object", source: "/srv/www/shell.php", sha256: "a".repeat(64), collectedAt: new Date().toISOString(), tool: "collect", metadata: { epochId: epoch.epochId, subjectRef: file.subjectRef, complete: true } });
    const approvedArgs = { evidenceRef: "EV-00000000-0000-4000-8000-000000000022" };
    const otherArgs = { evidenceRef: "EV-00000000-0000-4000-8000-000000000023" };
    const approval = approvals.request(task, "quarantine_file", approvedArgs);
    approvals.decide(approval.approvalId, true);
    await expect(requireTool(tools, "quarantine_file").execute("WRITE-DIGEST", otherArgs)).rejects.toMatchObject({ code: "APPROVAL_REQUIRED" });
    expect(maintenance).toHaveLength(0);
  });

  it("root 与当前 SSH 执行账户在触达 helper 前永久拒绝", async () => {
    const { store, task, epoch, approvals, tools, maintenance } = await fixture("backdoor_account");
    for (const [index, username] of ["root", task.target.username].entries()) {
      const fact = store.commitFactBatch({
        taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `ACCOUNT-${index}`, source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
        requestId: `ACCOUNT-${index}`, collector: { name: "enumerate", version: "2.0.0" },
        observations: [{ namespace: "account", identity: { uid: index, username }, fields: { uid: index, username, gid: index, home: `/home/${username}`, shell: "/bin/bash", locked: false }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }], edges: [], gaps: [], wireDigest: String(index + 1).repeat(64),
      }).facts[0]!;
      const args = { accountRef: fact.subjectRef };
      const approval = approvals.request(task, "disable_account", args);
      approvals.decide(approval.approvalId, true);
      await expect(requireTool(tools, "disable_account").execute(`DISABLE-${index}`, args)).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    }
    expect(maintenance).toHaveLength(0);
  });
});
