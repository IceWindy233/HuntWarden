import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createTriageTools } from "../../src/tools/triage/tools.js";
import { createProcessConnectionTool } from "../../src/tools/shared/process-connections.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

const stable = {
  bootId: "00000000-0000-4000-8000-000000000001",
  pid: 321,
  startTicks: "123456",
  exeInode: "98765",
  exeSha256: "a".repeat(64),
  exePath: "/tmp/.worker",
  exeDeleted: true,
  signals: ["deleted_executable"],
};

async function fixture(executor: FakeExecutor) {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-triage-tools-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  const task = testTask();
  store.createTask(task);
  const deps = {
    task,
    config: testConfig(directory),
    store,
    executor,
    approvals: new ApprovalService(store),
    evidence: new EvidenceStore(directory, store),
  };
  // list_process_connections 已提取为唯一共享实现，与 index.ts 的装配方式保持一致。
  const tools = [...createTriageTools(deps), createProcessConnectionTool(deps)];
  return { directory, store, task, tools };
}

describe("Linux 入侵分诊工具", () => {
  it("用不透明 processRef 绑定完整稳定身份并固化 Evidence", async () => {
    const executor = new FakeExecutor({
      list_suspicious_processes: () => ({ items: [stable], partial: false, warnings: [] }),
      inspect_process_fds: () => ({ items: [{ fd: 3, type: "socket", target: "socket:[42]" }], partial: false, warnings: [] }),
      list_process_connections: () => ({ items: [{ protocol: "tcp", state: "LISTEN" }], partial: false, warnings: [] }),
    });
    const { store, task, tools } = await fixture(executor);
    const listed = await tools.find((tool) => tool.name === "list_suspicious_processes")!
      .execute("triage-list-process", {}, undefined);
    const processRef = (listed.details as { items: { processRef: string }[] }).items[0]!.processRef;
    expect(processRef).toMatch(/^PROC-/);
    expect(store.listEvidence(task.taskId)).toHaveLength(1);

    await tools.find((tool) => tool.name === "inspect_process_fds")!
      .execute("triage-fds", { processRef }, undefined);
    await tools.find((tool) => tool.name === "list_process_connections")!
      .execute("triage-connections", { processRef }, undefined);

    expect(executor.calls[1]).toEqual({ operation: "inspect_process_fds", params: {
      bootId: stable.bootId, pid: stable.pid, startTicks: stable.startTicks,
      exeInode: stable.exeInode, exeSha256: stable.exeSha256, maxItems: 2500,
    } });
    expect(executor.calls[2]).toEqual({ operation: "list_process_connections", params: {
      bootId: stable.bootId, pid: stable.pid, startTicks: stable.startTicks,
      exeInode: stable.exeInode, exeSha256: stable.exeSha256, maxConnections: 2500,
    } });
    expect(store.listEvidence(task.taskId)).toHaveLength(3);
    store.close();
  });

  it("拒绝伪造或跨任务引用，不接受模型直接提供 PID/路径", async () => {
    const executor = new FakeExecutor();
    const { store, tools } = await fixture(executor);
    const fds = tools.find((tool) => tool.name === "inspect_process_fds")!;

    await expect(fds.execute("triage-invalid-ref", { processRef: "PROC-00000000-0000-4000-8000-000000000099" }, undefined))
      .rejects.toThrow(/无效或跨任务引用/);
    expect(executor.calls).toHaveLength(0);
    expect((fds.parameters as { properties?: Record<string, unknown> }).properties).not.toHaveProperty("pid");
    store.close();
  });

  it("传播缺少审计依赖的 PARTIAL 与 warnings", async () => {
    const executor = new FakeExecutor({
      query_exec_events: () => ({ items: [], partial: true, warnings: ["audit.log 不可用"] }),
    });
    const { store, tools } = await fixture(executor);
    const result = await tools.find((tool) => tool.name === "query_exec_events")!
      .execute("triage-exec-partial", {}, undefined);

    expect(result.details).toMatchObject({ status: "partial", warnings: ["audit.log 不可用"] });
    store.close();
  });

  it("通过 Artifact spool 流式采集进程可执行文件", async () => {
    const payload = Buffer.alloc(700_000, 0x5a);
    const sha256 = createHash("sha256").update(payload).digest("hex");
    const token = "b".repeat(64);
    const identity = { ...stable, exeSha256: sha256 };
    const executor = new FakeExecutor({
      list_suspicious_processes: () => ({ items: [identity], partial: false, warnings: [] }),
      collect_process_executable: () => ({
        sha256, size: payload.length,
        artifact: { artifactToken: token, sha256, size: payload.length, expiresAt: new Date(Date.now() + 60_000).toISOString() },
        process: { bootId: identity.bootId, pid: identity.pid, startTicks: identity.startTicks, exeInode: identity.exeInode, exeSha256: sha256 },
      }),
    }, { [token]: payload });
    const { store, tools } = await fixture(executor);
    const listed = await tools.find((tool) => tool.name === "list_suspicious_processes")!
      .execute("triage-list-for-collect", {}, undefined);
    const processRef = (listed.details as { items: { processRef: string }[] }).items[0]!.processRef;
    const collected = await tools.find((tool) => tool.name === "collect_process_executable")!
      .execute("triage-collect-exe", { processRef }, undefined);
    const evidenceId = (collected.details as { summary: { evidenceId: string } }).summary.evidenceId;
    const evidence = store.getEvidence(testTask().taskId, evidenceId)!;

    expect(evidence.sha256).toBe(sha256);
    await expect(readFile(evidence.storagePath!)).resolves.toEqual(payload);
    store.close();
  });

  it("按 Profile、任务时间窗与 config.triage 约束预算，DEEP 才开放深度工具", async () => {
    const executor = new FakeExecutor({
      capture_volatile_snapshot: () => ({ bootId: stable.bootId, capturedAt: new Date().toISOString(), processes: [], connections: [], partial: false, warnings: [] }),
      query_auth_events: () => ({ items: [], partial: false, warnings: [] }),
    });
    const { store, task, tools } = await fixture(executor);
    task.profile = "QUICK";
    task.timeWindowHours = 24;
    const quickTools = createTriageTools({ task, config: testConfig(directories.at(-1)!), store, executor,
      approvals: new ApprovalService(store), evidence: new EvidenceStore(directories.at(-1)!, store) });
    expect(quickTools.map(({ name }) => name)).not.toEqual(expect.arrayContaining(["verify_package_integrity", "build_incident_timeline"]));
    await quickTools.find(({ name }) => name === "capture_volatile_snapshot")!.execute("triage-quick-snapshot", {}, undefined);
    await quickTools.find(({ name }) => name === "query_auth_events")!.execute("triage-quick-auth", {}, undefined);
    expect(executor.calls).toEqual(expect.arrayContaining([
      { operation: "capture_volatile_snapshot", params: { maxProcesses: 500, maxConnections: 1250 } },
      { operation: "query_auth_events", params: { sinceHours: 24, maxEvents: 1250 } },
    ]));

    task.profile = "DEEP";
    const deepTools = createTriageTools({ task, config: testConfig(directories.at(-1)!), store, executor,
      approvals: new ApprovalService(store), evidence: new EvidenceStore(directories.at(-1)!, store) });
    expect(deepTools.map(({ name }) => name)).toEqual(expect.arrayContaining(["verify_package_integrity", "build_incident_timeline"]));
    expect(tools.length).toBeGreaterThan(0);
    store.close();
  });
});
