import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../../src/domain/types.js";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("RuntimeStore", () => {
  it("启用安全文件权限并按 toolCallId 幂等保存 Finding", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-store-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const finding: Finding = {
      findingId: "FIND-00000000-0000-4000-8000-000000000001", taskId: task.taskId,
      host: task.target.host, category: "webshell", severity: "INFO", confidence: 1,
      status: "NO_FINDING", title: "未发现", summary: "已完成检测", evidenceRefs: [],
      createdAt: new Date().toISOString(), toolCallId: "call-fixed",
    };
    const first = store.putFinding(finding);
    const second = store.putFinding({ ...finding, findingId: "FIND-00000000-0000-4000-8000-000000000002", title: "重复" });
    expect(second.findingId).toBe(first.findingId);
    expect(store.listFindings(task.taskId)).toHaveLength(1);
    expect(store.getTask(task.taskId)?.coverage.webshell).toBe("NO_FINDING");
    expect((await stat(store.databasePath)).mode & 0o777).toBe(0o600);
    store.close();
  });

  it("同一数据库只允许一个写实例并可清理已释放锁", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-lock-"));
    directories.push(directory);
    const first = await RuntimeStore.open(directory, "runtime.db");
    await expect(RuntimeStore.open(directory, "runtime.db")).rejects.toThrow(/写锁/);
    first.close();
    expect(() => first.close()).not.toThrow();
    const second = await RuntimeStore.open(directory, "runtime.db");
    second.close();
  });

  it("Evidence 落盘后按 toolCallId 幂等恢复", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const evidence = new EvidenceStore(directory, store);
    const input = { taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/item", tool: "collect_file", toolCallId: "call-evidence", data: Buffer.from("evidence") };
    const first = await evidence.putBuffer(input);
    const second = await evidence.putBuffer(input);
    expect(second.evidenceId).toBe(first.evidenceId);
    expect(store.listEvidence(task.taskId)).toHaveLength(1);
    store.close();
  });

  it("品牌迁移时只重写受管 Evidence 路径前缀", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-migration-"));
    directories.push(directory);
    const legacyRoot = join(directory, "SecHostAgent", "runtime");
    const currentRoot = join(directory, "HuntWarden", "runtime");
    const store = await RuntimeStore.open(join(directory, "database"), "runtime.db");
    const task = testTask();
    store.createTask(task);
    const evidence = new EvidenceStore(legacyRoot, store);
    const created = await evidence.putBuffer({ taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/item", tool: "collect_file", toolCallId: "call-migration", data: Buffer.from("evidence") });
    expect(created.storagePath).toContain(join("SecHostAgent", "runtime"));
    expect(store.relocateEvidencePaths([legacyRoot], currentRoot)).toBe(1);
    expect(store.getEvidence(task.taskId, created.evidenceId)?.storagePath).toContain(join("HuntWarden", "runtime"));
    expect(store.relocateEvidencePaths([legacyRoot], currentRoot)).toBe(0);
    store.close();
  });

  it("启动对账将遗留活动任务标记为待人工恢复并使旧审批失效", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-interruption-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.status = "WAITING_APPROVAL";
    store.createTask(task);
    const approvals = new ApprovalService(store);
    const pending = approvals.request(task, "quarantine_file", { evidenceRef: "EV-test" });
    const approved = approvals.request(task, "disable_account", { accountRef: "ACCT-test" });
    approvals.decide(approved.approvalId, true);

    const reconciled = store.reconcileInterruptedTasks();
    expect(reconciled).toHaveLength(1);
    expect(store.getTask(task.taskId)).toMatchObject({
      status: "ABORTED",
      interruption: { previousStatus: "WAITING_APPROVAL", reason: "PROCESS_INTERRUPTED", recoveryRequired: true },
    });
    expect(store.listApprovals(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ approvalId: pending.approvalId, status: "EXPIRED" }),
      expect.objectContaining({ approvalId: approved.approvalId, status: "EXPIRED" }),
    ]));
    expect(() => approvals.decide(pending.approvalId, true)).toThrow(/失效/);
    expect(store.listAudit(task.taskId).at(-1)?.event).toBe("task_interrupted_detected");
    expect(store.reconcileInterruptedTasks()).toHaveLength(0);
    store.close();
  });
});
