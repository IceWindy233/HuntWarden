import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("ApprovalService", () => {
  it("授权绑定目标和参数摘要且只能消费一次", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-approval-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.protocolVersion = 2;
    task.activeEpochId = "EPOCH-APPROVAL-1";
    store.createTask(task);
    const firstEpoch: ScanEpoch = { epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() };
    store.createScanEpoch(firstEpoch);
    const service = new ApprovalService(store);
    const args = { accountRef: "ACCT-00000000-0000-4000-8000-000000000001" };
    const ticket = service.request(task, "disable_account", args);
    expect(ticket.epochId).toBe(firstEpoch.epochId);
    expect(ticket.targetFingerprint).toBe(task.target.hostFingerprint);
    expect(service.consume(task, "disable_account", args)).toBeUndefined();
    service.decide(ticket.approvalId, true);
    expect(service.consume(task, "disable_account", args)?.status).toBe("CONSUMED");
    expect(service.consume(task, "disable_account", args)).toBeUndefined();
    expect(store.findLatestApproval(task.taskId, "disable_account", service.getArgsDigest(args))?.actionId).toBe(ticket.actionId);
    store.close();
  });

  it("新 Epoch 自动使旧审批失效，旧批准不能授权相同参数", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-approval-rescan-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.protocolVersion = 2;
    task.activeEpochId = "EPOCH-APPROVAL-OLD";
    store.createTask(task);
    store.createScanEpoch({ epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "COMPLETED", startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() });
    const service = new ApprovalService(store);
    const args = { evidenceRef: "EV-SAME" };
    const old = service.request(task, "quarantine_file", args);
    service.decide(old.approvalId, true);

    const nextEpochId = "EPOCH-APPROVAL-NEW";
    store.createScanEpoch({ epochId: nextEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "RESCAN", status: "RUNNING", startedAt: new Date().toISOString() });
    task.activeEpochId = nextEpochId;
    expect(store.listApprovals(task.taskId).find((item) => item.approvalId === old.approvalId)?.status).toBe("EXPIRED");
    expect(service.consume(task, "quarantine_file", args)).toBeUndefined();
    const current = service.request(task, "quarantine_file", args);
    expect(current.epochId).toBe(nextEpochId);
    expect(current.approvalId).not.toBe(old.approvalId);
    store.close();
  });
});
