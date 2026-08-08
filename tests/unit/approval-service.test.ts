import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
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
    store.createTask(task);
    const service = new ApprovalService(store);
    const args = { accountRef: "ACCT-00000000-0000-4000-8000-000000000001" };
    const ticket = service.request(task, "disable_account", args);
    expect(ticket.targetFingerprint).toBe(task.target.hostFingerprint);
    expect(service.consume(task, "disable_account", args)).toBeUndefined();
    service.decide(ticket.approvalId, true);
    expect(service.consume(task, "disable_account", args)?.status).toBe("CONSUMED");
    expect(service.consume(task, "disable_account", args)).toBeUndefined();
    expect(store.findLatestApproval(task.taskId, "disable_account", service.getArgsDigest(args))?.actionId).toBe(ticket.actionId);
    store.close();
  });
});
