import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportService } from "../../src/report/report-service.js";
import type { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("ReportService", () => {
  it("校验失败修复一次后使用确定性模板，并保留 ERROR/NOT_CHECKED 语义", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-report-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.coverage = { webshell: "NO_FINDING", java_memory_shell: "ERROR", backdoor_account: "NOT_CHECKED" };
    store.createTask(task);
    const promptWithoutTools = vi.fn(async () => undefined);
    const runtime = { promptWithoutTools, lastAssistantText: () => "# 无效报告" } as unknown as SecurityAgentRuntime;
    const path = await new ReportService(directory, store).generate(task, runtime);
    const markdown = await readFile(path, "utf8");
    expect(promptWithoutTools).toHaveBeenCalledTimes(2);
    expect(markdown).toContain("java_memory_shell: ERROR");
    expect(markdown).toContain("backdoor_account: NOT_CHECKED");
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    store.close();
  });

  it("拒绝不存在的 Finding 和 Evidence 引用", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-report-refs-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.coverage = { webshell: "NO_FINDING", java_memory_shell: "ERROR", backdoor_account: "NOT_CHECKED" };
    store.createTask(task);
    const result = new ReportService(directory, store).validate(task.taskId,
      "NO_FINDING ERROR NOT_CHECKED FIND-00000000-0000-4000-8000-999999999999 EV-00000000-0000-4000-8000-999999999999");
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(2);
    store.close();
  });
});
