import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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
    const report = await new ReportService(directory, store).generate(task, runtime);
    const markdown = await readFile(report.path, "utf8");
    expect(promptWithoutTools).toHaveBeenCalledTimes(2);
    expect(markdown).toContain("java_memory_shell: ERROR");
    expect(markdown).toContain("backdoor_account: NOT_CHECKED");
    expect(store.getTask(task.taskId)?.status).toBe("COMPLETED");
    expect(report.generationMode).toBe("FALLBACK");
    expect((await stat(report.path)).mode & 0o777).toBe(0o600);
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

  it("不可变生成多个报告版本并懒迁移旧版报告", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-report-version-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.coverage = { webshell: "NO_FINDING", java_memory_shell: "ERROR", backdoor_account: "NOT_CHECKED" };
    store.createTask(task);
    const runtime = {
      promptWithoutTools: vi.fn(async () => undefined),
      lastAssistantText: () => "NO_FINDING ERROR NOT_CHECKED",
    } as unknown as SecurityAgentRuntime;
    const service = new ReportService(directory, store);
    const first = await service.generate(task, runtime);
    const second = await service.generate(task, runtime);
    expect(first.version).toBe(1);
    expect(second.version).toBe(2);
    expect(first.path).not.toBe(second.path);
    expect(await service.list(task.taskId)).toHaveLength(2);

    const legacyTask = { ...testTask(), taskId: "TASK-00000000-0000-4000-8000-000000000099" };
    store.createTask(legacyTask);
    const reportDir = join(directory, "reports");
    await mkdir(reportDir, { recursive: true });
    const legacyPath = join(reportDir, `${legacyTask.taskId}.md`);
    await writeFile(legacyPath, "# legacy", "utf8");
    const imported = await service.list(legacyTask.taskId);
    expect(imported).toMatchObject([{ version: 1, generationMode: "LEGACY", path: legacyPath }]);
    expect(await readFile(legacyPath, "utf8")).toBe("# legacy");

    const unopenedTask = { ...testTask(), taskId: "TASK-00000000-0000-4000-8000-000000000098" };
    unopenedTask.coverage = { webshell: "NO_FINDING", java_memory_shell: "ERROR", backdoor_account: "NOT_CHECKED" };
    store.createTask(unopenedTask);
    const unopenedLegacyPath = join(reportDir, `${unopenedTask.taskId}.md`);
    await writeFile(unopenedLegacyPath, "# unopened legacy", "utf8");
    const regenerated = await service.generate(unopenedTask, runtime);
    expect(regenerated.version).toBe(2);
    expect(store.listReports(unopenedTask.taskId)).toMatchObject([
      { version: 1, generationMode: "LEGACY", path: unopenedLegacyPath },
      { version: 2, generationMode: "MODEL" },
    ]);
    expect(await readFile(unopenedLegacyPath, "utf8")).toBe("# unopened legacy");
    store.close();
  });
});
