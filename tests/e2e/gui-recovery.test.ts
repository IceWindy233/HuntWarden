import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { _electron as electron, type ElectronApplication, type Page } from "@playwright/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { HuntWardenDesktopApi, NewTaskInput, TaskSnapshot } from "../../src/gui/contracts.js";

const enabled = process.env.HUNTWARDEN_GUI_RECOVERY_TESTS === "1";
const projectRoot = resolve(".");
const run = promisify(execFile);
const applications: ElectronApplication[] = [];
const temporaryDirectories: string[] = [];
declare const window: { huntwarden: HuntWardenDesktopApi };

beforeEach(async () => {
  if (!enabled) return;
  await run("bash", ["labs/lab-reset.sh"], { cwd: projectRoot, timeout: 180_000, maxBuffer: 20 * 1024 * 1024 });
}, 180_000);

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.close().catch(() => undefined)));
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function launch(userDataDir: string, crashAt?: string): Promise<{ app: ElectronApplication; page: Page }> {
  const app = await electron.launch({
    args: [projectRoot, `--user-data-dir=${userDataDir}`], cwd: projectRoot,
    env: {
      ...process.env, NODE_ENV: "test", HUNTWARDEN_SKIP_LEGACY_MIGRATION: "1",
      HUNTWARDEN_E2E_FAUX_SCENARIO: "web-quarantine",
      ...(crashAt ? { HUNTWARDEN_E2E_CRASH_AT: crashAt } : {}),
    }, timeout: 30_000,
  });
  applications.push(app);
  const page = await app.firstWindow({ timeout: 30_000 });
  await page.waitForLoadState("domcontentloaded");
  return { app, page };
}

async function target(page: Page): Promise<NewTaskInput["target"]> {
  return await page.evaluate(async () => {
    const profile = await window.huntwarden.getConfigProfile("deepseek");
    return {
      host: "127.0.0.1", port: 2222, username: "secagent", hostFingerprint: "",
      privateKeyPath: profile.config.executor.privateKeyPath, knownHostsPath: profile.config.executor.knownHostsPath,
    };
  }).then(async (value) => {
    const profile = await page.evaluate(() => window.huntwarden.getConfigProfile("deepseek"));
    const text = await import("node:fs/promises").then(({ readFile }) => readFile(profile.config.executor.knownHostsPath, "utf8"));
    const fingerprint = text.match(/# (SHA256:[A-Za-z0-9+/]+) port=2222/)?.[1];
    if (!fingerprint) throw new Error("Lab-Web 指纹缺失");
    return { ...value, hostFingerprint: fingerprint };
  });
}

async function createAndStart(page: Page): Promise<string> {
  const task = await page.evaluate(async (value) => await window.huntwarden.createTask({
    request: "E2E：崩溃恢复 WebShell 调查", mode: "REMEDIATE", checks: ["webshell"], target: value,
  }), await target(page));
  const taskButton = page.locator(".sidebar-tasks button", { hasText: "崩溃恢复" });
  await taskButton.waitFor({ state: "visible", timeout: 10_000 });
  await taskButton.click();
  await page.evaluate((taskId) => window.huntwarden.startTask(taskId), task.taskId);
  return task.taskId;
}

async function waitForExit(app: ElectronApplication): Promise<void> {
  if (app.process().exitCode !== null) return;
  await new Promise<void>((resolveExit) => app.process().once("exit", () => resolveExit()));
}

async function snapshot(page: Page, taskId: string): Promise<TaskSnapshot> {
  return await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), taskId);
}

async function relaunchAndRecover(userDataDir: string, taskId: string, decision: "deny" | "approve" | "none"): Promise<{ page: Page; completed: TaskSnapshot }> {
  const { page } = await launch(userDataDir);
  const interrupted = await snapshot(page, taskId);
  expect(interrupted.task).toMatchObject({ status: "ABORTED", interruption: { recoveryRequired: true } });
  const taskButton = page.locator(".sidebar-tasks button", { hasText: "崩溃恢复" });
  await taskButton.click();
  await page.getByRole("button", { name: "恢复任务" }).click();
  if (decision !== "none") {
    await page.getByRole("heading", { name: "高风险写操作审批" }).waitFor({ state: "visible", timeout: 30_000 });
    if (decision === "deny") await page.getByRole("button", { name: "拒绝", exact: true }).click();
    else {
      await page.getByRole("button", { name: "批准一次" }).click();
      await page.getByRole("button", { name: "确认执行" }).click();
    }
  }
  await expect.poll(async () => {
    const current = await snapshot(page, taskId);
    if (current.task.status === "FAILED") {
      throw new Error(`恢复失败: ${JSON.stringify(current.audit.slice(-5))}`);
    }
    return current.task.status;
  }, { timeout: 45_000 }).toBe("COMPLETED");
  return { page, completed: await snapshot(page, taskId) };
}

describe.skipIf(!enabled)("GUI 进程级崩溃恢复", () => {
  for (const crashAt of ["model_streaming", "tool_started", "evidence_file_written_before_metadata", "approval_waiting"] as const) {
    it(`${crashAt} 中断后由分析师恢复且不重复 Evidence`, async () => {
      const userDataDir = await mkdtemp(join(tmpdir(), `huntwarden-recovery-${crashAt}-`));
      temporaryDirectories.push(userDataDir);
      const { app, page } = await launch(userDataDir, crashAt);
      const taskId = await createAndStart(page);
      await waitForExit(app);
      const { completed } = await relaunchAndRecover(userDataDir, taskId, "deny");
      expect(new Set(completed.evidence.map((item) => item.evidenceId)).size).toBe(completed.evidence.length);
      expect(completed.reports).toHaveLength(1);
      expect(completed.task.interruption?.recoveryRequired).toBe(false);
    }, 180_000);
  }

  it("远程隔离成功但本地未记账时仅查询回执且不重复写入", async () => {
    const userDataDir = await mkdtemp(join(tmpdir(), "huntwarden-recovery-write-"));
    temporaryDirectories.push(userDataDir);
    const { app, page } = await launch(userDataDir, "remote_write_succeeded_before_local_receipt");
    const taskId = await createAndStart(page);
    await page.getByRole("heading", { name: "高风险写操作审批" }).waitFor({ state: "visible", timeout: 30_000 });
    await page.getByRole("button", { name: "批准一次" }).click();
    await page.getByRole("button", { name: "确认执行" }).click();
    await waitForExit(app);
    const { completed } = await relaunchAndRecover(userDataDir, taskId, "none");
    expect(completed.actionReceipts).toMatchObject([{ tool: "quarantine_file", status: "SUCCEEDED" }]);
    expect(completed.approvals.filter((item) => item.tool === "quarantine_file")).toHaveLength(1);
    expect(completed.approvals[0]?.status).toBe("CONSUMED");
    expect(completed.actionReceipts.filter((item) => item.tool === "quarantine_file")).toHaveLength(1);
  }, 180_000);

  it("报告阶段中断后只生成报告且不重复调查工具", async () => {
    const userDataDir = await mkdtemp(join(tmpdir(), "huntwarden-recovery-report-"));
    temporaryDirectories.push(userDataDir);
    const { app, page } = await launch(userDataDir, "reporting_started");
    const taskId = await createAndStart(page);
    await page.getByRole("heading", { name: "高风险写操作审批" }).waitFor({ state: "visible", timeout: 30_000 });
    await page.getByRole("button", { name: "拒绝", exact: true }).click();
    await waitForExit(app);
    const { page: recoveredPage, completed } = await relaunchAndRecover(userDataDir, taskId, "none");
    const toolCount = completed.toolRuns.length;
    expect(completed.reports.length).toBeGreaterThanOrEqual(1);
    expect(new Set(completed.reports.map((item) => item.version)).size).toBe(completed.reports.length);
    expect(completed.task.interruption?.previousStatus).toBe("REPORTING");
    expect((await snapshot(recoveredPage, taskId)).toolRuns).toHaveLength(toolCount);
  }, 180_000);
});
