import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { _electron as electron, type ElectronApplication, type Page } from "@playwright/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { HuntWardenDesktopApi, NewTaskInput, TaskSnapshot } from "../../src/gui/contracts.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import { DockerV2Remote } from "../docker/v2-remote.js";

const enabled = process.env.HUNTWARDEN_GUI_REMEDIATION_TESTS === "1";
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

async function launchScenario(scenario: "web-quarantine" | "account-disable", port: number): Promise<{
  app: ElectronApplication;
  page: Page;
  target: NewTaskInput["target"];
}> {
  const userDataDir = await mkdtemp(join(tmpdir(), `huntwarden-gui-${scenario}-`));
  temporaryDirectories.push(userDataDir);
  const app = await electron.launch({
    args: [projectRoot, `--user-data-dir=${userDataDir}`],
    cwd: projectRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      HUNTWARDEN_SKIP_LEGACY_MIGRATION: "1",
      HUNTWARDEN_E2E_FAUX_SCENARIO: scenario,
    },
    timeout: 30_000,
  });
  applications.push(app);
  const page = await app.firstWindow({ timeout: 30_000 });
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.waitForLoadState("domcontentloaded");
  const profile = await page.evaluate(() => window.huntwarden.getConfigProfile("deepseek"));
  const knownHosts = await readFile(profile.config.executor.knownHostsPath, "utf8");
  const fingerprint = knownHosts.match(new RegExp(`# (SHA256:[A-Za-z0-9+/]+) port=${port}`))?.[1];
  if (!fingerprint) throw new Error(`known_hosts 缺少 ${port} 指纹`);
  expect(pageErrors).toEqual([]);
  return {
    app,
    page,
    target: {
      host: "127.0.0.1", port, username: "secagent", hostFingerprint: fingerprint,
      privateKeyPath: profile.config.executor.privateKeyPath,
      knownHostsPath: profile.config.executor.knownHostsPath,
    },
  };
}

async function createAndStart(page: Page, input: NewTaskInput): Promise<string> {
  const task = await page.evaluate((value) => window.huntwarden.createTask(value), input);
  const taskButton = page.locator(".sidebar-tasks button", { hasText: input.request });
  await taskButton.waitFor({ state: "visible", timeout: 10_000 });
  await taskButton.click();
  await page.getByRole("button", { name: "开始调查" }).click();
  await page.getByRole("heading", { name: "高风险写操作审批" }).waitFor({ state: "visible", timeout: 30_000 });
  return task.taskId;
}

async function snapshot(page: Page, taskId: string): Promise<TaskSnapshot> {
  return await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), taskId);
}

async function waitCompleted(page: Page, taskId: string): Promise<TaskSnapshot> {
  await expect.poll(async () => (await snapshot(page, taskId)).task.status, { timeout: 30_000 }).toBe("COMPLETED");
  return await snapshot(page, taskId);
}

describe.skipIf(!enabled)("GUI REMEDIATE 真实审批闭环", () => {
  it("拒绝 WebShell 隔离时远端零写入且 GUI 保留拒绝审计", async () => {
    const { page, target } = await launchScenario("web-quarantine", 2222);
    const request = "E2E：拒绝 Lab WebShell 隔离";
    const taskId = await createAndStart(page, { request, mode: "REMEDIATE", checks: ["webshell"], target });
    const waiting = await snapshot(page, taskId);
    expect(waiting.task.status).toBe("WAITING_APPROVAL");
    expect(waiting.approvals).toMatchObject([{ tool: "quarantine_file", status: "PENDING" }]);
    expect(waiting.actionReceipts).toHaveLength(0);

    await page.getByRole("button", { name: "拒绝", exact: true }).click();
    await page.getByRole("heading", { name: "高风险写操作审批" }).waitFor({ state: "hidden" });
    const completed = await waitCompleted(page, taskId);
    expect(completed.approvals).toMatchObject([{ tool: "quarantine_file", status: "DENIED" }]);
    expect(completed.actionReceipts).toHaveLength(0);
    expect(completed.toolRuns.find((item) => item.toolName === "quarantine_file")?.status).toBe("BLOCKED");

    const remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 30_000);
    try {
      const client = new DockerV2Remote(remote);
      const files = await client.enumerate("file", ["path"], { scope: { namespace: "file", canonicalRoot: "/var/www/html" }, predicate: { op: "eq", field: "path", value: "/var/www/html/lab-webshell.php" } });
      expect(files[0]?.fields.path).toBe("/var/www/html/lab-webshell.php");
    } finally { await remote.close(); }
    await page.getByRole("button", { name: "审计" }).click();
    expect(await page.locator(".audit-log").innerText()).toContain("write_tool_denied");
    expect(await page.locator(".receipt-section").count()).toBe(0);
  }, 120_000);

  it("双击确认后 WebShell 只隔离一次并在 GUI 展示成功回执", async () => {
    const { page, target } = await launchScenario("web-quarantine", 2222);
    const taskId = await createAndStart(page, { request: "E2E：批准 Lab WebShell 隔离", mode: "REMEDIATE", checks: ["webshell"], target });
    await page.getByRole("button", { name: "批准一次" }).click();
    await page.getByText("请再次点击“确认执行”完成授权。").waitFor({ state: "visible" });
    await page.getByRole("button", { name: "确认执行" }).click();
    const completed = await waitCompleted(page, taskId);
    expect(completed.approvals).toMatchObject([{ tool: "quarantine_file", status: "CONSUMED" }]);
    expect(completed.actionReceipts).toMatchObject([{ tool: "quarantine_file", status: "SUCCEEDED" }]);
    expect(completed.protocolV2?.assessments).toEqual(expect.arrayContaining([expect.objectContaining({ category: "webshell", authorType: "MODEL", verdict: "SUSPICIOUS" })]));

    const remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 30_000);
    try {
      const client = new DockerV2Remote(remote);
      const files = await client.enumerate("file", ["path"], { scope: { namespace: "file", canonicalRoot: "/var/www/html" }, predicate: { op: "eq", field: "path", value: "/var/www/html/lab-webshell.php" } });
      expect(files).toHaveLength(0);
    } finally { await remote.close(); }
    await page.getByRole("button", { name: "审计" }).click();
    expect(await page.locator(".receipt-section").innerText()).toContain("quarantine_file");
    expect(await page.locator(".receipt-section").innerText()).toContain("SUCCEEDED");
  }, 120_000);

  it("双击确认后禁用 labroot 并在 GUI 展示一次性回执", async () => {
    const { page, target } = await launchScenario("account-disable", 2224);
    const taskId = await createAndStart(page, { request: "E2E：批准禁用 Lab UID 0 账户", mode: "REMEDIATE", checks: ["backdoor_account"], target });
    expect(await page.locator(".approval-details").innerText()).toContain("labroot");
    await page.getByRole("button", { name: "批准一次" }).click();
    await page.getByRole("button", { name: "确认执行" }).click();
    const completed = await waitCompleted(page, taskId);
    expect(completed.approvals).toMatchObject([{ tool: "disable_account", status: "CONSUMED" }]);
    expect(completed.actionReceipts).toMatchObject([{ tool: "disable_account", status: "SUCCEEDED" }]);
    expect(completed.protocolV2?.assessments).toEqual(expect.arrayContaining([expect.objectContaining({ category: "backdoor_account", authorType: "MODEL", verdict: "SUSPICIOUS" })]));

    const remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 30_000);
    try {
      const client = new DockerV2Remote(remote);
      const accounts = await client.enumerate("account", ["uid", "username", "locked"]);
      expect(accounts.find((item) => item.fields.username === "labroot")?.fields.locked).toBe(true);
    } finally { await remote.close(); }
    await page.getByRole("button", { name: "审计" }).click();
    expect(await page.locator(".receipt-section").innerText()).toContain("disable_account");
    expect(await page.locator(".receipt-section").innerText()).toContain("SUCCEEDED");
  }, 120_000);
});
