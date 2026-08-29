import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { _electron as electron, type ElectronApplication, type Page } from "@playwright/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { HuntWardenDesktopApi, NewTaskInput, TaskSnapshot } from "../../src/gui/contracts.js";

const enabled = process.env.HUNTWARDEN_GUI_GRANT_TESTS === "1";
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

async function launch(): Promise<{ page: Page; target: NewTaskInput["target"] }> {
  const userDataDir = await mkdtemp(join(tmpdir(), "huntwarden-gui-grant-"));
  temporaryDirectories.push(userDataDir);
  const app = await electron.launch({
    args: [projectRoot, `--user-data-dir=${userDataDir}`],
    cwd: projectRoot,
    env: { ...process.env, NODE_ENV: "test", HUNTWARDEN_SKIP_LEGACY_MIGRATION: "1", HUNTWARDEN_E2E_FAUX_SCENARIO: "grant-sensitive-read" },
    timeout: 30_000,
  });
  applications.push(app);
  const page = await app.firstWindow({ timeout: 30_000 });
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.waitForLoadState("domcontentloaded");
  const profile = await page.evaluate(() => window.huntwarden.getConfigProfile("deepseek"));
  const knownHosts = await readFile(profile.config.executor.knownHostsPath, "utf8");
  const fingerprint = knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2222/)?.[1];
  if (!fingerprint) throw new Error("known_hosts 缺少 Lab-Web 2222 指纹");
  expect(pageErrors).toEqual([]);
  return { page, target: {
    host: "127.0.0.1", port: 2222, username: "secagent", hostFingerprint: fingerprint,
    privateKeyPath: profile.config.executor.privateKeyPath, knownHostsPath: profile.config.executor.knownHostsPath,
  } };
}

async function snapshot(page: Page, taskId: string): Promise<TaskSnapshot> {
  return await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), taskId);
}

/** 启动调查并等到模型提交了 Sensitive-read Grant Request，授权对话框已经在界面上。 */
async function startUntilGrantRequest(page: Page, request: string, target: NewTaskInput["target"]): Promise<string> {
  const task = await page.evaluate((value) => window.huntwarden.createTask(value), { request, mode: "SCAN", checks: ["webshell"], target } as NewTaskInput);
  const taskButton = page.locator(".sidebar-tasks button", { hasText: request });
  await taskButton.waitFor({ state: "visible", timeout: 10_000 });
  await taskButton.click();
  await page.getByRole("button", { name: "开始调查" }).click();
  try {
    await page.getByRole("heading", { name: "调查范围授权" }).waitFor({ state: "visible", timeout: 60_000 });
  } catch (error) {
    const current = await snapshot(page, task.taskId);
    throw new Error(`授权对话框未出现：status=${current.task.status} grantRequests=${JSON.stringify(current.grantRequests)} audit=${JSON.stringify(current.audit.slice(0, 8).map((item) => item.event))} 原因=${error instanceof Error ? error.message : String(error)}`);
  }
  const pending = await snapshot(page, task.taskId);
  expect(pending.grantRequests).toMatchObject([{ kind: "SENSITIVE_READ", status: "PENDING" }]);
  expect(pending.grants.filter((grant) => grant.kind === "SENSITIVE_READ")).toEqual([]);
  return task.taskId;
}

async function waitFinished(page: Page, taskId: string): Promise<TaskSnapshot> {
  await expect.poll(async () => (await snapshot(page, taskId)).task.status, { timeout: 60_000 }).toBe("COMPLETED");
  return await snapshot(page, taskId);
}

describe.skipIf(!enabled)("GUI Sensitive-read Grant 生命周期", () => {
  it("批准后 Grant 绑定到申请对象并生效，审计留下激活记录", async () => {
    const { page, target } = await launch();
    const taskId = await startUntilGrantRequest(page, "E2E：批准敏感读取授权", target);
    const requested = (await snapshot(page, taskId)).grantRequests[0];
    if (!requested) throw new Error("缺少 Grant Request");

    await page.getByRole("button", { name: "批准只读授权" }).click();
    await page.getByRole("heading", { name: "调查范围授权" }).waitFor({ state: "hidden", timeout: 15_000 });

    const finished = await waitFinished(page, taskId);
    expect(finished.grantRequests).toMatchObject([{ requestId: requested.requestId, status: "APPROVED" }]);
    const grant = finished.grants.find((item) => item.kind === "SENSITIVE_READ");
    if (!grant) throw new Error("批准后应存在 SENSITIVE_READ Grant");
    expect(grant.status).toBe("ACTIVE");
    // Grant 必须绑定到申请的那个对象，而不是整个 namespace。
    expect(grant.binding.subjectRef).toBe(requested.binding.subjectRef);
    expect(grant.targetFingerprint).toBe(target.hostFingerprint);
    expect(finished.audit.map((item) => item.event)).toContain("protocol_v2_grant_activated");
    // 批准不产生 GRANT_DENIED Gap。
    expect(finished.protocolV2?.investigationGaps.filter((gap) => gap.code === "GRANT_DENIED")).toEqual([]);
  }, 240_000);

  it("拒绝后不产生 Grant，且 InvestigationGap 记录 GRANT_DENIED 而不是当作已查清", async () => {
    const { page, target } = await launch();
    const taskId = await startUntilGrantRequest(page, "E2E：拒绝敏感读取授权", target);

    await page.getByRole("button", { name: "拒绝", exact: true }).click();
    await page.getByRole("heading", { name: "调查范围授权" }).waitFor({ state: "hidden", timeout: 15_000 });

    const finished = await waitFinished(page, taskId);
    expect(finished.grantRequests).toMatchObject([{ kind: "SENSITIVE_READ", status: "DENIED" }]);
    expect(finished.grants.filter((item) => item.kind === "SENSITIVE_READ")).toEqual([]);
    expect(finished.protocolV2?.investigationGaps).toMatchObject([{ code: "GRANT_DENIED", reasonCode: "SENSITIVE_READ" }]);
    expect(finished.audit.map((item) => item.event)).toContain("protocol_v2_grant_denied");
    expect(finished.audit.map((item) => item.event)).not.toContain("protocol_v2_grant_activated");
  }, 240_000);

  it("撤销已批准的 Grant 后授权立即失效，撤销理由进入审计", async () => {
    const { page, target } = await launch();
    const taskId = await startUntilGrantRequest(page, "E2E：撤销敏感读取授权", target);

    await page.getByRole("button", { name: "批准只读授权" }).click();
    await page.getByRole("heading", { name: "调查范围授权" }).waitFor({ state: "hidden", timeout: 15_000 });
    const finished = await waitFinished(page, taskId);
    const grant = finished.grants.find((item) => item.kind === "SENSITIVE_READ");
    if (!grant) throw new Error("撤销前应先存在 ACTIVE Grant");

    const reason = "E2E：调查范围已由分析师收回";
    await page.getByRole("button", { name: /^发现/ }).click();
    await page.getByText("活动 Task Grants").waitFor({ state: "visible", timeout: 15_000 });
    // Electron 的原生 prompt 在不同 Playwright/Chromium 组合下不稳定地产生 dialog
    // 事件；只替换输入源，撤销仍由真实 UI 按钮触发并穿过 renderer → IPC → store。
    await page.evaluate((value) => { (globalThis as unknown as { prompt: () => string }).prompt = () => value; }, reason);
    await page.locator(".receipt-card", { hasText: grant.grantId }).getByRole("button", { name: "撤销", exact: true }).click();
    await page.getByText("Grant 已撤销").waitFor({ state: "visible", timeout: 15_000 });
    await expect.poll(async () => (await snapshot(page, taskId)).grants.find((item) => item.grantId === grant.grantId)?.status, { timeout: 15_000 }).not.toBe("ACTIVE");

    const after = await snapshot(page, taskId);
    expect(after.grants.find((item) => item.grantId === grant.grantId)?.status).not.toBe("ACTIVE");
    expect(after.grants.filter((item) => item.kind === "SENSITIVE_READ" && item.status === "ACTIVE")).toEqual([]);
    // 撤销是安全语义变化，必须可审计。
    expect(JSON.stringify(after.audit)).toContain(reason);
  }, 240_000);
});
