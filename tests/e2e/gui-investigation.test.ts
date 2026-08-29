import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { _electron as electron, type ElectronApplication, type Page } from "@playwright/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CheckCategory } from "../../src/domain/types.js";
import type { DesktopEvent, HuntWardenDesktopApi, NewTaskInput, TaskSnapshot } from "../../src/gui/contracts.js";
import type { E2eFauxScenario } from "../../src/testing/e2e-faux-model.js";

const enabled = process.env.HUNTWARDEN_GUI_INVESTIGATION_TESTS === "1";
const projectRoot = resolve(".");
const run = promisify(execFile);
const applications: ElectronApplication[] = [];
const temporaryDirectories: string[] = [];
declare const window: { huntwarden: HuntWardenDesktopApi; __huntwardenStreamEvents?: DesktopEvent[] };

beforeEach(async () => {
  if (!enabled) return;
  await run("bash", ["labs/lab-reset.sh"], { cwd: projectRoot, timeout: 180_000, maxBuffer: 20 * 1024 * 1024 });
}, 180_000);

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.close().catch(() => undefined)));
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function launch(scenario: E2eFauxScenario, port: number): Promise<{ page: Page; target: NewTaskInput["target"] }> {
  const userDataDir = await mkdtemp(join(tmpdir(), `huntwarden-investigation-${scenario}-`));
  temporaryDirectories.push(userDataDir);
  const application = await electron.launch({
    args: [projectRoot, `--user-data-dir=${userDataDir}`], cwd: projectRoot,
    env: { ...process.env, NODE_ENV: "test", HUNTWARDEN_SKIP_LEGACY_MIGRATION: "1", HUNTWARDEN_E2E_FAUX_SCENARIO: scenario },
    timeout: 30_000,
  });
  applications.push(application);
  const page = await application.firstWindow({ timeout: 30_000 });
  await page.waitForLoadState("domcontentloaded");
  const profile = await page.evaluate(() => window.huntwarden.getConfigProfile("deepseek"));
  const knownHosts = await readFile(profile.config.executor.knownHostsPath, "utf8");
  const fingerprint = knownHosts.match(new RegExp(`# (SHA256:[A-Za-z0-9+/]+) port=${port}`))?.[1];
  if (!fingerprint) throw new Error(`known_hosts 缺少 ${port} 指纹`);
  return { page, target: {
    host: "127.0.0.1", port, username: "secagent", hostFingerprint: fingerprint,
    privateKeyPath: profile.config.executor.privateKeyPath, knownHostsPath: profile.config.executor.knownHostsPath,
  } };
}

async function runInvestigation(scenario: E2eFauxScenario, port: number, category: CheckCategory): Promise<{ page: Page; snapshot: TaskSnapshot; streamEvents: DesktopEvent[] }> {
  const { page, target } = await launch(scenario, port);
  await page.evaluate(() => {
    window.__huntwardenStreamEvents = [];
    window.huntwarden.subscribe((event) => {
      if (event.type === "agent_stream") window.__huntwardenStreamEvents?.push(event);
    });
  });
  const request = `E2E：${category} 只读调查`;
  const input: NewTaskInput = { request, mode: "SCAN", checks: [category], target };
  const task = await page.evaluate((value) => window.huntwarden.createTask(value), input);
  await page.locator(".sidebar-tasks button", { hasText: request }).click();
  await page.getByRole("button", { name: "开始调查" }).click();
  try {
    await expect.poll(async () => (await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId)).task.status, { timeout: 90_000 }).toMatch(/^(COMPLETED|FAILED)$/);
    expect((await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId)).task.status).toBe("COMPLETED");
  } catch (error) {
    const failed = await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId);
    console.error("GUI investigation failed", JSON.stringify({
      task: failed.task,
      conversation: failed.conversation.slice(-6),
      toolRuns: failed.toolRuns.slice(-8),
      audit: failed.audit.slice(-12),
    }, null, 2));
    throw error;
  }
  return {
    page,
    snapshot: await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId),
    streamEvents: await page.evaluate(() => window.__huntwardenStreamEvents ?? []),
  };
}

describe.skipIf(!enabled)("GUI 四场景只读调查与手动确认报告", () => {
  it.each([
    ["web-scan", 2222, "webshell"],
    ["java-scan", 2223, "java_memory_shell"],
    ["account-scan", 2224, "backdoor_account"],
    ["persistence-scan", 2225, "linux_persistence"],
  ] as const)("%s 完成 v2 Coverage/Assessment，并在确认后生成报告", async (scenario, port, category) => {
    const { page, snapshot: investigation, streamEvents } = await runInvestigation(scenario, port, category);
    expect(investigation.reports).toHaveLength(0);
    expect(await page.locator(".report-pending-banner").innerText()).toContain("报告待确认");
    const [tabs, content, composer] = await Promise.all([
      page.locator(".task-tabs").boundingBox(), page.locator(".task-content").boundingBox(), page.locator(".steering-composer").boundingBox(),
    ]);
    expect(tabs && content && composer).toBeTruthy();
    expect(tabs!.y + tabs!.height).toBeLessThanOrEqual(content!.y + 1);
    expect(content!.y + content!.height).toBeLessThanOrEqual(composer!.y + 1);
    const scrollRegions = await page.evaluate(() => {
      const browser = globalThis as unknown as {
        document: { querySelector(selector: string): unknown };
        getComputedStyle(element: unknown): { overflowY: string; scrollbarGutter: string };
      };
      const taskContent = browser.document.querySelector(".task-content");
      const taskList = browser.document.querySelector(".sidebar-tasks");
      if (!taskContent || !taskList) throw new Error("任务滚动区域缺失");
      const contentStyle = browser.getComputedStyle(taskContent);
      const listStyle = browser.getComputedStyle(taskList);
      return {
        contentOverflow: contentStyle.overflowY,
        contentGutter: contentStyle.scrollbarGutter,
        listOverflow: listStyle.overflowY,
        listGutter: listStyle.scrollbarGutter,
      };
    });
    expect(scrollRegions).toMatchObject({ contentOverflow: "scroll", listOverflow: "scroll" });
    expect(scrollRegions.contentGutter).toContain("stable");
    expect(scrollRegions.listGutter).toContain("stable");
    if (scenario === "web-scan") {
      await page.evaluate(async ({ target }) => {
        for (let index = 0; index < 20; index += 1) {
          await window.huntwarden.createTask({
            request: `E2E：侧栏滚动任务 ${index + 1}`,
            mode: "SCAN",
            checks: ["webshell"],
            target,
          });
        }
      }, { target: investigation.task.target });
      await expect.poll(async () => await page.locator(".sidebar-tasks button").count()).toBeGreaterThanOrEqual(21);
      const listScroll = await page.evaluate(() => {
        const browser = globalThis as unknown as { document: { querySelector(selector: string): unknown } };
        const taskList = browser.document.querySelector(".sidebar-tasks") as { clientHeight: number; scrollHeight: number; scrollTop: number } | null;
        if (!taskList) throw new Error("调查任务列表缺失");
        taskList.scrollTop = taskList.scrollHeight;
        return { clientHeight: taskList.clientHeight, scrollHeight: taskList.scrollHeight, scrollTop: taskList.scrollTop };
      });
      expect(listScroll.scrollHeight).toBeGreaterThan(listScroll.clientHeight);
      expect(listScroll.scrollTop).toBeGreaterThan(0);
    }
    page.once("dialog", async (dialog) => await dialog.accept());
    await page.getByRole("button", { name: "确认并生成报告" }).click();
    try {
      await expect.poll(async () => (await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), investigation.task.taskId)).reports.length, { timeout: 30_000 }).toBe(1);
    } catch (error) {
      const failed = await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), investigation.task.taskId);
      console.error("GUI report generation failed", JSON.stringify({ task: failed.task, audit: failed.audit.slice(-12) }, null, 2));
      throw error;
    }
    const result = await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), investigation.task.taskId);
    expect(result.task.protocolVersion).toBe(2);
    expect(result.protocolV2?.coverage.some((coverage) => coverage.category === category)).toBe(true);
    expect(result.protocolV2?.assessments.some((assessment) => assessment.category === category && assessment.authorType === "MODEL" && assessment.verdict === "SUSPICIOUS")).toBe(true);
    expect(result.protocolV2?.assessments.some((assessment) => assessment.category === category && assessment.authorType === "MODEL" && assessment.scope === "OBSERVED_CATEGORY")).toBe(true);
    if (scenario === "web-scan") expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.approvals).toHaveLength(0);
    expect(result.actionReceipts).toHaveLength(0);
    expect(result.reports).toMatchObject([{ version: 1 }]);
    expect(result.reports[0]?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.audit.map((event) => event.event)).toContain("report_generation_requested_by_analyst");
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "start")).toBe(true);
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "delta" && Boolean(event.delta))).toBe(true);
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "end")).toBe(true);

    page.once("dialog", async (dialog) => await dialog.accept());
    await page.getByRole("button", { name: "归档", exact: true }).click();
    await expect.poll(async () => await page.locator(".sidebar-tasks button", { hasText: result.task.request }).count()).toBe(0);
    await page.locator(".sidebar-label").getByRole("button", { name: "查看已归档任务" }).click();
    await expect.poll(async () => await page.locator(".sidebar-tasks button", { hasText: result.task.request }).count()).toBe(1);
    await page.getByRole("button", { name: "恢复归档" }).click();
    await expect.poll(async () => await page.locator(".sidebar-tasks button", { hasText: result.task.request }).count()).toBe(0);
    await page.locator(".sidebar-label").getByRole("button", { name: "返回当前任务" }).click();
    await expect.poll(async () => await page.locator(".sidebar-tasks button", { hasText: result.task.request }).count()).toBe(1);
    const restored = await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), result.task.taskId);
    expect(restored.task.archivedAt).toBeUndefined();
    expect(restored.audit.map((event) => event.event)).toEqual(expect.arrayContaining(["task_archived", "task_restored_from_archive"]));
  }, 150_000);
});
