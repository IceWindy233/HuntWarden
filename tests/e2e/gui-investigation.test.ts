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

async function runInvestigation(scenario: E2eFauxScenario, port: number, category: CheckCategory): Promise<{ snapshot: TaskSnapshot; streamEvents: DesktopEvent[] }> {
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
  await expect.poll(async () => (await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId)).task.status, { timeout: 90_000 }).toBe("COMPLETED");
  return {
    snapshot: await page.evaluate((id) => window.huntwarden.getTaskSnapshot(id), task.taskId),
    streamEvents: await page.evaluate(() => window.__huntwardenStreamEvents ?? []),
  };
}

describe.skipIf(!enabled)("GUI 三场景只读调查与自动报告", () => {
  it.each([
    ["web-scan", 2222, "webshell"],
    ["java-scan", 2223, "java_memory_shell"],
    ["account-scan", 2224, "backdoor_account"],
    ["persistence-scan", 2225, "linux_persistence"],
  ] as const)("%s 完成 Finding、Evidence 与 v1 报告", async (scenario, port, category) => {
    const { snapshot: result, streamEvents } = await runInvestigation(scenario, port, category);
    expect(result.findings[0]?.category).toBe(category);
    expect(["CONFIRMED", "HIGHLY_SUSPICIOUS"]).toContain(result.findings[0]?.status);
    expect(result.evidence.length).toBeGreaterThan(0);
    expect(result.approvals).toHaveLength(0);
    expect(result.actionReceipts).toHaveLength(0);
    expect(result.reports).toMatchObject([{ version: 1 }]);
    expect(result.reports[0]?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "start")).toBe(true);
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "delta" && Boolean(event.delta))).toBe(true);
    expect(streamEvents.some((event) => event.type === "agent_stream" && event.phase === "end")).toBe(true);
  }, 150_000);
});
