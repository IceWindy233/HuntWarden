import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportService } from "../../src/report/report-service.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import type { SecurityAgentRuntime } from "../../src/runtime/security-agent-runtime.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-report-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  const task = testTask();
  task.protocolVersion = 2;
  task.checks = ["webshell"];
  task.activeEpochId = "EPOCH-00000000-0000-4000-8000-000000000041";
  store.createTask(task);
  const epoch: ScanEpoch = { epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "2.1.0", helperVersion: "2.1.0", reason: "INITIAL", status: "PARTIAL", startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() };
  store.createScanEpoch(epoch);
  store.putCoverageRun({ coverageId: "COV-00000000-0000-4000-8000-000000000041", taskId: task.taskId, epochId: epoch.epochId, category: "webshell", presetId: "webshell-baseline", presetVersion: "2.0.0", status: "PARTIAL", applicability: "APPLICABLE", completedCriteria: ["web-root"], missingCriteria: [{ criterion: "web-log", reasonCode: "CAPABILITY_UNAVAILABLE" }], createdAt: new Date().toISOString() });
  store.putAssessment({ assessmentId: "ASM-00000000-0000-4000-8000-000000000041", taskId: task.taskId, epochId: epoch.epochId, authorType: "RULE", category: "webshell", scope: "OBSERVED_CATEGORY", verdict: "INCONCLUSIVE", severity: "INFO", confidence: 0.5, rationale: "日志覆盖不完整", evidenceRefs: [], factRefs: [], queryRefs: [], createdAt: new Date().toISOString() });
  store.putInvestigationGap({ gapId: "IGAP-00000000-0000-4000-8000-000000000041", taskId: task.taskId, epochId: epoch.epochId, category: "webshell", code: "MODEL_DID_NOT_INVESTIGATE", reasonCode: "NORMAL_SKIP", createdAt: new Date().toISOString() });
  return { directory, store, task };
}

describe("ReportService v2", () => {
  it("INV-14/INV-20：模型报告校验失败后回退确定性投影，并保留 Coverage/Assessment/Gap", async () => {
    const { directory, store, task } = await fixture();
    store.appendAudit({ taskId: task.taskId, event: "recovery_completed", level: "info", data: {} });
    const promptWithoutTools = vi.fn(async () => undefined);
    const runtime = { promptWithoutTools, lastAssistantText: () => "# 无效报告" } as unknown as SecurityAgentRuntime;
    const report = await new ReportService(directory, store).generate(task, runtime);
    const markdown = await readFile(report.path, "utf8");

    expect(promptWithoutTools).toHaveBeenCalledTimes(2);
    expect(markdown).toContain("COV-00000000-0000-4000-8000-000000000041 / PARTIAL / APPLICABLE / INCOMPLETE");
    expect(markdown).toContain("MODEL: NOT_CONCLUDED");
    expect(markdown).toContain("ASM-00000000-0000-4000-8000-000000000041");
    expect(markdown).toContain("IGAP-00000000-0000-4000-8000-000000000041");
    expect(report.generationMode).toBe("FALLBACK");
    expect((await stat(report.path)).mode & 0o777).toBe(0o600);
    store.close();
  });

  it("INV-20：拒绝投影外的 v2 引用", async () => {
    const { directory, store, task } = await fixture();
    const service = new ReportService(directory, store);
    const valid = [task.activeEpochId, "COV-00000000-0000-4000-8000-000000000041 PARTIAL APPLICABLE", "MODEL: NOT_CONCLUDED", "ASM-00000000-0000-4000-8000-000000000041 INCONCLUSIVE", "IGAP-00000000-0000-4000-8000-000000000041 MODEL_DID_NOT_INVESTIGATE", "INCOMPLETE"].join("\n");
    expect(service.validate(task.taskId, valid).valid).toBe(true);
    expect(service.validate(task.taskId, `${valid}\nFACT-00000000-0000-4000-8000-999999999999`).valid).toBe(true);
    const invalid = `${valid}\nASM-00000000-0000-4000-8000-999999999999\nEV-00000000-0000-4000-8000-999999999999`;
    expect(service.validate(task.taskId, invalid)).toMatchObject({ valid: false, errors: expect.arrayContaining([expect.stringContaining("未知 Assessment"), expect.stringContaining("未知 Evidence")]) });
    store.close();
  });

  it("v1 历史报告只读导入，禁止生成新版本", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-legacy-report-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const reportDir = join(directory, "reports");
    await mkdir(reportDir, { recursive: true });
    const legacyPath = join(reportDir, `${task.taskId}.md`);
    await writeFile(legacyPath, "# legacy", "utf8");
    const service = new ReportService(directory, store);
    expect(await service.list(task.taskId)).toMatchObject([{ version: 1, generationMode: "LEGACY", path: legacyPath }]);
    await expect(service.generate(task, {} as SecurityAgentRuntime)).rejects.toThrow(/v1 历史任务只读/);
    expect(await readFile(legacyPath, "utf8")).toBe("# legacy");
    store.close();
  });
});
