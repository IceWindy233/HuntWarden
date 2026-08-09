import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createModels } from "@earendil-works/pi-ai";
import { fauxProvider } from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigProfileService } from "../../src/config/profile-service.js";
import { DesktopCredentialStore, EncryptedCredentialStore, type SecretCipher } from "../../src/credentials/credential-store.js";
import { DesktopBackend } from "../../src/desktop/backend.js";
import type { DesktopEvent } from "../../src/gui/contracts.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testConfig, testTask } from "../helpers.js";

class TestCipher implements SecretCipher {
  async encrypt(value: string): Promise<string> { return Buffer.from(value).toString("base64"); }
  async decrypt(value: string): Promise<string> { return Buffer.from(value, "base64").toString(); }
  async isSecure(): Promise<boolean> { return true; }
  async backend(): Promise<string> { return "test-secure"; }
}

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("DesktopBackend 通知去重", () => {
  it("归档历史任务时不把已有 Finding 和 Evidence 重新通知为新增", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-notification-baseline-"));
    directories.push(directory);
    const runtimeDir = join(directory, "runtime");
    const config = testConfig(runtimeDir);
    const profiles = new ConfigProfileService(join(directory, "configuration"));
    await profiles.initialize();
    await profiles.save({ profileId: "test", name: "Test", config });
    await profiles.activate("test");

    const store = await RuntimeStore.open(runtimeDir, "runtime.db");
    const task = { ...testTask(), status: "COMPLETED" as const };
    store.createTask(task);
    store.putFinding({
      findingId: "FIND-HISTORICAL", taskId: task.taskId, host: task.target.host,
      category: "webshell", severity: "INFO", confidence: 1, status: "NO_FINDING",
      title: "历史 Finding", summary: "已经在上一次进程中通知", evidenceRefs: [],
      createdAt: new Date().toISOString(), toolCallId: "call-historical",
    });
    store.putEvidence({
      evidenceId: "EV-HISTORICAL", taskId: task.taskId, host: task.target.host,
      type: "json", source: "history", collectedAt: new Date().toISOString(), tool: "historical_tool",
    });
    store.appendAudit({ taskId: task.taskId, event: "historical_event", level: "info", data: {} });
    store.close();

    const faux = fauxProvider({ tokensPerSecond: 0 });
    const models = createModels();
    models.setProvider(faux.provider);
    const persistent = new EncryptedCredentialStore(join(directory, "credentials.enc.json"), new TestCipher());
    const backend = new DesktopBackend({
      userDataDir: directory,
      projectRoot: resolve("."),
      appVersion: "test",
      platform: "darwin",
      credentials: new DesktopCredentialStore(persistent),
      modelBundleFactory: () => ({ models, model: faux.getModel() }),
    });
    await backend.initialize();
    const events: DesktopEvent[] = [];
    backend.on("event", (event: DesktopEvent) => events.push(event));

    try {
      backend.archiveTask(task.taskId);
      backend.restoreTask(task.taskId);
      expect(events.filter((event) => event.type === "finding_recorded")).toHaveLength(0);
      expect(events.filter((event) => event.type === "evidence_recorded")).toHaveLength(0);
      expect(events.filter((event) => event.type === "audit_recorded").map((event) => event.event.event)).toEqual([
        "task_archived", "task_restored_from_archive",
      ]);
    } finally {
      await backend.close();
    }
  });
});
