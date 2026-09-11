import { DatabaseSync } from "node:sqlite";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { parseOperationalHostResult, runOperationalReadiness, type OperationalHostResult } from "../../src/qualification/operational-readiness.js";
import { RUNTIME_SCHEMA_VERSION, RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

function hostResult(commit: string, helperSha256: string, scriptSha256: string): OperationalHostResult {
  return {
    schemaVersion: 1,
    status: "PASS",
    commit,
    helperSha256,
    scriptSha256,
    evaluatedAt: "2026-09-10T00:00:00.000Z",
    platform: { distribution: "ubuntu", version: "24.04", architecture: "x86_64" },
    install: { freshInstall: true, upgrade: true, permissions: true, componentDigests: true, receiptPreserved: true },
    uninstall: { defaultPreservedState: true, purgeRemovedState: true, credentialsAbsent: true, targetJobsAbsent: true },
    failures: [],
  };
}

describe("运维发布资格", () => {
  it("迁移旧库、验证事务前回退并导出可离线核验的脱敏 Evidence", async () => {
    const root = await mkdtemp(join(tmpdir(), "huntwarden-operational-"));
    directories.push(root);
    const dataDir = join(root, "data");
    const exportDir = join(root, "export");
    const task = testTask();
    const runtime = await RuntimeStore.open(dataDir, "runtime.db");
    runtime.createTask(task);
    await new EvidenceStore(dataDir, runtime).putBuffer({
      taskId: task.taskId,
      host: task.target.host,
      type: "collected_object",
      source: "/tmp/forensic.bin",
      tool: "collect",
      toolCallId: "OPERATIONAL-COLLECT",
      data: Buffer.from("forensic-evidence"),
      metadata: {
        complete: true,
        nested: { secretToken: "must-not-export", privateKeyPath: "/home/operator/id_ed25519", storagePath: "/private/spool" },
      },
    });
    runtime.close();

    const legacy = new DatabaseSync(join(dataDir, "runtime.db"));
    legacy.exec(`PRAGMA user_version=${RUNTIME_SCHEMA_VERSION - 1}`);
    legacy.close();

    const commit = "a".repeat(40);
    const helperSha256 = "b".repeat(64);
    const scriptSha256 = "c".repeat(64);
    const result = await runOperationalReadiness({
      commit,
      expectedHelperSha256: helperSha256,
      expectedScriptSha256: scriptSha256,
      baseDir: dataDir,
      databaseFile: "runtime.db",
      taskId: task.taskId,
      outputDirectory: exportDir,
      host: hostResult(commit, helperSha256, scriptSha256),
      evaluatedAt: "2026-09-10T00:01:00.000Z",
    });

    expect(result).toMatchObject({
      status: "PASS",
      migration: { fromVersion: RUNTIME_SCHEMA_VERSION - 1, toVersion: RUNTIME_SCHEMA_VERSION, oldTaskReadable: true, rollbackVerified: true },
      evidenceExport: { evidenceCount: 1, artifactCount: 1, checksumsVerified: true, sensitiveFieldsAbsent: true },
      failures: [],
    });
    expect(result.migration.backupSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.evidenceExport.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    const manifest = await readFile(join(exportDir, "EVIDENCE-MANIFEST.json"), "utf8");
    expect(manifest).not.toContain("must-not-export");
    expect(manifest).not.toContain("privateKeyPath");
    expect(manifest).not.toContain("storagePath");
    expect(await readFile(join(exportDir, "SHA256SUMS"), "utf8")).toContain("EVIDENCE-MANIFEST.json");

    const reopened = await RuntimeStore.open(dataDir, "runtime.db");
    expect(reopened.getSchemaVersion()).toBe(RUNTIME_SCHEMA_VERSION);
    expect(reopened.getTask(task.taskId)?.taskId).toBe(task.taskId);
    reopened.close();
  });

  it("拒绝手写布尔值、未知字段和无效时间冒充目标端演练", () => {
    const valid = hostResult("a".repeat(40), "b".repeat(64), "c".repeat(64));
    expect(() => parseOperationalHostResult({ ...valid, install: { ...valid.install, upgrade: false } })).toThrow(/安装\/卸载验收结果无效/);
    expect(() => parseOperationalHostResult({ ...valid, manuallyApproved: true })).toThrow(/安装\/卸载验收结果无效/);
    expect(() => parseOperationalHostResult({ ...valid, evaluatedAt: "not-a-date-value-long-enough" })).toThrow(/时间无效/);
  });
});
