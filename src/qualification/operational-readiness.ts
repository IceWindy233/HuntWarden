import { createHash } from "node:crypto";
import { chmod, copyFile, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import { EvidenceStore } from "../evidence/evidence-store.js";
import { RUNTIME_SCHEMA_VERSION, RuntimeStore } from "../storage/runtime-store.js";

const Strict = { additionalProperties: false } as const;
export const OperationalHostResultSchema = Type.Object({
  schemaVersion: Type.Literal(1),
  status: Type.Literal("PASS"),
  commit: Type.String({ pattern: "^[a-f0-9]{40}$" }),
  helperSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  scriptSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  evaluatedAt: Type.String({ minLength: 20, maxLength: 64 }),
  platform: Type.Object({
    distribution: Type.String({ minLength: 1, maxLength: 128 }),
    version: Type.String({ minLength: 1, maxLength: 128 }),
    architecture: Type.String({ minLength: 1, maxLength: 128 }),
  }, Strict),
  install: Type.Object({
    freshInstall: Type.Literal(true),
    upgrade: Type.Literal(true),
    permissions: Type.Literal(true),
    componentDigests: Type.Literal(true),
    receiptPreserved: Type.Literal(true),
  }, Strict),
  uninstall: Type.Object({
    defaultPreservedState: Type.Literal(true),
    purgeRemovedState: Type.Literal(true),
    credentialsAbsent: Type.Literal(true),
    targetJobsAbsent: Type.Literal(true),
  }, Strict),
  failures: Type.Tuple([]),
}, Strict);
export type OperationalHostResult = Static<typeof OperationalHostResultSchema>;

export interface OperationalReadinessInput {
  commit: string;
  expectedHelperSha256: string;
  expectedScriptSha256: string;
  baseDir: string;
  databaseFile: string;
  taskId: string;
  outputDirectory: string;
  host: OperationalHostResult;
  evaluatedAt?: string;
}

export interface OperationalReadinessResult {
  schemaVersion: 1;
  status: "PASS" | "FAIL";
  commit: string;
  evaluatedAt: string;
  runtimeSchemaVersion: number;
  helperSha256: string;
  host: OperationalHostResult;
  migration: { fromVersion: number; toVersion: number; backupSha256: string | null; oldTaskReadable: boolean; rollbackVerified: boolean };
  evidenceExport: { evidenceCount: number; artifactCount: number; manifestSha256: string | null; checksumsVerified: boolean; sensitiveFieldsAbsent: boolean };
  failures: string[];
}

export function parseOperationalHostResult(value: unknown): OperationalHostResult {
  const errors = [...Value.Errors(OperationalHostResultSchema, value)];
  if (errors.length > 0) throw new Error(`安装/卸载验收结果无效:\n${errors.map((item) => `${item.instancePath || "/"}: ${item.message}`).join("\n")}`);
  const result = structuredClone(value) as OperationalHostResult;
  if (!Number.isFinite(Date.parse(result.evaluatedAt))) throw new Error("安装/卸载验收时间无效");
  return result;
}

export async function runOperationalReadiness(input: OperationalReadinessInput): Promise<OperationalReadinessResult> {
  const failures: string[] = [];
  const databasePath = join(input.baseDir, input.databaseFile);
  const probe = new DatabaseSync(databasePath, { readOnly: true });
  const versionRow = probe.prepare("PRAGMA user_version").get() as { user_version?: number };
  const fromVersion = Number(versionRow.user_version ?? 0);
  probe.close();
  let store: RuntimeStore | undefined;
  let backupSha256: string | null = null;
  let oldTaskReadable = false;
  let rollbackVerified = false;
  let evidenceExport: OperationalReadinessResult["evidenceExport"] = {
    evidenceCount: 0, artifactCount: 0, manifestSha256: null, checksumsVerified: false, sensitiveFieldsAbsent: false,
  };
  try {
    store = await RuntimeStore.open(input.baseDir, input.databaseFile);
    oldTaskReadable = Boolean(store.getTask(input.taskId));
    const backupPath = store.migrationBackupPath;
    if (backupPath) backupSha256 = await sha256File(backupPath);
    else failures.push("迁移没有生成事务前备份");
    const exported = await new EvidenceStore(input.baseDir, store).exportTask(input.taskId, input.outputDirectory);
    const manifest = await readFile(exported.manifestPath, "utf8");
    evidenceExport = {
      evidenceCount: exported.evidenceCount,
      artifactCount: exported.artifactCount,
      manifestSha256: exported.manifestSha256,
      checksumsVerified: await verifyChecksums(exported.directory),
      sensitiveFieldsAbsent: !/(?:storagePath|privateKey|credential|secret|token|id_ed25519|known_hosts|\/Users\/|\/home\/)/i.test(manifest),
    };
    store.close(); store = undefined;
    if (backupPath) {
      const migratedPath = `${databasePath}.migrated`;
      await copyFile(databasePath, migratedPath);
      try {
        await rm(`${databasePath}-wal`, { force: true });
        await rm(`${databasePath}-shm`, { force: true });
        await copyFile(backupPath, databasePath);
        await chmod(databasePath, 0o600);
        const restored = new DatabaseSync(databasePath, { readOnly: true });
        try {
          const quick = restored.prepare("PRAGMA quick_check").get() as { quick_check?: string };
          const restoredVersionRow = restored.prepare("PRAGMA user_version").get() as { user_version?: number };
          const taskTable = restored.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'").get();
          const restoredTask = taskTable ? restored.prepare("SELECT payload FROM tasks WHERE task_id=?").get(input.taskId) : undefined;
          rollbackVerified = quick.quick_check === "ok" && Number(restoredVersionRow.user_version ?? -1) === fromVersion && Boolean(restoredTask) && JSON.parse(String((restoredTask as { payload?: string }).payload)).taskId === input.taskId;
        } finally { restored.close(); }
      } finally {
        await copyFile(migratedPath, databasePath);
        await chmod(databasePath, 0o600);
        await rm(migratedPath, { force: true });
      }
      const reopened = await RuntimeStore.open(input.baseDir, input.databaseFile);
      try {
        if (reopened.getSchemaVersion() !== RUNTIME_SCHEMA_VERSION || !reopened.getTask(input.taskId)) failures.push("回退演练后迁移数据库不可重新打开或旧任务不可读");
      } finally { reopened.close(); }
    }
  } finally {
    store?.close();
  }
  if (!Number.isSafeInteger(fromVersion) || fromVersion < 0 || fromVersion >= RUNTIME_SCHEMA_VERSION) failures.push("演练数据库必须来自受支持的旧 schema");
  if (!/^[a-f0-9]{40}$/.test(input.commit)) failures.push("提交不是完整 Git SHA-1");
  if (input.host.commit !== input.commit) failures.push("安装/卸载验收提交与控制端不一致");
  if (input.host.helperSha256 !== input.expectedHelperSha256) failures.push("安装/卸载验收未绑定当前 Helper 摘要");
  if (input.host.scriptSha256 !== input.expectedScriptSha256) failures.push("安装/卸载验收未绑定当前演练脚本摘要");
  if (!oldTaskReadable || !rollbackVerified) failures.push("旧任务读取或数据库回退验收未通过");
  if (evidenceExport.evidenceCount < 1 || evidenceExport.artifactCount < 1 || !evidenceExport.checksumsVerified || !evidenceExport.sensitiveFieldsAbsent) failures.push("Evidence 离线导出内容、摘要或脱敏验收未通过");
  return {
    schemaVersion: 1, status: failures.length === 0 ? "PASS" : "FAIL", commit: input.commit,
    evaluatedAt: input.evaluatedAt ?? new Date().toISOString(), runtimeSchemaVersion: RUNTIME_SCHEMA_VERSION,
    helperSha256: input.expectedHelperSha256, host: input.host,
    migration: { fromVersion, toVersion: RUNTIME_SCHEMA_VERSION, backupSha256, oldTaskReadable, rollbackVerified },
    evidenceExport,
    failures,
  };
}

async function verifyChecksums(directory: string): Promise<boolean> {
  const content = await readFile(join(directory, "SHA256SUMS"), "utf8");
  for (const line of content.trim().split("\n")) {
    const match = /^([a-f0-9]{64})\s{2}(.+)$/.exec(line);
    if (!match) return false;
    const path = join(directory, match[2]!);
    if (!(await stat(path)).isFile() || await sha256File(path) !== match[1]) return false;
  }
  return true;
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}
