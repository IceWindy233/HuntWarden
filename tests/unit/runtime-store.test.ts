import { DatabaseSync } from "node:sqlite";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { RUNTIME_SCHEMA_VERSION, RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("RuntimeStore", () => {
  it("数据库以 0600 权限创建", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-store-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    store.createTask(testTask());
    expect((await stat(store.databasePath)).mode & 0o777).toBe(0o600);
    store.close();
  });

  it("同一数据库只允许一个写实例并可清理已释放锁", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-lock-"));
    directories.push(directory);
    const first = await RuntimeStore.open(directory, "runtime.db");
    await expect(RuntimeStore.open(directory, "runtime.db")).rejects.toThrow(/写锁/);
    first.close();
    expect(() => first.close()).not.toThrow();
    const second = await RuntimeStore.open(directory, "runtime.db");
    second.close();
  });

  it("无版本旧库在事务迁移前创建一致性备份并保留任务", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-migration-"));
    directories.push(directory);
    const databasePath = join(directory, "runtime.db");
    const legacy = new DatabaseSync(databasePath);
    const task = testTask();
    legacy.exec("CREATE TABLE tasks(task_id TEXT PRIMARY KEY,status TEXT NOT NULL,updated_at TEXT NOT NULL,payload TEXT NOT NULL)");
    legacy.prepare("INSERT INTO tasks(task_id,status,updated_at,payload) VALUES(?,?,?,?)").run(task.taskId, task.status, task.updatedAt, JSON.stringify(task));
    legacy.close();

    const migrated = await RuntimeStore.open(directory, "runtime.db");
    expect(migrated.getSchemaVersion()).toBe(RUNTIME_SCHEMA_VERSION);
    expect(migrated.listSchemaMigrations().map((item) => item.version)).toEqual([1, 2, 3, 4, 5]);
    expect(migrated.getTask(task.taskId)?.taskId).toBe(task.taskId);
    expect(migrated.migrationBackupPath).toMatch(/pre-migration-v0/);
    expect((await stat(migrated.migrationBackupPath!)).size).toBeGreaterThan(0);
    migrated.close();

    const reopened = await RuntimeStore.open(directory, "runtime.db");
    expect(reopened.migrationBackupPath).toBeUndefined();
    expect(reopened.listSchemaMigrations()).toHaveLength(5);
    reopened.close();
  });

  it("v2 调查义务表升级时回填 dedupeKey 并建立唯一约束", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-migration-v2-"));
    directories.push(directory);
    const databasePath = join(directory, "runtime.db");
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      PRAGMA user_version=2;
      CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
      CREATE TABLE investigation_obligations(
        obligation_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, epoch_id TEXT NOT NULL,
        hypothesis_id TEXT, obligation_kind TEXT NOT NULL, required INTEGER NOT NULL,
        status TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      INSERT INTO investigation_obligations VALUES(
        'OBL-legacy', 'TASK-legacy', 'EPOCH-legacy', NULL, 'CHECK_ALTERNATIVE', 1,
        'OPEN', '{"obligationId":"OBL-legacy","dedupeKey":"subject:alternative"}',
        '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'
      );
    `);
    legacy.close();

    const migrated = await RuntimeStore.open(directory, "runtime.db");
    expect(migrated.getSchemaVersion()).toBe(5);
    expect(migrated.migrationBackupPath).toMatch(/pre-migration-v2/);
    migrated.close();

    const verify = new DatabaseSync(databasePath);
    const row = verify.prepare("SELECT dedupe_key FROM investigation_obligations WHERE obligation_id='OBL-legacy'").get();
    expect(row).toEqual({ dedupe_key: "subject:alternative" });
    expect(() => verify.prepare("INSERT INTO investigation_obligations(obligation_id,task_id,epoch_id,obligation_kind,dedupe_key,required,status,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
      .run("OBL-duplicate", "TASK-legacy", "EPOCH-legacy", "CHECK_ALTERNATIVE", "subject:alternative", 1, "OPEN", "{}", "2026-01-01", "2026-01-01")).toThrow();
    verify.close();
  });

  it("v4 ToolRun 升级后保留旧记录为无 Epoch，并让新记录显式绑定 Epoch", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-migration-v4-"));
    directories.push(directory);
    const databasePath = join(directory, "runtime.db");
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      PRAGMA user_version=4;
      CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
      CREATE TABLE tool_runs(
        tool_call_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, tool_name TEXT NOT NULL,
        risk TEXT NOT NULL, replay_policy TEXT NOT NULL, status TEXT NOT NULL,
        args_json TEXT NOT NULL, result_json TEXT, error TEXT, started_at TEXT NOT NULL, finished_at TEXT
      );
      INSERT INTO tool_runs(tool_call_id,task_id,tool_name,risk,replay_policy,status,args_json,started_at)
      VALUES('LEGACY-RUN','TASK-LEGACY','enumerate','READ','SAFE_REOBSERVE','SUCCEEDED','{}','2026-01-01T00:00:00.000Z');
      CREATE TABLE messages(
        message_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, seq INTEGER NOT NULL, payload TEXT NOT NULL,
        created_at TEXT NOT NULL, UNIQUE(task_id,seq)
      );
      INSERT INTO messages VALUES('LEGACY-MESSAGE','TASK-LEGACY',1,'{"role":"user","content":"old","timestamp":1}','2026-01-01T00:00:00.000Z');
      CREATE TABLE queued_inputs(
        input_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL,
        created_at TEXT NOT NULL, delivered_at TEXT
      );
      INSERT INTO queued_inputs VALUES('LEGACY-INPUT','TASK-LEGACY','PENDING','{"role":"user","content":"old","timestamp":1}','2026-01-01T00:00:00.000Z',NULL);
    `);
    legacy.close();

    const migrated = await RuntimeStore.open(directory, "runtime.db");
    expect(migrated.getSchemaVersion()).toBe(5);
    expect(migrated.migrationBackupPath).toMatch(/pre-migration-v4/);
    expect(migrated.getToolRun("LEGACY-RUN")?.epochId).toBeUndefined();
    expect(migrated.loadMessages("TASK-LEGACY")).toHaveLength(1);
    expect(migrated.loadMessages("TASK-LEGACY", "EPOCH-CURRENT")).toHaveLength(0);
    expect(migrated.listPendingInputs("TASK-LEGACY")).toHaveLength(1);
    expect(migrated.listPendingInputs("TASK-LEGACY", "EPOCH-CURRENT")).toHaveLength(0);
    migrated.startToolRun({ toolCallId: "CURRENT-RUN", taskId: "TASK-CURRENT", epochId: "EPOCH-CURRENT", toolName: "query_facts", risk: "LOCAL", replayPolicy: "IDEMPOTENT_LOCAL", args: {} });
    migrated.appendMessage("TASK-CURRENT", { role: "user", content: "current", timestamp: 2 }, "EPOCH-CURRENT");
    migrated.enqueueInput("TASK-CURRENT", { role: "user", content: "current", timestamp: 3 }, "EPOCH-CURRENT");
    expect(migrated.getToolRun("CURRENT-RUN")?.epochId).toBe("EPOCH-CURRENT");
    expect(migrated.loadMessages("TASK-CURRENT", "EPOCH-CURRENT")).toHaveLength(1);
    expect(migrated.listPendingInputs("TASK-CURRENT", "EPOCH-CURRENT")).toHaveLength(1);
    migrated.close();

    const verify = new DatabaseSync(databasePath, { readOnly: true });
    expect((verify.prepare("SELECT epoch_id FROM tool_runs WHERE tool_call_id='LEGACY-RUN'").get() as { epoch_id: null }).epoch_id).toBeNull();
    expect((verify.prepare("SELECT epoch_id FROM tool_runs WHERE tool_call_id='CURRENT-RUN'").get() as { epoch_id: string }).epoch_id).toBe("EPOCH-CURRENT");
    expect((verify.prepare("SELECT epoch_id FROM messages WHERE message_id='LEGACY-MESSAGE'").get() as { epoch_id: null }).epoch_id).toBeNull();
    expect((verify.prepare("SELECT epoch_id FROM queued_inputs WHERE input_id='LEGACY-INPUT'").get() as { epoch_id: null }).epoch_id).toBeNull();
    verify.close();
  });

  it("未来 schema 版本在任何写入或迁移前被拒绝", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-future-schema-"));
    directories.push(directory);
    const future = new DatabaseSync(join(directory, "runtime.db"));
    future.exec(`PRAGMA user_version=${RUNTIME_SCHEMA_VERSION + 1}; CREATE TABLE future_data(value TEXT); INSERT INTO future_data VALUES('preserve-me')`);
    future.close();
    await expect(RuntimeStore.open(directory, "runtime.db")).rejects.toThrow(/高于当前程序支持/);
    const verify = new DatabaseSync(join(directory, "runtime.db"), { readOnly: true });
    expect(verify.prepare("SELECT value FROM future_data").get()).toEqual({ value: "preserve-me" });
    verify.close();
  });

  it("迁移中途校验失败时回滚全部 schema 变更并保留可恢复备份", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-migration-rollback-"));
    directories.push(directory);
    const databasePath = join(directory, "runtime.db");
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      PRAGMA user_version=2;
      CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
      INSERT INTO schema_migrations VALUES(2,'tampered-migration','invalid-checksum','2026-01-01T00:00:00.000Z');
      CREATE TABLE migration_sentinel(value TEXT NOT NULL);
      INSERT INTO migration_sentinel VALUES('preserve-me');
    `);
    legacy.close();

    await expect(RuntimeStore.open(directory, "runtime.db")).rejects.toThrow(/摘要不匹配/);
    const verify = new DatabaseSync(databasePath, { readOnly: true });
    expect((verify.prepare("PRAGMA user_version").get() as { user_version: number }).user_version).toBe(2);
    expect(verify.prepare("SELECT value FROM migration_sentinel").get()).toEqual({ value: "preserve-me" });
    expect(verify.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_gaps_v2'").get()).toBeUndefined();
    verify.close();
    const files = await readdir(directory);
    expect(files.filter((name) => name.includes("pre-migration-v2") && name.endsWith(".bak"))).toHaveLength(1);
    expect(files.some((name) => name.endsWith(".partial"))).toBe(false);
    expect(files).not.toContain("runtime.db.writer.lock");
  });

  it("SQLite 容量耗尽时不提交半套 schema，原库和事务前备份仍可读取", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-migration-full-"));
    directories.push(directory);
    const databasePath = join(directory, "runtime.db");
    const legacy = new DatabaseSync(databasePath);
    legacy.exec(`
      CREATE TABLE migration_sentinel(value TEXT NOT NULL);
      INSERT INTO migration_sentinel VALUES('preserve-me');
      CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL);
      CREATE TRIGGER inject_sqlite_full BEFORE INSERT ON schema_migrations
      BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;
    `);
    legacy.close();

    await expect(RuntimeStore.open(directory, "runtime.db")).rejects.toThrow(/full|满|容量/i);
    const verify = new DatabaseSync(databasePath, { readOnly: true });
    expect((verify.prepare("PRAGMA user_version").get() as { user_version: number }).user_version).toBe(0);
    expect(verify.prepare("SELECT value FROM migration_sentinel").get()).toEqual({ value: "preserve-me" });
    expect(verify.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()).toEqual({ count: 0 });
    expect(verify.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_sessions'").get()).toBeUndefined();
    verify.close();
    const files = await readdir(directory);
    expect(files.filter((name) => name.includes("pre-migration-v0") && name.endsWith(".bak"))).toHaveLength(1);
    expect(files).not.toContain("runtime.db.writer.lock");
  });

  it("Evidence 落盘后按 toolCallId 幂等恢复", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const evidence = new EvidenceStore(directory, store);
    const input = { taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/item", tool: "collect_file", toolCallId: "call-evidence", data: Buffer.from("evidence") };
    const first = await evidence.putBuffer(input);
    const second = await evidence.putBuffer(input);
    expect(second.evidenceId).toBe(first.evidenceId);
    expect(store.listEvidence(task.taskId)).toHaveLength(1);
    store.close();
  });

  it("ToolCall ID 只能复用完全相同的 task、Epoch、工具、策略和参数绑定", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-toolrun-binding-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const input = {
      toolCallId: "CALL-BOUND",
      taskId: task.taskId,
      epochId: "EPOCH-A",
      toolName: "enumerate",
      risk: "READ",
      replayPolicy: "SAFE_REOBSERVE",
      args: { namespace: "process", limit: 10 },
    };
    const first = store.startToolRun(input);
    expect(store.startToolRun(input)).toEqual(first);
    expect(store.getToolRunForScope(task.taskId, "EPOCH-A", input.toolCallId)).toEqual(first);
    expect(store.getToolRunForScope(task.taskId, "EPOCH-B", input.toolCallId)).toBeUndefined();
    expect(() => store.startToolRun({ ...input, epochId: "EPOCH-B" })).toThrow(/拒绝复用/);
    expect(() => store.startToolRun({ ...input, args: { namespace: "process", limit: 11 } })).toThrow(/拒绝复用/);
    expect(() => store.startToolRun({ ...input, taskId: "TASK-B" })).toThrow(/拒绝复用/);
    expect(store.getToolRun(input.toolCallId)).toEqual(first);
    store.close();
  });

  it("Evidence 幂等恢复核对 Epoch、来源和实际内容", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-binding-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);
    const evidence = new EvidenceStore(directory, store);
    const input = {
      taskId: task.taskId,
      host: task.target.host,
      type: "file",
      source: "/tmp/bound",
      tool: "collect",
      toolCallId: "CALL-EVIDENCE-BOUND",
      data: Buffer.from("original"),
      metadata: { epochId: "EPOCH-A", complete: true },
    };
    const first = await evidence.putBuffer(input);
    expect((await evidence.putBuffer(input)).evidenceId).toBe(first.evidenceId);
    await expect(evidence.putBuffer({ ...input, metadata: { ...input.metadata, epochId: "EPOCH-B" } })).rejects.toThrow(/拒绝复用/);
    await expect(evidence.putBuffer({ ...input, source: "/tmp/other" })).rejects.toThrow(/拒绝复用/);
    await expect(evidence.putBuffer({ ...input, data: Buffer.from("changed") })).rejects.toThrow(/摘要冲突/);
    expect(store.listEvidence(task.taskId)).toHaveLength(1);
    store.close();
  });

  it("品牌迁移时只重写受管 Evidence 路径前缀", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-evidence-migration-"));
    directories.push(directory);
    const legacyRoot = join(directory, "SecHostAgent", "runtime");
    const currentRoot = join(directory, "HuntWarden", "runtime");
    const store = await RuntimeStore.open(join(directory, "database"), "runtime.db");
    const task = testTask();
    store.createTask(task);
    const evidence = new EvidenceStore(legacyRoot, store);
    const created = await evidence.putBuffer({ taskId: task.taskId, host: task.target.host, type: "file", source: "/tmp/item", tool: "collect_file", toolCallId: "call-migration", data: Buffer.from("evidence") });
    expect(created.storagePath).toContain(join("SecHostAgent", "runtime"));
    expect(store.relocateEvidencePaths([legacyRoot], currentRoot)).toBe(1);
    expect(store.getEvidence(task.taskId, created.evidenceId)?.storagePath).toContain(join("HuntWarden", "runtime"));
    expect(store.relocateEvidencePaths([legacyRoot], currentRoot)).toBe(0);
    store.close();
  });

  it("启动对账将遗留活动任务标记为待人工恢复并使旧审批失效", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-interruption-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.status = "WAITING_APPROVAL";
    task.protocolVersion = 2;
    task.activeEpochId = "EPOCH-INTERRUPTION";
    store.createTask(task);
    store.createScanEpoch({ epochId: task.activeEpochId, taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() });
    const approvals = new ApprovalService(store);
    const pending = approvals.request(task, "quarantine_file", { evidenceRef: "EV-test" });
    const approved = approvals.request(task, "disable_account", { accountRef: "ACCT-test" });
    approvals.decide(approved.approvalId, true);

    const reconciled = store.reconcileInterruptedTasks();
    expect(reconciled).toHaveLength(1);
    expect(store.getTask(task.taskId)).toMatchObject({
      status: "ABORTED",
      interruption: { previousStatus: "WAITING_APPROVAL", reason: "PROCESS_INTERRUPTED", recoveryRequired: true },
    });
    expect(store.listApprovals(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ approvalId: pending.approvalId, status: "EXPIRED" }),
      expect.objectContaining({ approvalId: approved.approvalId, status: "EXPIRED" }),
    ]));
    expect(() => approvals.decide(pending.approvalId, true)).toThrow(/失效/);
    expect(store.listAudit(task.taskId).at(-1)?.event).toBe("task_interrupted_detected");
    expect(store.reconcileInterruptedTasks()).toHaveLength(0);
    store.close();
  });
});
