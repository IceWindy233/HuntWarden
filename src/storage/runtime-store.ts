import { backup, DatabaseSync } from "node:sqlite";
import { chmod, mkdir, readFile, rename, unlink } from "node:fs/promises";
import { closeSync, existsSync, openSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import type {
  ActionReceipt,
  ApprovalStatus,
  ApprovalTicket,
  AuditEvent,
  Evidence,
  ReportRecord,
  TaskContext,
  TaskStatus,
} from "../domain/types.js";
import { digestObject } from "../common/json.js";
import { createId } from "../common/ids.js";
import { prepareFactBatch } from "../facts/normalizer.js";
import { runFactQuery, runStaticQuery, type FactQueryAst, type FactQueryCursor, type FactQueryPage, type StaticQueryCursor } from "../facts/query.js";
import { validateAssessment } from "../assessments/validation.js";
import type {
  Assessment,
  AssessmentRelation,
  CoverageRun,
  EdgeRecord,
  FactBatchInput,
  FactBatchResult,
  FactRecord,
  GrantRequest,
  InvestigationGap,
  NamespaceName,
  ObjectReference,
  QuerySnapshot,
  ScanEpoch,
  TaskGrant,
  WireCost,
} from "../protocol-v2/types.js";
import { InvalidArgumentError, SecurityError } from "../common/errors.js";
import type { KnownHashDataSet, KnownHashDataSetSummary } from "../datasets/known-hash-registry.js";
import { summarizeKnownHashDataSet } from "../datasets/known-hash-registry.js";
import type {
  CompletionSnapshot,
  DiscoveryCheckpoint,
  EntityVersion,
  InvestigationAction,
  InvestigationActionAttempt,
  InvestigationEvent,
  InvestigationHypothesis,
  InvestigationLead,
  InvestigationObligation,
  InvestigationSession,
  RelationProvenance,
} from "../investigation/types.js";

interface JsonRow { payload: string }
interface CountRow { count: number }

export const RUNTIME_SCHEMA_VERSION = 5;
export const MAX_ACTIVE_INVESTIGATION_ACTIONS = 1_000;

export interface SchemaMigrationRecord {
  version: number;
  name: string;
  checksum: string;
  appliedAt: string;
}

export interface BudgetAccountSnapshot {
  owner: "PRESET" | "MODEL" | "DISCOVERY";
  limits: WireCost;
  used: WireCost;
  reserved: WireCost;
  remaining: WireCost;
}

const budgetKeys = ["remoteCalls", "nodes", "bytes", "wallTimeMs", "probeCalls"] as const;
function addCost(left: WireCost, right: WireCost): WireCost {
  return {
    remoteCalls: left.remoteCalls + right.remoteCalls,
    nodes: left.nodes + right.nodes,
    bytes: left.bytes + right.bytes,
    wallTimeMs: left.wallTimeMs + right.wallTimeMs,
    probeCalls: (left.probeCalls ?? 0) + (right.probeCalls ?? 0),
  };
}
function subtractCost(left: WireCost, right: WireCost): WireCost {
  return {
    remoteCalls: Math.max(0, left.remoteCalls - right.remoteCalls),
    nodes: Math.max(0, left.nodes - right.nodes),
    bytes: Math.max(0, left.bytes - right.bytes),
    wallTimeMs: Math.max(0, left.wallTimeMs - right.wallTimeMs),
    probeCalls: Math.max(0, (left.probeCalls ?? 0) - (right.probeCalls ?? 0)),
  };
}

export interface ToolRunRecord {
  toolCallId: string;
  taskId: string;
  /** v2 调用所属 Epoch；v1 和迁移前记录为空，不能用于正式资格证据。 */
  epochId?: string;
  toolName: string;
  risk: string;
  replayPolicy: string;
  args: unknown;
  status: "STARTED" | "SUCCEEDED" | "FAILED" | "BLOCKED";
  result?: unknown;
  error?: string;
  startedAt: string;
  finishedAt?: string;
}

export class RuntimeStore {
  private readonly db: DatabaseSync;
  readonly databasePath: string;
  readonly migrationBackupPath: string | undefined;
  private lockFd: number | undefined;
  private readonly lockPath: string;
  private closed = false;

  private constructor(databasePath: string, lockFd: number, lockPath: string, migrationBackupPath?: string) {
    this.databasePath = databasePath;
    this.migrationBackupPath = migrationBackupPath;
    this.lockFd = lockFd;
    this.lockPath = lockPath;
    this.db = new DatabaseSync(databasePath);
    try {
      this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      this.migrate();
    } catch (error) {
      // 构造失败时实例不会返回给调用方，必须在这里关闭 SQLite 句柄。
      // 否则失败迁移仍可能占用 WAL/SHM，妨碍从事务前备份恢复。
      try { this.db.close(); } catch { /* 保留原始迁移错误 */ }
      throw error;
    }
  }

  static async open(baseDir: string, databaseFile: string): Promise<RuntimeStore> {
    await mkdir(baseDir, { recursive: true, mode: 0o700 });
    await chmod(baseDir, 0o700);
    const databasePath = join(baseDir, databaseFile);
    await mkdir(dirname(databasePath), { recursive: true, mode: 0o700 });
    const lockPath = `${databasePath}.writer.lock`;
    const lockFd = await RuntimeStore.acquireWriterLock(lockPath);
    const previousUmask = process.umask(0o077);
    let store: RuntimeStore;
    try {
      const migrationBackupPath = await RuntimeStore.prepareMigrationBackup(databasePath);
      store = new RuntimeStore(databasePath, lockFd, lockPath, migrationBackupPath);
    } catch (error) {
      closeSync(lockFd);
      await unlink(lockPath).catch(() => undefined);
      throw error;
    } finally {
      process.umask(previousUmask);
    }
    await chmod(databasePath, 0o600);
    await Promise.all([`${databasePath}-wal`, `${databasePath}-shm`].map((path) => chmod(path, 0o600).catch(() => undefined)));
    return store;
  }

  private static async prepareMigrationBackup(databasePath: string): Promise<string | undefined> {
    if (!existsSync(databasePath) || statSync(databasePath).size === 0) return undefined;
    const source = new DatabaseSync(databasePath);
    try {
      source.exec("PRAGMA busy_timeout=5000; PRAGMA wal_checkpoint(FULL);");
      const version = Number((source.prepare("PRAGMA user_version").get() as { user_version?: number } | undefined)?.user_version ?? 0);
      if (!Number.isSafeInteger(version) || version < 0) throw new Error("HuntWarden 数据库 schema 版本非法");
      if (version > RUNTIME_SCHEMA_VERSION) throw new Error(`数据库 schema v${version} 高于当前程序支持的 v${RUNTIME_SCHEMA_VERSION}，拒绝写入`);
      const tableCount = Number((source.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").get() as { count?: number } | undefined)?.count ?? 0);
      if (version === RUNTIME_SCHEMA_VERSION || tableCount === 0) return undefined;
      const destination = `${databasePath}.pre-migration-v${version}-${Date.now()}.bak`;
      const partial = `${destination}.partial`;
      try {
        await backup(source, partial);
        await chmod(partial, 0o600);
        const verification = new DatabaseSync(partial, { readOnly: true });
        try {
          const result = verification.prepare("PRAGMA quick_check").get() as { quick_check?: string } | undefined;
          if (result?.quick_check !== "ok") throw new Error("事务前数据库备份完整性校验失败");
        } finally {
          verification.close();
        }
        await rename(partial, destination);
      } catch (error) {
        await unlink(partial).catch(() => undefined);
        throw error;
      }
      return destination;
    } finally {
      source.close();
    }
  }

  private static async acquireWriterLock(lockPath: string): Promise<number> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const fd = openSync(lockPath, "wx", 0o600);
        writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }), { encoding: "utf8" });
        return fd;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        let ownerPid = 0;
        try { ownerPid = Number(JSON.parse(await readFile(lockPath, "utf8")).pid); } catch { ownerPid = 0; }
        let alive = ownerPid > 0;
        if (alive) {
          try { process.kill(ownerPid, 0); } catch (probeError) { alive = (probeError as NodeJS.ErrnoException).code === "EPERM"; }
        }
        if (alive) throw new Error(`HuntWarden 数据库已由 PID ${ownerPid} 持有写锁`);
        await unlink(lockPath).catch(() => undefined);
      }
    }
    throw new Error("无法获取 HuntWarden 单实例写锁");
  }

  private migrate(): void {
    const currentVersion = Number((this.db.prepare("PRAGMA user_version").get() as { user_version?: number } | undefined)?.user_version ?? 0);
    if (currentVersion > RUNTIME_SCHEMA_VERSION) throw new Error(`数据库 schema v${currentVersion} 高于当前程序支持的 v${RUNTIME_SCHEMA_VERSION}，拒绝写入`);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT,
        seq INTEGER NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(task_id, seq),
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS tool_runs (
        tool_call_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT,
        tool_name TEXT NOT NULL,
        risk TEXT NOT NULL,
        replay_policy TEXT NOT NULL,
        status TEXT NOT NULL,
        args_json TEXT NOT NULL,
        result_json TEXT,
        error TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS queued_inputs (
        input_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        delivered_at TEXT,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS evidence (
        evidence_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        args_digest TEXT NOT NULL,
        action_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS action_receipts (
        action_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS reports (
        report_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(task_id, version),
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS artifact_refs (
        ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        task_id TEXT,
        event TEXT NOT NULL,
        level TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scan_epochs (
        epoch_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        started_at TEXT NOT NULL,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS object_refs_v2 (
        ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        namespace TEXT NOT NULL,
        identity_digest TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(task_id,epoch_id,namespace,identity_digest),
        FOREIGN KEY(epoch_id) REFERENCES scan_epochs(epoch_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS facts_v2 (
        fact_seq INTEGER PRIMARY KEY AUTOINCREMENT,
        fact_id TEXT NOT NULL UNIQUE,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        namespace TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        source_run_id TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        private_payload TEXT NOT NULL,
        model_payload TEXT NOT NULL,
        payload TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        FOREIGN KEY(epoch_id) REFERENCES scan_epochs(epoch_id) ON DELETE CASCADE,
        FOREIGN KEY(subject_ref) REFERENCES object_refs_v2(ref)
      );
      CREATE TABLE IF NOT EXISTS fact_edges_v2 (
        edge_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        from_ref TEXT NOT NULL,
        to_ref TEXT NOT NULL,
        relation TEXT NOT NULL,
        source_run_id TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS fact_batches_v2 (
        batch_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        source_run_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status='COMMITTED'),
        first_fact_seq INTEGER,
        last_fact_seq INTEGER,
        fact_count INTEGER NOT NULL,
        edge_count INTEGER NOT NULL,
        committed_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS coverage_runs_v2 (
        coverage_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL,
        applicability TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS investigation_gaps_v2 (
        gap_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        code TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS assessments_v2 (
        assessment_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        author_type TEXT NOT NULL,
        category TEXT NOT NULL,
        subject_ref TEXT,
        verdict TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS assessment_relations_v2 (
        relation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        from_assessment_id TEXT NOT NULL,
        to_assessment_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS task_grants_v2 (
        grant_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS grant_requests_v2 (
        request_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS budget_accounts_v2 (
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        limits_json TEXT NOT NULL,
        used_json TEXT NOT NULL,
        reserved_json TEXT NOT NULL,
        PRIMARY KEY(task_id,epoch_id,owner)
      );
      CREATE TABLE IF NOT EXISTS budget_reservations_v2 (
        reservation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        status TEXT NOT NULL,
        estimate_json TEXT NOT NULL,
        actual_json TEXT,
        created_at TEXT NOT NULL,
        settled_at TEXT
      );
      CREATE TABLE IF NOT EXISTS usage_counters_v2 (
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        limit_value INTEGER NOT NULL,
        used_value INTEGER NOT NULL,
        PRIMARY KEY(task_id,epoch_id,kind)
      );
      CREATE TABLE IF NOT EXISTS query_snapshots_v2 (
        query_ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS query_cursors_v2 (
        cursor_ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS remote_cursors_v2 (
        cursor_ref TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        epoch_id TEXT NOT NULL,
        namespace TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS known_hash_datasets_v2 (
        data_set_ref TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        digest TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL,
        imported_at TEXT NOT NULL,
        UNIQUE(name, version)
      );
      CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
      CREATE INDEX IF NOT EXISTS idx_tool_runs_task ON tool_runs(task_id, status);
      CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id, seq);
      CREATE INDEX IF NOT EXISTS idx_reports_task ON reports(task_id, version);
      CREATE INDEX IF NOT EXISTS idx_epochs_task ON scan_epochs(task_id, started_at);
      CREATE INDEX IF NOT EXISTS idx_facts_scope ON facts_v2(task_id, epoch_id, fact_seq);
      CREATE INDEX IF NOT EXISTS idx_facts_run ON facts_v2(task_id, epoch_id, source_run_id);
      CREATE INDEX IF NOT EXISTS idx_assessments_scope ON assessments_v2(task_id, epoch_id, category, created_at);
    `);
      this.recordMigration(1, "baseline-runtime-and-protocol-v2", digestObject({ version: 1, schema: "baseline-runtime-and-protocol-v2" }));
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS investigation_sessions (
          session_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          engine_version TEXT NOT NULL,
          authorization_version TEXT NOT NULL,
          execution_status TEXT NOT NULL,
          investigation_status TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 0),
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(task_id, epoch_id),
          FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
          FOREIGN KEY(epoch_id) REFERENCES scan_epochs(epoch_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS entity_versions (
          version_ref TEXT PRIMARY KEY,
          entity_ref TEXT NOT NULL,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          namespace TEXT NOT NULL,
          identity_digest TEXT NOT NULL,
          content_digest TEXT,
          source_fact_ref TEXT NOT NULL,
          valid_from TEXT NOT NULL,
          valid_to TEXT,
          payload TEXT NOT NULL,
          UNIQUE(task_id, epoch_id, entity_ref, identity_digest, content_digest),
          FOREIGN KEY(entity_ref) REFERENCES object_refs_v2(ref),
          FOREIGN KEY(source_fact_ref) REFERENCES facts_v2(fact_id)
        );
        CREATE TABLE IF NOT EXISTS relation_provenance (
          edge_ref TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          from_version_ref TEXT,
          to_version_ref TEXT,
          derivation TEXT NOT NULL,
          resolver_version TEXT NOT NULL,
          time_error_ms INTEGER NOT NULL CHECK(time_error_ms >= 0),
          payload TEXT NOT NULL,
          FOREIGN KEY(edge_ref) REFERENCES fact_edges_v2(edge_id),
          FOREIGN KEY(from_version_ref) REFERENCES entity_versions(version_ref),
          FOREIGN KEY(to_version_ref) REFERENCES entity_versions(version_ref)
        );
        CREATE TABLE IF NOT EXISTS investigation_leads (
          lead_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          subject_ref TEXT NOT NULL,
          trigger_kind TEXT NOT NULL,
          trigger_version TEXT NOT NULL,
          observation_round TEXT NOT NULL,
          priority INTEGER NOT NULL,
          status TEXT NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(task_id, epoch_id, subject_ref, trigger_kind, trigger_version, observation_round)
        );
        CREATE TABLE IF NOT EXISTS investigation_hypotheses (
          hypothesis_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          subject_ref TEXT NOT NULL,
          status TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 0),
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_obligations (
          obligation_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          hypothesis_id TEXT,
          obligation_kind TEXT NOT NULL,
          dedupe_key TEXT NOT NULL,
          required INTEGER NOT NULL CHECK(required IN (0,1)),
          status TEXT NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(task_id, epoch_id, dedupe_key),
          FOREIGN KEY(hypothesis_id) REFERENCES investigation_hypotheses(hypothesis_id)
        );
        CREATE TABLE IF NOT EXISTS investigation_actions (
          action_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE,
          action_kind TEXT NOT NULL,
          operation_ref TEXT NOT NULL,
          authorization_version TEXT NOT NULL,
          status TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 0),
          priority INTEGER NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_action_attempts (
          attempt_id TEXT PRIMARY KEY,
          action_id TEXT NOT NULL,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          attempt INTEGER NOT NULL CHECK(attempt > 0),
          tool_call_id TEXT,
          status TEXT NOT NULL,
          payload TEXT NOT NULL,
          started_at TEXT NOT NULL,
          finished_at TEXT,
          UNIQUE(action_id, attempt),
          FOREIGN KEY(action_id) REFERENCES investigation_actions(action_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS investigation_events (
          event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id TEXT NOT NULL UNIQUE,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          source_batch_ref TEXT,
          event_type TEXT NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS investigation_consumers (
          consumer TEXT NOT NULL,
          version TEXT NOT NULL,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          last_event_seq INTEGER NOT NULL CHECK(last_event_seq >= 0),
          updated_at TEXT NOT NULL,
          PRIMARY KEY(consumer, version, task_id, epoch_id)
        );
        CREATE TABLE IF NOT EXISTS discovery_checkpoints (
          checkpoint_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          namespace TEXT NOT NULL,
          request_digest TEXT NOT NULL,
          status TEXT NOT NULL,
          scanned_count INTEGER NOT NULL CHECK(scanned_count >= 0),
          matched_count INTEGER NOT NULL CHECK(matched_count >= 0),
          returned_count INTEGER NOT NULL CHECK(returned_count >= 0),
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(task_id, epoch_id, namespace, request_digest)
        );
        CREATE TABLE IF NOT EXISTS completion_snapshots (
          snapshot_ref TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          epoch_id TEXT NOT NULL,
          investigation_status TEXT NOT NULL,
          max_event_seq INTEGER NOT NULL,
          payload TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_entity_versions_subject ON entity_versions(task_id, epoch_id, entity_ref, valid_from);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_versions_identity ON entity_versions(task_id, epoch_id, entity_ref, identity_digest, COALESCE(content_digest,''));
        CREATE INDEX IF NOT EXISTS idx_relation_provenance_scope ON relation_provenance(task_id, epoch_id, derivation);
        CREATE INDEX IF NOT EXISTS idx_investigation_leads_status ON investigation_leads(task_id, epoch_id, status, priority, created_at);
        CREATE INDEX IF NOT EXISTS idx_investigation_obligations_status ON investigation_obligations(task_id, epoch_id, required, status);
        CREATE INDEX IF NOT EXISTS idx_investigation_actions_ready ON investigation_actions(task_id, epoch_id, status, priority, created_at);
        CREATE INDEX IF NOT EXISTS idx_investigation_events_scope ON investigation_events(task_id, epoch_id, event_seq);
        CREATE INDEX IF NOT EXISTS idx_discovery_checkpoints_scope ON discovery_checkpoints(task_id, epoch_id, namespace, status);
      `);
      this.recordMigration(2, "autonomous-investigation-state", digestObject({ version: 2, schema: "autonomous-investigation-state" }));
      const obligationColumns = this.db.prepare("PRAGMA table_info(investigation_obligations)").all() as Array<{ name?: string }>;
      if (!obligationColumns.some((column) => column.name === "dedupe_key")) {
        this.db.exec("ALTER TABLE investigation_obligations ADD COLUMN dedupe_key TEXT");
      }
      this.db.exec(`
        UPDATE investigation_obligations
        SET dedupe_key=COALESCE(NULLIF(json_extract(payload, '$.dedupeKey'), ''), obligation_id)
        WHERE dedupe_key IS NULL OR dedupe_key='';
        CREATE UNIQUE INDEX IF NOT EXISTS idx_investigation_obligations_dedupe
          ON investigation_obligations(task_id, epoch_id, dedupe_key);
        CREATE TRIGGER IF NOT EXISTS trg_investigation_obligations_dedupe_insert
          BEFORE INSERT ON investigation_obligations
          WHEN NEW.dedupe_key IS NULL OR NEW.dedupe_key=''
          BEGIN SELECT RAISE(ABORT, 'investigation obligation dedupe_key is required'); END;
        CREATE TRIGGER IF NOT EXISTS trg_investigation_obligations_dedupe_update
          BEFORE UPDATE OF dedupe_key ON investigation_obligations
          WHEN NEW.dedupe_key IS NULL OR NEW.dedupe_key=''
          BEGIN SELECT RAISE(ABORT, 'investigation obligation dedupe_key is required'); END;
      `);
      this.recordMigration(3, "investigation-obligation-dedupe", digestObject({ version: 3, schema: "investigation-obligation-dedupe" }));
      this.db.exec(`
        DELETE FROM investigation_gaps_v2
        WHERE rowid NOT IN (
          SELECT MIN(rowid) FROM investigation_gaps_v2
          GROUP BY task_id, epoch_id, code,
            COALESCE(json_extract(payload, '$.category'), ''),
            COALESCE(json_extract(payload, '$.reasonCode'), '')
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_investigation_gaps_semantic
          ON investigation_gaps_v2(
            task_id, epoch_id, code,
            COALESCE(json_extract(payload, '$.category'), ''),
            COALESCE(json_extract(payload, '$.reasonCode'), '')
          );
      `);
      this.recordMigration(4, "investigation-gap-semantic-dedupe", digestObject({ version: 4, schema: "investigation-gap-semantic-dedupe" }));
      for (const table of ["tool_runs", "messages", "queued_inputs"] as const) {
        const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name?: string }>;
        if (!columns.some((column) => column.name === "epoch_id")) this.db.exec(`ALTER TABLE ${table} ADD COLUMN epoch_id TEXT`);
      }
      this.db.exec(`
        CREATE INDEX IF NOT EXISTS idx_tool_runs_epoch ON tool_runs(task_id, epoch_id, started_at);
        CREATE INDEX IF NOT EXISTS idx_messages_epoch ON messages(task_id, epoch_id, seq);
        CREATE INDEX IF NOT EXISTS idx_queued_inputs_epoch ON queued_inputs(task_id, epoch_id, status, created_at);
      `);
      this.recordMigration(5, "runtime-epoch-binding", digestObject({ version: 5, schema: "runtime-epoch-binding" }));
      this.db.exec(`PRAGMA user_version=${RUNTIME_SCHEMA_VERSION}; COMMIT`);
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction may already be closed */ }
      throw error;
    }
  }

  private recordMigration(version: number, name: string, checksum: string): void {
    const existing = this.db.prepare("SELECT name,checksum FROM schema_migrations WHERE version=?").get(version) as { name?: string; checksum?: string } | undefined;
    if (existing && (existing.name !== name || existing.checksum !== checksum)) throw new Error(`数据库迁移 v${version} 摘要不匹配`);
    if (!existing) this.db.prepare("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)")
      .run(version, name, checksum, new Date().toISOString());
  }

  getSchemaVersion(): number {
    return Number((this.db.prepare("PRAGMA user_version").get() as { user_version?: number } | undefined)?.user_version ?? 0);
  }

  listSchemaMigrations(): SchemaMigrationRecord[] {
    const rows = this.db.prepare("SELECT version,name,checksum,applied_at FROM schema_migrations ORDER BY version").all() as Array<Record<string, unknown>>;
    return rows.map((row) => ({ version: Number(row.version), name: String(row.name), checksum: String(row.checksum), appliedAt: String(row.applied_at) }));
  }

  private assertInvestigationScope(taskId: string, epochId: string): void {
    const epoch = this.getScanEpoch(taskId, epochId);
    if (!epoch || epoch.taskId !== taskId) throw new InvalidArgumentError("调查状态必须绑定已存在的 task + epoch");
  }

  private appendInvestigationEvent(input: Omit<InvestigationEvent, "eventSeq">): InvestigationEvent {
    const result = this.db.prepare("INSERT INTO investigation_events(event_id,task_id,epoch_id,source_batch_ref,event_type,payload,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(input.eventId, input.taskId, input.epochId, input.sourceBatchRef ?? null, input.eventType, JSON.stringify(input.payload), input.createdAt);
    return { ...input, eventSeq: Number(result.lastInsertRowid) };
  }

  createInvestigationSession(session: InvestigationSession): void {
    this.assertInvestigationScope(session.taskId, session.epochId);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO investigation_sessions(session_id,task_id,epoch_id,engine_version,authorization_version,execution_status,investigation_status,revision,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .run(session.sessionId, session.taskId, session.epochId, session.engineVersion, session.authorizationVersion, session.executionStatus, session.investigationStatus, session.revision, JSON.stringify(session), session.createdAt, session.updatedAt);
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: session.taskId, epochId: session.epochId, eventType: "SESSION_CREATED", payload: { sessionId: session.sessionId }, createdAt: session.createdAt });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  getInvestigationSession(taskId: string, epochId: string): InvestigationSession | undefined {
    const row = this.db.prepare("SELECT payload FROM investigation_sessions WHERE task_id=? AND epoch_id=?").get(taskId, epochId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as InvestigationSession : undefined;
  }

  updateInvestigationSession(session: InvestigationSession, expectedRevision: number): void {
    if (session.revision !== expectedRevision + 1) throw new InvalidArgumentError("调查会话 revision 必须递增 1");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("UPDATE investigation_sessions SET authorization_version=?,execution_status=?,investigation_status=?,revision=?,payload=?,updated_at=? WHERE session_id=? AND task_id=? AND epoch_id=? AND revision=?")
        .run(session.authorizationVersion, session.executionStatus, session.investigationStatus, session.revision, JSON.stringify(session), session.updatedAt, session.sessionId, session.taskId, session.epochId, expectedRevision);
      if (Number(result.changes) !== 1) throw new InvalidArgumentError("调查会话已被其他执行路径更新");
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: session.taskId, epochId: session.epochId, eventType: "SESSION_UPDATED", payload: { sessionId: session.sessionId, revision: session.revision, executionStatus: session.executionStatus, investigationStatus: session.investigationStatus }, createdAt: session.updatedAt });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  putEntityVersion(value: EntityVersion): EntityVersion {
    this.assertInvestigationScope(value.taskId, value.epochId);
    const subject = this.listObjectReferences(value.taskId, value.epochId).find((item) => item.ref === value.entityRef && item.namespace === value.namespace);
    const fact = this.getFact(value.taskId, value.epochId, value.sourceFactRef);
    if (!subject || !fact || fact.subjectRef !== value.entityRef) throw new InvalidArgumentError("实体版本必须绑定当前对象及其来源 Fact");
    this.db.prepare("INSERT OR IGNORE INTO entity_versions(version_ref,entity_ref,task_id,epoch_id,namespace,identity_digest,content_digest,source_fact_ref,valid_from,valid_to,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
      .run(value.versionRef, value.entityRef, value.taskId, value.epochId, value.namespace, value.identityDigest, value.contentDigest ?? null, value.sourceFactRef, value.validFrom, value.validTo ?? null, JSON.stringify(value));
    const row = this.db.prepare("SELECT payload FROM entity_versions WHERE task_id=? AND epoch_id=? AND entity_ref=? AND identity_digest=? AND content_digest IS ?")
      .get(value.taskId, value.epochId, value.entityRef, value.identityDigest, value.contentDigest ?? null) as unknown as JsonRow;
    return JSON.parse(row.payload) as EntityVersion;
  }

  listEntityVersions(taskId: string, epochId: string, entityRef?: string): EntityVersion[] {
    const rows = (entityRef
      ? this.db.prepare("SELECT payload FROM entity_versions WHERE task_id=? AND epoch_id=? AND entity_ref=? ORDER BY valid_from").all(taskId, epochId, entityRef)
      : this.db.prepare("SELECT payload FROM entity_versions WHERE task_id=? AND epoch_id=? ORDER BY valid_from").all(taskId, epochId)) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as EntityVersion);
  }

  putRelationProvenance(value: RelationProvenance): void {
    const edge = this.listEdges(value.taskId, value.epochId).find((item) => item.edgeId === value.edgeRef);
    const versions = new Set(this.listEntityVersions(value.taskId, value.epochId).map((item) => item.versionRef));
    if (!edge || (value.fromVersionRef && !versions.has(value.fromVersionRef)) || (value.toVersionRef && !versions.has(value.toVersionRef))) throw new InvalidArgumentError("关系谱系必须绑定当前 Epoch 的 Edge 和实体版本");
    this.db.prepare("INSERT INTO relation_provenance(edge_ref,task_id,epoch_id,from_version_ref,to_version_ref,derivation,resolver_version,time_error_ms,payload) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(value.edgeRef, value.taskId, value.epochId, value.fromVersionRef ?? null, value.toVersionRef ?? null, value.derivation, value.resolverVersion, value.timeErrorMs, JSON.stringify(value));
  }

  listRelationProvenance(taskId: string, epochId: string): RelationProvenance[] {
    const rows = this.db.prepare("SELECT payload FROM relation_provenance WHERE task_id=? AND epoch_id=? ORDER BY edge_ref").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as RelationProvenance);
  }

  putInvestigationLead(lead: InvestigationLead): InvestigationLead {
    this.assertInvestigationScope(lead.taskId, lead.epochId);
    if (!this.listObjectReferences(lead.taskId, lead.epochId).some((item) => item.ref === lead.subjectRef)) throw new InvalidArgumentError("Lead subjectRef 不属于当前 Epoch");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("INSERT OR IGNORE INTO investigation_leads(lead_id,task_id,epoch_id,subject_ref,trigger_kind,trigger_version,observation_round,priority,status,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
        .run(lead.leadId, lead.taskId, lead.epochId, lead.subjectRef, lead.triggerKind, lead.triggerVersion, lead.observationRound, lead.priority, lead.status, JSON.stringify(lead), lead.createdAt, lead.updatedAt);
      const row = this.db.prepare("SELECT payload FROM investigation_leads WHERE task_id=? AND epoch_id=? AND subject_ref=? AND trigger_kind=? AND trigger_version=? AND observation_round=?")
        .get(lead.taskId, lead.epochId, lead.subjectRef, lead.triggerKind, lead.triggerVersion, lead.observationRound) as unknown as JsonRow;
      let stored = JSON.parse(row.payload) as InvestigationLead;
      if (Number(result.changes) === 1) {
        this.appendInvestigationEvent({ eventId: createId("action"), taskId: lead.taskId, epochId: lead.epochId, eventType: "LEAD_CREATED", payload: { leadId: stored.leadId, subjectRef: stored.subjectRef }, createdAt: stored.createdAt });
      } else {
        const triggerFactRefs = [...new Set([...stored.triggerFactRefs, ...lead.triggerFactRefs])];
        if (triggerFactRefs.length !== stored.triggerFactRefs.length || lead.priority > stored.priority) {
          stored = { ...stored, triggerFactRefs, priority: Math.max(stored.priority, lead.priority), updatedAt: lead.updatedAt };
          this.db.prepare("UPDATE investigation_leads SET priority=?,payload=?,updated_at=? WHERE lead_id=?")
            .run(stored.priority, JSON.stringify(stored), stored.updatedAt, stored.leadId);
          this.appendInvestigationEvent({ eventId: createId("action"), taskId: lead.taskId, epochId: lead.epochId, eventType: "LEAD_UPDATED", payload: { leadId: stored.leadId, triggerFactRefs: stored.triggerFactRefs }, createdAt: stored.updatedAt });
        }
      }
      this.db.exec("COMMIT");
      return stored;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationLeads(taskId: string, epochId: string): InvestigationLead[] {
    const rows = this.db.prepare("SELECT payload FROM investigation_leads WHERE task_id=? AND epoch_id=? ORDER BY priority DESC,created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationLead);
  }

  putInvestigationHypothesis(value: InvestigationHypothesis): void {
    if (!this.listObjectReferences(value.taskId, value.epochId).some((item) => item.ref === value.subjectRef)) throw new InvalidArgumentError("Hypothesis subjectRef 不属于当前 Epoch");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO investigation_hypotheses(hypothesis_id,task_id,epoch_id,subject_ref,status,revision,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
        .run(value.hypothesisId, value.taskId, value.epochId, value.subjectRef, value.status, value.revision, JSON.stringify(value), value.createdAt, value.updatedAt);
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "HYPOTHESIS_CREATED", payload: { hypothesisId: value.hypothesisId, subjectRef: value.subjectRef }, createdAt: value.createdAt });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationHypotheses(taskId: string, epochId: string): InvestigationHypothesis[] {
    const rows = this.db.prepare("SELECT payload FROM investigation_hypotheses WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationHypothesis);
  }

  putInvestigationObligation(value: InvestigationObligation): InvestigationObligation {
    this.assertInvestigationScope(value.taskId, value.epochId);
    if (value.hypothesisId && !this.listInvestigationHypotheses(value.taskId, value.epochId).some((item) => item.hypothesisId === value.hypothesisId)) throw new InvalidArgumentError("Obligation hypothesisId 不属于当前 Epoch");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("INSERT OR IGNORE INTO investigation_obligations(obligation_id,task_id,epoch_id,hypothesis_id,obligation_kind,dedupe_key,required,status,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .run(value.obligationId, value.taskId, value.epochId, value.hypothesisId ?? null, value.obligationKind, value.dedupeKey, value.required ? 1 : 0, value.status, JSON.stringify(value), value.createdAt, value.updatedAt);
      const row = this.db.prepare("SELECT payload FROM investigation_obligations WHERE task_id=? AND epoch_id=? AND dedupe_key=?")
        .get(value.taskId, value.epochId, value.dedupeKey) as unknown as JsonRow;
      const stored = JSON.parse(row.payload) as InvestigationObligation;
      if (Number(result.changes) === 1) this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "OBLIGATION_CREATED", payload: { obligationId: stored.obligationId, hypothesisId: stored.hypothesisId, required: stored.required }, createdAt: stored.createdAt });
      this.db.exec("COMMIT");
      return stored;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationObligations(taskId: string, epochId: string): InvestigationObligation[] {
    const rows = this.db.prepare("SELECT payload FROM investigation_obligations WHERE task_id=? AND epoch_id=? ORDER BY required DESC,created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationObligation);
  }

  updateInvestigationObligation(value: InvestigationObligation, expectedStatus: InvestigationObligation["status"]): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("UPDATE investigation_obligations SET status=?,payload=?,updated_at=? WHERE obligation_id=? AND task_id=? AND epoch_id=? AND status=?")
        .run(value.status, JSON.stringify(value), value.updatedAt, value.obligationId, value.taskId, value.epochId, expectedStatus);
      if (Number(result.changes) !== 1) throw new InvalidArgumentError("Obligation 状态已被其他执行路径更新");
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "OBLIGATION_UPDATED", payload: { obligationId: value.obligationId, status: value.status, resultRefs: value.resultRefs, gapRefs: value.gapRefs }, createdAt: value.updatedAt });
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  putInvestigationAction(value: InvestigationAction): InvestigationAction {
    this.assertInvestigationScope(value.taskId, value.epochId);
    if (value.dependsOn.includes(value.actionId)) throw new InvalidArgumentError("Action 不能依赖自身");
    const scopedActions = new Set(this.listInvestigationActions(value.taskId, value.epochId).map((item) => item.actionId));
    if (value.dependsOn.some((item) => !scopedActions.has(item))) throw new InvalidArgumentError("Action 依赖必须属于当前 Epoch");
    const obligationIds = new Set(this.listInvestigationObligations(value.taskId, value.epochId).map((item) => item.obligationId));
    if (value.obligationIds.some((item) => !obligationIds.has(item))) throw new InvalidArgumentError("Action obligationId 必须属于当前 Epoch");
    const existingRow = this.db.prepare("SELECT payload FROM investigation_actions WHERE idempotency_key=?").get(value.idempotencyKey) as JsonRow | undefined;
    const activeCount = existingRow ? 0 : Number((this.db.prepare("SELECT COUNT(*) AS count FROM investigation_actions WHERE task_id=? AND epoch_id=? AND status IN ('READY','RUNNING')")
      .get(value.taskId, value.epochId) as unknown as CountRow).count);
    const capacityExceeded = !existingRow && value.status === "READY" && activeCount >= MAX_ACTIVE_INVESTIGATION_ACTIONS;
    const candidate: InvestigationAction = capacityExceeded
      ? { ...value, status: "BLOCKED", error: `ACTION_QUEUE_CAPACITY:${MAX_ACTIVE_INVESTIGATION_ACTIONS}`, revision: value.revision + 1 }
      : value;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("INSERT OR IGNORE INTO investigation_actions(action_id,task_id,epoch_id,idempotency_key,action_kind,operation_ref,authorization_version,status,revision,priority,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .run(candidate.actionId, candidate.taskId, candidate.epochId, candidate.idempotencyKey, candidate.kind, candidate.operationRef, candidate.authorizationVersion, candidate.status, candidate.revision, candidate.priority, JSON.stringify(candidate), candidate.createdAt, candidate.updatedAt);
      const row = this.db.prepare("SELECT payload FROM investigation_actions WHERE idempotency_key=?").get(value.idempotencyKey) as unknown as JsonRow;
      let stored = JSON.parse(row.payload) as InvestigationAction;
      if (stored.taskId !== value.taskId || stored.epochId !== value.epochId) throw new InvalidArgumentError("Action idempotencyKey 与其他调查冲突");
      if (Number(result.changes) === 1) {
        this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "ACTION_CREATED", payload: { actionId: stored.actionId, operationRef: stored.operationRef, status: stored.status }, createdAt: stored.createdAt });
        if (capacityExceeded) {
          const now = new Date().toISOString();
          const reason = `活动调查 Action 已达到 ${MAX_ACTIVE_INVESTIGATION_ACTIONS} 条上限`;
          const gap: InvestigationGap = { gapId: `IGAP-${createId("action")}`, taskId: value.taskId, epochId: value.epochId, code: "QUEUE_CAPACITY", reasonCode: `ACTIVE_ACTION_LIMIT:${MAX_ACTIVE_INVESTIGATION_ACTIONS}`, createdAt: now };
          this.db.prepare("INSERT OR IGNORE INTO investigation_gaps_v2(gap_id,task_id,epoch_id,code,payload,created_at) VALUES(?,?,?,?,?,?)")
            .run(gap.gapId, gap.taskId, gap.epochId, gap.code, JSON.stringify(gap), gap.createdAt);
          for (const obligationId of stored.obligationIds) {
            const obligationRow = this.db.prepare("SELECT payload FROM investigation_obligations WHERE obligation_id=? AND task_id=? AND epoch_id=?")
              .get(obligationId, value.taskId, value.epochId) as JsonRow | undefined;
            if (!obligationRow) continue;
            const obligation = JSON.parse(obligationRow.payload) as InvestigationObligation;
            if (!["OPEN", "QUEUED"].includes(obligation.status)) continue;
            const updated: InvestigationObligation = { ...obligation, status: "LIMITED", gapRefs: [...new Set([...obligation.gapRefs, reason])], updatedAt: now };
            this.db.prepare("UPDATE investigation_obligations SET status='LIMITED',payload=?,updated_at=? WHERE obligation_id=? AND status=?")
              .run(JSON.stringify(updated), now, obligationId, obligation.status);
            this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "OBLIGATION_UPDATED", payload: { obligationId, status: "LIMITED", resultRefs: updated.resultRefs, gapRefs: updated.gapRefs }, createdAt: now });
          }
          this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "ACTION_QUEUE_CAPACITY_REACHED", payload: { actionId: stored.actionId, activeCount, maximum: MAX_ACTIVE_INVESTIGATION_ACTIONS }, createdAt: now });
        }
      } else {
        // 一个语义 Action 可以同时服务多个流程义务。去重命中时必须把新义务挂到
        // 已有 Action 上；若它已经结束，还要立即复用其终态，否则会留下没有可执行
        // Action 的永久 QUEUED obligation。
        const mergedObligationIds = [...new Set([...stored.obligationIds, ...value.obligationIds])];
        if (mergedObligationIds.length !== stored.obligationIds.length) {
          const now = new Date().toISOString();
          stored = { ...stored, obligationIds: mergedObligationIds, priority: Math.max(stored.priority, value.priority), updatedAt: now };
          this.db.prepare("UPDATE investigation_actions SET priority=?,payload=?,updated_at=? WHERE action_id=?")
            .run(stored.priority, JSON.stringify(stored), now, stored.actionId);
          this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "ACTION_OBLIGATIONS_MERGED", payload: { actionId: stored.actionId, obligationIds: mergedObligationIds }, createdAt: now });
          if (["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"].includes(stored.status)) {
            for (const obligationId of value.obligationIds) {
              const obligationRow = this.db.prepare("SELECT payload FROM investigation_obligations WHERE obligation_id=? AND task_id=? AND epoch_id=?")
                .get(obligationId, value.taskId, value.epochId) as JsonRow | undefined;
              if (!obligationRow) continue;
              const obligation = JSON.parse(obligationRow.payload) as InvestigationObligation;
              if (!["OPEN", "QUEUED"].includes(obligation.status)) continue;
              const status: InvestigationObligation["status"] = stored.status === "SUCCEEDED" ? "SATISFIED" : "LIMITED";
              const updated: InvestigationObligation = {
                ...obligation,
                status,
                resultRefs: [...new Set([...obligation.resultRefs, ...(stored.resultRefs ?? [])])],
                gapRefs: stored.status === "SUCCEEDED" ? obligation.gapRefs : [...new Set([...obligation.gapRefs, stored.error ?? `复用的 Action 以 ${stored.status} 结束`])],
                updatedAt: now,
              };
              this.db.prepare("UPDATE investigation_obligations SET status=?,payload=?,updated_at=? WHERE obligation_id=? AND status=?")
                .run(status, JSON.stringify(updated), now, obligationId, obligation.status);
              this.appendInvestigationEvent({ eventId: createId("action"), taskId: value.taskId, epochId: value.epochId, eventType: "OBLIGATION_UPDATED", payload: { obligationId, status, resultRefs: updated.resultRefs, gapRefs: updated.gapRefs }, createdAt: now });
            }
          }
        }
      }
      this.db.exec("COMMIT");
      return stored;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationActions(taskId: string, epochId: string): InvestigationAction[] {
    const rows = this.db.prepare("SELECT payload FROM investigation_actions WHERE task_id=? AND epoch_id=? ORDER BY priority DESC,created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationAction);
  }

  claimNextInvestigationAction(taskId: string, epochId: string, workerId: string, authorizationVersion: string, eligibleActionIds?: ReadonlySet<string>): { action: InvestigationAction; attempt: InvestigationActionAttempt } | undefined {
    this.assertInvestigationScope(taskId, epochId);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const candidates = this.listInvestigationActions(taskId, epochId).filter((item) => item.status === "READY" && (!eligibleActionIds || eligibleActionIds.has(item.actionId)));
      for (const candidate of candidates) {
        if (candidate.authorizationVersion !== authorizationVersion) continue;
        const dependencies = candidate.dependsOn.map((id) => this.db.prepare("SELECT status FROM investigation_actions WHERE action_id=? AND task_id=? AND epoch_id=?").get(id, taskId, epochId) as { status?: string } | undefined);
        if (dependencies.some((item) => item?.status !== "SUCCEEDED" && item?.status !== "PARTIAL")) continue;
        const now = new Date().toISOString();
        const action: InvestigationAction = { ...candidate, status: "RUNNING", workerId, revision: candidate.revision + 1, updatedAt: now };
        const update = this.db.prepare("UPDATE investigation_actions SET status='RUNNING',revision=?,payload=?,updated_at=? WHERE action_id=? AND status='READY' AND revision=?")
          .run(action.revision, JSON.stringify(action), now, action.actionId, candidate.revision);
        if (Number(update.changes) !== 1) continue;
        const attemptNumber = Number((this.db.prepare("SELECT COUNT(*) AS count FROM investigation_action_attempts WHERE action_id=?").get(action.actionId) as { count: number }).count) + 1;
        const attempt: InvestigationActionAttempt = { attemptId: createId("action"), actionId: action.actionId, taskId, epochId, attempt: attemptNumber, status: "RUNNING", startedAt: now };
        this.db.prepare("INSERT INTO investigation_action_attempts(attempt_id,action_id,task_id,epoch_id,attempt,tool_call_id,status,payload,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
          .run(attempt.attemptId, attempt.actionId, taskId, epochId, attempt.attempt, null, attempt.status, JSON.stringify(attempt), now, null);
        this.appendInvestigationEvent({ eventId: createId("action"), taskId, epochId, eventType: "ACTION_CLAIMED", payload: { actionId: action.actionId, attemptId: attempt.attemptId, workerId }, createdAt: now });
        this.db.exec("COMMIT");
        return { action, attempt };
      }
      this.db.exec("COMMIT");
      return undefined;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  finishInvestigationAction(actionId: string, expectedRevision: number, status: Extract<InvestigationAction["status"], "SUCCEEDED" | "PARTIAL" | "FAILED" | "BLOCKED" | "CANCELLED">, resultRefs: string[] = [], error?: string): InvestigationAction {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT payload FROM investigation_actions WHERE action_id=?").get(actionId) as JsonRow | undefined;
      if (!row) throw new InvalidArgumentError("未知 Investigation Action");
      const current = JSON.parse(row.payload) as InvestigationAction;
      if (current.status !== "RUNNING" || current.revision !== expectedRevision) throw new InvalidArgumentError("Action 状态或 revision 已变化");
      const now = new Date().toISOString();
      const action: InvestigationAction = { ...current, status, resultRefs, ...(error ? { error } : {}), revision: current.revision + 1, updatedAt: now };
      this.db.prepare("UPDATE investigation_actions SET status=?,revision=?,payload=?,updated_at=? WHERE action_id=? AND revision=?")
        .run(status, action.revision, JSON.stringify(action), now, actionId, expectedRevision);
      const attemptRow = this.db.prepare("SELECT payload FROM investigation_action_attempts WHERE action_id=? AND status='RUNNING' ORDER BY attempt DESC LIMIT 1").get(actionId) as JsonRow | undefined;
      if (!attemptRow) throw new InvalidArgumentError("Action 缺少运行中的 Attempt");
      const attempt = JSON.parse(attemptRow.payload) as InvestigationActionAttempt;
      const finishedAttempt: InvestigationActionAttempt = { ...attempt, status, ...(error ? { error } : {}), finishedAt: now };
      this.db.prepare("UPDATE investigation_action_attempts SET status=?,payload=?,finished_at=? WHERE attempt_id=? AND status='RUNNING'")
        .run(status, JSON.stringify(finishedAttempt), now, attempt.attemptId);
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: action.taskId, epochId: action.epochId, eventType: "ACTION_FINISHED", payload: { actionId, status, resultRefs }, createdAt: now });
      this.db.exec("COMMIT");
      return action;
    } catch (caught) { this.db.exec("ROLLBACK"); throw caught; }
  }

  blockReadyInvestigationAction(actionId: string, reason: string): InvestigationAction {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT payload FROM investigation_actions WHERE action_id=?").get(actionId) as JsonRow | undefined;
      if (!row) throw new InvalidArgumentError("未知 Investigation Action");
      const current = JSON.parse(row.payload) as InvestigationAction;
      if (current.status !== "READY") throw new InvalidArgumentError("只有 READY Action 可以直接阻塞");
      const now = new Date().toISOString();
      const blocked: InvestigationAction = { ...current, status: "BLOCKED", error: reason, revision: current.revision + 1, updatedAt: now };
      const result = this.db.prepare("UPDATE investigation_actions SET status='BLOCKED',revision=?,payload=?,updated_at=? WHERE action_id=? AND status='READY' AND revision=?")
        .run(blocked.revision, JSON.stringify(blocked), now, actionId, current.revision);
      if (Number(result.changes) !== 1) throw new InvalidArgumentError("Action 已被其他执行路径更新");
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: blocked.taskId, epochId: blocked.epochId, eventType: "ACTION_BLOCKED", payload: { actionId, reason }, createdAt: now });
      this.db.exec("COMMIT");
      return blocked;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationActionAttempts(taskId: string, epochId: string, actionId?: string): InvestigationActionAttempt[] {
    const rows = (actionId
      ? this.db.prepare("SELECT payload FROM investigation_action_attempts WHERE task_id=? AND epoch_id=? AND action_id=? ORDER BY attempt").all(taskId, epochId, actionId)
      : this.db.prepare("SELECT payload FROM investigation_action_attempts WHERE task_id=? AND epoch_id=? ORDER BY started_at").all(taskId, epochId)) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationActionAttempt);
  }

  recoverInterruptedInvestigationActions(taskId: string, epochId: string): InvestigationAction[] {
    const running = this.listInvestigationActions(taskId, epochId).filter((item) => item.status === "RUNNING");
    if (running.length === 0) return [];
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const recovered: InvestigationAction[] = [];
      for (const current of running) {
        const now = new Date().toISOString();
        const status: InvestigationAction["status"] = current.replayPolicy === "SAFE_REOBSERVE" ? "READY" : "BLOCKED";
        const error = status === "READY" ? "控制端中断，安全读取已重新排队" : "控制端中断后远端结果不确定，需要恢复核对";
        const { workerId: _workerId, ...unclaimed } = current;
        const action: InvestigationAction = { ...unclaimed, status, error, revision: current.revision + 1, updatedAt: now };
        this.db.prepare("UPDATE investigation_actions SET status=?,revision=?,payload=?,updated_at=? WHERE action_id=? AND status='RUNNING' AND revision=?")
          .run(status, action.revision, JSON.stringify(action), now, action.actionId, current.revision);
        const attemptRow = this.db.prepare("SELECT payload FROM investigation_action_attempts WHERE action_id=? AND status='RUNNING' ORDER BY attempt DESC LIMIT 1").get(action.actionId) as JsonRow | undefined;
        if (attemptRow) {
          const attempt = JSON.parse(attemptRow.payload) as InvestigationActionAttempt;
          const finished: InvestigationActionAttempt = { ...attempt, status: status === "READY" ? "FAILED" : "BLOCKED", error, finishedAt: now };
          this.db.prepare("UPDATE investigation_action_attempts SET status=?,payload=?,finished_at=? WHERE attempt_id=? AND status='RUNNING'")
            .run(finished.status, JSON.stringify(finished), now, attempt.attemptId);
        }
        this.appendInvestigationEvent({ eventId: createId("action"), taskId, epochId, eventType: "ACTION_RECOVERED", payload: { actionId: action.actionId, status, replayPolicy: action.replayPolicy }, createdAt: now });
        recovered.push(action);
      }
      this.db.exec("COMMIT");
      return recovered;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listInvestigationEvents(taskId: string, epochId: string, afterEventSeq = 0, limit = 500): InvestigationEvent[] {
    if (!Number.isSafeInteger(afterEventSeq) || afterEventSeq < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 5_000) throw new InvalidArgumentError("Investigation Event 分页参数非法");
    const rows = this.db.prepare("SELECT event_seq,event_id,task_id,epoch_id,source_batch_ref,event_type,payload,created_at FROM investigation_events WHERE task_id=? AND epoch_id=? AND event_seq>? ORDER BY event_seq LIMIT ?")
      .all(taskId, epochId, afterEventSeq, limit) as Array<Record<string, unknown>>;
    return rows.map((row) => ({ eventSeq: Number(row.event_seq), eventId: String(row.event_id), taskId: String(row.task_id), epochId: String(row.epoch_id), ...(row.source_batch_ref ? { sourceBatchRef: String(row.source_batch_ref) } : {}), eventType: String(row.event_type), payload: JSON.parse(String(row.payload)) as Record<string, unknown>, createdAt: String(row.created_at) }));
  }

  maxInvestigationEventSeq(taskId: string, epochId: string): number {
    const row = this.db.prepare("SELECT COALESCE(MAX(event_seq),0) AS count FROM investigation_events WHERE task_id=? AND epoch_id=?").get(taskId, epochId) as unknown as CountRow;
    return row.count;
  }

  getInvestigationConsumerWatermark(consumer: string, version: string, taskId: string, epochId: string): number {
    const row = this.db.prepare("SELECT last_event_seq FROM investigation_consumers WHERE consumer=? AND version=? AND task_id=? AND epoch_id=?").get(consumer, version, taskId, epochId) as { last_event_seq?: number } | undefined;
    return Number(row?.last_event_seq ?? 0);
  }

  advanceInvestigationConsumerWatermark(consumer: string, version: string, taskId: string, epochId: string, expected: number, next: number): void {
    if (!Number.isSafeInteger(next) || next < expected) throw new InvalidArgumentError("consumer watermark 不能倒退");
    const current = this.getInvestigationConsumerWatermark(consumer, version, taskId, epochId);
    if (current !== expected) throw new InvalidArgumentError("consumer watermark 已被其他执行路径更新");
    const result = this.db.prepare("INSERT INTO investigation_consumers(consumer,version,task_id,epoch_id,last_event_seq,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(consumer,version,task_id,epoch_id) DO UPDATE SET last_event_seq=excluded.last_event_seq,updated_at=excluded.updated_at WHERE investigation_consumers.last_event_seq=?")
      .run(consumer, version, taskId, epochId, next, new Date().toISOString(), expected);
    if (Number(result.changes) !== 1) throw new InvalidArgumentError("consumer watermark 已被其他执行路径更新");
  }

  putDiscoveryCheckpoint(value: DiscoveryCheckpoint): DiscoveryCheckpoint {
    this.assertInvestigationScope(value.taskId, value.epochId);
    const existing = this.db.prepare("SELECT payload FROM discovery_checkpoints WHERE task_id=? AND epoch_id=? AND namespace=? AND request_digest=?").get(value.taskId, value.epochId, value.namespace, value.requestDigest) as JsonRow | undefined;
    const previous = existing ? JSON.parse(existing.payload) as DiscoveryCheckpoint : undefined;
    const stored = previous ? { ...value, checkpointId: previous.checkpointId, createdAt: previous.createdAt } : value;
    this.db.prepare("INSERT INTO discovery_checkpoints(checkpoint_id,task_id,epoch_id,namespace,request_digest,status,scanned_count,matched_count,returned_count,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(task_id,epoch_id,namespace,request_digest) DO UPDATE SET status=excluded.status,scanned_count=excluded.scanned_count,matched_count=excluded.matched_count,returned_count=excluded.returned_count,payload=excluded.payload,updated_at=excluded.updated_at")
      .run(stored.checkpointId, stored.taskId, stored.epochId, stored.namespace, stored.requestDigest, stored.status, stored.scannedCount, stored.matchedCount, stored.returnedCount, JSON.stringify(stored), stored.createdAt, stored.updatedAt);
    const row = this.db.prepare("SELECT payload FROM discovery_checkpoints WHERE task_id=? AND epoch_id=? AND namespace=? AND request_digest=?").get(value.taskId, value.epochId, value.namespace, value.requestDigest) as unknown as JsonRow;
    return JSON.parse(row.payload) as DiscoveryCheckpoint;
  }

  listDiscoveryCheckpoints(taskId: string, epochId: string): DiscoveryCheckpoint[] {
    const rows = this.db.prepare("SELECT payload FROM discovery_checkpoints WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as DiscoveryCheckpoint);
  }

  putCompletionSnapshot(value: CompletionSnapshot): void {
    this.assertInvestigationScope(value.taskId, value.epochId);
    this.db.prepare("INSERT INTO completion_snapshots(snapshot_ref,task_id,epoch_id,investigation_status,max_event_seq,payload,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(value.snapshotRef, value.taskId, value.epochId, value.investigationStatus, value.maxEventSeq, JSON.stringify(value), value.createdAt);
  }

  getCompletionSnapshot(taskId: string, epochId: string, snapshotRef: string): CompletionSnapshot | undefined {
    const row = this.db.prepare("SELECT payload FROM completion_snapshots WHERE snapshot_ref=? AND task_id=? AND epoch_id=?").get(snapshotRef, taskId, epochId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as CompletionSnapshot : undefined;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
    if (this.lockFd !== undefined) {
      closeSync(this.lockFd);
      this.lockFd = undefined;
      try { unlinkSync(this.lockPath); } catch { /* already removed */ }
    }
  }

  createTask(task: TaskContext): void {
    this.db.prepare("INSERT INTO tasks(task_id,status,updated_at,payload) VALUES(?,?,?,?)")
      .run(task.taskId, task.status, task.updatedAt, JSON.stringify(task));
  }

  saveTask(task: TaskContext): void {
    task.updatedAt = new Date().toISOString();
    this.db.prepare("UPDATE tasks SET status=?,updated_at=?,payload=? WHERE task_id=?")
      .run(task.status, task.updatedAt, JSON.stringify(task), task.taskId);
  }

  getTask(taskId: string): TaskContext | undefined {
    const row = this.db.prepare("SELECT payload FROM tasks WHERE task_id=?").get(taskId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as TaskContext : undefined;
  }

  listTasks(): TaskContext[] {
    const rows = this.db.prepare("SELECT payload FROM tasks ORDER BY updated_at DESC").all() as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as TaskContext);
  }

  putKnownHashDataSet(value: KnownHashDataSet): KnownHashDataSet {
    const byVersion = this.db.prepare("SELECT payload FROM known_hash_datasets_v2 WHERE name=? AND version=?")
      .get(value.name, value.version) as JsonRow | undefined;
    if (byVersion) {
      const existing = JSON.parse(byVersion.payload) as KnownHashDataSet;
      if (existing.digest !== value.digest) throw new InvalidArgumentError(`数据集 ${value.name}@${value.version} 已存在且内容不同；版本不可变`);
      return existing;
    }
    const byDigest = this.db.prepare("SELECT payload FROM known_hash_datasets_v2 WHERE digest=?").get(value.digest) as JsonRow | undefined;
    if (byDigest) return JSON.parse(byDigest.payload) as KnownHashDataSet;
    this.db.prepare("INSERT INTO known_hash_datasets_v2(data_set_ref,name,version,digest,payload,imported_at) VALUES(?,?,?,?,?,?)")
      .run(value.dataSetRef, value.name, value.version, value.digest, JSON.stringify(value), value.importedAt);
    return value;
  }

  getKnownHashDataSet(dataSetRef: string): KnownHashDataSet | undefined {
    const row = this.db.prepare("SELECT payload FROM known_hash_datasets_v2 WHERE data_set_ref=?").get(dataSetRef) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as KnownHashDataSet : undefined;
  }

  listKnownHashDataSets(): KnownHashDataSetSummary[] {
    const rows = this.db.prepare("SELECT payload FROM known_hash_datasets_v2 ORDER BY imported_at,name,version").all() as unknown as JsonRow[];
    return rows.map((row) => summarizeKnownHashDataSet(JSON.parse(row.payload) as KnownHashDataSet));
  }

  reconcileInterruptedTasks(): TaskContext[] {
    const active = new Set<TaskStatus>(["RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"]);
    const tasks = this.listTasks().filter((task) => active.has(task.status));
    if (tasks.length === 0) return [];
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const task of tasks) {
        const previousStatus = task.status as Extract<TaskStatus, "RUNNING" | "WAITING_APPROVAL" | "RECOVERING" | "REPORTING">;
        const detectedAt = new Date().toISOString();
        task.status = "ABORTED";
        task.interruption = { previousStatus, reason: "PROCESS_INTERRUPTED", detectedAt, recoveryRequired: true };
        this.saveTask(task);
        const approvals = this.db.prepare("SELECT payload FROM approvals WHERE task_id=? AND status IN ('PENDING','APPROVED')")
          .all(task.taskId) as unknown as JsonRow[];
        for (const row of approvals) {
          const ticket = JSON.parse(row.payload) as ApprovalTicket;
          ticket.status = "EXPIRED";
          this.putApproval(ticket);
        }
        const expiredGrantRequests = this.expirePendingGrantRequests(task.taskId);
        this.appendAudit({
          taskId: task.taskId,
          event: "task_interrupted_detected",
          level: "warn",
          data: { epochId: task.activeEpochId, previousStatus, expiredApprovals: approvals.length, expiredGrantRequests, detectedAt },
        });
      }
      this.db.exec("COMMIT");
      return tasks;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  relocateEvidencePaths(legacyRoots: string[], currentRoot: string): number {
    const rows = this.db.prepare("SELECT evidence_id,payload FROM evidence").all() as unknown as { evidence_id: string; payload: string }[];
    let changed = 0;
    const normalizedCurrent = resolve(currentRoot);
    const normalizedLegacy = legacyRoots.map((root) => resolve(root));
    const update = this.db.prepare("UPDATE evidence SET payload=? WHERE evidence_id=?");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const row of rows) {
        const evidence = JSON.parse(row.payload) as Evidence;
        if (!evidence.storagePath) continue;
        const candidate = resolve(evidence.storagePath);
        const legacyRoot = normalizedLegacy.find((root) => candidate === root || candidate.startsWith(`${root}${sep}`));
        if (!legacyRoot) continue;
        evidence.storagePath = join(normalizedCurrent, relative(legacyRoot, candidate));
        update.run(JSON.stringify(evidence), row.evidence_id);
        changed += 1;
      }
      this.db.exec("COMMIT");
      return changed;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  hasActiveTask(excludingTaskId?: string): boolean {
    const statuses: TaskStatus[] = ["RUNNING", "PAUSED", "WAITING_APPROVAL", "RECOVERING", "REPORTING"];
    const placeholders = statuses.map(() => "?").join(",");
    const args: string[] = [...statuses];
    let sql = `SELECT COUNT(*) AS count FROM tasks WHERE status IN (${placeholders})`;
    if (excludingTaskId) { sql += " AND task_id<>?"; args.push(excludingTaskId); }
    const row = this.db.prepare(sql).get(...args) as unknown as CountRow;
    return row.count > 0;
  }

  createScanEpoch(epoch: ScanEpoch): void {
    const task = this.requireTask(epoch.taskId);
    if (task.protocolVersion !== 2) throw new SecurityError("RECOVERY_UNCERTAIN", "v1 历史任务只读，不能创建 v2 epoch");
    if (epoch.protocolVersion !== 2 || epoch.targetFingerprint !== task.target.hostFingerprint) throw new InvalidArgumentError("Epoch 协议或目标身份与任务不匹配");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const staleApprovals = this.db.prepare("SELECT payload FROM approvals WHERE task_id=? AND status IN ('PENDING','APPROVED')")
        .all(epoch.taskId) as unknown as JsonRow[];
      for (const row of staleApprovals) {
        const ticket = JSON.parse(row.payload) as ApprovalTicket;
        if (ticket.epochId === epoch.epochId) continue;
        ticket.status = "EXPIRED";
        this.putApproval(ticket);
      }
      this.db.prepare("INSERT INTO scan_epochs(epoch_id,task_id,status,payload,started_at) VALUES(?,?,?,?,?)")
        .run(epoch.epochId, epoch.taskId, epoch.status, JSON.stringify(epoch), epoch.startedAt);
      task.activeEpochId = epoch.epochId;
      this.saveTask(task);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  getScanEpoch(taskId: string, epochId: string): ScanEpoch | undefined {
    const row = this.db.prepare("SELECT payload FROM scan_epochs WHERE task_id=? AND epoch_id=?").get(taskId, epochId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ScanEpoch : undefined;
  }

  listScanEpochs(taskId: string): ScanEpoch[] {
    const rows = this.db.prepare("SELECT payload FROM scan_epochs WHERE task_id=? ORDER BY started_at").all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ScanEpoch);
  }

  finishScanEpoch(taskId: string, epochId: string, status: Exclude<ScanEpoch["status"], "RUNNING">, controllerIdentity?: { commit: string; clean: boolean }): ScanEpoch {
    const epoch = this.getScanEpoch(taskId, epochId);
    if (!epoch) throw new InvalidArgumentError("未知 ScanEpoch");
    if (epoch.status !== "RUNNING") return epoch;
    epoch.status = status;
    epoch.finishedAt = new Date().toISOString();
    if (controllerIdentity) {
      epoch.controllerCommitAtFinish = controllerIdentity.commit;
      epoch.controllerTreeCleanAtFinish = controllerIdentity.clean;
    }
    this.db.prepare("UPDATE scan_epochs SET status=?,payload=? WHERE task_id=? AND epoch_id=?")
      .run(status, JSON.stringify(epoch), taskId, epochId);
    return epoch;
  }

  getObjectReference(taskId: string, epochId: string, ref: string, namespace?: NamespaceName): ObjectReference | undefined {
    const row = this.db.prepare("SELECT payload FROM object_refs_v2 WHERE task_id=? AND epoch_id=? AND ref=?").get(taskId, epochId, ref) as JsonRow | undefined;
    if (!row) return undefined;
    const value = JSON.parse(row.payload) as ObjectReference;
    return namespace && value.namespace !== namespace ? undefined : value;
  }

  listObjectReferences(taskId: string, epochId: string, namespace?: NamespaceName): ObjectReference[] {
    const rows = namespace
      ? this.db.prepare("SELECT payload FROM object_refs_v2 WHERE task_id=? AND epoch_id=? AND namespace=? ORDER BY created_at").all(taskId, epochId, namespace)
      : this.db.prepare("SELECT payload FROM object_refs_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId);
    return (rows as unknown as JsonRow[]).map((row) => JSON.parse(row.payload) as ObjectReference);
  }

  private findObjectReferenceByIdentity(taskId: string, epochId: string, namespace: NamespaceName, digest: string): ObjectReference | undefined {
    const row = this.db.prepare("SELECT payload FROM object_refs_v2 WHERE task_id=? AND epoch_id=? AND namespace=? AND identity_digest=?")
      .get(taskId, epochId, namespace, digest) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ObjectReference : undefined;
  }

  /** INV-13：Fact、Ref、Edge、FactBatch 与 ToolRun 终态在同一事务内提交。 */
  commitFactBatch(input: FactBatchInput): FactBatchResult {
    const epoch = this.getScanEpoch(input.taskId, input.epochId);
    if (epoch?.status !== "RUNNING") throw new SecurityError("RECOVERY_UNCERTAIN", "FactBatch 必须写入当前 RUNNING epoch");
    if (epoch.targetFingerprint !== input.targetFingerprint) throw new SecurityError("INVALID_TARGET", "FactBatch 目标身份与 epoch 不匹配");
    const prepared = prepareFactBatch(input, (namespace, digest) => this.findObjectReferenceByIdentity(input.taskId, input.epochId, namespace, digest));
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const current = this.db.prepare("SELECT COALESCE(MAX(fact_seq),0) AS count FROM facts_v2").get() as unknown as CountRow;
      let nextSeq = current.count + 1;
      const putRef = this.db.prepare(`INSERT OR IGNORE INTO object_refs_v2(ref,task_id,epoch_id,namespace,identity_digest,payload,created_at)
        VALUES(?,?,?,?,?,?,?)`);
      for (const ref of prepared.refs) putRef.run(ref.ref, ref.taskId, ref.epochId, ref.namespace, ref.stableIdentityDigest, JSON.stringify(ref), ref.createdAt);
      const putFact = this.db.prepare(`INSERT INTO facts_v2(fact_seq,fact_id,task_id,epoch_id,namespace,subject_ref,source_run_id,source_kind,private_payload,model_payload,payload,observed_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`);
      for (const fact of prepared.facts) {
        fact.factSeq = nextSeq++;
        putFact.run(fact.factSeq, fact.factId, fact.taskId, fact.epochId, fact.namespace, fact.subjectRef, fact.sourceRunId, fact.source.kind,
          JSON.stringify(fact.privatePayload), JSON.stringify(fact.modelPayload), JSON.stringify(fact), fact.observedAt);
        const openVersions = this.db.prepare("SELECT version_ref,payload FROM entity_versions WHERE task_id=? AND epoch_id=? AND entity_ref=? AND valid_to IS NULL AND COALESCE(content_digest,'')<>?")
          .all(fact.taskId, fact.epochId, fact.subjectRef, fact.payloadDigest) as Array<Record<string, unknown>>;
        for (const row of openVersions) {
          const previous = JSON.parse(String(row.payload)) as EntityVersion;
          const closed: EntityVersion = { ...previous, validTo: fact.observedAt };
          this.db.prepare("UPDATE entity_versions SET valid_to=?,payload=? WHERE version_ref=?")
            .run(fact.observedAt, JSON.stringify(closed), String(row.version_ref));
        }
        const versionRef = `EVER-${digestObject({ subjectRef: fact.subjectRef, identityDigest: fact.provenance.stableIdentityDigest, contentDigest: fact.payloadDigest }).slice(0, 40)}`;
        const version: EntityVersion = {
          versionRef,
          entityRef: fact.subjectRef,
          taskId: fact.taskId,
          epochId: fact.epochId,
          namespace: fact.namespace,
          identityDigest: fact.provenance.stableIdentityDigest,
          contentDigest: fact.payloadDigest,
          sourceFactRef: fact.factId,
          validFrom: fact.observedAt,
          assertions: [{ kind: "OBSERVATION_PAYLOAD", valueDigest: fact.payloadDigest }],
        };
        this.db.prepare("INSERT OR IGNORE INTO entity_versions(version_ref,entity_ref,task_id,epoch_id,namespace,identity_digest,content_digest,source_fact_ref,valid_from,valid_to,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
          .run(version.versionRef, version.entityRef, version.taskId, version.epochId, version.namespace, version.identityDigest, fact.payloadDigest, version.sourceFactRef, version.validFrom, null, JSON.stringify(version));
      }
      const putEdge = this.db.prepare("INSERT INTO fact_edges_v2(edge_id,task_id,epoch_id,from_ref,to_ref,relation,source_run_id,payload) VALUES(?,?,?,?,?,?,?,?)");
      for (const edge of prepared.edges) {
        putEdge.run(edge.edgeId, edge.taskId, edge.epochId, edge.fromRef, edge.toRef, edge.relation, edge.sourceRunId, JSON.stringify(edge));
        const latestVersion = (entityRef: string) => {
          const row = this.db.prepare("SELECT version_ref FROM entity_versions WHERE task_id=? AND epoch_id=? AND entity_ref=? ORDER BY valid_from DESC LIMIT 1").get(edge.taskId, edge.epochId, entityRef) as { version_ref?: string } | undefined;
          return row?.version_ref;
        };
        const fromVersionRef = latestVersion(edge.fromRef);
        const toVersionRef = latestVersion(edge.toRef);
        const provenance: RelationProvenance = {
          edgeRef: edge.edgeId,
          taskId: edge.taskId,
          epochId: edge.epochId,
          ...(fromVersionRef ? { fromVersionRef } : {}),
          ...(toVersionRef ? { toVersionRef } : {}),
          derivation: "OBSERVED",
          sourceRefs: [edge.sourceRunId],
          resolverVersion: "fact-normalizer@2.1.0",
          timeErrorMs: 0,
        };
        this.db.prepare("INSERT INTO relation_provenance(edge_ref,task_id,epoch_id,from_version_ref,to_version_ref,derivation,resolver_version,time_error_ms,payload) VALUES(?,?,?,?,?,?,?,?,?)")
          .run(provenance.edgeRef, provenance.taskId, provenance.epochId, provenance.fromVersionRef ?? null, provenance.toVersionRef ?? null, provenance.derivation, provenance.resolverVersion, provenance.timeErrorMs, JSON.stringify(provenance));
      }
      this.db.prepare(`INSERT INTO fact_batches_v2(batch_id,task_id,epoch_id,source_run_id,status,first_fact_seq,last_fact_seq,fact_count,edge_count,committed_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).run(prepared.batchId, input.taskId, input.epochId, input.sourceRunId, "COMMITTED",
        prepared.facts[0]?.factSeq ?? null, prepared.facts.at(-1)?.factSeq ?? null, prepared.facts.length, prepared.edges.length, new Date().toISOString());
      if (input.toolRun) {
        const run = this.getToolRun(input.toolRun.toolCallId);
        if (!run || run.taskId !== input.taskId || run.epochId !== input.epochId) {
          throw new InvalidArgumentError("FactBatch ToolRun 不属于当前任务与 Epoch");
        }
        if (run.status !== "STARTED" || input.toolRun.toolCallId !== input.sourceRunId) {
          throw new InvalidArgumentError("FactBatch ToolRun 状态或 sourceRunId 绑定无效");
        }
        const terminalResult = input.toolRun.resultFactory ? input.toolRun.resultFactory(prepared) : input.toolRun.result;
        this.db.prepare("UPDATE tool_runs SET status=?,result_json=?,error=?,finished_at=? WHERE tool_call_id=?")
          .run(input.toolRun.status, terminalResult === undefined ? null : JSON.stringify(terminalResult), input.toolRun.error ?? null, new Date().toISOString(), input.toolRun.toolCallId);
      }
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: input.taskId, epochId: input.epochId, sourceBatchRef: prepared.batchId, eventType: "FACT_BATCH_COMMITTED", payload: { batchId: prepared.batchId, sourceRunId: input.sourceRunId, factRefs: prepared.facts.map((fact) => fact.factId), edgeRefs: prepared.edges.map((edge) => edge.edgeId) }, createdAt: new Date().toISOString() });
      this.db.exec("COMMIT");
      return prepared;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listFacts(taskId: string, epochId: string, options: {
    namespace?: NamespaceName;
    sourceRunId?: string;
    sourceKind?: FactRecord["source"]["kind"];
    subjectRef?: string;
    completeness?: FactRecord["completeness"];
    minFactSeqExclusive?: number;
    maxFactSeq?: number;
    limit?: number;
  } = {}): FactRecord[] {
    const clauses = ["task_id=?", "epoch_id=?"];
    const args: Array<string | number> = [taskId, epochId];
    if (options.namespace) { clauses.push("namespace=?"); args.push(options.namespace); }
    if (options.sourceRunId) { clauses.push("source_run_id=?"); args.push(options.sourceRunId); }
    if (options.sourceKind) { clauses.push("source_kind=?"); args.push(options.sourceKind); }
    if (options.subjectRef) { clauses.push("subject_ref=?"); args.push(options.subjectRef); }
    if (options.completeness) { clauses.push("json_extract(payload,'$.completeness')=?"); args.push(options.completeness); }
    if (options.minFactSeqExclusive !== undefined) { clauses.push("fact_seq>?"); args.push(options.minFactSeqExclusive); }
    if (options.maxFactSeq !== undefined) { clauses.push("fact_seq<=?"); args.push(options.maxFactSeq); }
    if (options.limit !== undefined && (!Number.isSafeInteger(options.limit) || options.limit < 1)) throw new InvalidArgumentError("Fact 查询 SQL limit 非法");
    const rows = this.db.prepare(`SELECT payload FROM facts_v2 WHERE ${clauses.join(" AND ")} ORDER BY fact_seq${options.limit === undefined ? "" : " LIMIT ?"}`)
      .all(...args, ...(options.limit === undefined ? [] : [options.limit])) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as FactRecord);
  }

  getFact(taskId: string, epochId: string, factId: string): FactRecord | undefined {
    const row = this.db.prepare("SELECT payload FROM facts_v2 WHERE task_id=? AND epoch_id=? AND fact_id=?").get(taskId, epochId, factId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as FactRecord : undefined;
  }

  listEdges(taskId: string, epochId: string): EdgeRecord[] {
    const rows = this.db.prepare("SELECT payload FROM fact_edges_v2 WHERE task_id=? AND epoch_id=? ORDER BY edge_id")
      .all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as EdgeRecord);
  }

  putDerivedEdge(edge: EdgeRecord, provenance: RelationProvenance): EdgeRecord {
    this.assertInvestigationScope(edge.taskId, edge.epochId);
    if (provenance.edgeRef !== edge.edgeId || provenance.taskId !== edge.taskId || provenance.epochId !== edge.epochId || provenance.derivation !== "DERIVED") {
      throw new InvalidArgumentError("派生关系与来源谱系不匹配");
    }
    const refs = new Set(this.listObjectReferences(edge.taskId, edge.epochId).map((item) => item.ref));
    const versions = new Set(this.listEntityVersions(edge.taskId, edge.epochId).map((item) => item.versionRef));
    if (!refs.has(edge.fromRef) || !refs.has(edge.toRef)
      || (provenance.fromVersionRef && !versions.has(provenance.fromVersionRef))
      || (provenance.toVersionRef && !versions.has(provenance.toVersionRef))
      || provenance.sourceRefs.some((ref) => !this.getFact(edge.taskId, edge.epochId, ref))) {
      throw new InvalidArgumentError("派生关系必须绑定当前 Epoch 的对象、版本和来源 Fact");
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT OR IGNORE INTO fact_edges_v2(edge_id,task_id,epoch_id,from_ref,to_ref,relation,source_run_id,payload) VALUES(?,?,?,?,?,?,?,?)")
        .run(edge.edgeId, edge.taskId, edge.epochId, edge.fromRef, edge.toRef, edge.relation, edge.sourceRunId, JSON.stringify(edge));
      this.db.prepare("INSERT OR IGNORE INTO relation_provenance(edge_ref,task_id,epoch_id,from_version_ref,to_version_ref,derivation,resolver_version,time_error_ms,payload) VALUES(?,?,?,?,?,?,?,?,?)")
        .run(provenance.edgeRef, provenance.taskId, provenance.epochId, provenance.fromVersionRef ?? null, provenance.toVersionRef ?? null, provenance.derivation, provenance.resolverVersion, provenance.timeErrorMs, JSON.stringify(provenance));
      this.appendInvestigationEvent({ eventId: createId("action"), taskId: edge.taskId, epochId: edge.epochId, sourceBatchRef: edge.sourceRunId, eventType: "DERIVED_EDGE_COMMITTED", payload: { edgeRef: edge.edgeId, resolverVersion: provenance.resolverVersion, sourceRefs: provenance.sourceRefs }, createdAt: new Date().toISOString() });
      this.db.exec("COMMIT");
      return this.listEdges(edge.taskId, edge.epochId).find((item) => item.edgeId === edge.edgeId)!;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  maxFactSeq(taskId: string, epochId: string): number {
    const row = this.db.prepare("SELECT COALESCE(MAX(fact_seq),0) AS count FROM facts_v2 WHERE task_id=? AND epoch_id=?").get(taskId, epochId) as unknown as CountRow;
    return row.count;
  }

  private prepareQueryFacts(taskId: string, epochId: string, ast: FactQueryAst) {
    let cursorPayload: Record<string, unknown> | undefined;
    if (ast.cursorRef) {
      const row = this.db.prepare("SELECT payload FROM query_cursors_v2 WHERE cursor_ref=? AND task_id=? AND epoch_id=?").get(ast.cursorRef, taskId, epochId) as JsonRow | undefined;
      if (!row) throw new InvalidArgumentError("未知或跨 task/epoch 的 Query cursor");
      cursorPayload = JSON.parse(row.payload) as Record<string, unknown>;
    }
    const snapshotMax = typeof cursorPayload?.snapshotMaxFactSeq === "number" ? cursorPayload.snapshotMaxFactSeq : this.maxFactSeq(taskId, epochId);
    const factCursor = cursorPayload as FactQueryCursor | undefined;
    const defaultFactOrder = !ast.orderBy || (ast.orderBy.length === 1 && ast.orderBy[0]?.field === "factSeq" && ast.orderBy[0].direction === "asc");
    const result = ast.view === "facts"
      ? runFactQuery(taskId, epochId, ast, this.listFacts(taskId, epochId, {
          ...(ast.namespace ? { namespace: ast.namespace } : {}),
          ...(ast.sourceRunId ? { sourceRunId: ast.sourceRunId } : {}),
          ...(ast.sourceKind ? { sourceKind: ast.sourceKind } : {}),
          ...(ast.subjectRef ? { subjectRef: ast.subjectRef } : {}),
          ...(ast.completeness ? { completeness: ast.completeness } : {}),
          ...(factCursor && factCursor.mode !== "REMAINING" ? { minFactSeqExclusive: factCursor.lastFactSeq } : {}),
          maxFactSeq: snapshotMax,
          ...(!ast.predicate && defaultFactOrder && factCursor?.mode !== "REMAINING" ? { limit: ast.limit + 1 } : {}),
        }), snapshotMax, factCursor)
      : runStaticQuery(taskId, epochId, ast, this.modelViewRows(taskId, epochId, ast.view), snapshotMax, cursorPayload as StaticQueryCursor | undefined);
    return result;
  }

  /**
   * 仅用于控制端输出预算试算。预览会执行完整的 Query AST 校验与快照边界计算，
   * 但绝不创建模型尚未实际收到的 QueryRef/CursorRef 持久记录。
   */
  previewQueryFacts(taskId: string, epochId: string, ast: FactQueryAst): FactQueryPage {
    return this.prepareQueryFacts(taskId, epochId, ast).page;
  }

  queryFacts(taskId: string, epochId: string, ast: FactQueryAst): FactQueryPage {
    const result = this.prepareQueryFacts(taskId, epochId, ast);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("INSERT INTO query_snapshots_v2(query_ref,task_id,epoch_id,payload,created_at) VALUES(?,?,?,?,?)")
        .run(result.snapshot.queryRef, taskId, epochId, JSON.stringify(result.snapshot), result.snapshot.createdAt);
      if (result.cursor) this.db.prepare("INSERT INTO query_cursors_v2(cursor_ref,task_id,epoch_id,payload,created_at) VALUES(?,?,?,?,?)")
        .run(result.cursor.ref, taskId, epochId, JSON.stringify(result.cursor.value), new Date().toISOString());
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
    return result.page;
  }

  private modelViewRows(taskId: string, epochId: string, view: Exclude<FactQueryAst["view"], "facts">): Array<Record<string, unknown> & { _key: string }> {
    if (view === "edges") return this.listEdges(taskId, epochId).map((edge) => ({ _key: edge.edgeId, edgeId: edge.edgeId, relation: edge.relation, fromRef: edge.fromRef, toRef: edge.toRef, sourceRunId: edge.sourceRunId, observedAt: edge.observedAt }));
    if (view === "evidence_meta") return this.listEvidence(taskId)
      .filter((evidence) => evidence.metadata?.epochId === epochId)
      .map((evidence) => ({
        _key: evidence.evidenceId, evidenceId: evidence.evidenceId, type: evidence.type, source: evidence.source,
        sha256: evidence.sha256, size: evidence.metadata?.remoteSize, collectedAt: evidence.collectedAt,
        tool: evidence.tool, toolCallId: evidence.toolCallId, subjectRef: evidence.metadata?.subjectRef,
        complete: evidence.metadata?.complete,
      }));
    if (view === "assessments") return this.listAssessments(taskId, epochId).map((item) => ({ _key: item.assessmentId, ...item, taskId: undefined, epochId: undefined }));
    return this.listCoverageRuns(taskId, epochId).map((item) => ({ _key: item.coverageId, ...item, taskId: undefined, epochId: undefined }));
  }

  listQuerySnapshots(taskId: string, epochId: string): QuerySnapshot[] {
    const rows = this.db.prepare("SELECT payload FROM query_snapshots_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as QuerySnapshot);
  }

  putRemoteCursor(input: { cursorRef: string; taskId: string; epochId: string; namespace: NamespaceName; requestDigest: string; helperCursor: string; scopeIdentityDigest?: string }): void {
    this.db.prepare("INSERT INTO remote_cursors_v2(cursor_ref,task_id,epoch_id,namespace,request_digest,payload,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(input.cursorRef, input.taskId, input.epochId, input.namespace, input.requestDigest, JSON.stringify(input), new Date().toISOString());
  }

  getRemoteCursor(taskId: string, epochId: string, cursorRef: string): { cursorRef: string; taskId: string; epochId: string; namespace: NamespaceName; requestDigest: string; helperCursor: string; scopeIdentityDigest?: string } | undefined {
    const row = this.db.prepare("SELECT payload FROM remote_cursors_v2 WHERE cursor_ref=? AND task_id=? AND epoch_id=?").get(cursorRef, taskId, epochId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ReturnType<RuntimeStore["getRemoteCursor"]> : undefined;
  }

  putCoverageRun(run: CoverageRun): void {
    if (!this.getScanEpoch(run.taskId, run.epochId)) throw new InvalidArgumentError("CoverageRun 引用未知 epoch");
    if (run.applicability === "NOT_APPLICABLE" && run.status !== "COMPLETE") throw new InvalidArgumentError("NOT_APPLICABLE 只允许在 COMPLETE Coverage 上声明");
    this.db.prepare("INSERT INTO coverage_runs_v2(coverage_id,task_id,epoch_id,category,status,applicability,payload,created_at) VALUES(?,?,?,?,?,?,?,?)")
      .run(run.coverageId, run.taskId, run.epochId, run.category, run.status, run.applicability, JSON.stringify(run), run.createdAt);
  }

  listCoverageRuns(taskId: string, epochId: string): CoverageRun[] {
    const rows = this.db.prepare("SELECT payload FROM coverage_runs_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as CoverageRun);
  }

  putInvestigationGap(gap: InvestigationGap): void {
    if (!this.getScanEpoch(gap.taskId, gap.epochId)) throw new InvalidArgumentError("InvestigationGap 引用未知 epoch");
    this.db.prepare("INSERT OR IGNORE INTO investigation_gaps_v2(gap_id,task_id,epoch_id,code,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(gap.gapId, gap.taskId, gap.epochId, gap.code, JSON.stringify(gap), gap.createdAt);
  }

  listInvestigationGaps(taskId: string, epochId: string): InvestigationGap[] {
    const rows = this.db.prepare("SELECT payload FROM investigation_gaps_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as InvestigationGap);
  }

  putAssessment(assessment: Assessment): void {
    validateAssessment(assessment, {
      taskId: assessment.taskId, epochId: assessment.epochId,
      refs: this.listObjectReferences(assessment.taskId, assessment.epochId),
      facts: this.listFacts(assessment.taskId, assessment.epochId),
      edges: this.listEdges(assessment.taskId, assessment.epochId),
      relationProvenance: this.listRelationProvenance(assessment.taskId, assessment.epochId),
      evidence: this.listEvidence(assessment.taskId).map((item) => ({ evidenceId: item.evidenceId, taskId: item.taskId, ...(item.sha256 ? { sha256: item.sha256 } : {}), ...(item.storagePath ? { storagePath: item.storagePath } : {}), ...(item.metadata ? { metadata: item.metadata } : {}) })),
      queryRefs: new Set(this.listQuerySnapshots(assessment.taskId, assessment.epochId).map((item) => item.queryRef)),
    });
    this.db.prepare("INSERT INTO assessments_v2(assessment_id,task_id,epoch_id,author_type,category,subject_ref,verdict,payload,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .run(assessment.assessmentId, assessment.taskId, assessment.epochId, assessment.authorType, assessment.category, assessment.subjectRef ?? null, assessment.verdict, JSON.stringify(assessment), assessment.createdAt);
  }

  listAssessments(taskId: string, epochId: string): Assessment[] {
    const rows = this.db.prepare("SELECT payload FROM assessments_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as Assessment);
  }

  putAssessmentRelation(relation: AssessmentRelation): void {
    const assessments = new Set(this.listAssessments(relation.taskId, relation.epochId).map((item) => item.assessmentId));
    if (!assessments.has(relation.fromAssessmentId) || !assessments.has(relation.toAssessmentId)) throw new InvalidArgumentError("Assessment relation 端点必须属于当前 task + epoch");
    this.db.prepare("INSERT INTO assessment_relations_v2(relation_id,task_id,epoch_id,from_assessment_id,to_assessment_id,kind,payload,created_at) VALUES(?,?,?,?,?,?,?,?)")
      .run(relation.relationId, relation.taskId, relation.epochId, relation.fromAssessmentId, relation.toAssessmentId, relation.kind, JSON.stringify(relation), relation.createdAt);
  }

  listAssessmentRelations(taskId: string, epochId: string): AssessmentRelation[] {
    const rows = this.db.prepare("SELECT payload FROM assessment_relations_v2 WHERE task_id=? AND epoch_id=? ORDER BY created_at").all(taskId, epochId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as AssessmentRelation);
  }

  putTaskGrant(grant: TaskGrant): void {
    if (grant.kind === "BUDGET_EXTENSION" && Object.keys(grant.binding).length === 0) throw new InvalidArgumentError("Budget Extension 必须包含明确 binding");
    this.db.prepare("INSERT INTO task_grants_v2(grant_id,task_id,kind,status,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(grant.grantId, grant.taskId, grant.kind, grant.status, JSON.stringify(grant), grant.createdAt);
  }

  listTaskGrants(taskId: string): TaskGrant[] {
    const rows = this.db.prepare("SELECT payload FROM task_grants_v2 WHERE task_id=? ORDER BY created_at").all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as TaskGrant);
  }

  revokeTaskGrant(taskId: string, grantId: string, reason: string): TaskGrant {
    const grant = this.listTaskGrants(taskId).find((item) => item.grantId === grantId);
    if (grant?.status !== "ACTIVE") throw new InvalidArgumentError("Task Grant 不存在或已失效");
    if (reason.trim().length < 1 || reason.length > 1_000) throw new InvalidArgumentError("Grant 撤销原因不能为空且不能超过 1000 字符");
    grant.status = "REVOKED";
    grant.revokedAt = new Date().toISOString();
    grant.revocationReason = reason.trim();
    this.db.prepare("UPDATE task_grants_v2 SET status=?,payload=? WHERE grant_id=? AND task_id=?")
      .run(grant.status, JSON.stringify(grant), grantId, taskId);
    return grant;
  }

  putGrantRequest(request: GrantRequest): void {
    this.db.prepare("INSERT OR REPLACE INTO grant_requests_v2(request_id,task_id,kind,status,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(request.requestId, request.taskId, request.kind, request.status, JSON.stringify(request), request.createdAt);
  }

  getGrantRequest(requestId: string): GrantRequest | undefined {
    const row = this.db.prepare("SELECT payload FROM grant_requests_v2 WHERE request_id=?").get(requestId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as GrantRequest : undefined;
  }

  listGrantRequests(taskId: string): GrantRequest[] {
    const rows = this.db.prepare("SELECT payload FROM grant_requests_v2 WHERE task_id=? ORDER BY created_at").all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as GrantRequest);
  }

  updateGrantRequest(requestId: string, status: GrantRequest["status"]): GrantRequest {
    const request = this.getGrantRequest(requestId);
    if (request?.status !== "PENDING") throw new InvalidArgumentError("Grant Request 不存在或已结束");
    request.status = status;
    request.decidedAt = new Date().toISOString();
    this.putGrantRequest(request);
    return request;
  }

  expirePendingGrantRequests(taskId: string): number {
    const rows = this.db.prepare("SELECT payload FROM grant_requests_v2 WHERE task_id=? AND status='PENDING'").all(taskId) as unknown as JsonRow[];
    for (const row of rows) { const request = JSON.parse(row.payload) as GrantRequest; request.status = "EXPIRED"; this.putGrantRequest(request); }
    return rows.length;
  }

  initializeBudget(taskId: string, epochId: string, owner: "PRESET" | "MODEL" | "DISCOVERY", limits: WireCost): void {
    const zero: WireCost = { remoteCalls: 0, nodes: 0, bytes: 0, wallTimeMs: 0, probeCalls: 0 };
    this.db.prepare("INSERT OR IGNORE INTO budget_accounts_v2(task_id,epoch_id,owner,limits_json,used_json,reserved_json) VALUES(?,?,?,?,?,?)")
      .run(taskId, epochId, owner, JSON.stringify(limits), JSON.stringify(zero), JSON.stringify(zero));
  }

  getBudgetAccount(taskId: string, epochId: string, owner: "PRESET" | "MODEL" | "DISCOVERY"): BudgetAccountSnapshot | undefined {
    const row = this.db.prepare("SELECT limits_json,used_json,reserved_json FROM budget_accounts_v2 WHERE task_id=? AND epoch_id=? AND owner=?")
      .get(taskId, epochId, owner) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    const limits = JSON.parse(String(row.limits_json)) as WireCost;
    const used = JSON.parse(String(row.used_json)) as WireCost;
    const reserved = JSON.parse(String(row.reserved_json)) as WireCost;
    return { owner, limits, used, reserved, remaining: subtractCost(limits, addCost(used, reserved)) };
  }

  reserveBudget(reservationId: string, taskId: string, epochId: string, owner: "PRESET" | "MODEL" | "DISCOVERY", estimate: WireCost): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT * FROM budget_accounts_v2 WHERE task_id=? AND epoch_id=? AND owner=?").get(taskId, epochId, owner) as Record<string, unknown> | undefined;
      if (!row) throw new SecurityError("BUDGET_EXCEEDED", "预算账户尚未初始化");
      const limits = JSON.parse(String(row.limits_json)) as WireCost;
      const used = JSON.parse(String(row.used_json)) as WireCost;
      const reserved = JSON.parse(String(row.reserved_json)) as WireCost;
      for (const key of budgetKeys) if ((used[key] ?? 0) + (reserved[key] ?? 0) + (estimate[key] ?? 0) > (limits[key] ?? 0)) throw new SecurityError("BUDGET_EXCEEDED", `预算不足: ${key}`);
      const next = addCost(reserved, estimate);
      this.db.prepare("UPDATE budget_accounts_v2 SET reserved_json=? WHERE task_id=? AND epoch_id=? AND owner=?").run(JSON.stringify(next), taskId, epochId, owner);
      this.db.prepare("INSERT INTO budget_reservations_v2(reservation_id,task_id,epoch_id,owner,status,estimate_json,created_at) VALUES(?,?,?,?,?,?,?)")
        .run(reservationId, taskId, epochId, owner, "RESERVED", JSON.stringify(estimate), new Date().toISOString());
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  settleBudget(reservationId: string, actual: WireCost): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const reservation = this.db.prepare("SELECT * FROM budget_reservations_v2 WHERE reservation_id=?").get(reservationId) as Record<string, unknown> | undefined;
      if (reservation?.status !== "RESERVED") throw new InvalidArgumentError("未知或已结算预算预留");
      const estimate = JSON.parse(String(reservation.estimate_json)) as WireCost;
      for (const key of budgetKeys) if ((actual[key] ?? 0) > (estimate[key] ?? 0)) throw new SecurityError("INTERNAL_ERROR", `实际成本超过预留: ${key}`);
      const row = this.db.prepare("SELECT * FROM budget_accounts_v2 WHERE task_id=? AND epoch_id=? AND owner=?")
        .get(String(reservation.task_id), String(reservation.epoch_id), String(reservation.owner)) as Record<string, unknown>;
      const reserved = subtractCost(JSON.parse(String(row.reserved_json)) as WireCost, estimate);
      const used = addCost(JSON.parse(String(row.used_json)) as WireCost, actual);
      this.db.prepare("UPDATE budget_accounts_v2 SET used_json=?,reserved_json=? WHERE task_id=? AND epoch_id=? AND owner=?")
        .run(JSON.stringify(used), JSON.stringify(reserved), String(reservation.task_id), String(reservation.epoch_id), String(reservation.owner));
      this.db.prepare("UPDATE budget_reservations_v2 SET status='SETTLED',actual_json=?,settled_at=? WHERE reservation_id=?")
        .run(JSON.stringify(actual), new Date().toISOString(), reservationId);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  initializeUsageCounter(taskId: string, epochId: string, kind: string, limit: number): void {
    if (!Number.isSafeInteger(limit) || limit < 0) throw new InvalidArgumentError("Usage Counter limit 非法");
    this.db.prepare("INSERT OR IGNORE INTO usage_counters_v2(task_id,epoch_id,kind,limit_value,used_value) VALUES(?,?,?,?,0)")
      .run(taskId, epochId, kind, limit);
  }

  remainingUsage(taskId: string, epochId: string, kind: string): number {
    const row = this.db.prepare("SELECT limit_value,used_value FROM usage_counters_v2 WHERE task_id=? AND epoch_id=? AND kind=?")
      .get(taskId, epochId, kind) as { limit_value: number; used_value: number } | undefined;
    if (!row) throw new SecurityError("BUDGET_EXCEEDED", `Usage Counter 尚未初始化: ${kind}`);
    return Math.max(0, row.limit_value - row.used_value);
  }

  consumeUsage(taskId: string, epochId: string, kind: string, amount: number): void {
    if (!Number.isSafeInteger(amount) || amount < 0) throw new InvalidArgumentError("Usage Counter amount 非法");
    const result = this.db.prepare("UPDATE usage_counters_v2 SET used_value=used_value+? WHERE task_id=? AND epoch_id=? AND kind=? AND used_value+?<=limit_value")
      .run(amount, taskId, epochId, kind, amount);
    if (result.changes !== 1) throw new SecurityError("BUDGET_EXCEEDED", `预算不足: ${kind}`);
  }

  refundUsage(taskId: string, epochId: string, kind: string, amount: number): void {
    if (!Number.isSafeInteger(amount) || amount < 0) throw new InvalidArgumentError("Usage Counter refund amount 非法");
    const result = this.db.prepare("UPDATE usage_counters_v2 SET used_value=MAX(0,used_value-?) WHERE task_id=? AND epoch_id=? AND kind=?")
      .run(amount, taskId, epochId, kind);
    if (result.changes !== 1) throw new SecurityError("INTERNAL_ERROR", `Usage Counter 不存在: ${kind}`);
  }

  appendMessage(taskId: string, message: AgentMessage, epochId?: string): number {
    const count = this.db.prepare("SELECT COUNT(*) AS count FROM messages WHERE task_id=?").get(taskId) as unknown as CountRow;
    const seq = count.count + 1;
    const messageId = digestObject({ taskId, epochId, seq, message });
    this.db.prepare("INSERT OR IGNORE INTO messages(message_id,task_id,epoch_id,seq,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(messageId, taskId, epochId ?? null, seq, JSON.stringify(message), new Date().toISOString());
    return seq;
  }

  loadMessages(taskId: string, epochId?: string): AgentMessage[] {
    const rows = (epochId === undefined
      ? this.db.prepare("SELECT payload FROM messages WHERE task_id=? ORDER BY seq").all(taskId)
      : this.db.prepare("SELECT payload FROM messages WHERE task_id=? AND epoch_id=? ORDER BY seq").all(taskId, epochId)) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as AgentMessage);
  }

  startToolRun(record: Omit<ToolRunRecord, "status" | "startedAt">): ToolRunRecord {
    const existing = this.getToolRun(record.toolCallId);
    if (existing) {
      const sameBinding = existing.taskId === record.taskId
        && existing.epochId === record.epochId
        && existing.toolName === record.toolName
        && existing.risk === record.risk
        && existing.replayPolicy === record.replayPolicy
        && digestObject(existing.args) === digestObject(record.args);
      if (!sameBinding) {
        throw new SecurityError(
          "RECOVERY_UNCERTAIN",
          "ToolCall ID 已绑定其他任务、Epoch、工具或参数，拒绝复用",
          { toolCallIdDigest: digestObject(record.toolCallId) },
        );
      }
      return existing;
    }
    const result: ToolRunRecord = { ...record, status: "STARTED", startedAt: new Date().toISOString() };
    this.db.prepare(`INSERT INTO tool_runs(
      tool_call_id,task_id,epoch_id,tool_name,risk,replay_policy,status,args_json,started_at
    ) VALUES(?,?,?,?,?,?,?,?,?)`).run(
      result.toolCallId, result.taskId, result.epochId ?? null, result.toolName, result.risk, result.replayPolicy,
      result.status, JSON.stringify(result.args), result.startedAt,
    );
    return result;
  }

  finishToolRun(toolCallId: string, status: ToolRunRecord["status"], result?: unknown, error?: string): void {
    this.db.prepare("UPDATE tool_runs SET status=?,result_json=?,error=?,finished_at=? WHERE tool_call_id=?")
      .run(status, result === undefined ? null : JSON.stringify(result), error ?? null, new Date().toISOString(), toolCallId);
  }

  getToolRun(toolCallId: string): ToolRunRecord | undefined {
    const row = this.db.prepare("SELECT * FROM tool_runs WHERE tool_call_id=?").get(toolCallId) as Record<string, unknown> | undefined;
    return row ? this.decodeToolRun(row) : undefined;
  }

  /**
   * 按任务作用域读取工具运行记录。
   *
   * `getToolRun` 只按 `tool_call_id` 查，模型可达的回取路径必须用本方法，否则一个跨任务的
   * `toolCallId` 就能读到别的任务的采集结果。
   */
  getToolRunForTask(taskId: string, toolCallId: string): ToolRunRecord | undefined {
    const record = this.getToolRun(toolCallId);
    return record?.taskId === taskId ? record : undefined;
  }

  /** v2 调用必须同时绑定任务和 Epoch，迁移前的无 Epoch 记录不会被当前调查复用。 */
  getToolRunForScope(taskId: string, epochId: string, toolCallId: string): ToolRunRecord | undefined {
    const record = this.getToolRun(toolCallId);
    return record?.taskId === taskId && record.epochId === epochId ? record : undefined;
  }

  listIncompleteToolRuns(taskId: string): ToolRunRecord[] {
    const rows = this.db.prepare("SELECT * FROM tool_runs WHERE task_id=? AND status='STARTED' ORDER BY started_at")
      .all(taskId) as unknown as Record<string, unknown>[];
    return rows.map((row) => this.decodeToolRun(row));
  }

  listToolRuns(taskId: string, limit = 500): ToolRunRecord[] {
    const rows = this.db.prepare("SELECT * FROM tool_runs WHERE task_id=? ORDER BY started_at DESC LIMIT ?")
      .all(taskId, limit) as unknown as Record<string, unknown>[];
    return rows.reverse().map((row) => this.decodeToolRun(row));
  }

  putEvidence(evidence: Evidence): void {
    this.db.prepare("INSERT OR REPLACE INTO evidence(evidence_id,task_id,payload,created_at) VALUES(?,?,?,?)")
      .run(evidence.evidenceId, evidence.taskId, JSON.stringify(evidence), evidence.collectedAt);
  }

  getEvidence(taskId: string, evidenceId: string): Evidence | undefined {
    const row = this.db.prepare("SELECT payload FROM evidence WHERE task_id=? AND evidence_id=?")
      .get(taskId, evidenceId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as Evidence : undefined;
  }

  listEvidence(taskId: string): Evidence[] {
    const rows = this.db.prepare("SELECT payload FROM evidence WHERE task_id=? ORDER BY created_at")
      .all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as Evidence);
  }

  putApproval(ticket: ApprovalTicket): void {
    this.db.prepare(`INSERT OR REPLACE INTO approvals(
      approval_id,task_id,tool_name,args_digest,action_id,status,payload,created_at
    ) VALUES(?,?,?,?,?,?,?,?)`).run(
      ticket.approvalId, ticket.taskId, ticket.tool, ticket.argsDigest, ticket.actionId,
      ticket.status, JSON.stringify(ticket), ticket.createdAt,
    );
  }

  updateApproval(approvalId: string, status: ApprovalStatus): ApprovalTicket {
    const row = this.db.prepare("SELECT payload FROM approvals WHERE approval_id=?").get(approvalId) as JsonRow | undefined;
    if (!row) throw new Error(`Approval not found: ${approvalId}`);
    const ticket = JSON.parse(row.payload) as ApprovalTicket;
    const now = new Date().toISOString();
    ticket.status = status;
    if (status === "APPROVED" || status === "DENIED") ticket.decidedAt = now;
    if (status === "CONSUMED") ticket.consumedAt = now;
    this.putApproval(ticket);
    return ticket;
  }

  findApproval(taskId: string, tool: string, argsDigest: string, epochId?: string): ApprovalTicket | undefined {
    const rows = this.db.prepare(`SELECT payload FROM approvals
      WHERE task_id=? AND tool_name=? AND args_digest=? AND status='APPROVED'
      ORDER BY created_at DESC`).all(taskId, tool, argsDigest) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ApprovalTicket)
      .find((ticket) => epochId === undefined || ticket.epochId === epochId);
  }

  findLatestApproval(taskId: string, tool: string, argsDigest: string, epochId?: string): ApprovalTicket | undefined {
    const rows = this.db.prepare(`SELECT payload FROM approvals
      WHERE task_id=? AND tool_name=? AND args_digest=?
      ORDER BY created_at DESC`).all(taskId, tool, argsDigest) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ApprovalTicket)
      .find((ticket) => epochId === undefined || ticket.epochId === epochId);
  }

  listPendingApprovals(taskId?: string): ApprovalTicket[] {
    const rows = taskId
      ? this.db.prepare("SELECT payload FROM approvals WHERE status='PENDING' AND task_id=? ORDER BY created_at").all(taskId)
      : this.db.prepare("SELECT payload FROM approvals WHERE status='PENDING' ORDER BY created_at").all();
    return (rows as unknown as JsonRow[]).map((row) => JSON.parse(row.payload) as ApprovalTicket);
  }

  listApprovals(taskId: string): ApprovalTicket[] {
    const rows = this.db.prepare("SELECT payload FROM approvals WHERE task_id=? ORDER BY created_at").all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ApprovalTicket);
  }

  putActionReceipt(receipt: ActionReceipt): void {
    this.db.prepare("INSERT OR REPLACE INTO action_receipts(action_id,task_id,status,payload,updated_at) VALUES(?,?,?,?,?)")
      .run(receipt.actionId, receipt.taskId, receipt.status, JSON.stringify(receipt), new Date().toISOString());
  }

  getActionReceipt(actionId: string): ActionReceipt | undefined {
    const row = this.db.prepare("SELECT payload FROM action_receipts WHERE action_id=?").get(actionId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ActionReceipt : undefined;
  }

  listActionReceipts(taskId: string): ActionReceipt[] {
    const rows = this.db.prepare("SELECT payload FROM action_receipts WHERE task_id=? ORDER BY updated_at").all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ActionReceipt);
  }

  putReport(report: ReportRecord): void {
    this.db.prepare("INSERT INTO reports(report_id,task_id,version,payload,created_at) VALUES(?,?,?,?,?)")
      .run(report.reportId, report.taskId, report.version, JSON.stringify(report), report.createdAt);
  }

  listReports(taskId: string): ReportRecord[] {
    const rows = this.db.prepare("SELECT payload FROM reports WHERE task_id=? ORDER BY version")
      .all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as ReportRecord);
  }

  getReport(taskId: string, reportId: string): ReportRecord | undefined {
    const row = this.db.prepare("SELECT payload FROM reports WHERE task_id=? AND report_id=?")
      .get(taskId, reportId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ReportRecord : undefined;
  }

  latestReport(taskId: string): ReportRecord | undefined {
    const row = this.db.prepare("SELECT payload FROM reports WHERE task_id=? ORDER BY version DESC LIMIT 1")
      .get(taskId) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ReportRecord : undefined;
  }

  enqueueInput(taskId: string, message: AgentMessage, epochId?: string): string {
    const inputId = createId("action");
    this.db.prepare("INSERT INTO queued_inputs(input_id,task_id,epoch_id,status,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(inputId, taskId, epochId ?? null, "PENDING", JSON.stringify(message), new Date().toISOString());
    return inputId;
  }

  listPendingInputs(taskId: string, epochId?: string): { inputId: string; message: AgentMessage }[] {
    const rows = (epochId === undefined
      ? this.db.prepare("SELECT input_id,payload FROM queued_inputs WHERE task_id=? AND status='PENDING' ORDER BY created_at").all(taskId)
      : this.db.prepare("SELECT input_id,payload FROM queued_inputs WHERE task_id=? AND epoch_id=? AND status='PENDING' ORDER BY created_at").all(taskId, epochId)) as unknown as { input_id: string; payload: string }[];
    return rows.map((row) => ({ inputId: row.input_id, message: JSON.parse(row.payload) as AgentMessage }));
  }

  markInputDelivered(inputId: string): void {
    this.db.prepare("UPDATE queued_inputs SET status='DELIVERED',delivered_at=? WHERE input_id=?")
      .run(new Date().toISOString(), inputId);
  }

  appendAudit(event: Omit<AuditEvent, "eventId" | "createdAt">): AuditEvent {
    const stored: AuditEvent = { ...event, eventId: createId("action"), createdAt: new Date().toISOString() };
    this.db.prepare("INSERT INTO audit_events(event_id,task_id,event,level,payload,created_at) VALUES(?,?,?,?,?,?)")
      .run(stored.eventId, stored.taskId ?? null, stored.event, stored.level, JSON.stringify(stored.data), stored.createdAt);
    return stored;
  }

  listAudit(taskId: string, limit = 500): AuditEvent[] {
    const rows = this.db.prepare("SELECT event_id,task_id,event,level,payload,created_at FROM audit_events WHERE task_id=? ORDER BY seq DESC LIMIT ?")
      .all(taskId, limit) as unknown as Record<string, unknown>[];
    return rows.reverse().map((row) => ({
      eventId: String(row.event_id),
      ...(row.task_id ? { taskId: String(row.task_id) } : {}),
      event: String(row.event),
      level: String(row.level) as AuditEvent["level"],
      data: JSON.parse(String(row.payload)) as Record<string, unknown>,
      createdAt: String(row.created_at),
    }));
  }

  private requireTask(taskId: string): TaskContext {
    const task = this.getTask(taskId);
    if (!task) throw new Error(`Task not found: ${taskId}`);
    return task;
  }

  private decodeToolRun(row: Record<string, unknown>): ToolRunRecord {
    const record: ToolRunRecord = {
      toolCallId: String(row.tool_call_id), taskId: String(row.task_id), toolName: String(row.tool_name),
      risk: String(row.risk), replayPolicy: String(row.replay_policy),
      args: JSON.parse(String(row.args_json)), status: String(row.status) as ToolRunRecord["status"],
      startedAt: String(row.started_at),
    };
    if (row.epoch_id) record.epochId = String(row.epoch_id);
    if (row.result_json) record.result = JSON.parse(String(row.result_json));
    if (row.error) record.error = String(row.error);
    if (row.finished_at) record.finishedAt = String(row.finished_at);
    return record;
  }
}
