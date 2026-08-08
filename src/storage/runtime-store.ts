import { DatabaseSync } from "node:sqlite";
import { chmod, mkdir, readFile, unlink } from "node:fs/promises";
import { closeSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import type {
  ActionReceipt,
  ApprovalStatus,
  ApprovalTicket,
  AuditEvent,
  CandidateReference,
  Evidence,
  Finding,
  FindingStatus,
  TaskContext,
  TaskStatus,
} from "../domain/types.js";
import { digestObject } from "../common/json.js";
import { createId } from "../common/ids.js";

interface JsonRow { payload: string }
interface CountRow { count: number }

export interface ToolRunRecord {
  toolCallId: string;
  taskId: string;
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
  private lockFd: number | undefined;
  private readonly lockPath: string;
  private closed = false;

  private constructor(databasePath: string, lockFd: number, lockPath: string) {
    this.databasePath = databasePath;
    this.lockFd = lockFd;
    this.lockPath = lockPath;
    this.db = new DatabaseSync(databasePath);
    this.db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.migrate();
  }

  static async open(baseDir: string, databaseFile: string): Promise<RuntimeStore> {
    await mkdir(baseDir, { recursive: true, mode: 0o700 });
    await chmod(baseDir, 0o700);
    const databasePath = join(baseDir, databaseFile);
    await mkdir(dirname(databasePath), { recursive: true, mode: 0o700 });
    const lockPath = `${databasePath}.writer.lock`;
    const lockFd = await this.acquireWriterLock(lockPath);
    const previousUmask = process.umask(0o077);
    let store: RuntimeStore;
    try {
      store = new RuntimeStore(databasePath, lockFd, lockPath);
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
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(task_id, seq),
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS tool_runs (
        tool_call_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
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
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        delivered_at TEXT,
        FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS findings (
        finding_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        tool_call_id TEXT NOT NULL UNIQUE,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
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
      CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
      CREATE INDEX IF NOT EXISTS idx_tool_runs_task ON tool_runs(task_id, status);
      CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id, seq);
    `);
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
    const statuses: TaskStatus[] = ["RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"];
    const placeholders = statuses.map(() => "?").join(",");
    const args: string[] = [...statuses];
    let sql = `SELECT COUNT(*) AS count FROM tasks WHERE status IN (${placeholders})`;
    if (excludingTaskId) { sql += " AND task_id<>?"; args.push(excludingTaskId); }
    const row = this.db.prepare(sql).get(...args) as unknown as CountRow;
    return row.count > 0;
  }

  updateCoverage(taskId: string, category: keyof TaskContext["coverage"], status: FindingStatus): void {
    const task = this.requireTask(taskId);
    task.coverage[category] = status;
    this.saveTask(task);
  }

  appendMessage(taskId: string, message: AgentMessage): number {
    const count = this.db.prepare("SELECT COUNT(*) AS count FROM messages WHERE task_id=?").get(taskId) as unknown as CountRow;
    const seq = count.count + 1;
    const messageId = digestObject({ taskId, seq, message });
    this.db.prepare("INSERT OR IGNORE INTO messages(message_id,task_id,seq,payload,created_at) VALUES(?,?,?,?,?)")
      .run(messageId, taskId, seq, JSON.stringify(message), new Date().toISOString());
    return seq;
  }

  loadMessages(taskId: string): AgentMessage[] {
    const rows = this.db.prepare("SELECT payload FROM messages WHERE task_id=? ORDER BY seq")
      .all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as AgentMessage);
  }

  startToolRun(record: Omit<ToolRunRecord, "status" | "startedAt">): ToolRunRecord {
    const existing = this.getToolRun(record.toolCallId);
    if (existing) return existing;
    const result: ToolRunRecord = { ...record, status: "STARTED", startedAt: new Date().toISOString() };
    this.db.prepare(`INSERT INTO tool_runs(
      tool_call_id,task_id,tool_name,risk,replay_policy,status,args_json,started_at
    ) VALUES(?,?,?,?,?,?,?,?)`).run(
      result.toolCallId, result.taskId, result.toolName, result.risk, result.replayPolicy,
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

  putReference<T>(reference: CandidateReference<T>): void {
    this.db.prepare("INSERT OR REPLACE INTO artifact_refs(ref,task_id,kind,payload,created_at) VALUES(?,?,?,?,?)")
      .run(reference.ref, reference.taskId, reference.kind, JSON.stringify(reference), reference.createdAt);
  }

  getReference<T>(taskId: string, ref: string, expectedKind?: CandidateReference["kind"]): CandidateReference<T> | undefined {
    const row = this.db.prepare("SELECT payload FROM artifact_refs WHERE task_id=? AND ref=?")
      .get(taskId, ref) as JsonRow | undefined;
    if (!row) return undefined;
    const value = JSON.parse(row.payload) as CandidateReference<T>;
    return expectedKind && value.kind !== expectedKind ? undefined : value;
  }

  putFinding(finding: Finding): Finding {
    const existing = this.db.prepare("SELECT payload FROM findings WHERE tool_call_id=?")
      .get(finding.toolCallId) as JsonRow | undefined;
    if (existing) return JSON.parse(existing.payload) as Finding;
    this.db.prepare("INSERT INTO findings(finding_id,task_id,tool_call_id,payload,created_at) VALUES(?,?,?,?,?)")
      .run(finding.findingId, finding.taskId, finding.toolCallId, JSON.stringify(finding), finding.createdAt);
    this.updateCoverage(finding.taskId, finding.category, finding.status);
    return finding;
  }

  listFindings(taskId: string): Finding[] {
    const rows = this.db.prepare("SELECT payload FROM findings WHERE task_id=? ORDER BY created_at")
      .all(taskId) as unknown as JsonRow[];
    return rows.map((row) => JSON.parse(row.payload) as Finding);
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

  findApproval(taskId: string, tool: string, argsDigest: string): ApprovalTicket | undefined {
    const row = this.db.prepare(`SELECT payload FROM approvals
      WHERE task_id=? AND tool_name=? AND args_digest=? AND status='APPROVED'
      ORDER BY created_at DESC LIMIT 1`).get(taskId, tool, argsDigest) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ApprovalTicket : undefined;
  }

  findLatestApproval(taskId: string, tool: string, argsDigest: string): ApprovalTicket | undefined {
    const row = this.db.prepare(`SELECT payload FROM approvals
      WHERE task_id=? AND tool_name=? AND args_digest=?
      ORDER BY created_at DESC LIMIT 1`).get(taskId, tool, argsDigest) as JsonRow | undefined;
    return row ? JSON.parse(row.payload) as ApprovalTicket : undefined;
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

  enqueueInput(taskId: string, message: AgentMessage): string {
    const inputId = createId("action");
    this.db.prepare("INSERT INTO queued_inputs(input_id,task_id,status,payload,created_at) VALUES(?,?,?,?,?)")
      .run(inputId, taskId, "PENDING", JSON.stringify(message), new Date().toISOString());
    return inputId;
  }

  listPendingInputs(taskId: string): { inputId: string; message: AgentMessage }[] {
    const rows = this.db.prepare("SELECT input_id,payload FROM queued_inputs WHERE task_id=? AND status='PENDING' ORDER BY created_at")
      .all(taskId) as unknown as { input_id: string; payload: string }[];
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
    if (row.result_json) record.result = JSON.parse(String(row.result_json));
    if (row.error) record.error = String(row.error);
    if (row.finished_at) record.finishedAt = String(row.finished_at);
    return record;
  }
}
