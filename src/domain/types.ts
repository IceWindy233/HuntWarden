import type { AgentTool } from "@earendil-works/pi-agent-core";
import type { TSchema } from "typebox";

export type TaskMode = "SCAN" | "REMEDIATE";
export type TaskStatus =
  | "CREATED"
  | "RUNNING"
  | "WAITING_APPROVAL"
  | "RECOVERING"
  | "REPORTING"
  | "COMPLETED"
  | "FAILED"
  | "ABORTED";

export type CheckCategory = "webshell" | "java_memory_shell" | "backdoor_account" | "linux_persistence";
export type FindingStatus =
  | "CONFIRMED"
  | "HIGHLY_SUSPICIOUS"
  | "SUSPICIOUS"
  | "NO_FINDING"
  | "NOT_CHECKED"
  | "ERROR";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ToolRisk = "LOCAL" | "READ" | "COLLECT" | "WRITE";
export type ReplayPolicy = "SAFE" | "NEVER";

export interface TargetConfig {
  host: string;
  port: number;
  username: string;
  hostFingerprint: string;
  privateKeyPath: string;
  knownHostsPath: string;
}

export interface TaskContext {
  taskId: string;
  request: string;
  target: TargetConfig;
  mode: TaskMode;
  status: TaskStatus;
  modelProvider: string;
  modelId: string;
  promptVersion: string;
  checks: CheckCategory[];
  coverage: Partial<Record<CheckCategory, FindingStatus>>;
  createdAt: string;
  updatedAt: string;
  /** 归档只影响默认列表可见性，不删除任务关联数据。 */
  archivedAt?: string;
  turnCount: number;
  toolCallCount: number;
  interruption?: {
    previousStatus: Extract<TaskStatus, "RUNNING" | "WAITING_APPROVAL" | "RECOVERING" | "REPORTING">;
    reason: "PROCESS_INTERRUPTED";
    detectedAt: string;
    recoveryRequired: boolean;
  };
}

export interface SecurityToolResult<TSummary = unknown, TItem = unknown> {
  status: "success" | "partial";
  summary: TSummary;
  items: TItem[];
  artifactRefs: string[];
  warnings: string[];
}

export interface SecurityToolDefinition<
  TParameters extends TSchema = TSchema,
  TDetails = unknown,
> extends AgentTool<TParameters, TDetails> {
  risk: ToolRisk;
  replayPolicy: ReplayPolicy;
  timeoutMs: number;
  auditEvent: string;
}

export interface Finding {
  findingId: string;
  taskId: string;
  host: string;
  category: CheckCategory;
  severity: Severity;
  confidence: number;
  status: FindingStatus;
  title: string;
  summary: string;
  evidenceRefs: string[];
  recommendation?: string;
  createdAt: string;
  toolCallId: string;
}

export interface Evidence {
  evidenceId: string;
  taskId: string;
  host: string;
  type: string;
  source: string;
  sha256?: string;
  collectedAt: string;
  tool: string;
  toolCallId?: string;
  storagePath?: string;
  metadata?: Record<string, unknown>;
}

export type ApprovalStatus = "PENDING" | "APPROVED" | "DENIED" | "CONSUMED" | "EXPIRED";

export interface ApprovalTicket {
  approvalId: string;
  taskId: string;
  targetFingerprint: string;
  tool: string;
  argsDigest: string;
  actionId: string;
  actionSummary: string;
  status: ApprovalStatus;
  createdAt: string;
  decidedAt?: string;
  consumedAt?: string;
}

export type ActionReceiptStatus = "STARTED" | "SUCCEEDED" | "FAILED" | "UNKNOWN";

export interface ActionReceipt {
  actionId: string;
  taskId: string;
  tool: string;
  targetFingerprint: string;
  status: ActionReceiptStatus;
  result?: Record<string, unknown>;
  startedAt: string;
  finishedAt?: string;
}

export type ReportGenerationMode = "MODEL" | "REPAIRED" | "FALLBACK" | "LEGACY";

export interface ReportRecord {
  reportId: string;
  taskId: string;
  version: number;
  path: string;
  sha256: string;
  generationMode: ReportGenerationMode;
  validationErrors: string[];
  createdAt: string;
}

/** 仅存在于当前进程内的模型文本流；不会写入任务消息历史。 */
export interface AgentStreamUpdate {
  taskId: string;
  streamId: string;
  phase: "start" | "delta" | "end" | "error";
  timestamp: number;
  delta?: string;
}

export interface CandidateReference<T = Record<string, unknown>> {
  ref: string;
  taskId: string;
  kind: "candidate" | "process" | "component" | "class" | "account" | "persistence";
  value: T;
  createdAt: string;
}

export interface AuditEvent {
  eventId: string;
  taskId?: string;
  event: string;
  level: "debug" | "info" | "warn" | "error";
  data: Record<string, unknown>;
  createdAt: string;
}
