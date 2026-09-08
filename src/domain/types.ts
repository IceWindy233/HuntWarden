import type { AgentTool } from "@earendil-works/pi-agent-core";
import type { TSchema } from "typebox";

export type TaskMode = "SCAN" | "REMEDIATE";
export type TaskStatus =
  | "CREATED"
  | "RUNNING"
  | "PAUSED"
  | "WAITING_APPROVAL"
  | "RECOVERING"
  | "REPORTING"
  | "COMPLETED"
  | "FAILED"
  | "ABORTED";

export type CheckCategory =
  | "webshell"
  | "java_memory_shell"
  | "backdoor_account"
  | "linux_persistence"
  | "linux_intrusion_triage";
export type ScanProfile = "QUICK" | "STANDARD" | "DEEP";

export interface InvestigationIocs {
  hash?: string[];
  domain?: string[];
  ip?: string[];
  path?: string[];
  processName?: string[];
}

export const CHECK_CATEGORY_LABELS: Record<CheckCategory, string> = {
  webshell: "WebShell",
  java_memory_shell: "Java 内存马",
  backdoor_account: "后门账户",
  linux_persistence: "Linux 持久化",
  linux_intrusion_triage: "Linux 入侵分诊",
};

export const CHECK_CATEGORY_SHORT_LABELS: Record<CheckCategory, string> = {
  webshell: "WEB",
  java_memory_shell: "JAVA",
  backdoor_account: "ACCOUNT",
  linux_persistence: "PERSIST",
  linux_intrusion_triage: "TRIAGE",
};
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ToolRisk = "LOCAL" | "READ" | "INTRUSIVE_READ" | "COLLECT" | "WRITE";
export type ReplayPolicy = "SAFE" | "SAFE_REOBSERVE" | "LOCAL_REPLAY" | "IDEMPOTENT_LOCAL" | "RESUME_OR_RECOLLECT" | "NEVER";

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
  /** 历史任务可能没有扫描预设、时间窗与定向 IOC。 */
  profile?: ScanProfile;
  timeWindowHours?: number;
  iocs?: InvestigationIocs;
  focus?: {
    categories: CheckCategory[];
    entryMode: "ZERO_IOC" | "SINGLE_LEAD" | "MULTI_LEAD";
    iocKinds: Array<keyof InvestigationIocs>;
    priority: "VOLATILE_FIRST";
  };
  createdAt: string;
  updatedAt: string;
  /** 归档只影响默认列表可见性，不删除任务关联数据。 */
  archivedAt?: string;
  turnCount: number;
  toolCallCount: number;
  /** 新任务恒为 2；字段缺失表示只读 v1 历史任务。 */
  protocolVersion?: 2;
  activeEpochId?: string;
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
  /** 票据只能授权创建时的 v2 Epoch；迁移前票据没有此字段并按失效处理。 */
  epochId?: string;
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
  epochId?: string;
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
  /** 生成该不可变报告时使用的 v2 Epoch；历史导入报告没有此字段。 */
  epochId?: string;
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

export interface AuditEvent {
  eventId: string;
  taskId?: string;
  event: string;
  level: "debug" | "info" | "warn" | "error";
  data: Record<string, unknown>;
  createdAt: string;
}
