import type { AppConfig } from "../config/schema.js";
import type { ActionReceipt, ApprovalTicket, AuditEvent, Evidence, Finding, TaskContext, TaskMode, CheckCategory } from "../domain/types.js";

export const DESKTOP_API_VERSION = 1 as const;

export interface ConfigProfileSummary {
  profileId: string;
  name: string;
  provider: string;
  model: string;
  active: boolean;
  updatedAt: string;
}

export interface ConfigProfile extends ConfigProfileSummary {
  config: AppConfig;
  yamlPreview: string;
}

export interface ConfigValidationResult {
  valid: boolean;
  issues: { path: string; message: string }[];
  warnings: string[];
}

export interface CredentialStatus {
  provider: string;
  configured: boolean;
  source?: string;
  persistent: boolean;
  secureStorageBackend?: string;
  notice?: string;
}

export interface ModelProviderSummary {
  id: string;
  name: string;
  modelCount: number;
}

export interface ModelSummary {
  id: string;
  name: string;
  provider: string;
  protocol: string;
  reasoning: boolean;
  thinkingLevels: string[];
  contextWindow: number;
  maxTokens: number;
}

export interface ModelCheckResult {
  ok: boolean;
  provider: string;
  model: string;
  protocol: string;
  endpoint: string;
  credentialSource?: string;
  toolCallVerified: boolean;
  message: string;
}

export interface NewTaskInput {
  request: string;
  mode: TaskMode;
  checks: CheckCategory[];
  target: {
    host: string;
    port: number;
    username: string;
    hostFingerprint: string;
    privateKeyPath: string;
    knownHostsPath: string;
  };
}

export interface TaskSnapshot {
  task: TaskContext;
  findings: Finding[];
  evidence: Evidence[];
  approvals: ApprovalTicket[];
  actionReceipts: ActionReceipt[];
  audit: AuditEvent[];
  conversation: {
    role: "user" | "assistant" | "tool";
    text: string;
    timestamp: number;
    toolName?: string;
    isError?: boolean;
  }[];
  toolRuns: {
    toolCallId: string;
    toolName: string;
    risk: string;
    status: "STARTED" | "SUCCEEDED" | "FAILED" | "BLOCKED";
    startedAt: string;
    finishedAt?: string;
    error?: string;
  }[];
}

export type DesktopEvent =
  | { type: "task_updated"; task: TaskContext }
  | { type: "approval_requested"; ticket: ApprovalTicket }
  | { type: "finding_recorded"; finding: Finding }
  | { type: "evidence_recorded"; evidence: Evidence }
  | { type: "audit_recorded"; event: AuditEvent }
  | { type: "runtime_error"; taskId?: string; message: string };

/**
 * Renderer 只能获得这组最小能力；Preload 必须逐方法桥接，禁止暴露 ipcRenderer、
 * 任意 channel、文件系统、Shell、数据库句柄或已有凭据明文。
 */
export interface HuntWardenDesktopApi {
  getBootstrap(): Promise<{
    apiVersion: typeof DESKTOP_API_VERSION;
    appVersion: string;
    platform: string;
    activeProfileId?: string;
    profiles: ConfigProfileSummary[];
    tasks: TaskContext[];
  }>;

  listConfigProfiles(): Promise<ConfigProfileSummary[]>;
  getConfigProfile(profileId: string): Promise<ConfigProfile>;
  validateConfigProfile(config: AppConfig): Promise<ConfigValidationResult>;
  saveConfigProfile(input: { profileId?: string; name: string; config: AppConfig }): Promise<ConfigProfile>;
  activateConfigProfile(profileId: string): Promise<void>;
  deleteConfigProfile(profileId: string): Promise<void>;
  importConfigProfile(): Promise<ConfigProfile | undefined>;
  exportConfigProfile(profileId: string): Promise<string | undefined>;

  listModelProviders(): Promise<ModelProviderSummary[]>;
  listModels(provider: string): Promise<ModelSummary[]>;
  getCredentialStatus(provider: string): Promise<CredentialStatus>;
  saveCredential(input: { provider: string; secret: string; persist: boolean }): Promise<CredentialStatus>;
  deleteCredential(provider: string): Promise<void>;
  checkModel(profileId: string): Promise<ModelCheckResult>;
  smokeModel(profileId: string): Promise<ModelCheckResult>;

  selectPrivateKey(): Promise<string | undefined>;
  selectKnownHosts(): Promise<string | undefined>;
  testSshTarget(input: NewTaskInput["target"]): Promise<{ ok: boolean; fingerprint?: string; message: string }>;

  listTasks(): Promise<TaskContext[]>;
  getTaskSnapshot(taskId: string): Promise<TaskSnapshot>;
  createTask(input: NewTaskInput): Promise<TaskContext>;
  startTask(taskId: string): Promise<void>;
  abortTask(taskId: string): Promise<void>;
  recoverTask(taskId: string): Promise<void>;
  steerTask(input: { taskId: string; text: string }): Promise<void>;
  decideApproval(input: { approvalId: string; approved: boolean }): Promise<void>;
  generateReport(taskId: string): Promise<{ path: string }>;
  readReport(taskId: string): Promise<string | undefined>;
  revealEvidence(evidenceId: string): Promise<void>;
  revealReport(taskId: string): Promise<void>;

  subscribe(listener: (event: DesktopEvent) => void): () => void;
}
