import type { CheckCategory, Severity } from "../domain/types.js";
import type { ProtocolV2ErrorCode } from "../common/errors.js";

export const PROTOCOL_VERSION = 2 as const;
export const MANIFEST_VERSION = "2.0.0";

export const NAMESPACE_NAMES = [
  "host", "process", "socket", "file", "account", "ssh_key", "cron_entry", "unit",
  "persistence", "module", "log_source", "log_event", "auth_event", "exec_event", "web_stack",
  "web_root", "jvm", "java_component", "class", "package", "task_ioc",
] as const;
export type NamespaceName = typeof NAMESPACE_NAMES[number];

export type Consistency = "OBJECT_STABLE" | "CURSOR_BEST_EFFORT" | "POINT_IN_TIME" | "EXTERNAL_BASELINE";
export type FactSourceKind = "PRESET" | "MODEL" | "SYSTEM" | "EXTERNAL";
export type Sensitivity = "PUBLIC" | "SENSITIVE" | "SECRET" | "EVIDENCE_ONLY";
export type ModelExposure = "VALUE" | "HASH_ONLY" | "PRESENCE_ONLY" | "DENY";
export type ContentClass = "SAFE_TEXT" | "SENSITIVE_TEXT" | "DENIED_TEXT";

export type PredicateOperator = "eq" | "neq" | "lt" | "lte" | "gt" | "gte" | "in" | "contains" | "starts_with" | "exists";
export type Predicate =
  | { op: "and" | "or"; args: Predicate[] }
  | { op: "not"; arg: Predicate }
  | { op: PredicateOperator; field: string; value?: string | number | boolean | null | Array<string | number | boolean> };

export const COVERAGE_GAP_CODES = [
  "PERMISSION_DENIED", "CAPABILITY_UNAVAILABLE", "DEADLINE", "NODE_LIMIT", "BYTE_LIMIT",
  "OUTPUT_LIMIT", "SOURCE_CHANGED", "FIELD_UNAVAILABLE", "COLLECTOR_ERROR",
] as const;
export type CoverageGapCode = typeof COVERAGE_GAP_CODES[number];
export interface CoverageGap {
  code: CoverageGapCode;
  detail?: string;
  field?: string;
  resumable: boolean;
}

export const INVESTIGATION_GAP_CODES = ["GRANT_DENIED", "GRANT_EXPIRED", "BUDGET_DENIED", "MODEL_DID_NOT_INVESTIGATE"] as const;
export type InvestigationGapCode = typeof INVESTIGATION_GAP_CODES[number];
export interface InvestigationGap {
  gapId: string;
  taskId: string;
  epochId: string;
  category?: CheckCategory;
  code: InvestigationGapCode;
  reasonCode: string;
  createdAt: string;
}

export interface ScanEpoch {
  epochId: string;
  taskId: string;
  targetFingerprint: string;
  protocolVersion: 2;
  manifestVersion: string;
  helperVersion: string;
  reason: "INITIAL" | "RESCAN" | "RECOVERY_REOBSERVE";
  status: "RUNNING" | "COMPLETED" | "PARTIAL" | "ABORTED";
  startedAt: string;
  finishedAt?: string;
}

export interface FactSource {
  kind: FactSourceKind;
  presetRunId?: string;
  presetId?: string;
  presetVersion?: string;
  stepId?: string;
  externalProvider?: string;
}

export interface Provenance {
  targetFingerprint: string;
  requestId: string;
  wireDigest: string;
  stableIdentityDigest: string;
}

export interface FactRecord {
  factId: string;
  factSeq: number;
  taskId: string;
  epochId: string;
  namespace: NamespaceName;
  subjectRef: string;
  schemaVersion: string;
  observedAt: string;
  sourceRunId: string;
  source: FactSource;
  collector: { name: string; version: string };
  consistency: Consistency;
  completeness: "COMPLETE" | "PARTIAL";
  gaps: CoverageGap[];
  privatePayload: Record<string, unknown>;
  modelPayload: Record<string, unknown>;
  redactedFields: string[];
  unavailableFields: Array<{ field: string; reasonCode: string }>;
  payloadDigest: string;
  provenance: Provenance;
}

export interface ObjectReference {
  ref: string;
  taskId: string;
  epochId: string;
  targetFingerprint: string;
  namespace: NamespaceName;
  stableIdentityDigest: string;
  stableIdentity: Record<string, unknown>;
  assertions: Array<{ kind: string; valueDigest: string; observedAt: string }>;
  createdAt: string;
}

export interface EdgeRecord {
  edgeId: string;
  taskId: string;
  epochId: string;
  relation: string;
  fromRef: string;
  toRef: string;
  sourceRunId: string;
  observedAt: string;
}

export interface WireObservation {
  namespace: NamespaceName;
  identity: Record<string, unknown>;
  fields: Record<string, unknown>;
  unavailableFields?: Array<{ field: string; reasonCode: string }>;
  observedAt: string;
  consistency: Consistency;
}

export interface WireEdge {
  relation: string;
  fromIdentity: { namespace: NamespaceName; identity: Record<string, unknown> };
  toIdentity: { namespace: NamespaceName; identity: Record<string, unknown> };
  observedAt: string;
}

export interface WireCost { remoteCalls: number; nodes: number; bytes: number; wallTimeMs: number; probeCalls?: number }
export interface BudgetReservation { reservationId: string; estimate: WireCost }

export interface WireRequest<T = Record<string, unknown>> {
  protocolVersion: 2;
  requestId: string;
  epochId: string;
  deadlineMs: number;
  reservation: BudgetReservation;
  params: T;
}

export interface WireSuccess {
  protocolVersion: 2;
  requestId: string;
  status: "SUCCESS" | "PARTIAL";
  objects: WireObservation[];
  edges: WireEdge[];
  cursor?: string;
  artifact?: { token: string; sha256: string; size: number; complete: boolean; expiresAt: string };
  cost: WireCost;
  gaps: CoverageGap[];
}

export interface WireFailure {
  protocolVersion: 2;
  requestId: string;
  status: "ERROR";
  error: { code: ProtocolV2ErrorCode; message?: string };
  cost: WireCost;
}
export type WireResponse = WireSuccess | WireFailure;

export interface HelperCapabilitiesV2 {
  protocolVersion: 2;
  manifestVersion: string;
  helper: { name: string; version: string };
  namespaces: Partial<Record<NamespaceName, { fields: string[]; relations: string[]; verbs?: Array<"enumerate" | "project" | "read" | "match" | "relate" | "verify" | "collect" | "probe"> }>>;
  matchers: Array<"literal" | "re2" | "yara">;
  probes: Array<"jvm.tomcat.inventory" | "jvm.class.inspect">;
  verbs: Array<"enumerate" | "project" | "read" | "match" | "relate" | "verify" | "collect" | "probe">;
  limits: { maxObjects: number; maxOutputBytes: number; maxReadBytes: number; maxCollectBytes: number };
}

export interface CoverageRun {
  coverageId: string;
  taskId: string;
  epochId: string;
  category: CheckCategory;
  presetId: string;
  presetVersion: string;
  status: "COMPLETE" | "PARTIAL" | "ERROR" | "NOT_RUN";
  applicability: "APPLICABLE" | "NOT_APPLICABLE" | "UNKNOWN";
  completedCriteria: string[];
  missingCriteria: Array<{ criterion: string; reasonCode: string; sourceRunId?: string }>;
  createdAt: string;
}

export type AssessmentVerdict = "CONFIRMED_MALICIOUS" | "HIGHLY_SUSPICIOUS" | "SUSPICIOUS" | "BENIGN" | "NO_OBSERVED_FINDING" | "INCONCLUSIVE";
export interface Assessment {
  assessmentId: string;
  taskId: string;
  epochId: string;
  authorType: "RULE" | "MODEL" | "HUMAN" | "SYSTEM";
  category: CheckCategory;
  subjectRef?: string;
  scope: "SUBJECT" | "OBSERVED_CATEGORY";
  verdict: AssessmentVerdict;
  severity: Severity;
  confidence: number;
  rationale: string;
  evidenceRefs: string[];
  factRefs: string[];
  queryRefs: string[];
  createdAt: string;
}

export interface AssessmentRelation {
  relationId: string;
  taskId: string;
  epochId: string;
  kind: "SUPPORTS" | "CONTRADICTS" | "ADJUDICATES" | "SUPERSEDES";
  fromAssessmentId: string;
  toAssessmentId: string;
  createdAt: string;
}

export type GrantKind = "CATEGORY" | "SCOPE" | "SENSITIVE_READ" | "PROBE" | "BUDGET_EXTENSION";
export interface TaskGrant {
  grantId: string;
  taskId: string;
  targetFingerprint: string;
  kind: GrantKind;
  status: "ACTIVE" | "REVOKED" | "EXPIRED";
  binding: Record<string, unknown>;
  createdAt: string;
  expiresAt?: string;
  revokedAt?: string;
  revocationReason?: string;
}

export interface GrantRequest {
  requestId: string;
  taskId: string;
  targetFingerprint: string;
  kind: Exclude<GrantKind, "CATEGORY" | "PROBE" | "BUDGET_EXTENSION">;
  status: "PENDING" | "APPROVED" | "DENIED" | "CANCELLED" | "EXPIRED";
  bindingDigest: string;
  binding: Record<string, unknown>;
  createdAt: string;
  decidedAt?: string;
}

export interface QuerySnapshot {
  queryRef: string;
  taskId: string;
  epochId: string;
  view?: "facts" | "edges" | "evidence_meta" | "assessments" | "coverage";
  astDigest: string;
  maxFactSeq: number;
  rowCount: number;
  /** Controller-only provenance keys for release evaluation and Assessment audit. */
  rowRefs?: string[];
  createdAt: string;
}

export interface FactBatchInput {
  taskId: string;
  epochId: string;
  sourceRunId: string;
  source: FactSource;
  targetFingerprint: string;
  requestId: string;
  collector: { name: string; version: string };
  observations: WireObservation[];
  edges: WireEdge[];
  gaps: CoverageGap[];
  wireDigest: string;
  toolRun?: { toolCallId: string; status: "SUCCEEDED" | "FAILED"; result?: unknown; resultFactory?: (batch: FactBatchResult) => unknown; error?: string };
}

export interface FactBatchResult {
  batchId: string;
  facts: FactRecord[];
  refs: ObjectReference[];
  edges: EdgeRecord[];
}
