import type { NamespaceName, WireCost } from "../protocol-v2/types.js";

export type InvestigationExecutionStatus = "STARTING" | "RUNNING" | "PAUSED" | "CANCELLING" | "STOPPED" | "FAILED";
export type InvestigationStatus = "OPEN" | "LIMITED" | "CLOSED_WITH_FINDINGS" | "CLOSED_NO_OBSERVED_FINDING" | "CANCELLED";

export interface InvestigationSession {
  sessionId: string;
  taskId: string;
  epochId: string;
  engineVersion: string;
  playbookRegistryDigest: string;
  ruleRegistryDigest: string;
  authorizationVersion: string;
  authorizationEnvelope?: AuthorizationEnvelope;
  executionStatus: InvestigationExecutionStatus;
  investigationStatus: InvestigationStatus;
  revision: number;
  completionSnapshotRef?: string;
  createdAt: string;
  updatedAt: string;
}

export interface EntityVersion {
  versionRef: string;
  entityRef: string;
  taskId: string;
  epochId: string;
  namespace: NamespaceName;
  identityDigest: string;
  contentDigest?: string;
  sourceFactRef: string;
  validFrom: string;
  validTo?: string;
  assertions: Array<{ kind: string; valueDigest: string }>;
}

export type RelationDerivation = "OBSERVED" | "DERIVED" | "INFERRED";

export interface RelationProvenance {
  edgeRef: string;
  taskId: string;
  epochId: string;
  fromVersionRef?: string;
  toVersionRef?: string;
  derivation: RelationDerivation;
  sourceRefs: string[];
  resolverVersion: string;
  timeErrorMs: number;
}

export type DerivedResolverRef = "socket.owner_by_pid@1.0.0" | "process.parent_by_ppid@1.0.0";

export interface DerivedObjectRequest {
  requestId: string;
  taskId: string;
  epochId: string;
  resolverRef: DerivedResolverRef;
  sourceFactRef: string;
}

export interface DerivedObjectResult {
  requestId: string;
  resolverRef: DerivedResolverRef;
  sourceFactRef: string;
  status: "RESOLVED" | "NO_MATCH" | "AMBIGUOUS";
  objectRefs: string[];
  edgeRefs: string[];
}

export type LeadStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "DISMISSED" | "LIMITED";

export interface InvestigationLead {
  leadId: string;
  taskId: string;
  epochId: string;
  subjectRef: string;
  triggerKind: string;
  triggerVersion: string;
  triggerFactRefs: string[];
  observationRound: string;
  priority: number;
  status: LeadStatus;
  createdAt: string;
  updatedAt: string;
}

export type HypothesisStatus = "OPEN" | "SUPPORTED" | "REFUTED" | "LIMITED" | "SUPERSEDED";

export interface InvestigationHypothesis {
  hypothesisId: string;
  taskId: string;
  epochId: string;
  subjectRef: string;
  claim: string;
  proposedBy: "DISCOVERY" | "PLAYBOOK" | "MODEL" | "ANALYST";
  supportRefs: string[];
  counterEvidenceRefs: string[];
  alternativeExplanations: string[];
  status: HypothesisStatus;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export type ObligationStatus = "OPEN" | "QUEUED" | "SATISFIED" | "LIMITED" | "CANCELLED";

export interface InvestigationObligation {
  obligationId: string;
  taskId: string;
  epochId: string;
  hypothesisId?: string;
  obligationKind: string;
  dedupeKey: string;
  subjectRefs: string[];
  required: boolean;
  status: ObligationStatus;
  resultRefs: string[];
  gapRefs: string[];
  createdAt: string;
  updatedAt: string;
}

export type InvestigationActionKind = "REMOTE_PRIMITIVE" | "LOCAL_QUERY" | "DERIVE" | "MODEL_REVIEW";
export type InvestigationActionStatus = "READY" | "RUNNING" | "BLOCKED" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "CANCELLED";

export interface InvestigationAction {
  actionId: string;
  taskId: string;
  epochId: string;
  kind: InvestigationActionKind;
  requestedBy: "DISCOVERY" | "PLAYBOOK" | "MODEL" | "ANALYST";
  obligationIds: string[];
  subjectRefs: string[];
  entityVersionRefs: string[];
  operationRef: string;
  replayPolicy: "SAFE_REOBSERVE" | "RESUME_OR_RECOLLECT" | "NEVER";
  args: Record<string, unknown>;
  argsDigest: string;
  dependsOn: string[];
  authorizationVersion: string;
  observationRound: string;
  idempotencyKey: string;
  priority: number;
  status: InvestigationActionStatus;
  revision: number;
  workerId?: string;
  resultRefs?: string[];
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface InvestigationActionAttempt {
  attemptId: string;
  actionId: string;
  taskId: string;
  epochId: string;
  attempt: number;
  toolCallId?: string;
  status: "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "BLOCKED" | "CANCELLED";
  error?: string;
  startedAt: string;
  finishedAt?: string;
}

export interface InvestigationEvent {
  eventSeq: number;
  eventId: string;
  taskId: string;
  epochId: string;
  sourceBatchRef?: string;
  eventType: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface DiscoveryCheckpoint {
  checkpointId: string;
  taskId: string;
  epochId: string;
  namespace: NamespaceName;
  requestDigest: string;
  status: "RUNNING" | "COMPLETE" | "LIMITED" | "FAILED";
  sourceGeneration?: string;
  cursorRef?: string;
  scannedCount: number;
  matchedCount: number;
  returnedCount: number;
  remainingDescription?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthorizationEnvelope {
  version: string;
  targetFingerprint: string;
  namespaces: NamespaceName[];
  scopeRefs: string[];
  derivedRelations: string[];
  sensitiveRead: boolean;
  collectEvidence: boolean;
  probes: string[];
  expiresAt?: string;
  budget: WireCost;
}

export interface CompletionSnapshot {
  snapshotRef: string;
  taskId: string;
  epochId: string;
  investigationStatus: InvestigationStatus;
  maxEventSeq: number;
  openRequiredObligationIds: string[];
  runningActionIds: string[];
  limitedObligationIds: string[];
  findingAssessmentIds: string[];
  createdAt: string;
}
