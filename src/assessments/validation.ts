import { InvalidArgumentError } from "../common/errors.js";
import type { RelationProvenance } from "../investigation/types.js";
import type { Assessment, CoverageRun, EdgeRecord, FactRecord, ObjectReference } from "../protocol-v2/types.js";

export interface AssessmentValidationContext {
  taskId: string;
  epochId: string;
  refs: readonly ObjectReference[];
  facts: readonly FactRecord[];
  edges: readonly EdgeRecord[];
  relationProvenance: readonly RelationProvenance[];
  evidence: ReadonlyArray<{ evidenceId: string; taskId: string; sha256?: string; storagePath?: string; metadata?: Record<string, unknown> }>;
  queryRefs: ReadonlySet<string>;
}

export function validateAssessment(input: Assessment, context: AssessmentValidationContext): void {
  if (input.taskId !== context.taskId || input.epochId !== context.epochId) throw new InvalidArgumentError("Assessment 必须绑定当前 task + epoch");
  if (!Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1) throw new InvalidArgumentError("Assessment confidence 必须在 0..1");
  if (input.rationale.trim().length < 1 || input.rationale.length > 8_000) throw new InvalidArgumentError("Assessment rationale 不能为空且不能超过 8000 字符");
  if (input.scope === "SUBJECT" && !input.subjectRef) throw new InvalidArgumentError("主体 Assessment 必须绑定 subjectRef");
  if (input.scope === "OBSERVED_CATEGORY" && input.subjectRef) throw new InvalidArgumentError("类别 Assessment 不得绑定 subjectRef");
  if (["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS", "BENIGN"].includes(input.verdict) && !input.subjectRef) throw new InvalidArgumentError("对象级风险或良性裁定必须绑定 subjectRef");
  if (input.verdict === "NO_OBSERVED_FINDING" && input.scope !== "OBSERVED_CATEGORY") throw new InvalidArgumentError("NO_OBSERVED_FINDING 只能用于类别观察范围");
  if (input.subjectRef && !context.refs.some((ref) => ref.ref === input.subjectRef && ref.taskId === context.taskId && ref.epochId === context.epochId)) throw new InvalidArgumentError("Assessment 引用未知或跨 epoch 的 subjectRef");
  for (const factId of input.factRefs) if (!context.facts.some((fact) => fact.factId === factId && fact.taskId === context.taskId && fact.epochId === context.epochId)) throw new InvalidArgumentError(`Assessment 引用未知 Fact: ${factId}`);
  for (const evidenceId of input.evidenceRefs) if (!context.evidence.some((item) => item.evidenceId === evidenceId && item.taskId === context.taskId)) throw new InvalidArgumentError(`Assessment 引用未知 Evidence: ${evidenceId}`);
  for (const queryRef of input.queryRefs) if (!context.queryRefs.has(queryRef)) throw new InvalidArgumentError(`Assessment 引用未知 Query: ${queryRef}`);
  if (input.verdict === "CONFIRMED_MALICIOUS") {
    const completeEvidence = input.evidenceRefs.some((id) => context.evidence.some((item) => item.evidenceId === id
      && completeEvidenceMetadata(item)
      && item.metadata?.epochId === context.epochId
      && evidenceSupportsSubject(item.metadata, input.subjectRef, context)));
    if (!completeEvidence) throw new InvalidArgumentError("CONFIRMED_MALICIOUS 必须绑定当前 epoch 被裁定对象或经实测关系验证的直接相关对象的完整 Evidence");
    const hostFacts = context.facts.filter((fact) => input.factRefs.includes(fact.factId) && fact.source.kind !== "EXTERNAL");
    const strong = hostFacts.some((fact) => fact.modelPayload.signalStrength === "STRONG");
    const independent = new Set(hostFacts.map((fact) => `${fact.collector.name}:${fact.subjectRef}`)).size;
    if (!strong && independent < 2) throw new InvalidArgumentError("CONFIRMED_MALICIOUS 需要一个强主机信号或两个独立主机事实信号");
  }
}

function completeEvidenceMetadata(item: AssessmentValidationContext["evidence"][number]): item is typeof item & { metadata: Record<string, unknown> } {
  const metadata = item.metadata;
  if (metadata?.complete !== true || metadata.integrityStatus === "FAILED") return false;
  const range = metadata.range;
  if (!range || typeof range !== "object" || Array.isArray(range)) return false;
  const values = range as Record<string, unknown>;
  if (values.start !== 0 || values.complete !== true || !Number.isSafeInteger(values.length) || Number(values.length) < 0) return false;
  if (!Number.isSafeInteger(metadata.artifactSize) || metadata.artifactSize !== values.length) return false;
  const digest = metadata.artifactDigest;
  if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) return false;
  if (item.sha256 && item.sha256 !== digest) return false;
  return true;
}

function evidenceSupportsSubject(metadata: Record<string, unknown>, subjectRef: string | undefined, context: AssessmentValidationContext): boolean {
  if (!subjectRef || typeof metadata.subjectRef !== "string") return false;
  if (metadata.subjectRef === subjectRef) return true;
  const observedEdges = context.edges.filter((edge) => (
    (edge.fromRef === metadata.subjectRef && edge.toRef === subjectRef)
    || (edge.toRef === metadata.subjectRef && edge.fromRef === subjectRef)
  ) && context.relationProvenance.some((item) => item.edgeRef === edge.edgeId && item.derivation === "OBSERVED"));
  if (observedEdges.length === 0) return false;

  // JVM retransformation 证据先绑定实际 Attach 的 JVM。只有当前 Class Fact
  // 与证据中的类名、ClassLoader 精确一致，且存在实测 loads_class 边，才允许支撑 Class 裁定。
  if (metadata.captureMethod === "JVM_RETRANSFORM") {
    if (!observedEdges.some((edge) => edge.relation === "loads_class")) return false;
    return context.facts.some((fact) => fact.subjectRef === subjectRef
      && fact.namespace === "class"
      && fact.privatePayload.className === metadata.className
      && fact.privatePayload.loaderId === metadata.classLoaderId);
  }
  return false;
}

export function safetyProjection(coverage: CoverageRun | undefined, assessments: readonly Assessment[]): { state: "RISK" | "NO_OBSERVED_FINDING" | "INCOMPLETE" | "NOT_APPLICABLE"; model: string } {
  const risks = assessments.filter((item) => ["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"].includes(item.verdict));
  if (risks.length > 0) return { state: "RISK", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  if (coverage?.status !== "COMPLETE" || coverage.applicability === "UNKNOWN") return { state: "INCOMPLETE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  if (coverage.applicability === "NOT_APPLICABLE") return { state: "NOT_APPLICABLE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  return { state: assessments.some((item) => item.verdict === "NO_OBSERVED_FINDING") ? "NO_OBSERVED_FINDING" : "INCOMPLETE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
}
