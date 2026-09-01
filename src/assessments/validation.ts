import { InvalidArgumentError } from "../common/errors.js";
import type { Assessment, CoverageRun, FactRecord, ObjectReference } from "../protocol-v2/types.js";

export interface AssessmentValidationContext {
  taskId: string;
  epochId: string;
  refs: readonly ObjectReference[];
  facts: readonly FactRecord[];
  evidence: ReadonlyArray<{ evidenceId: string; taskId: string; metadata?: Record<string, unknown> }>;
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
    const completeEvidence = input.evidenceRefs.some((id) => context.evidence.some((item) => item.evidenceId === id && item.metadata?.complete !== false));
    if (!completeEvidence) throw new InvalidArgumentError("CONFIRMED_MALICIOUS 必须绑定完整 Evidence");
    const hostFacts = context.facts.filter((fact) => input.factRefs.includes(fact.factId) && fact.source.kind !== "EXTERNAL");
    const strong = hostFacts.some((fact) => fact.modelPayload.signalStrength === "STRONG");
    const independent = new Set(hostFacts.map((fact) => `${fact.collector.name}:${fact.subjectRef}`)).size;
    if (!strong && independent < 2) throw new InvalidArgumentError("CONFIRMED_MALICIOUS 需要一个强主机信号或两个独立主机事实信号");
  }
}

export function safetyProjection(coverage: CoverageRun | undefined, assessments: readonly Assessment[]): { state: "RISK" | "NO_OBSERVED_FINDING" | "INCOMPLETE" | "NOT_APPLICABLE"; model: string } {
  const risks = assessments.filter((item) => ["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"].includes(item.verdict));
  if (risks.length > 0) return { state: "RISK", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  if (coverage?.status !== "COMPLETE" || coverage.applicability === "UNKNOWN") return { state: "INCOMPLETE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  if (coverage.applicability === "NOT_APPLICABLE") return { state: "NOT_APPLICABLE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
  return { state: assessments.some((item) => item.verdict === "NO_OBSERVED_FINDING") ? "NO_OBSERVED_FINDING" : "INCOMPLETE", model: assessments.some((item) => item.authorType === "MODEL") ? "CONCLUDED" : "NOT_CONCLUDED" };
}
