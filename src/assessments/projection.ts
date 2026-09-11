import type { Assessment, AssessmentRelation, AssessmentVerdict } from "../protocol-v2/types.js";

export type EffectiveAssessmentConclusion = AssessmentVerdict | "CONFLICT";

export interface EffectiveAssessmentProjection {
  projectionKey: string;
  category: Assessment["category"];
  scope: Assessment["scope"];
  subjectRef?: string;
  conclusion: EffectiveAssessmentConclusion;
  effectiveAssessmentIds: string[];
  supersededAssessmentIds: string[];
  conflictAssessmentIds: string[];
  ignoredRelationIds: string[];
}

const RISK_RANK: Partial<Record<AssessmentVerdict, number>> = {
  SUSPICIOUS: 1,
  HIGHLY_SUSPICIOUS: 2,
  CONFIRMED_MALICIOUS: 3,
};

const AUTHOR_AUTHORITY: Record<Assessment["authorType"], number> = {
  RULE: 1,
  MODEL: 2,
  SYSTEM: 3,
  HUMAN: 4,
};

function keyOf(assessment: Assessment): string {
  return `${assessment.category}::${assessment.scope}::${assessment.subjectRef ?? "OBSERVED_CATEGORY"}`;
}

function sameProjection(left: Assessment, right: Assessment): boolean {
  return keyOf(left) === keyOf(right) && left.taskId === right.taskId && left.epochId === right.epochId;
}

function resolveConclusion(active: Assessment[]): { conclusion: EffectiveAssessmentConclusion; conflicts: string[] } {
  const risks = active.filter((item) => RISK_RANK[item.verdict] !== undefined);
  const clearances = active.filter((item) => item.verdict === "BENIGN" || item.verdict === "NO_OBSERVED_FINDING");
  if (risks.length > 0 && clearances.length > 0) {
    return { conclusion: "CONFLICT", conflicts: [...risks, ...clearances].map((item) => item.assessmentId).sort() };
  }
  if (risks.length > 0) {
    const verdict = risks.reduce((best, item) => (RISK_RANK[item.verdict] ?? 0) > (RISK_RANK[best] ?? 0) ? item.verdict : best, risks[0]!.verdict);
    return { conclusion: verdict, conflicts: [] };
  }
  if (active.some((item) => item.verdict === "BENIGN")) return { conclusion: "BENIGN", conflicts: [] };
  if (active.some((item) => item.verdict === "NO_OBSERVED_FINDING")) return { conclusion: "NO_OBSERVED_FINDING", conflicts: [] };
  return { conclusion: "INCONCLUSIVE", conflicts: [] };
}

/**
 * Assessment 是不可变账本。只有同 task/epoch、同类别、同 scope、同主体的显式
 * ADJUDICATES/SUPERSEDES 关系可以让旧结论退出有效集合。其余关系仍保留在账本中，
 * 但不会隐式消除冲突。
 */
export function projectEffectiveAssessments(assessments: Assessment[], relations: AssessmentRelation[]): EffectiveAssessmentProjection[] {
  const byId = new Map(assessments.map((item) => [item.assessmentId, item]));
  const superseded = new Set<string>();
  const ignoredByKey = new Map<string, Set<string>>();
  const replacements = new Map<string, Set<string>>();
  const ignoreRelation = (relationId: string, ...items: Array<Assessment | undefined>): void => {
    for (const item of items) {
      if (!item) continue;
      const key = keyOf(item);
      const ids = ignoredByKey.get(key) ?? new Set<string>();
      ids.add(relationId);
      ignoredByKey.set(key, ids);
    }
  };

  const reaches = (start: string, target: string): boolean => {
    const pending = [start];
    const seen = new Set<string>();
    while (pending.length > 0) {
      const current = pending.pop()!;
      if (current === target) return true;
      if (seen.has(current)) continue;
      seen.add(current);
      pending.push(...(replacements.get(current) ?? []));
    }
    return false;
  };

  for (const relation of [...relations].sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.relationId.localeCompare(right.relationId))) {
    if (relation.kind !== "ADJUDICATES" && relation.kind !== "SUPERSEDES") continue;
    const from = byId.get(relation.fromAssessmentId);
    const to = byId.get(relation.toAssessmentId);
    const relationTime = Date.parse(relation.createdAt);
    const fromTime = from ? Date.parse(from.createdAt) : Number.NaN;
    const toTime = to ? Date.parse(to.createdAt) : Number.NaN;
    if (!from || !to || from.assessmentId === to.assessmentId || !sameProjection(from, to)
      || relation.taskId !== from.taskId || relation.epochId !== from.epochId
      || !Number.isFinite(relationTime) || !Number.isFinite(fromTime) || !Number.isFinite(toTime)
      || fromTime < toTime || relationTime < fromTime
      || AUTHOR_AUTHORITY[from.authorType] < AUTHOR_AUTHORITY[to.authorType]
      || reaches(to.assessmentId, from.assessmentId)) {
      ignoreRelation(relation.relationId, from, to);
      continue;
    }
    const targets = replacements.get(from.assessmentId) ?? new Set<string>();
    targets.add(to.assessmentId);
    replacements.set(from.assessmentId, targets);
    superseded.add(to.assessmentId);
  }

  const groups = new Map<string, Assessment[]>();
  for (const assessment of assessments) {
    const key = keyOf(assessment);
    const items = groups.get(key) ?? [];
    items.push(assessment);
    groups.set(key, items);
  }

  return [...groups.entries()].map(([projectionKey, items]) => {
    const ordered = [...items].sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.assessmentId.localeCompare(right.assessmentId));
    const active = ordered.filter((item) => !superseded.has(item.assessmentId));
    const effective = active.length > 0 ? active : [ordered.at(-1)!];
    const resolved = resolveConclusion(effective);
    const first = ordered[0]!;
    return {
      projectionKey,
      category: first.category,
      scope: first.scope,
      ...(first.subjectRef ? { subjectRef: first.subjectRef } : {}),
      conclusion: resolved.conclusion,
      effectiveAssessmentIds: effective.map((item) => item.assessmentId),
      supersededAssessmentIds: ordered.filter((item) => superseded.has(item.assessmentId)).map((item) => item.assessmentId),
      conflictAssessmentIds: resolved.conflicts,
      ignoredRelationIds: [...(ignoredByKey.get(projectionKey) ?? [])].sort(),
    };
  }).sort((left, right) => left.projectionKey.localeCompare(right.projectionKey));
}
