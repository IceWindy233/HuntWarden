import { describe, expect, it } from "vitest";
import { projectEffectiveAssessments } from "../../src/assessments/projection.js";
import type { Assessment, AssessmentRelation } from "../../src/protocol-v2/types.js";

const taskId = "TASK-PROJECTION";
const epochId = "EPOCH-PROJECTION";

function assessment(id: string, verdict: Assessment["verdict"], createdAt: string, subjectRef = "REF-file-1"): Assessment {
  return {
    assessmentId: id, taskId, epochId, authorType: id.includes("HUMAN") ? "HUMAN" : "RULE",
    category: "webshell", subjectRef, scope: "SUBJECT", verdict,
    severity: verdict === "CONFIRMED_MALICIOUS" ? "CRITICAL" : verdict === "BENIGN" ? "INFO" : "MEDIUM",
    confidence: 0.8, rationale: id, evidenceRefs: [], factRefs: [], queryRefs: [], createdAt,
  };
}

function withAuthor(item: Assessment, authorType: Assessment["authorType"]): Assessment {
  return { ...item, authorType };
}

function relation(id: string, from: string, to: string, createdAt: string): AssessmentRelation {
  return { relationId: id, taskId, epochId, kind: "ADJUDICATES", fromAssessmentId: from, toAssessmentId: to, createdAt };
}

describe("Assessment 有效结论投影", () => {
  it("保留未裁定的风险与良性冲突", () => {
    const items = [
      assessment("ASM-RISK", "SUSPICIOUS", "2026-01-01T00:00:00.000Z"),
      assessment("ASM-BENIGN", "BENIGN", "2026-01-01T00:00:01.000Z"),
    ];
    expect(projectEffectiveAssessments(items, [])).toEqual([expect.objectContaining({
      conclusion: "CONFLICT",
      effectiveAssessmentIds: ["ASM-RISK", "ASM-BENIGN"],
      conflictAssessmentIds: ["ASM-BENIGN", "ASM-RISK"],
    })]);
  });

  it("只允许同主体的显式新裁定替代旧结论，并保留无效关系", () => {
    const items = [
      assessment("ASM-RISK", "SUSPICIOUS", "2026-01-01T00:00:00.000Z"),
      assessment("ASM-HUMAN", "BENIGN", "2026-01-01T00:00:01.000Z"),
      assessment("ASM-OTHER", "BENIGN", "2026-01-01T00:00:02.000Z", "REF-file-2"),
    ];
    const relations = [
      relation("AREL-VALID", "ASM-HUMAN", "ASM-RISK", "2026-01-01T00:00:03.000Z"),
      relation("AREL-CROSS-SUBJECT", "ASM-OTHER", "ASM-HUMAN", "2026-01-01T00:00:04.000Z"),
    ];
    const projected = projectEffectiveAssessments(items, relations);
    expect(projected.find((item) => item.subjectRef === "REF-file-1")).toMatchObject({
      conclusion: "BENIGN", effectiveAssessmentIds: ["ASM-HUMAN"], supersededAssessmentIds: ["ASM-RISK"],
      ignoredRelationIds: ["AREL-CROSS-SUBJECT"],
    });
    expect(projected.find((item) => item.subjectRef === "REF-file-2")).toMatchObject({ conclusion: "BENIGN", effectiveAssessmentIds: ["ASM-OTHER"] });
  });

  it("拒绝倒序裁定与替代环", () => {
    const items = [
      assessment("ASM-OLD", "SUSPICIOUS", "2026-01-01T00:00:00.000Z"),
      assessment("ASM-NEW", "BENIGN", "2026-01-01T00:00:01.000Z"),
    ];
    const projected = projectEffectiveAssessments(items, [
      relation("AREL-FORWARD", "ASM-NEW", "ASM-OLD", "2026-01-01T00:00:02.000Z"),
      relation("AREL-CYCLE", "ASM-OLD", "ASM-NEW", "2026-01-01T00:00:03.000Z"),
    ])[0]!;
    expect(projected).toMatchObject({ conclusion: "BENIGN", ignoredRelationIds: ["AREL-CYCLE"] });
  });

  it("拒绝低权限作者覆盖高权限裁定", () => {
    const items = [
      withAuthor(assessment("ASM-HUMAN", "BENIGN", "2026-01-01T00:00:00.000Z"), "HUMAN"),
      withAuthor(assessment("ASM-MODEL", "SUSPICIOUS", "2026-01-01T00:00:01.000Z"), "MODEL"),
    ];
    expect(projectEffectiveAssessments(items, [
      relation("AREL-LOWER-AUTHORITY", "ASM-MODEL", "ASM-HUMAN", "2026-01-01T00:00:02.000Z"),
    ])).toEqual([expect.objectContaining({
      conclusion: "CONFLICT",
      ignoredRelationIds: ["AREL-LOWER-AUTHORITY"],
    })]);
  });
});
