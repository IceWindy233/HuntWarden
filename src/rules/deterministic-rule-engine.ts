import { createId } from "../common/ids.js";
import { digestObject } from "../common/json.js";
import type { Finding, SecurityToolResult, TaskContext } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { ScanStepOutcome } from "../checks/scan-planner.js";
import { DETERMINISTIC_RULES } from "./registry.js";
import type { DeterministicRuleContext, DeterministicRuleDefinition } from "./types.js";

const preflightSteps = ["capabilities", "host-info"] as const;

function normalizedDetails(outcome: ScanStepOutcome): SecurityToolResult | undefined {
  const details = outcome.details;
  if (!details || typeof details !== "object" || !("status" in details)) return undefined;
  return details.status === "success" || details.status === "partial" ? details as SecurityToolResult : undefined;
}

function contextFor(task: TaskContext, outcomes: readonly ScanStepOutcome[]): DeterministicRuleContext {
  const stepOutcomes = (stepId: string) => outcomes.filter((outcome) => outcome.stepId === stepId);
  return {
    task,
    outcomes,
    stepOutcomes,
    items: (stepId) => stepOutcomes(stepId).flatMap((outcome) => {
      const details = normalizedDetails(outcome);
      return (details?.items ?? []).filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object");
    }),
    evidenceRefs: (stepIds) => [...new Set(stepIds.flatMap((stepId) => stepOutcomes(stepId).flatMap((outcome) => {
      const details = normalizedDetails(outcome);
      return details?.artifactRefs.filter((ref) => ref.startsWith("EV-")) ?? [];
    })))],
    inputDigest: (stepIds) => digestObject(stepIds.flatMap((stepId) => stepOutcomes(stepId).map(({ stepId: id, toolName, invocation, status, details, error }) => ({ stepId: id, toolName, invocation, status, details, error })))),
    complete: (stepIds) => stepIds.every((stepId) => {
      const values = stepOutcomes(stepId);
      return values.length > 0 && values.every((outcome) => outcome.status === "success" && normalizedDetails(outcome)?.status === "success");
    }),
  };
}

function summary(rule: DeterministicRuleDefinition, inputDigest: string, basis: string[], counterEvidence: string[]): string {
  return [
    `确定性规则：${rule.ruleId}@${rule.ruleVersion}`,
    `输入摘要：${inputDigest}`,
    `规则依据：${basis.join("；")}`,
    `反证与限制：${counterEvidence.join("；")}`,
  ].join("\n").slice(0, 8_000);
}

export class DeterministicRuleEngine {
  constructor(
    private readonly store: RuntimeStore,
    private readonly registry: readonly DeterministicRuleDefinition[] = DETERMINISTIC_RULES,
  ) {}

  evaluate(task: TaskContext, outcomes: readonly ScanStepOutcome[]): Finding[] {
    const context = contextFor(task, outcomes);
    const selected = new Set(task.checks);
    const findings: Finding[] = [];
    for (const rule of this.registry) {
      if (!selected.has(rule.category)) continue;
      const required = [...preflightSteps, ...rule.requiredStepIds];
      if (!context.complete(required)) {
        this.store.appendAudit({
          taskId: task.taskId,
          event: "deterministic_rule_skipped_incomplete",
          level: "warn",
          data: { ruleId: rule.ruleId, ruleVersion: rule.ruleVersion, category: rule.category, requiredStepIds: required },
        });
        continue;
      }
      const evaluation = rule.evaluate(context);
      if (!evaluation) {
        this.store.appendAudit({
          taskId: task.taskId,
          event: "deterministic_rule_no_decision",
          level: "info",
          data: { ruleId: rule.ruleId, ruleVersion: rule.ruleVersion, category: rule.category },
        });
        continue;
      }
      const validEvidenceRefs = [...new Set(evaluation.evidenceRefs)]
        .filter((evidenceId) => this.store.getEvidence(task.taskId, evidenceId) !== undefined)
        .slice(0, 100);
      if (evaluation.status === "SUSPICIOUS" && validEvidenceRefs.length === 0) {
        this.store.appendAudit({
          taskId: task.taskId,
          event: "deterministic_rule_suppressed",
          level: "warn",
          data: {
            ruleId: rule.ruleId,
            ruleVersion: rule.ruleVersion,
            category: rule.category,
            reason: "SUSPICIOUS 规则缺少当前任务中可解析的 Evidence",
            requestedEvidenceRefs: evaluation.evidenceRefs,
          },
        });
        continue;
      }
      const inputDigest = context.inputDigest(required);
      const finding = this.store.putFinding({
        findingId: createId("finding"),
        taskId: task.taskId,
        host: task.target.host,
        category: rule.category,
        severity: evaluation.severity,
        confidence: Math.min(evaluation.confidence, 0.85),
        status: evaluation.status,
        title: evaluation.title,
        summary: summary(rule, inputDigest, evaluation.basis, evaluation.counterEvidence),
        evidenceRefs: validEvidenceRefs,
        ...(evaluation.recommendation ? { recommendation: evaluation.recommendation } : {}),
        createdAt: new Date().toISOString(),
        toolCallId: `deterministic-rule:${task.taskId}:${rule.ruleId}:${rule.ruleVersion}:${inputDigest}`,
      });
      findings.push(finding);
      this.store.appendAudit({
        taskId: task.taskId,
        event: "deterministic_rule_evaluated",
        level: evaluation.status === "SUSPICIOUS" ? "warn" : "info",
        data: {
          ruleId: rule.ruleId,
          ruleVersion: rule.ruleVersion,
          category: rule.category,
          inputDigest,
          status: evaluation.status,
          findingId: finding.findingId,
          basis: evaluation.basis,
          counterEvidence: evaluation.counterEvidence,
          evidenceRefs: validEvidenceRefs,
        },
      });
    }
    return findings;
  }
}
