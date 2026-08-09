import type { CheckCategory, FindingStatus, Severity, TaskContext } from "../domain/types.js";
import type { ScanStepOutcome } from "../checks/scan-planner.js";

export interface DeterministicRuleContext {
  task: TaskContext;
  outcomes: readonly ScanStepOutcome[];
  stepOutcomes(stepId: string): readonly ScanStepOutcome[];
  items(stepId: string): readonly Record<string, unknown>[];
  evidenceRefs(stepIds: readonly string[]): string[];
  inputDigest(stepIds: readonly string[]): string;
  complete(stepIds: readonly string[]): boolean;
}

export interface DeterministicRuleEvaluation {
  status: Extract<FindingStatus, "SUSPICIOUS" | "NO_FINDING">;
  severity: Extract<Severity, "MEDIUM" | "INFO">;
  confidence: number;
  title: string;
  basis: string[];
  counterEvidence: string[];
  evidenceRefs: string[];
  recommendation?: string;
}

export interface DeterministicRuleDefinition {
  ruleId: string;
  ruleVersion: string;
  category: CheckCategory;
  requiredStepIds: readonly string[];
  evaluate(context: DeterministicRuleContext): DeterministicRuleEvaluation | undefined;
}
