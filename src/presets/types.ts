import type { CheckCategory } from "../domain/types.js";
import type { NamespaceName } from "../protocol-v2/types.js";
import type { ForensicVerb } from "../executor/protocol-v2-executor.js";

export interface CapabilityRequirement { namespace: NamespaceName; verb: ForensicVerb; fields?: string[]; optional?: boolean }
export interface PresetStep {
  stepId: string;
  verb: ForensicVerb;
  params: Record<string, unknown>;
  required: boolean;
}
export interface CoverageCriterion { criterion: string; stepIds: string[] }
export interface PresetDefinition {
  presetId: string;
  version: string;
  category: CheckCategory;
  requiredCapabilities: CapabilityRequirement[];
  steps: PresetStep[];
  coverageCriteria: CoverageCriterion[];
}
