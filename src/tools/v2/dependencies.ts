import type { ApprovalService } from "../../agent/approval-service.js";
import type { AppConfig } from "../../config/schema.js";
import type { TaskContext } from "../../domain/types.js";
import type { EvidenceStore } from "../../evidence/evidence-store.js";
import type { ProtocolV2Executor } from "../../executor/protocol-v2-executor.js";
import type { EffectiveCapabilities } from "../../protocol-v2/capability.js";
import type { ScanEpoch } from "../../protocol-v2/types.js";
import type { FactSource } from "../../protocol-v2/types.js";
import type { RuntimeStore } from "../../storage/runtime-store.js";
import type { ThreatIntelClient } from "../../threat-intel/types.js";

export interface V2ToolDependencies {
  task: TaskContext;
  epoch: ScanEpoch;
  config: AppConfig;
  store: RuntimeStore;
  evidence: EvidenceStore;
  executor: ProtocolV2Executor;
  capabilities: EffectiveCapabilities;
  approvals: ApprovalService;
  checkpoint?: (name: string) => void;
  threatIntel?: ThreatIntelClient;
  budgetOwner: "MODEL" | "PRESET";
  factSource?: FactSource;
}
