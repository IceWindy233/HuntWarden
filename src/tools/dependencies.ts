import type { ApprovalService } from "../agent/approval-service.js";
import type { AppConfig } from "../config/schema.js";
import type { TaskContext } from "../domain/types.js";
import type { EvidenceStore } from "../evidence/evidence-store.js";
import type { HostExecutor } from "../executor/operations.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

export interface ToolDependencies {
  task: TaskContext;
  config: AppConfig;
  store: RuntimeStore;
  evidence: EvidenceStore;
  executor: HostExecutor;
  approvals: ApprovalService;
}
