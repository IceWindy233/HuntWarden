import { VolatileDiscoveryPlanner, VOLATILE_DISCOVERY_NAMESPACES } from "../discovery/volatile-discovery.js";
import { DeterministicRuleEngineV2 } from "../rules/deterministic-rule-engine-v2.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { SecurityToolDefinition } from "../domain/types.js";
import { InvestigationActionExecutor, type ActionExecutionSummary } from "./action-executor.js";
import type { InvestigationSession } from "./types.js";
import { InvestigationPlaybookPlanner } from "../playbooks/registry.js";
import { JavaRelationResolver } from "./java-relation-resolver.js";

const SCHEDULER_CONSUMER = "investigation-scheduler";
const SCHEDULER_VERSION = "1.0.0";

export interface InvestigationSchedulerSummary extends ActionExecutionSummary {
  cycles: number;
  eventsConsumed: number;
  assessmentsCreated: string[];
  leadIds: string[];
  obligationIds: string[];
  actionIds: string[];
  hypothesisIds: string[];
}

export class InvestigationScheduler {
  constructor(
    private readonly store: RuntimeStore,
    private readonly taskId: string,
    private readonly epochId: string,
    private readonly session: InvestigationSession,
    private readonly discoveryTools: readonly SecurityToolDefinition[],
    private readonly modelTools: readonly SecurityToolDefinition[] = [],
  ) {}

  async runUntilQuiescent(signal?: AbortSignal, maxCycles = 20, eligibleModelActionIds?: ReadonlySet<string>): Promise<InvestigationSchedulerSummary> {
    const summary: InvestigationSchedulerSummary = {
      cycles: 0, eventsConsumed: 0, assessmentsCreated: [], leadIds: [], hypothesisIds: [], obligationIds: [], actionIds: [],
      executed: 0, succeeded: 0, partial: 0, failed: 0,
    };
    for (let cycle = 0; cycle < maxCycles; cycle += 1) {
      signal?.throwIfAborted();
      summary.cycles += 1;
      const watermark = this.store.getInvestigationConsumerWatermark(SCHEDULER_CONSUMER, SCHEDULER_VERSION, this.taskId, this.epochId);
      const events = this.store.listInvestigationEvents(this.taskId, this.epochId, watermark, 5_000);
      const factRefs = events
        .filter((event) => event.eventType === "FACT_BATCH_COMMITTED")
        .flatMap((event) => Array.isArray(event.payload.factRefs) ? event.payload.factRefs.filter((ref): ref is string => typeof ref === "string") : []);
      if (factRefs.length > 0) {
        const assessments = new DeterministicRuleEngineV2(this.store).evaluateFactRefs(this.taskId, this.epochId, factRefs);
        summary.assessmentsCreated.push(...assessments.map((item) => item.assessmentId));
        if (factRefs.some((ref) => ["jvm", "java_component", "class", "file"].includes(this.store.getFact(this.taskId, this.epochId, ref)?.namespace ?? ""))) {
          new JavaRelationResolver(this.store).resolve(this.taskId, this.epochId);
        }
        const volatile = factRefs.some((ref) => {
          const fact = this.store.getFact(this.taskId, this.epochId, ref);
          return fact ? VOLATILE_DISCOVERY_NAMESPACES.includes(fact.namespace) : false;
        });
        if (volatile) {
          const plan = new VolatileDiscoveryPlanner(this.store).plan(this.taskId, this.epochId, this.session);
          summary.leadIds.push(...plan.leadIds);
          summary.obligationIds.push(...plan.obligationIds);
          summary.actionIds.push(...plan.actionIds);
        }
      }
      // Coverage 在 Preset 的全部步骤结束后落库，不一定伴随新的 Fact 事件。
      // 每轮都重算类别范围，才能把分页期间建立的 OPEN 聚合义务收敛为
      // SATISFIED/LIMITED；有新事实时同一次调用仍负责增量规划具体对象动作。
      const playbook = new InvestigationPlaybookPlanner(this.store).plan(this.taskId, this.epochId, this.session);
      summary.hypothesisIds.push(...playbook.hypothesisIds);
      summary.obligationIds.push(...playbook.obligationIds);
      summary.actionIds.push(...playbook.actionIds);
      if (events.length > 0) {
        this.store.advanceInvestigationConsumerWatermark(SCHEDULER_CONSUMER, SCHEDULER_VERSION, this.taskId, this.epochId, watermark, events.at(-1)!.eventSeq);
        summary.eventsConsumed += events.length;
      }

      // Preset Coverage 在 FactBatch 之后落库，本身不会制造新的 volatile Fact 事件。
      // 每轮重算一次（稳定键去重）才能把 prelude 阶段的 OPEN 发现范围收敛为
      // SATISFIED/LIMITED，而不会留下已无后续事件可唤醒的 RUNNING checkpoint。
      const volatilePlan = new VolatileDiscoveryPlanner(this.store).plan(this.taskId, this.epochId, this.session);
      summary.leadIds.push(...volatilePlan.leadIds);
      summary.obligationIds.push(...volatilePlan.obligationIds);
      summary.actionIds.push(...volatilePlan.actionIds);

      const discoveryIds = new Set(this.store.listInvestigationActions(this.taskId, this.epochId)
        .filter((action) => (action.requestedBy === "DISCOVERY" || action.requestedBy === "PLAYBOOK") && action.status === "READY")
        .map((action) => action.actionId));
      const discovery = await new InvestigationActionExecutor(this.store, this.discoveryTools, this.taskId, this.epochId, this.session.authorizationVersion)
        .runUntilIdle(signal, 100, discoveryIds);
      mergeExecution(summary, discovery);

      let model: ActionExecutionSummary = { executed: 0, succeeded: 0, partial: 0, failed: 0 };
      if (this.modelTools.length > 0) {
        const modelIds = new Set(this.store.listInvestigationActions(this.taskId, this.epochId)
          .filter((action) => action.requestedBy === "MODEL" && action.status === "READY" && (!eligibleModelActionIds || eligibleModelActionIds.has(action.actionId)))
          .map((action) => action.actionId));
        model = await new InvestigationActionExecutor(this.store, this.modelTools, this.taskId, this.epochId, this.session.authorizationVersion, "model-action-scheduler")
          .runUntilIdle(signal, 100, modelIds);
        mergeExecution(summary, model);
      }
      if (events.length === 0 && discovery.executed === 0 && model.executed === 0) break;
    }
    summary.assessmentsCreated = [...new Set(summary.assessmentsCreated)];
    summary.leadIds = [...new Set(summary.leadIds)];
    summary.hypothesisIds = [...new Set(summary.hypothesisIds)];
    summary.obligationIds = [...new Set(summary.obligationIds)];
    summary.actionIds = [...new Set(summary.actionIds)];
    return summary;
  }

}

function mergeExecution(target: ActionExecutionSummary, addition: ActionExecutionSummary): void {
  target.executed += addition.executed;
  target.succeeded += addition.succeeded;
  target.partial += addition.partial;
  target.failed += addition.failed;
}
