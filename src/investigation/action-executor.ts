import type { SecurityToolDefinition } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { InvestigationAction } from "./types.js";
import { Value } from "typebox/value";
import { digestObject } from "../common/json.js";

export interface ActionExecutionSummary {
  executed: number;
  succeeded: number;
  partial: number;
  failed: number;
}

const ACTION_MAX_PAGES = 100;

export class InvestigationActionExecutor {
  private readonly tools: Map<string, SecurityToolDefinition>;

  constructor(
    private readonly store: RuntimeStore,
    tools: readonly SecurityToolDefinition[],
    private readonly taskId: string,
    private readonly epochId: string,
    private readonly authorizationVersion: string,
    private readonly workerId = "deterministic-scheduler",
  ) {
    this.tools = new Map(tools.map((tool) => [tool.name, tool]));
  }

  async runUntilIdle(signal?: AbortSignal, maxActions = 100, eligibleActionIds?: ReadonlySet<string>): Promise<ActionExecutionSummary> {
    const summary: ActionExecutionSummary = { executed: 0, succeeded: 0, partial: 0, failed: 0 };
    while (summary.executed < maxActions) {
      signal?.throwIfAborted();
      const claimed = this.store.claimNextInvestigationAction(this.taskId, this.epochId, this.workerId, this.authorizationVersion, eligibleActionIds);
      if (!claimed) break;
      summary.executed += 1;
      const tool = this.tools.get(claimed.action.operationRef);
      if (!tool) {
        const error = `未注册调查操作 ${claimed.action.operationRef}`;
        this.store.finishInvestigationAction(claimed.action.actionId, claimed.action.revision, "FAILED", [], error);
        this.resolveObligations(claimed.action, "LIMITED", [], error);
        summary.failed += 1;
        continue;
      }
      try {
        let args = claimed.action.args;
        let partial = false;
        let partialReason: string | undefined;
        let cursorRef: string | undefined;
        const resultRefs: string[] = [];
        const paged = claimed.action.operationRef === "enumerate" || claimed.action.operationRef === "relate";
        const reusablePreset = paged ? undefined : this.findReusablePresetResult(claimed.action);
        if (reusablePreset) {
          const details = reusablePreset.details as Record<string, unknown>;
          resultRefs.push(...collectResultRefs(details));
          partial = details.status === "partial";
          this.store.appendAudit({ taskId: this.taskId, event: "investigation_action_reused_preset_primitive", level: "info", data: { actionId: claimed.action.actionId, operationRef: claimed.action.operationRef, argsDigest: claimed.action.argsDigest } });
        }
        for (let page = 0; !reusablePreset && page < ACTION_MAX_PAGES; page += 1) {
          if (!Value.Check(tool.parameters, args)) throw new Error(`调查 Action ${claimed.action.actionId} 参数不符合 ${claimed.action.operationRef} Schema`);
          try {
            const toolCallId = page === 0 ? claimed.attempt.attemptId : `${claimed.attempt.attemptId}-PAGE-${page + 1}`;
            const result = await tool.execute(toolCallId, args as never, signal);
            const details = result.details as Record<string, unknown>;
            resultRefs.push(...collectResultRefs(details));
            partial = partial || details.status === "partial";
            cursorRef = paged && typeof details.cursorRef === "string" ? details.cursorRef : undefined;
            if (!cursorRef) break;
            args = { ...claimed.action.args, cursorRef };
            if (page === ACTION_MAX_PAGES - 1) {
              partial = true;
              partialReason = `调查 Action 分页达到 ${ACTION_MAX_PAGES} 页上限`;
              this.limitDiscoveryCheckpoint(cursorRef, partialReason);
            }
          } catch (error) {
            if (page === 0) throw error;
            partial = true;
            partialReason = `调查 Action 分页中断：${error instanceof Error ? error.message : String(error)}`;
            this.limitDiscoveryCheckpoint(cursorRef, partialReason);
            break;
          }
        }
        const uniqueResultRefs = [...new Set(resultRefs)];
        const reason = partialReason ?? (partial ? "远程原语返回 PARTIAL" : undefined);
        this.store.finishInvestigationAction(claimed.action.actionId, claimed.action.revision, partial ? "PARTIAL" : "SUCCEEDED", uniqueResultRefs, reason);
        this.resolveObligations(claimed.action, partial ? "LIMITED" : "SATISFIED", uniqueResultRefs, reason);
        if (partial) summary.partial += 1;
        else summary.succeeded += 1;
      } catch (caught) {
        const error = caught instanceof Error ? caught.message : String(caught);
        this.store.finishInvestigationAction(claimed.action.actionId, claimed.action.revision, "FAILED", [], error);
        this.resolveObligations(claimed.action, "LIMITED", [], error);
        summary.failed += 1;
      }
    }
    const actions = new Map(this.store.listInvestigationActions(this.taskId, this.epochId).map((item) => [item.actionId, item]));
    for (const action of actions.values()) {
      if (action.status !== "READY") continue;
      const failedDependency = action.dependsOn.map((id) => actions.get(id)).find((item) => item && ["FAILED", "BLOCKED", "CANCELLED"].includes(item.status));
      if (!failedDependency) continue;
      const reason = `依赖 Action ${failedDependency.actionId} 以 ${failedDependency.status} 结束`;
      this.store.blockReadyInvestigationAction(action.actionId, reason);
      this.resolveObligations(action, "LIMITED", [], reason);
    }
    return summary;
  }

  private findReusablePresetResult(action: InvestigationAction): { details: unknown } | undefined {
    const run = this.store.listToolRuns(this.taskId, 100_000).find((item) => item.epochId === this.epochId
      && item.status === "SUCCEEDED" && item.toolCallId.startsWith("PRESET-")
      && item.toolName === action.operationRef && digestObject(item.args) === action.argsDigest
      && item.result !== undefined);
    if (!run?.result || typeof run.result !== "object" || !("details" in run.result)) return undefined;
    return run.result as { details: unknown };
  }

  private limitDiscoveryCheckpoint(cursorRef: string | undefined, reason: string): void {
    if (!cursorRef) return;
    const checkpoint = this.store.listDiscoveryCheckpoints(this.taskId, this.epochId).find((item) => item.cursorRef === cursorRef);
    if (!checkpoint) return;
    this.store.putDiscoveryCheckpoint({ ...checkpoint, status: "LIMITED", remainingDescription: reason, updatedAt: new Date().toISOString() });
  }

  private resolveObligations(action: InvestigationAction, status: "SATISFIED" | "LIMITED", resultRefs: string[], reason?: string): void {
    const obligations = new Map(this.store.listInvestigationObligations(this.taskId, this.epochId).map((item) => [item.obligationId, item]));
    const actions = this.store.listInvestigationActions(this.taskId, this.epochId);
    for (const obligationId of action.obligationIds) {
      const current = obligations.get(obligationId);
      if (!current || !["OPEN", "QUEUED"].includes(current.status)) continue;
      const contributors = actions.filter((item) => item.obligationIds.includes(obligationId));
      if (contributors.some((item) => ["READY", "RUNNING"].includes(item.status))) continue;
      const limited = status === "LIMITED" || contributors.some((item) => ["PARTIAL", "FAILED", "BLOCKED", "CANCELLED"].includes(item.status));
      const contributorRefs = contributors.flatMap((item) => item.resultRefs ?? []);
      const contributorErrors = contributors.flatMap((item) => item.error ? [item.error] : []);
      this.store.updateInvestigationObligation({
        ...current,
        status: limited ? "LIMITED" : "SATISFIED",
        resultRefs: [...new Set([...current.resultRefs, ...contributorRefs, ...resultRefs])],
        gapRefs: [...new Set([...current.gapRefs, ...contributorErrors, ...(reason ? [reason] : [])])],
        updatedAt: new Date().toISOString(),
      }, current.status);
    }
  }
}

function collectResultRefs(details: Record<string, unknown>): string[] {
  const refs: string[] = [];
  for (const key of ["factRefs", "objectRefs", "edgeRefs", "evidenceRefs"] as const) {
    const values = details[key];
    if (Array.isArray(values)) refs.push(...values.filter((value): value is string => typeof value === "string"));
  }
  if (typeof details.queryRef === "string") refs.push(details.queryRef);
  return [...new Set(refs)];
}
