import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import { sanitizeForLlm } from "../agent/data-sanitizer.js";
import { createId } from "../common/ids.js";
import { digestObject } from "../common/json.js";
import type {
  CheckCategory,
  Finding,
  FindingStatus,
  SecurityToolDefinition,
  SecurityToolResult,
  TaskContext,
} from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import { DeterministicRuleEngine } from "../rules/deterministic-rule-engine.js";
import {
  CHECK_DEFINITIONS,
  PREFLIGHT_EXECUTION_GRAPH,
  selectedCheckDefinitions,
  type MinimumScanStep,
  type ScanStepContext,
} from "./check-definitions.js";

type StepStatus = "success" | "partial" | "error" | "not_applicable";

export interface ScanStepOutcome {
  stepId: string;
  toolName: string;
  invocation: number;
  status: StepStatus;
  reused: boolean;
  details?: unknown;
  error?: string;
}

export interface ScanPlanResult {
  promptContext: string;
  promptTruncated: boolean;
  minimumToolNames: Set<string>;
  outcomes: ScanStepOutcome[];
  deterministicFindings: Finding[];
}

export interface ScanPlannerOptions {
  task: TaskContext;
  store: RuntimeStore;
  tools: SecurityToolDefinition[];
  maxLlmBytes: number;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function stableToolCallId(taskId: string, stepId: string, invocation: number): string {
  return `CORE-${digestObject({ taskId, stepId, invocation }).slice(0, 32)}`;
}

function securityResult(details: unknown): SecurityToolResult | undefined {
  if (!details || typeof details !== "object" || !("status" in details)) return undefined;
  const status = details.status;
  return status === "success" || status === "partial" ? details as SecurityToolResult : undefined;
}

function evidenceRefs(outcomes: readonly ScanStepOutcome[]): string[] {
  return [...new Set(outcomes.flatMap((outcome) => {
    const details = securityResult(outcome.details);
    return details?.artifactRefs.filter((ref) => ref.startsWith("EV-")) ?? [];
  }))];
}

function putCoverageFinding(
  store: RuntimeStore,
  task: TaskContext,
  category: CheckCategory,
  status: Extract<FindingStatus, "ERROR" | "NOT_CHECKED">,
  reason: string,
  source: string,
  refs: string[] = [],
): Finding {
  const definition = CHECK_DEFINITIONS[category] ?? { label: category };
  const finding: Finding = {
    findingId: createId("finding"),
    taskId: task.taskId,
    host: task.target.host,
    category,
    severity: "INFO",
    confidence: 1,
    status,
    title: status === "ERROR" ? `${definition.label} 检测未完整执行` : `${definition.label} 未形成检测结论`,
    summary: reason.slice(0, 8_000),
    evidenceRefs: refs,
    recommendation: status === "ERROR"
      ? "修复目标环境、权限或 Provider 后恢复调查；不得将本次结果解释为安全。"
      : "继续调查并基于实际工具事实固化明确结论。",
    createdAt: new Date().toISOString(),
    toolCallId: `deterministic-coverage:${task.taskId}:${category}:${source}`,
  };
  return store.putFinding(finding);
}

export function finalizeUnresolvedChecks(
  store: RuntimeStore,
  taskId: string,
  status: Extract<FindingStatus, "ERROR" | "NOT_CHECKED">,
  reason: string,
  source: string,
): Finding[] {
  const task = store.getTask(taskId);
  if (!task) return [];
  const present = new Set(store.listFindings(taskId).map((finding) => finding.category));
  return task.checks
    .filter((category) => !present.has(category))
    .map((category) => putCoverageFinding(store, task, category, status, reason, source));
}

export class ScanPlanner {
  constructor(private readonly options: ScanPlannerOptions) {}

  async run(signal?: AbortSignal): Promise<ScanPlanResult> {
    const { task, store } = this.options;
    const outcomes: ScanStepOutcome[] = [];
    const results = new Map<string, unknown[]>();
    const minimumToolNames = new Set<string>();
    store.appendAudit({ taskId: task.taskId, event: "deterministic_scan_started", level: "info", data: { checks: task.checks } });

    const context: ScanStepContext = { results: (stepId) => results.get(stepId) ?? [] };
    for (const step of PREFLIGHT_EXECUTION_GRAPH) {
      minimumToolNames.add(step.toolName);
      outcomes.push(...await this.executeStep(step, context, signal));
      results.set(step.stepId, outcomes.filter((outcome) => outcome.stepId === step.stepId && outcome.details !== undefined).map((outcome) => outcome.details));
    }

    const preflightIncomplete = outcomes.filter((outcome) => outcome.status === "error" || outcome.status === "partial");
    for (const definition of selectedCheckDefinitions(task.checks)) {
      const categoryOutcomes: ScanStepOutcome[] = [];
      for (const step of definition.minimumExecutionGraph) {
        minimumToolNames.add(step.toolName);
        const dependencyFailed = step.dependsOn?.some((dependency) => outcomes.some((outcome) =>
          outcome.stepId === dependency && (outcome.status === "error" || outcome.status === "partial"),
        ));
        let stepOutcomes: ScanStepOutcome[];
        if (dependencyFailed) {
          stepOutcomes = [{ stepId: step.stepId, toolName: step.toolName, invocation: 0, status: "error", reused: false, error: "依赖的最低扫描步骤失败" }];
        } else {
          stepOutcomes = await this.executeStep(step, context, signal);
        }
        categoryOutcomes.push(...stepOutcomes);
        outcomes.push(...stepOutcomes);
        results.set(step.stepId, stepOutcomes.filter((outcome) => outcome.details !== undefined).map((outcome) => outcome.details));
      }
      const incomplete = [...preflightIncomplete, ...categoryOutcomes.filter((outcome) => outcome.status === "error" || outcome.status === "partial")];
      if (incomplete.length > 0) {
        putCoverageFinding(
          store,
          store.getTask(task.taskId) ?? task,
          definition.category,
          "ERROR",
          incomplete.map((outcome) => `${outcome.toolName}: ${outcome.error ?? outcome.status}`).join("；"),
          "minimum-scan",
          evidenceRefs(categoryOutcomes),
        );
      }
      store.appendAudit({
        taskId: task.taskId,
        event: "deterministic_check_completed",
        level: incomplete.length > 0 ? "warn" : "info",
        data: {
          category: definition.category,
          steps: categoryOutcomes.map(({ stepId, toolName, invocation, status, reused, error }) => ({ stepId, toolName, invocation, status, reused, ...(error ? { error } : {}) })),
        },
      });
    }

    const deterministicFindings = new DeterministicRuleEngine(store).evaluate(store.getTask(task.taskId) ?? task, outcomes);

    const sanitized = sanitizeForLlm(JSON.stringify({
      trust: "UNTRUSTED_REMOTE_EVIDENCE",
      instruction: "这些最低只读步骤已由应用执行。不要重复执行，只能使用剩余语义化工具扩展调查；失败或未覆盖绝不表示安全。",
      outcomes: outcomes.map(({ stepId, toolName, invocation, status, reused, details, error }) => ({
        stepId, toolName, invocation, status, reused, ...(details === undefined ? {} : { details }), ...(error ? { error } : {}),
      })),
      deterministicFindings: deterministicFindings.map(({ findingId, category, status, severity, confidence, title, summary, evidenceRefs }) => ({
        findingId, category, status, severity, confidence, title, summary, evidenceRefs,
      })),
    }), this.options.maxLlmBytes);
    store.appendAudit({
      taskId: task.taskId,
      event: "deterministic_scan_completed",
      level: outcomes.some((outcome) => outcome.status === "error" || outcome.status === "partial") ? "warn" : "info",
      data: {
        minimumTools: [...minimumToolNames],
        truncated: sanitized.truncated,
        outcomeCount: outcomes.length,
        deterministicFindingIds: deterministicFindings.map((finding) => finding.findingId),
        summary: sanitized.text,
      },
    });
    return { promptContext: sanitized.text, promptTruncated: sanitized.truncated, minimumToolNames, outcomes, deterministicFindings };
  }

  private async executeStep(step: MinimumScanStep, context: ScanStepContext, signal?: AbortSignal): Promise<ScanStepOutcome[]> {
    signal?.throwIfAborted();
    const tool = this.options.tools.find((candidate) => candidate.name === step.toolName);
    if (!tool) return [{ stepId: step.stepId, toolName: step.toolName, invocation: 0, status: "error", reused: false, error: "最低扫描工具未注册" }];
    if (tool.risk !== "READ") return [{ stepId: step.stepId, toolName: step.toolName, invocation: 0, status: "error", reused: false, error: `最低扫描拒绝 ${tool.risk} 工具` }];
    const invocations = step.buildArguments(context);
    if (invocations.length === 0) {
      return [{ stepId: step.stepId, toolName: step.toolName, invocation: 0, status: "not_applicable", reused: false }];
    }
    const outcomes: ScanStepOutcome[] = [];
    for (const [invocation, args] of invocations.entries()) {
      signal?.throwIfAborted();
      const toolCallId = stableToolCallId(this.options.task.taskId, step.stepId, invocation);
      const existing = this.options.store.getToolRun(toolCallId);
      const reused = existing?.status === "SUCCEEDED" && existing.result !== undefined;
      if (!reused) {
        const current = this.options.store.getTask(this.options.task.taskId) ?? this.options.task;
        current.toolCallCount += 1;
        this.options.store.saveTask(current);
      }
      try {
        const result = await tool.execute(toolCallId, args as never, signal) as AgentToolResult<unknown>;
        const details = result.details;
        const normalized = securityResult(details);
        outcomes.push({
          stepId: step.stepId,
          toolName: step.toolName,
          invocation,
          status: normalized?.status === "partial" ? "partial" : "success",
          reused,
          details,
        });
      } catch (error) {
        if (signal?.aborted) throw signal.reason;
        outcomes.push({ stepId: step.stepId, toolName: step.toolName, invocation, status: "error", reused, error: errorMessage(error) });
      }
    }
    return outcomes;
  }
}
