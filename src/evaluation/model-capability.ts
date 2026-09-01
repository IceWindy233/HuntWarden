import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import type { CheckCategory } from "../domain/types.js";
import { NAMESPACE_NAMES, type FactRecord, type WireCost } from "../protocol-v2/types.js";
import type { RuntimeStore, ToolRunRecord } from "../storage/runtime-store.js";

const categories = ["webshell", "java_memory_shell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"] as const;
const primitive = Type.Union([Type.String({ maxLength: 4096 }), Type.Number(), Type.Boolean(), Type.Null()]);
const ExpectedFactSchema = Type.Object({
  namespace: Type.Union(NAMESPACE_NAMES.map((value) => Type.Literal(value))),
  field: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9_.-]+$" }),
  operator: Type.Union([Type.Literal("eq"), Type.Literal("contains")]),
  value: primitive,
}, { additionalProperties: false });
const ThresholdsSchema = Type.Object({
  minFactReachability: Type.Number({ minimum: 0, maximum: 1 }),
  maxTruncationLossRate: Type.Number({ minimum: 0, maximum: 1 }),
  maxModelNotConcludedRate: Type.Number({ minimum: 0, maximum: 1 }),
  maxPresetPartialRate: Type.Number({ minimum: 0, maximum: 1 }),
  minNovelRecall: Type.Number({ minimum: 0, maximum: 1 }),
  maxInvalidToolCallRate: Type.Number({ minimum: 0, maximum: 1 }),
  maxBenignFalsePositiveRate: Type.Number({ minimum: 0, maximum: 1 }),
}, { additionalProperties: false });
export const ModelCapabilityManifestSchema = Type.Object({
  schemaVersion: Type.Literal(1),
  suiteId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
  cases: Type.Array(Type.Object({
    caseId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
    taskId: Type.String({ minLength: 1, maxLength: 128 }),
    epochId: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })),
    disposition: Type.Union([Type.Literal("MALICIOUS"), Type.Literal("BENIGN")]),
    novel: Type.Boolean(),
    expectedCategories: Type.Array(Type.Union(categories.map((value) => Type.Literal(value))), { minItems: 1, maxItems: 5, uniqueItems: true }),
    expectedFacts: Type.Array(ExpectedFactSchema, { minItems: 1, maxItems: 100 }),
  }, { additionalProperties: false }), { minItems: 2, maxItems: 500 }),
  thresholds: ThresholdsSchema,
}, { additionalProperties: false });

export type ModelCapabilityManifest = Static<typeof ModelCapabilityManifestSchema>;
export interface EvaluationMetric { numerator: number; denominator: number; rate: number | null }
export interface ModelCapabilityCaseResult {
  caseId: string;
  taskId: string;
  epochId: string;
  disposition: "MALICIOUS" | "BENIGN";
  novel: boolean;
  expectedFactLabels: number;
  availableFactLabels: number;
  reachedFactLabels: number;
  modelNotConcludedCategories: CheckCategory[];
  presetPartialCategories: CheckCategory[];
  detectedCategories: CheckCategory[];
  falsePositiveCategories: CheckCategory[];
  fixtureFailures: string[];
}

export interface ModelCapabilityEvaluation {
  schemaVersion: 1;
  suiteId: string;
  evaluatedAt: string;
  status: "PASS" | "FAIL";
  models: Array<{ provider: string; model: string }>;
  metrics: {
    factReachability: EvaluationMetric;
    truncationLoss: EvaluationMetric;
    modelNotConcluded: EvaluationMetric;
    presetPartial: EvaluationMetric;
    novelRecall: EvaluationMetric;
    invalidToolCalls: EvaluationMetric;
    benignFalsePositive: EvaluationMetric;
    ruleAdjudication: { riskyRuleAssessments: number; humanAdjudicated: number; humanOverturned: number };
    tokens: { input: number; output: number; cacheRead: number; cacheWrite: number; total: number };
    latencyMs: { epochWall: number; modelToolWall: number };
    remoteCost: WireCost;
  };
  thresholdResults: Array<{ metric: string; comparator: ">=" | "<="; threshold: number; actual: number | null; pass: boolean }>;
  fixtureFailures: string[];
  cases: ModelCapabilityCaseResult[];
}

const riskyVerdicts = new Set(["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"]);
const truncationGapCodes = new Set(["NODE_LIMIT", "BYTE_LIMIT", "OUTPUT_LIMIT"]);

export function parseModelCapabilityManifest(value: unknown): ModelCapabilityManifest {
  const issues = [...Value.Errors(ModelCapabilityManifestSchema, value)];
  if (issues.length > 0) throw new Error(`模型能力评测清单无效:\n${issues.map((issue) => `${issue.instancePath || "/"}: ${issue.message}`).join("\n")}`);
  const manifest = structuredClone(value) as ModelCapabilityManifest;
  const ids = new Set<string>();
  const tasks = new Set<string>();
  for (const item of manifest.cases) {
    if (ids.has(item.caseId)) throw new Error(`模型能力评测清单 caseId 重复: ${item.caseId}`);
    ids.add(item.caseId);
    if (tasks.has(item.taskId)) throw new Error(`模型能力评测 taskId 重复，避免成本与比率重复计数: ${item.taskId}`);
    tasks.add(item.taskId);
    if (item.disposition === "BENIGN" && item.novel) throw new Error(`良性 case 不得标为 novel: ${item.caseId}`);
    for (const matcher of item.expectedFacts) {
      if (matcher.operator === "contains" && typeof matcher.value !== "string") throw new Error(`contains 只接受字符串: ${item.caseId}/${matcher.field}`);
    }
  }
  if (!manifest.cases.some((item) => item.disposition === "BENIGN")) throw new Error("模型能力评测至少需要一个 BENIGN case");
  if (!manifest.cases.some((item) => item.disposition === "MALICIOUS" && item.novel)) throw new Error("模型能力评测至少需要一个 novel MALICIOUS case");
  return manifest;
}

export function evaluateModelCapability(store: RuntimeStore, manifest: ModelCapabilityManifest): ModelCapabilityEvaluation {
  const results: ModelCapabilityCaseResult[] = [];
  const fixtureFailures: string[] = [];
  const modelNames = new Map<string, { provider: string; model: string }>();
  let expectedFactLabels = 0; let reachedFactLabels = 0;
  let categoryUnits = 0; let notConcluded = 0; let presetPartial = 0;
  let novelUnits = 0; let novelHits = 0; let benignUnits = 0; let benignFalsePositives = 0;
  let riskyRuleAssessments = 0; let humanAdjudicated = 0; let humanOverturned = 0;
  let epochWall = 0;
  const allModelToolRuns: ToolRunRecord[] = [];
  const unknownToolCalls: number[] = [];
  const tokens = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 };

  for (const definition of manifest.cases) {
    const task = store.getTask(definition.taskId);
    if (task?.protocolVersion !== 2) throw new Error(`评测 case 引用未知或非 v2 task: ${definition.caseId}`);
    const epochId = definition.epochId ?? task.activeEpochId;
    if (!epochId) throw new Error(`评测 case 没有可用 epoch: ${definition.caseId}`);
    const epoch = store.getScanEpoch(task.taskId, epochId);
    if (!epoch || epoch.status === "RUNNING") throw new Error(`评测 case epoch 不存在或尚未结束: ${definition.caseId}`);
    modelNames.set(`${task.modelProvider}/${task.modelId}`, { provider: task.modelProvider, model: task.modelId });
    if (epoch.finishedAt) epochWall += Math.max(0, Date.parse(epoch.finishedAt) - Date.parse(epoch.startedAt));

    const facts = store.listFacts(task.taskId, epochId);
    const reachedRefs = new Set(store.listQuerySnapshots(task.taskId, epochId).filter((snapshot) => snapshot.view === "facts").flatMap((snapshot) => snapshot.rowRefs ?? []));
    const caseFixtureFailures: string[] = [];
    let caseAvailable = 0; let caseReached = 0;
    definition.expectedFacts.forEach((matcher, index) => {
      expectedFactLabels += 1;
      const matching = facts.filter((fact) => fact.namespace === matcher.namespace && matchesExpectedFact(fact, matcher));
      if (matching.length === 0) {
        const failure = `${definition.caseId}:expectedFacts[${index}] ${matcher.namespace}.${matcher.field} 在 FactStore 不存在`;
        caseFixtureFailures.push(failure); fixtureFailures.push(failure); return;
      }
      caseAvailable += 1;
      if (matching.some((fact) => reachedRefs.has(fact.factId))) { caseReached += 1; reachedFactLabels += 1; }
    });

    const assessments = store.listAssessments(task.taskId, epochId);
    const coverage = store.listCoverageRuns(task.taskId, epochId);
    const modelNotConcludedCategories: CheckCategory[] = [];
    const presetPartialCategories: CheckCategory[] = [];
    const detectedCategories: CheckCategory[] = [];
    const falsePositiveCategories: CheckCategory[] = [];
    for (const category of definition.expectedCategories as CheckCategory[]) {
      categoryUnits += 1;
      const modelAssessment = assessments.filter((item) => item.authorType === "MODEL" && item.scope === "OBSERVED_CATEGORY" && item.category === category).at(-1);
      if (!modelAssessment) { notConcluded += 1; modelNotConcludedCategories.push(category); }
      const latestCoverage = coverage.filter((item) => item.category === category).at(-1);
      if (latestCoverage?.status !== "COMPLETE" || latestCoverage.applicability === "UNKNOWN") { presetPartial += 1; presetPartialCategories.push(category); }
      const risky = assessments.some((item) => (item.authorType === "MODEL" || item.authorType === "RULE") && item.category === category && riskyVerdicts.has(item.verdict));
      const modelRisky = assessments.some((item) => item.authorType === "MODEL" && item.category === category && riskyVerdicts.has(item.verdict));
      if (definition.disposition === "MALICIOUS" && modelRisky) detectedCategories.push(category);
      if (definition.disposition === "MALICIOUS" && definition.novel) { novelUnits += 1; if (modelRisky) novelHits += 1; }
      if (definition.disposition === "BENIGN") { benignUnits += 1; if (risky) { benignFalsePositives += 1; falsePositiveCategories.push(category); } }
    }

    const byId = new Map(assessments.map((item) => [item.assessmentId, item]));
    const adjudications = store.listAssessmentRelations(task.taskId, epochId).filter((item) => item.kind === "ADJUDICATES");
    for (const rule of assessments.filter((item) => item.authorType === "RULE" && riskyVerdicts.has(item.verdict))) {
      riskyRuleAssessments += 1;
      const relation = adjudications.find((item) => item.toAssessmentId === rule.assessmentId);
      const human = relation ? byId.get(relation.fromAssessmentId) : undefined;
      if (human?.authorType === "HUMAN") {
        humanAdjudicated += 1;
        if (human.verdict === "BENIGN" || human.verdict === "NO_OBSERVED_FINDING") humanOverturned += 1;
      }
    }

    allModelToolRuns.push(...store.listToolRuns(task.taskId, 100_000).filter((run) => !run.toolCallId.startsWith("PRESET-")));
    unknownToolCalls.push(...store.listAudit(task.taskId, 100_000).filter((event) => event.event === "model_invalid_tool_call").map(() => 1));
    addMessageUsage(tokens, store.loadMessages(task.taskId));
    results.push({
      caseId: definition.caseId, taskId: task.taskId, epochId, disposition: definition.disposition, novel: definition.novel,
      expectedFactLabels: definition.expectedFacts.length, availableFactLabels: caseAvailable, reachedFactLabels: caseReached,
      modelNotConcludedCategories, presetPartialCategories, detectedCategories, falsePositiveCategories, fixtureFailures: caseFixtureFailures,
    });
  }

  const truncationRuns = allModelToolRuns.filter(isTruncationRun).length;
  const invalidRuns = allModelToolRuns.filter(isInvalidToolRun).length + unknownToolCalls.length;
  const remoteCost = allModelToolRuns.reduce<WireCost>((sum, run) => addWireCost(sum, extractWireCost(run)), zeroWireCost());
  const modelToolWall = allModelToolRuns.reduce((sum, run) => sum + (run.finishedAt ? Math.max(0, Date.parse(run.finishedAt) - Date.parse(run.startedAt)) : 0), 0);
  const metrics = {
    factReachability: metric(reachedFactLabels, expectedFactLabels),
    truncationLoss: metric(truncationRuns, allModelToolRuns.length),
    modelNotConcluded: metric(notConcluded, categoryUnits),
    presetPartial: metric(presetPartial, categoryUnits),
    novelRecall: metric(novelHits, novelUnits),
    invalidToolCalls: metric(invalidRuns, allModelToolRuns.length + unknownToolCalls.length),
    benignFalsePositive: metric(benignFalsePositives, benignUnits),
    ruleAdjudication: { riskyRuleAssessments, humanAdjudicated, humanOverturned },
    tokens, latencyMs: { epochWall, modelToolWall }, remoteCost,
  };
  const thresholdResults = [
    threshold("factReachability", ">=", manifest.thresholds.minFactReachability, metrics.factReachability.rate),
    threshold("truncationLoss", "<=", manifest.thresholds.maxTruncationLossRate, metrics.truncationLoss.rate),
    threshold("modelNotConcluded", "<=", manifest.thresholds.maxModelNotConcludedRate, metrics.modelNotConcluded.rate),
    threshold("presetPartial", "<=", manifest.thresholds.maxPresetPartialRate, metrics.presetPartial.rate),
    threshold("novelRecall", ">=", manifest.thresholds.minNovelRecall, metrics.novelRecall.rate),
    threshold("invalidToolCalls", "<=", manifest.thresholds.maxInvalidToolCallRate, metrics.invalidToolCalls.rate),
    threshold("benignFalsePositive", "<=", manifest.thresholds.maxBenignFalsePositiveRate, metrics.benignFalsePositive.rate),
  ];
  return {
    schemaVersion: 1, suiteId: manifest.suiteId, evaluatedAt: new Date().toISOString(),
    status: fixtureFailures.length === 0 && thresholdResults.every((item) => item.pass) ? "PASS" : "FAIL",
    models: [...modelNames.values()], metrics, thresholdResults, fixtureFailures, cases: results,
  };
}

export function renderModelCapabilityMarkdown(result: ModelCapabilityEvaluation): string {
  const percentage = (value: number | null) => value === null ? "N/A" : `${(value * 100).toFixed(2)}%`;
  const lines = [
    `# 模型能力统计评测：${result.suiteId}`,
    "", `- 结果：**${result.status}**`, `- 时间：${result.evaluatedAt}`,
    `- 模型：${result.models.map((item) => `${item.provider}/${item.model}`).join(", ") || "N/A"}`, "",
    "| 指标 | 数值 | 分子/分母 | 门槛 | 结果 |", "| --- | ---: | ---: | ---: | --- |",
  ];
  for (const item of result.thresholdResults) {
    const value = result.metrics[item.metric as keyof typeof result.metrics] as EvaluationMetric;
    lines.push(`| ${item.metric} | ${percentage(item.actual)} | ${value.numerator}/${value.denominator} | ${item.comparator} ${percentage(item.threshold)} | ${item.pass ? "PASS" : "FAIL"} |`);
  }
  lines.push("", "## 成本与裁定", "",
    `- Token：input=${result.metrics.tokens.input}，output=${result.metrics.tokens.output}，cacheRead=${result.metrics.tokens.cacheRead}，cacheWrite=${result.metrics.tokens.cacheWrite}，total=${result.metrics.tokens.total}`,
    `- 延迟：epochWall=${result.metrics.latencyMs.epochWall}ms，modelToolWall=${result.metrics.latencyMs.modelToolWall}ms`,
    `- 远程成本：calls=${result.metrics.remoteCost.remoteCalls}，nodes=${result.metrics.remoteCost.nodes}，bytes=${result.metrics.remoteCost.bytes}，wall=${result.metrics.remoteCost.wallTimeMs}ms，probe=${result.metrics.remoteCost.probeCalls ?? 0}`,
    `- 规则裁定：risky=${result.metrics.ruleAdjudication.riskyRuleAssessments}，humanAdjudicated=${result.metrics.ruleAdjudication.humanAdjudicated}，humanOverturned=${result.metrics.ruleAdjudication.humanOverturned}`);
  if (result.fixtureFailures.length > 0) lines.push("", "## 语料错误", "", ...result.fixtureFailures.map((item) => `- ${item}`));
  return `${lines.join("\n")}\n`;
}

function matchesExpectedFact(fact: FactRecord, matcher: ModelCapabilityManifest["cases"][number]["expectedFacts"][number]): boolean {
  const actual = fieldValue(fact.modelPayload, matcher.field);
  if (matcher.operator === "eq") return Object.is(actual, matcher.value);
  return typeof actual === "string" && typeof matcher.value === "string" && actual.includes(matcher.value);
}

function fieldValue(value: Record<string, unknown>, path: string): unknown {
  let current: unknown = value;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function metric(numerator: number, denominator: number): EvaluationMetric { return { numerator, denominator, rate: denominator === 0 ? null : numerator / denominator }; }
function threshold(metricName: string, comparator: ">=" | "<=", value: number, actual: number | null) {
  return { metric: metricName, comparator, threshold: value, actual, pass: actual !== null && (comparator === ">=" ? actual >= value : actual <= value) };
}

function record(value: unknown): Record<string, unknown> | undefined { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function runDetails(run: ToolRunRecord): Record<string, unknown> | undefined { return record(record(run.result)?.details); }
function isTruncationRun(run: ToolRunRecord): boolean {
  const details = runDetails(run);
  if (details?.error === "ROW_TOO_LARGE") return true;
  return Array.isArray(details?.gaps) && details.gaps.some((gap) => truncationGapCodes.has(String(record(gap)?.code)));
}
function isInvalidToolRun(run: ToolRunRecord): boolean {
  if (run.status !== "FAILED") return false;
  return /INVALID_ARGUMENT|invalid tool|schema validation|未注册工具|参数.*非法|非法字段|不允许 (?:filterable|sortable|projectable|enumerable)|不接受.*参数|必须绑定|不得绑定|has no bound source/iu.test(JSON.stringify({ error: run.error, result: run.result }));
}
function extractWireCost(run: ToolRunRecord): WireCost {
  const cost = record(runDetails(run)?.cost);
  return {
    remoteCalls: number(cost?.remoteCalls), nodes: number(cost?.nodes), bytes: number(cost?.bytes),
    wallTimeMs: number(cost?.wallTimeMs), probeCalls: number(cost?.probeCalls),
  };
}
function number(value: unknown): number { return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0; }
function zeroWireCost(): WireCost { return { remoteCalls: 0, nodes: 0, bytes: 0, wallTimeMs: 0, probeCalls: 0 }; }
function addWireCost(left: WireCost, right: WireCost): WireCost {
  return { remoteCalls: left.remoteCalls + right.remoteCalls, nodes: left.nodes + right.nodes, bytes: left.bytes + right.bytes, wallTimeMs: left.wallTimeMs + right.wallTimeMs, probeCalls: (left.probeCalls ?? 0) + (right.probeCalls ?? 0) };
}
function addMessageUsage(target: ModelCapabilityEvaluation["metrics"]["tokens"], messages: ReturnType<RuntimeStore["loadMessages"]>): void {
  for (const message of messages) {
    if (message.role !== "assistant") continue;
    target.input += number(message.usage.input); target.output += number(message.usage.output);
    target.cacheRead += number(message.usage.cacheRead); target.cacheWrite += number(message.usage.cacheWrite);
    target.total += number(message.usage.totalTokens);
  }
}
