import { createModels, type Context } from "@earendil-works/pi-ai";
import { fauxAssistantMessage, fauxProvider, fauxToolCall, type FauxResponseStep } from "@earendil-works/pi-ai/providers/faux";
import type { ModelBundle } from "../agent/model.js";
import type { CheckCategory } from "../domain/types.js";

export type E2eFauxScenario = "web-quarantine" | "account-disable" | "web-scan" | "java-scan" | "account-scan" | "persistence-scan" | "grant-sensitive-read";

interface ScenarioDefinition { category: CheckCategory; namespace: "file" | "class" | "account" | "unit"; write?: "quarantine_file" | "disable_account"; collect?: boolean; requestSensitiveRead?: boolean }
const scenarios: Record<E2eFauxScenario, ScenarioDefinition> = {
  "web-quarantine": { category: "webshell", namespace: "file", write: "quarantine_file", collect: true },
  "account-disable": { category: "backdoor_account", namespace: "account", write: "disable_account" },
  "web-scan": { category: "webshell", namespace: "file", collect: true },
  "java-scan": { category: "java_memory_shell", namespace: "class" },
  "account-scan": { category: "backdoor_account", namespace: "account" },
  "persistence-scan": { category: "linux_persistence", namespace: "unit" },
  "grant-sensitive-read": { category: "webshell", namespace: "file", requestSensitiveRead: true },
};

function call(name: string, args: Record<string, unknown>, id: string) {
  return fauxAssistantMessage(fauxToolCall(name, args, { id }), { stopReason: "toolUse" });
}

function result(context: Context, toolCallId: string): Record<string, unknown> | undefined {
  const message = [...context.messages].reverse().find((item) => item.role === "toolResult" && item.toolCallId === toolCallId);
  return message?.role === "toolResult" && message.details && typeof message.details === "object" ? message.details as Record<string, unknown> : undefined;
}

function rows(value: Record<string, unknown> | undefined): Record<string, unknown>[] {
  return Array.isArray(value?.rows) ? value.rows.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object") : [];
}

function selectedRow(definition: ScenarioDefinition, query: Record<string, unknown>): Record<string, unknown> {
  const values = rows(query);
  const selected = values.find((row) => {
    const payload = row.payload as Record<string, unknown> | undefined;
    if (definition.namespace === "file") return payload?.path === "/var/www/html/lab-webshell.php";
    if (definition.namespace === "class") return payload?.className === "lab.DynamicMarkerFilter";
    if (definition.namespace === "account") return payload?.username === "labroot";
    return payload?.name === "huntwarden-lab.service";
  }) ?? values[0];
  if (!selected || typeof selected.factId !== "string" || typeof selected.subjectRef !== "string") throw new Error(`E2E Faux 的 ${definition.namespace} 查询没有可裁定 Fact`);
  return selected;
}

function assessmentArgs(definition: ScenarioDefinition, query: Record<string, unknown>, evidenceRefs: string[]) {
  const selected = selectedRow(definition, query);
  return {
    category: definition.category, subjectRef: selected.subjectRef, scope: "SUBJECT", verdict: "SUSPICIOUS", severity: definition.namespace === "account" ? "CRITICAL" : "HIGH", confidence: 0.96,
    rationale: `E2E v2 分析师模型基于 Preset Fact 复核 ${definition.namespace} 对象；这是测试环境的结构化裁定。`,
    evidenceRefs, factRefs: [selected.factId], queryRefs: typeof query.queryRef === "string" ? [query.queryRef] : [],
  };
}

function nextResponse(definition: ScenarioDefinition, context: Context) {
  const query = result(context, "e2e-v2-query");
  if (!query) return call("query_facts", { view: "facts", namespace: definition.namespace, select: ["factId", "subjectRef", "payload"], limit: 500 }, "e2e-v2-query");
  const selected = selectedRow(definition, query);
  const collect = result(context, "e2e-v2-collect");
  if (definition.collect && !collect) return call("collect", { ref: selected.subjectRef, maxBytes: 10 * 1024 * 1024, purpose: "E2E_V2_EVIDENCE" }, "e2e-v2-collect");
  const evidenceRefs = Array.isArray(collect?.evidenceRefs) ? collect.evidenceRefs.map(String) : [];
  if (definition.write === "quarantine_file" && !result(context, "e2e-v2-write")) return call("quarantine_file", { evidenceRef: evidenceRefs[0] }, "e2e-v2-write");
  if (definition.write === "disable_account" && !result(context, "e2e-v2-write")) return call("disable_account", { accountRef: selected.subjectRef }, "e2e-v2-write");
  // Grant Request 是异步的：设计 §11.1 要求模型拿到 PENDING 后转向其他路径，不阻塞等待审批。
  // 因此这里申请一次就继续裁定，把「授权待批」当作调查限制写进结论，而不是空转重试 read。
  if (definition.requestSensitiveRead && !result(context, "e2e-v2-grant")) {
    return call("request_sensitive_read", { ref: selected.subjectRef, reason: "E2E：需要读取候选 WebShell 正文才能判定动态分派是后门还是框架特性。" }, "e2e-v2-grant");
  }
  if (!result(context, "e2e-v2-risk-assessment")) return call("record_assessment", assessmentArgs(definition, query, evidenceRefs), "e2e-v2-risk-assessment");
  if (!result(context, "e2e-v2-category-assessment")) return call("record_assessment", {
    category: definition.category, scope: "OBSERVED_CATEGORY", verdict: "INCONCLUSIVE", severity: "INFO", confidence: 0.8,
    rationale: "E2E v2 已完成风险对象裁定；类别级别保留 INCONCLUSIVE，避免把最低覆盖误写为全局安全。",
    evidenceRefs: [], factRefs: [], queryRefs: typeof query.queryRef === "string" ? [query.queryRef] : [],
  }, "e2e-v2-category-assessment");
  return fauxAssistantMessage(`v2 ${definition.category} 调查场景已完成。`);
}

export function createE2eFauxModelBundle(scenario: string): ModelBundle {
  const definition = scenarios[scenario as E2eFauxScenario];
  if (!definition) throw new Error(`未知 E2E Faux 场景: ${scenario}`);
  const faux = fauxProvider({ provider: "huntwarden-e2e", tokensPerSecond: 0 });
  const responses: FauxResponseStep[] = Array.from({ length: 50 }, () => (context: Context) => nextResponse(definition, context));
  faux.setResponses(responses);
  const models = createModels(); models.setProvider(faux.provider);
  return { models, model: faux.getModel() } as ModelBundle;
}
