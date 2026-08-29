import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentMessage } from "@earendil-works/pi-agent-core";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateModelCapability, parseModelCapabilityManifest, renderModelCapabilityMarkdown } from "../../src/evaluation/model-capability.js";
import type { AssessmentVerdict, ScanEpoch } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const stores: RuntimeStore[] = [];
afterEach(() => { for (const store of stores.splice(0)) store.close(); });

async function observedCase(store: RuntimeStore, input: { suffix: string; username: string; verdict: AssessmentVerdict }) {
  const task = testTask();
  task.taskId = `TASK-00000000-0000-4000-8000-0000000000${input.suffix}`;
  task.protocolVersion = 2;
  task.checks = ["backdoor_account"];
  task.modelProvider = "openai";
  task.modelId = "gpt-eval";
  store.createTask(task);
  const epoch: ScanEpoch = {
    epochId: `EPOCH-00000000-0000-4000-8000-0000000000${input.suffix}`, taskId: task.taskId,
    targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "2.0.0", helperVersion: "2.0.0",
    reason: "INITIAL", status: "RUNNING", startedAt: new Date(Date.now() - 1000).toISOString(),
  };
  store.createScanEpoch(epoch);
  const batch = store.commitFactBatch({
    taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `MODEL-ENUM-${input.suffix}`, source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
    requestId: `MODEL-ENUM-${input.suffix}`, collector: { name: "enumerate", version: "2.0.0" },
    observations: [{ namespace: "account", identity: { uid: Number(input.suffix) + 1000, username: input.username }, fields: { uid: Number(input.suffix) + 1000, username: input.username }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
    edges: [], gaps: [], wireDigest: input.suffix.repeat(64),
  });
  const query = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["factId"], limit: 10 });
  store.putCoverageRun({ coverageId: `COV-${input.suffix}`, taskId: task.taskId, epochId: epoch.epochId, category: "backdoor_account", presetId: "account-baseline", presetVersion: "2.0.0", status: "COMPLETE", applicability: "APPLICABLE", completedCriteria: ["account-db"], missingCriteria: [], createdAt: new Date().toISOString() });
  if (input.verdict !== "BENIGN") store.putAssessment({ assessmentId: `ASM-SUBJECT-${input.suffix}`, taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL", category: "backdoor_account", subjectRef: batch.facts[0]!.subjectRef, scope: "SUBJECT", verdict: input.verdict, severity: "HIGH", confidence: 0.9, rationale: "评测风险结论", evidenceRefs: [], factRefs: [batch.facts[0]!.factId], queryRefs: [query.queryRef], createdAt: new Date().toISOString() });
  store.putAssessment({ assessmentId: `ASM-CATEGORY-${input.suffix}`, taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL", category: "backdoor_account", scope: "OBSERVED_CATEGORY", verdict: input.verdict === "BENIGN" ? "NO_OBSERVED_FINDING" : "INCONCLUSIVE", severity: "INFO", confidence: 0.9, rationale: "评测类别结论", evidenceRefs: [], factRefs: [batch.facts[0]!.factId], queryRefs: [query.queryRef], createdAt: new Date().toISOString() });
  store.startToolRun({ toolCallId: `MODEL-TOOL-${input.suffix}`, taskId: task.taskId, toolName: "enumerate", risk: "READ", replayPolicy: "SAFE_REOBSERVE", args: {} });
  store.finishToolRun(`MODEL-TOOL-${input.suffix}`, "SUCCEEDED", { details: { status: "success", gaps: [], cost: { remoteCalls: 1, nodes: 1, bytes: 128, wallTimeMs: 10, probeCalls: 0 } } });
  const message: AgentMessage = {
    role: "assistant", content: [{ type: "text", text: "done" }], api: "openai-responses", provider: "openai", model: "gpt-eval",
    usage: { input: 100, output: 20, cacheRead: 5, cacheWrite: 0, totalTokens: 125, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: "stop", timestamp: Date.now(),
  };
  store.appendMessage(task.taskId, message);
  store.finishScanEpoch(task.taskId, epoch.epochId, "COMPLETED");
  const completed = store.getTask(task.taskId)!; completed.status = "COMPLETED"; store.saveTask(completed);
  return { taskId: task.taskId, epochId: epoch.epochId };
}

describe("Tool Protocol v2 model capability evaluation", () => {
  it("从 QuerySnapshot provenance 计算发布指标并执行冻结阈值", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-model-eval-"));
    const store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
    const malicious = await observedCase(store, { suffix: "1", username: "novel-backdoor", verdict: "SUSPICIOUS" });
    const benign = await observedCase(store, { suffix: "2", username: "normal-user", verdict: "BENIGN" });
    const manifest = parseModelCapabilityManifest({
      schemaVersion: 1, suiteId: "unit-release",
      cases: [
        { caseId: "novel-malicious", taskId: malicious.taskId, disposition: "MALICIOUS", novel: true, expectedCategories: ["backdoor_account"], expectedFacts: [{ namespace: "account", field: "username", operator: "eq", value: "novel-backdoor" }] },
        { caseId: "known-benign", taskId: benign.taskId, disposition: "BENIGN", novel: false, expectedCategories: ["backdoor_account"], expectedFacts: [{ namespace: "account", field: "username", operator: "eq", value: "normal-user" }] },
      ],
      thresholds: { minFactReachability: 1, maxTruncationLossRate: 0, maxModelNotConcludedRate: 0, maxPresetPartialRate: 0, minNovelRecall: 1, maxInvalidToolCallRate: 0, maxBenignFalsePositiveRate: 0 },
    });
    const result = evaluateModelCapability(store, manifest);
    expect(result.status).toBe("PASS");
    expect(result.metrics.factReachability).toEqual({ numerator: 2, denominator: 2, rate: 1 });
    expect(result.metrics.novelRecall.rate).toBe(1);
    expect(result.metrics.benignFalsePositive.rate).toBe(0);
    expect(result.metrics.tokens).toMatchObject({ input: 200, output: 40, total: 250 });
    expect(result.metrics.remoteCost).toMatchObject({ remoteCalls: 2, nodes: 2, bytes: 256 });
    expect(renderModelCapabilityMarkdown(result)).toContain("结果：**PASS**");
  });

  it("严格拒绝重复 task、缺少良性/新颖样本和 contains 非字符串", () => {
    const base = {
      schemaVersion: 1, suiteId: "bad",
      thresholds: { minFactReachability: 1, maxTruncationLossRate: 0, maxModelNotConcludedRate: 0, maxPresetPartialRate: 0, minNovelRecall: 1, maxInvalidToolCallRate: 0, maxBenignFalsePositiveRate: 0 },
    };
    const malicious = { caseId: "m", taskId: "TASK-M", disposition: "MALICIOUS", novel: true, expectedCategories: ["webshell"], expectedFacts: [{ namespace: "file", field: "size", operator: "contains", value: 1 }] };
    const benign = { caseId: "b", taskId: "TASK-B", disposition: "BENIGN", novel: false, expectedCategories: ["webshell"], expectedFacts: [{ namespace: "file", field: "path", operator: "eq", value: "/safe" }] };
    expect(() => parseModelCapabilityManifest({ ...base, cases: [malicious, benign] })).toThrow(/contains/);
    expect(() => parseModelCapabilityManifest({ ...base, cases: [{ ...malicious, expectedFacts: benign.expectedFacts }, { ...benign, taskId: "TASK-M" }] })).toThrow(/taskId 重复/);
    expect(() => parseModelCapabilityManifest({ ...base, cases: [{ ...malicious, expectedFacts: benign.expectedFacts }, { ...malicious, caseId: "m2", taskId: "TASK-M2", expectedFacts: benign.expectedFacts }] })).toThrow(/BENIGN/);
  });
});
