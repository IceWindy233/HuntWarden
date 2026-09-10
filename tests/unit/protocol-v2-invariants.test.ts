import { createHash } from "node:crypto";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Value } from "typebox/value";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { gateCapabilities } from "../../src/protocol-v2/capability.js";
import { PROTOCOL_MANIFEST } from "../../src/protocol-v2/manifest.js";
import { validatePredicate } from "../../src/protocol-v2/predicate.js";
import { PRESET_REGISTRY } from "../../src/presets/registry.js";
import { COVERAGE_GAP_CODES, INVESTIGATION_GAP_CODES, type Assessment, type HelperCapabilitiesV2, type ScanEpoch, type TaskGrant } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { DETERMINISTIC_RULES_V2, DeterministicRuleEngineV2 } from "../../src/rules/deterministic-rule-engine-v2.js";
import { BUILTIN_YARA_RULESETS } from "../../src/rulesets/registry.js";
import { DBAPP_THREAT_INTEL_SOURCE, type ThreatIntelClient } from "../../src/threat-intel/types.js";
import { createV2SecurityTools, estimateRemoteCost } from "../../src/tools/v2/tools.js";
import { testConfig, testTask } from "../helpers.js";

const stores: RuntimeStore[] = [];
afterEach(() => { for (const store of stores.splice(0)) store.close(); });

async function v2Store() {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-"));
  const store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
  const task = testTask(); task.protocolVersion = 2; store.createTask(task);
  const epoch: ScanEpoch = {
    epochId: "EPOCH-00000000-0000-4000-8000-000000000001", taskId: task.taskId,
    targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0",
    reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString(),
  };
  store.createScanEpoch(epoch);
  task.activeEpochId = epoch.epochId;
  return { store, task, epoch };
}

describe("Tool Protocol v2 invariants", () => {
  it("read 预算覆盖 Observation JSON 与最坏字符转义开销", () => {
    expect(estimateRemoteCost("read", { length: 467 }).bytes).toBe(19_186);
    expect(estimateRemoteCost("read", { length: 65_536 }).bytes).toBe(409_600);
    expect(estimateRemoteCost("collect", { maxBytes: 12_345 }).bytes).toBe(12_345);
    expect(estimateRemoteCost("enumerate", { namespace: "account", predicate: { op: "eq", field: "uid", value: 1 }, limit: 10 }).nodes).toBe(5_000);
    expect(estimateRemoteCost("enumerate", { namespace: "file", limit: 10 }).nodes).toBe(5_000);
  });

  it("五类 Preset 覆盖最低检测维度，且每类至少有一条版本化确定性规则", () => {
    const steps = Object.fromEntries(PRESET_REGISTRY.map((preset) => [preset.category, new Set(preset.steps.map((step) => step.stepId))]));
    expect([...steps.webshell!]).toEqual(expect.arrayContaining(["web-stack", "web-root", "web-candidate-file", "web-log-sources"]));
    expect([...steps.java_memory_shell!]).toEqual(expect.arrayContaining(["jvm-discovery", "tomcat-inventory", "jvm-class-inspect"]));
    expect([...steps.backdoor_account!]).toEqual(expect.arrayContaining(["account-db", "authorized-keys", "delegation-rules", "effective-ssh-trust", "account-auth-events"]));
    expect([...steps.linux_persistence!]).toEqual(expect.arrayContaining(["cron-source", "unit-source", "ssh-persistence", "shell-loader-persistence"]));
    expect([...steps.linux_intrusion_triage!]).toEqual(expect.arrayContaining(["process-snapshot", "socket-snapshot", "triage-file-scopes", "auth-events", "exec-events", "kernel-modules", "package-baseline", "package-owned-files", "package-file-verify"]));
    for (const preset of PRESET_REGISTRY) expect(DETERMINISTIC_RULES_V2.some((rule) => rule.category === preset.category && /^HW2-/.test(rule.ruleId) && /^2\./.test(rule.version))).toBe(true);
  });

  it("内置 YARA RuleSet Registry 的固定摘要与实际规则一致", async () => {
    const bytes = await readFile(resolve("rules/yara/webshell.yar"));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(BUILTIN_YARA_RULESETS["RULESET-WEBSHELL-BUILTIN-2"].sha256);
  });

  it("INV-01/INV-06/INV-21：调查表始终含本地事实工具，报告表只含本地工具，SCAN 不含写工具", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-tool-table-"));
    const { store, task, epoch } = await v2Store();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const helper: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: { process: { fields: ["bootId", "pid", "startTicks", "exeInode", "exeSha256"], relations: ["children"], verbs: ["enumerate", "project", "relate"] } },
      matchers: ["literal"], probes: [], verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    const grant: TaskGrant = { grantId: "GRANT-TOOLS", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "linux_intrusion_triage" }, createdAt: new Date().toISOString() };
    store.putTaskGrant(grant);
    const capabilities = gateCapabilities(helper, [grant]);
    const executor = new FakeProtocolV2Executor(helper, async () => { throw new Error("本测试不应触发远程调用"); });
    const deps = { task, epoch, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), capabilities, approvals: new ApprovalService(store), budgetOwner: "MODEL" as const };

    const investigate = createV2SecurityTools(deps);
    const investigateNames = investigate.map((tool) => tool.name);
    expect(investigateNames).toEqual(expect.arrayContaining(["query_facts", "query_investigation", "propose_hypothesis", "propose_actions", "get_assessment_projection", "describe_capabilities", "enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"]));
    expect(investigateNames).not.toContain("quarantine_file");
    expect(investigateNames).not.toContain("disable_account");
    expect(new Set(investigateNames).size).toBe(investigateNames.length);
    // DeepSeek 等 OpenAI-compatible Provider 要求函数参数 Schema 顶层显式为
    // object，不能只给 allOf/anyOf。该断言覆盖完整调查工具表，避免模型在
    // 首个 token 前因任一未调用工具的 Schema 无效而整体返回 400。
    for (const tool of investigate) expect((tool.parameters as { type?: string }).type, tool.name).toBe("object");
    const probe = investigate.find((tool) => tool.name === "probe");
    expect(probe).toBeDefined();
    expect(Value.Check(probe!.parameters, {
      ref: "OBJ-00000000-0000-4000-8000-000000000001",
      probeKind: "jvm.tomcat.inventory",
      parameters: { pid: 999 },
    })).toBe(false);
    expect(Value.Check(probe!.parameters, {
      ref: "OBJ-00000000-0000-4000-8000-000000000001",
      probeKind: "jvm.class.inspect",
      parameters: { className: "example.Filter$Inner1", classLoaderId: "loader-A" },
    })).toBe(true);
    for (const className of ["lab.", "org.apache.catalina.core.", "lab.*", ".lab.Filter", "lab..Filter"]) {
      expect(Value.Check(probe!.parameters, {
        ref: "OBJ-00000000-0000-4000-8000-000000000001",
        probeKind: "jvm.class.inspect",
        parameters: { className },
      }), className).toBe(false);
    }
    const queryFacts = investigate.find((tool) => tool.name === "query_facts")!;
    expect(Value.Check(queryFacts.parameters, { view: "facts", namespace: "process", predicate: JSON.stringify({ op: "eq", field: "pid", value: 1 }), limit: 10 })).toBe(false);
    expect(Value.Check(queryFacts.parameters, { view: "facts", namespace: "process", predicate: { op: "eq", field: "pid", value: 1 }, limit: 10 })).toBe(true);
    expect(Value.Check(queryFacts.parameters, { view: "facts", namespace: "process", predicate: { op: "and", args: [{ op: "eq", field: "pid", value: 1 }] }, limit: 10 })).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(queryFacts.parameters), "utf8")).toBeLessThan(24_000);
    await expect(queryFacts.execute("CALL-INVALID-PREDICATE-SHAPE", {
      view: "facts", namespace: "process", predicate: JSON.stringify({ op: "eq", field: "pid", value: 1 }), limit: 10,
    } as never)).rejects.toThrow(/参数不符合工具 Schema/);
    expect(store.getToolRunForScope(task.taskId, epoch.epochId, "CALL-INVALID-PREDICATE-SHAPE")).toMatchObject({ status: "FAILED" });

    const reportNames = createV2SecurityTools(deps, "REPORT").map((tool) => tool.name);
    expect(reportNames).toEqual(["query_facts", "query_investigation", "get_assessment_projection"]);

    task.mode = "REMEDIATE";
    const remediationNames = createV2SecurityTools(deps).map((tool) => tool.name);
    expect(remediationNames).toEqual(expect.arrayContaining(["quarantine_file", "disable_account"]));
  });

  it("query_investigation 压缩批次引用并严格服从模型文本字节上限", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-investigation-query-"));
    const { store, task, epoch } = await v2Store();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const now = new Date().toISOString();
    store.createInvestigationSession({
      sessionId: "ISESS-QUERY-BOUND", taskId: task.taskId, epochId: epoch.epochId,
      engineVersion: "1.0.0", playbookRegistryDigest: "a".repeat(64), ruleRegistryDigest: "b".repeat(64),
      authorizationVersion: "AUTH-QUERY-BOUND", executionStatus: "RUNNING", investigationStatus: "OPEN",
      revision: 0, createdAt: now, updatedAt: now,
    });
    store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN-QUERY-BOUND",
      source: { kind: "PRESET", presetRunId: "PRUN-QUERY-BOUND", presetId: "linux-triage-baseline", presetVersion: "2.5.0", stepId: "process-snapshot" },
      targetFingerprint: task.target.hostFingerprint, requestId: "RUN-QUERY-BOUND", collector: { name: "enumerate", version: "3.0.0" },
      observations: Array.from({ length: 200 }, (_, index) => ({
        namespace: "process" as const,
        identity: { bootId: "boot-query", pid: 10_000 + index, startTicks: String(index + 1), exeInode: String(index + 1) },
        fields: { bootId: "boot-query", pid: 10_000 + index, startTicks: String(index + 1), exeInode: String(index + 1) },
        observedAt: now, consistency: "OBJECT_STABLE" as const,
      })),
      edges: [], gaps: [], wireDigest: "c".repeat(64),
    });
    const grant: TaskGrant = { grantId: "GRANT-QUERY-BOUND", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "linux_intrusion_triage" }, createdAt: now };
    store.putTaskGrant(grant);
    const helper: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: { process: { fields: ["bootId", "pid", "startTicks", "exeInode"], relations: [], verbs: ["enumerate"] } },
      matchers: ["literal"], probes: [], verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    const config = testConfig(directory);
    config.llmData.maxTextBytes = 4_096;
    const tools = createV2SecurityTools({
      task, epoch, config, store,
      executor: new FakeProtocolV2Executor(helper, async () => { throw new Error("本测试不应触发远程调用"); }),
      evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, [grant]), approvals: new ApprovalService(store), budgetOwner: "MODEL",
    });
    const query = tools.find((item) => item.name === "query_investigation")!;
    const result = await query.execute("CALL-QUERY-BOUND", { limit: 200 } as never);
    const text = result.content.find((item) => item.type === "text")?.text ?? "";
    expect(Buffer.byteLength(text, "utf8")).toBeLessThanOrEqual(config.llmData.maxTextBytes);
    const parsed = JSON.parse(text) as { events: Array<{ eventType: string; payload: Record<string, unknown> }>; summary: { events: { maxEventSeq: number } } };
    const batch = parsed.events.find((item) => item.eventType === "FACT_BATCH_COMMITTED");
    expect(batch?.payload).toMatchObject({ factRefsCount: 200, edgeRefsCount: 0 });
    expect(batch?.payload).not.toHaveProperty("factRefs");
    expect(parsed.summary.events.maxEventSeq).toBeGreaterThan(0);
  });

  it("模型假设与动作提议必须绑定当前 Epoch，并由持久化调度器执行", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-model-proposal-"));
    const { store, task, epoch } = await v2Store();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    const helper: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: {
        process: { fields: ["bootId", "pid", "startTicks", "exeInode", "exeSha256"], relations: ["parent"], verbs: ["enumerate", "project", "relate", "collect"] },
        file: { fields: ["mountId", "device", "inode", "path", "kind", "size", "contentClass"], relations: [], verbs: ["match"] },
      },
      matchers: ["literal"], probes: [], verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    const grant: TaskGrant = { grantId: "GRANT-PROPOSAL", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "linux_intrusion_triage" }, createdAt: new Date().toISOString() };
    store.putTaskGrant(grant);
    const now = new Date().toISOString();
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN-PROPOSAL",
      source: { kind: "PRESET", presetRunId: "PRUN-PROPOSAL", presetId: "linux-triage-baseline", presetVersion: "2.5.0", stepId: "processes" },
      targetFingerprint: task.target.hostFingerprint,
      requestId: "RUN-PROPOSAL", collector: { name: "enumerate", version: "2.1.0" },
      observations: [
        { namespace: "process", identity: { bootId: "boot", pid: 77, startTicks: "100", exeInode: "200", exeSha256: "a".repeat(64) }, fields: { bootId: "boot", pid: 77, startTicks: "100", exeInode: "200", exeSha256: "a".repeat(64) }, observedAt: now, consistency: "OBJECT_STABLE" },
        { namespace: "file", identity: { mountId: "1", device: "1", inode: "300" }, fields: { mountId: "1", device: "1", inode: "300", path: "/tmp/fixture", kind: "regular", size: 12, contentClass: "SAFE_TEXT" }, observedAt: now, consistency: "OBJECT_STABLE" },
      ],
      edges: [], gaps: [], wireDigest: "b".repeat(64),
    });
    store.createInvestigationSession({
      sessionId: "ISESS-PROPOSAL", taskId: task.taskId, epochId: epoch.epochId, engineVersion: "1.0.0", playbookRegistryDigest: "c".repeat(64), ruleRegistryDigest: "d".repeat(64),
      authorizationVersion: "AUTH-PROPOSAL", executionStatus: "RUNNING", investigationStatus: "OPEN", revision: 0, createdAt: now, updatedAt: now,
    });
    for (const [kind, limit] of [["LOCAL_QUERY_CALLS", 10], ["LOCAL_QUERY_ROWS", 100], ["LOCAL_QUERY_WALL_MS", 10_000]] as const) store.initializeUsageCounter(task.taskId, epoch.epochId, kind, limit);
    const capabilities = gateCapabilities(helper, [grant]);
    const tools = createV2SecurityTools({ task, epoch, config: testConfig(directory), store, executor: new FakeProtocolV2Executor(helper, async () => { throw new Error("本测试动作应为本地查询"); }), evidence: new EvidenceStore(directory, store), capabilities, approvals: new ApprovalService(store), budgetOwner: "MODEL" });
    const hypothesisTool = tools.find((item) => item.name === "propose_hypothesis")!;
    const hypothesisResult = await hypothesisTool.execute("CALL-HYP", {
      subjectRef: batch.facts[0]!.subjectRef, claim: "该进程的外连需要排除正常运维解释", supportRefs: [batch.facts[0]!.factId], counterEvidenceRefs: [], alternativeExplanations: ["合法运维程序"],
    } as never);
    const hypothesis = hypothesisResult.details as { hypothesisId: string; obligationId: string };
    const proposalTool = tools.find((item) => item.name === "propose_actions")!;
    const proposal = await proposalTool.execute("CALL-ACTIONS", {
      hypothesisId: hypothesis.hypothesisId,
      obligationId: hypothesis.obligationId,
      actions: [{ clientRef: "counter", operationRef: "query_facts", subjectRefs: [batch.facts[0]!.subjectRef], args: { view: "facts", namespace: "process", subjectRef: batch.facts[0]!.subjectRef, limit: 10 }, dependsOnClientRefs: [] }],
    } as never);
    expect(proposal.details).toMatchObject({ scheduler: { executed: 1, succeeded: 1, failed: 0 } });
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ requestedBy: "MODEL", status: "SUCCEEDED" })]);
    expect(store.listInvestigationObligations(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([expect.objectContaining({ obligationId: hypothesis.obligationId, status: "SATISFIED", resultRefs: [expect.stringMatching(/^QUERY-/)] })]));
    const existingActionId = store.listInvestigationActions(task.taskId, epoch.epochId)[0]!.actionId;
    const dependentProposal = await proposalTool.execute("CALL-DEPENDENT-DEDUPE", {
      hypothesisId: hypothesis.hypothesisId,
      obligationId: hypothesis.obligationId,
      actions: [
        { clientRef: "existing", operationRef: "query_facts", subjectRefs: [batch.facts[0]!.subjectRef], args: { view: "facts", namespace: "process", subjectRef: batch.facts[0]!.subjectRef, limit: 10 }, dependsOnClientRefs: [] },
        { clientRef: "dependent", operationRef: "query_facts", subjectRefs: [batch.facts[0]!.subjectRef], args: { view: "facts", namespace: "process", subjectRef: batch.facts[0]!.subjectRef, limit: 9 }, dependsOnClientRefs: ["existing"] },
      ],
    } as never);
    expect(dependentProposal.details).toMatchObject({ accepted: [
      { clientRef: "existing", actionId: existingActionId },
      { clientRef: "dependent", actionId: expect.stringMatching(/^IACT-/) },
    ] });
    expect(store.listInvestigationActions(task.taskId, epoch.epochId).find((item) => item.args.limit === 9)).toMatchObject({
      status: "SUCCEEDED", dependsOn: [existingActionId],
    });
    const processRef = batch.facts.find((fact) => fact.namespace === "process")!.subjectRef;
    const fileRef = batch.facts.find((fact) => fact.namespace === "file")!.subjectRef;
    const normalized = await proposalTool.execute("CALL-NORMALIZED-ACTIONS", {
      hypothesisId: hypothesis.hypothesisId,
      obligationId: hypothesis.obligationId,
      actions: [
        { clientRef: "parent", operationRef: "relate", subjectRefs: [processRef], args: { fromRef: processRef, relation: "parent" }, dependsOnClientRefs: [] },
        { clientRef: "literal", operationRef: "match", subjectRefs: [fileRef], args: { matchType: "literal", namespace: "file", pattern: "fixture" }, dependsOnClientRefs: [] },
      ],
    } as never);
    expect(normalized.details).toMatchObject({ accepted: [{ clientRef: "parent" }, { clientRef: "literal" }] });
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ operationRef: "relate", args: { ref: processRef, relation: "parent", limit: 100 } }),
      expect.objectContaining({ operationRef: "match", args: { refs: [fileRef], matcher: { engine: "literal", pattern: "fixture" }, maxHits: 50, includeContext: false } }),
    ]));
    await expect(proposalTool.execute("CALL-MISMATCHED-BINDING", {
      hypothesisId: hypothesis.hypothesisId,
      obligationId: hypothesis.obligationId,
      actions: [{ clientRef: "mismatch", operationRef: "relate", subjectRefs: [processRef], args: { ref: fileRef, relation: "parent", limit: 10 }, dependsOnClientRefs: [] }],
    } as never)).rejects.toThrow(/ref 必须与唯一 subjectRef 一致/);
    await expect(proposalTool.execute("CALL-BAD-ACTIONS", {
      hypothesisId: hypothesis.hypothesisId, obligationId: hypothesis.obligationId,
      actions: [{ clientRef: "bad", operationRef: "query_facts", subjectRefs: [batch.facts[0]!.subjectRef], args: { view: "facts", limit: 0 }, dependsOnClientRefs: [] }],
    } as never)).rejects.toThrow(/不符合工具 Schema/);

    const actionCount = store.listInvestigationActions(task.taskId, epoch.epochId).length;
    await expect(proposalTool.execute("CALL-FILE-ENUMERATE-WITHOUT-SCOPE", {
      hypothesisId: hypothesis.hypothesisId, obligationId: hypothesis.obligationId,
      actions: [{ clientRef: "unscoped-file", operationRef: "enumerate", subjectRefs: [fileRef], args: { namespace: "file", predicate: { op: "starts_with", field: "path", value: "/tmp" }, limit: 100 }, dependsOnClientRefs: [] }],
    } as never)).rejects.toThrow(/Scope Grant scopeRef/);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toHaveLength(actionCount);
    await expect(proposalTool.execute("CALL-REDUNDANT-ENUMERATE", {
      hypothesisId: hypothesis.hypothesisId, obligationId: hypothesis.obligationId,
      actions: [{ clientRef: "redundant", operationRef: "enumerate", subjectRefs: [], args: { namespace: "process", limit: 100 }, dependsOnClientRefs: [] }],
    } as never)).rejects.toThrow(/已有 process 的 PRESET 事实/);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toHaveLength(actionCount);

    await expect(proposalTool.execute("CALL-SEMANTIC-BAD-ACTIONS", {
      hypothesisId: hypothesis.hypothesisId, obligationId: hypothesis.obligationId,
      actions: [
        { clientRef: "valid-first", operationRef: "query_facts", subjectRefs: [batch.facts[0]!.subjectRef], args: { view: "facts", namespace: "process", subjectRef: batch.facts[0]!.subjectRef, limit: 10 }, dependsOnClientRefs: [] },
        { clientRef: "invalid-second", operationRef: "verify", subjectRefs: [batch.facts[0]!.subjectRef], args: { ref: batch.facts[0]!.subjectRef, baseline: "package_db" }, dependsOnClientRefs: ["valid-first"] },
      ],
    } as never)).rejects.toThrow(/ObjectRef 不存在、类型错误/);
    expect(store.listInvestigationActions(task.taskId, epoch.epochId)).toHaveLength(actionCount);
  });

  it("INV-07：read 拒绝 DENIED_TEXT、无授权的 SENSITIVE_TEXT 与非 file 引用，且拒绝时不触达目标", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-read-gate-"));
    const { store, task, epoch } = await v2Store();
    task.checks = ["webshell"]; store.saveTask(task);
    const helper: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: {
        file: { fields: ["mountId", "device", "inode", "path", "kind", "size", "contentClass", "content"], relations: [], verbs: ["enumerate", "read", "match"] },
        process: { fields: ["bootId", "pid", "startTicks", "exeInode", "exeSha256"], relations: [], verbs: ["enumerate"] },
      },
      matchers: ["literal"], probes: [], verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"],
      limits: { maxObjects: 500, maxOutputBytes: 1_572_864, maxReadBytes: 65_536, maxCollectBytes: 104_857_600 },
    };
    const grant: TaskGrant = { grantId: "GRANT-READ", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "webshell" }, createdAt: new Date().toISOString() };
    store.putTaskGrant(grant);
    const observedAt = new Date().toISOString();
    const fileFact = (inode: string, path: string, contentClass: string) => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `RUN-${inode}`, source: { kind: "MODEL" },
      targetFingerprint: task.target.hostFingerprint, requestId: `RUN-${inode}`, collector: { name: "enumerate", version: "2.0.0" },
      observations: [{ namespace: "file", identity: { mountId: "1", device: "1", inode }, consistency: "OBJECT_STABLE", observedAt,
        fields: { mountId: "1", device: "1", inode, path, kind: "regular", size: 64, mode: 384, uid: 0, gid: 0, mtime: observedAt, contentClass } }],
      edges: [], gaps: [], wireDigest: inode.padStart(64, "0"),
    }).facts[0]!.subjectRef;
    // Helper 声称 SAFE_TEXT 也不能放行：内容分类由两端各自计算并取更严格结果。
    const deniedRef = fileFact("11", "/etc/shadow", "SAFE_TEXT");
    const sensitiveRef = fileFact("12", "/etc/nginx/nginx.conf", "SENSITIVE_TEXT");
    const processRef = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN-PROC", source: { kind: "MODEL" },
      targetFingerprint: task.target.hostFingerprint, requestId: "RUN-PROC", collector: { name: "enumerate", version: "2.0.0" },
      observations: [{ namespace: "process", identity: { bootId: "boot", pid: 42, startTicks: "9", exeInode: "7", exeSha256: "c".repeat(64) }, consistency: "OBJECT_STABLE", observedAt,
        fields: { bootId: "boot", pid: 42, startTicks: "9", exeInode: "7", exeSha256: "c".repeat(64) } }],
      edges: [], gaps: [], wireDigest: "d".repeat(64),
    }).facts[0]!.subjectRef;

    store.initializeBudget(task.taskId, epoch.epochId, "MODEL", { remoteCalls: 8, nodes: 64, bytes: 8_388_608, wallTimeMs: 600_000, probeCalls: 0 });
    store.initializeUsageCounter(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES", 4_096);
    const capabilities = gateCapabilities(helper, [grant]);
    const executor = new FakeProtocolV2Executor(helper, async (_verb, request) => ({
      protocolVersion: 2, requestId: request.requestId, status: "SUCCESS", edges: [], gaps: [],
      cost: { remoteCalls: 1, nodes: 1, bytes: 512, wallTimeMs: 5, probeCalls: 0 },
      objects: [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "12" }, consistency: "OBJECT_STABLE", observedAt,
        fields: { mountId: "1", device: "1", inode: "12", path: "/etc/nginx/nginx.conf", kind: "regular", size: 64, mode: 384, uid: 0, gid: 0, mtime: observedAt, contentClass: "SENSITIVE_TEXT", content: "server { root /var/www; }" } }],
    }));
    const deps = { task, epoch, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), capabilities, approvals: new ApprovalService(store), budgetOwner: "MODEL" as const };
    const read = createV2SecurityTools(deps).find((tool) => tool.name === "read");
    if (!read) throw new Error("read 工具未注册");
    const enumerate = createV2SecurityTools(deps).find((tool) => tool.name === "enumerate");
    if (!enumerate) throw new Error("enumerate 工具未注册");
    const args = { offset: 0, length: 512, encoding: "utf-8", purpose: "CONFIG_REVIEW" };

    // 内容出境上限由工具 Schema 承担：Agent 在调用前用同一 Schema 校验模型参数。
    expect(Value.Check(read.parameters, { ...args, ref: sensitiveRef })).toBe(true);
    expect(Value.Check(read.parameters, { ...args, ref: sensitiveRef, length: 65_537 })).toBe(false);
    await expect(enumerate.execute("CALL-FILE-ENUMERATE-WITHOUT-SCOPE", { namespace: "file", limit: 10 } as never)).rejects.toThrow(/Scope Grant scopeRef/);
    await expect(read.execute("CALL-READ-DENIED", { ...args, ref: deniedRef } as never)).rejects.toThrow(/DENIED_TEXT/);
    await expect(read.execute("CALL-READ-NOGRANT", { ...args, ref: sensitiveRef } as never)).rejects.toThrow(/Sensitive-read Grant/);
    await expect(read.execute("CALL-READ-PROCESS", { ...args, ref: processRef } as never)).rejects.toThrow(/ObjectRef/);
    expect(executor.calls).toEqual([]);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES")).toBe(4_096);

    store.putTaskGrant({ grantId: "GRANT-SENSITIVE", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "SENSITIVE_READ", status: "ACTIVE", binding: { subjectRef: sensitiveRef, contentClass: "SENSITIVE_TEXT" }, createdAt: new Date().toISOString() });
    await read.execute("CALL-READ-GRANTED", { ...args, ref: sensitiveRef } as never);
    expect(executor.calls.map((call) => call.verb)).toEqual(["read"]);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES")).toBe(3_584);

    // match 的 includeContext 把命中处正文送进模型平面，因此必须复用 read 的同一条分级与
    // 授权链路，而不是另开一条只检查 matcher 能力的捷径。
    const match = createV2SecurityTools(deps).find((tool) => tool.name === "match");
    if (!match) throw new Error("match 工具未注册");
    const matcher = { engine: "literal", pattern: "root" };
    const beforeContext = store.remainingUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES");
    const remoteCalls = executor.calls.length;
    await expect(match.execute("CALL-MATCH-DENIED-CTX", { refs: [deniedRef], matcher, maxHits: 1, includeContext: true } as never)).rejects.toThrow(/DENIED_TEXT/);
    // 混合批次里只要有一个对象缺授权就整体失败：部分成功会让模型无法判断缺的是哪些对象。
    const otherRef = fileFact("13", "/var/www/html/index.php", "SENSITIVE_TEXT");
    await expect(match.execute("CALL-MATCH-MIXED-CTX", { refs: [sensitiveRef, otherRef], matcher, maxHits: 1, includeContext: true } as never)).rejects.toThrow(/Sensitive-read Grant/);
    expect(executor.calls.length).toBe(remoteCalls);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES")).toBe(beforeContext);

    await match.execute("CALL-MATCH-GRANTED-CTX", { refs: [sensitiveRef], matcher, maxHits: 1, includeContext: true } as never);
    expect(executor.calls.map((call) => call.verb)).toEqual(["read", "match"]);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES")).toBe(beforeContext - 2_560);
  });

  it("Manifest 是静态安全上限，Helper 的未知能力只记录异常且 task_ioc 不进入远程能力", () => {
    const capabilities: HelperCapabilitiesV2 = {
      protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" },
      namespaces: { process: { fields: ["pid", "doesNotExist"], relations: ["children", "invented"] }, task_ioc: { fields: ["kind"], relations: [] } },
      matchers: ["literal"], probes: [], verbs: ["enumerate"],
      limits: { maxObjects: 99999, maxOutputBytes: 99999999, maxReadBytes: 99999999, maxCollectBytes: 999999999 },
    };
    const grants: TaskGrant[] = [{ grantId: "GRANT-1", taskId: "TASK-1", targetFingerprint: "FP", kind: "CATEGORY", status: "ACTIVE", binding: { category: "linux_intrusion_triage" }, createdAt: new Date().toISOString() }];
    const effective = gateCapabilities(capabilities, grants);
    expect([...effective.namespaces.process!.fields]).toEqual(["pid"]);
    expect(effective.namespaces.task_ioc).toBeUndefined();
    expect(effective.limits.maxObjects).toBe(PROTOCOL_MANIFEST.hardLimits.enumerateLimit);
    expect(effective.protocolAnomalies).toEqual(expect.arrayContaining([
      "helper_advertised_unknown_field:process.doesNotExist", "helper_advertised_unknown_relation:process.invented", "helper_advertised_unknown_namespace:task_ioc",
    ]));
  });

  it("Predicate 拒绝 Manifest 外字段、类型不兼容与超深 AST", () => {
    expect(() => validatePredicate("process", { op: "eq", field: "pid", value: 1 })).not.toThrow();
    expect(() => validatePredicate("process", { op: "eq", field: "evil", value: 1 })).toThrow(/不允许/);
    expect(() => validatePredicate("process", { op: "contains", field: "pid", value: "1" })).toThrow(/字符串/);
    const deep = { op: "not", arg: { op: "not", arg: { op: "not", arg: { op: "not", arg: { op: "eq", field: "pid", value: 1 } } } } } as const;
    expect(() => validatePredicate("process", deep)).toThrow(/深度/);
    expect(() => validatePredicate("process", JSON.stringify({ op: "eq", field: "pid", value: 1 }))).toThrow(/带 op 的对象/);
    expect(() => validatePredicate("process", null)).toThrow(/带 op 的对象/);
    expect(() => validatePredicate("process", { op: "and", args: "invalid" })).toThrow(/args 必须是数组/);
    expect(() => validatePredicate("process", { op: "invented", field: "pid", value: 1 })).toThrow(/未知 Predicate/);
  });

  it("FactBatch 原子提交引用、双平面投影和 ToolRun 终态，失败批次不泄漏半批事实", async () => {
    const { store, task, epoch } = await v2Store();
    store.startToolRun({ toolCallId: "CALL-1", taskId: task.taskId, epochId: epoch.epochId, toolName: "enumerate", risk: "READ", replayPolicy: "SAFE_REOBSERVE", args: {} });
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "CALL-1", source: { kind: "MODEL" },
      targetFingerprint: task.target.hostFingerprint, requestId: "CALL-1", collector: { name: "enumerate", version: "2.0.0" },
      observations: [{ namespace: "account", identity: { uid: 0, username: "root" }, fields: { uid: 0, username: "root", gid: 0, home: "/root", shell: "/bin/bash", groups: ["root"], locked: false, passwordHash: "$secret" }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "a".repeat(64), toolRun: { toolCallId: "CALL-1", status: "SUCCEEDED", resultFactory: (value) => ({ factRefs: value.facts.map((fact) => fact.factId) }) },
    });
    // INV-05：Fact 必须绑定 task + epoch + 目标指纹，指纹不符的批次整批拒绝。
    expect(() => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "CALL-OTHER-TARGET", source: { kind: "MODEL" },
      targetFingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", requestId: "CALL-OTHER-TARGET",
      collector: { name: "enumerate", version: "2.0.0" },
      observations: [{ namespace: "host", identity: { bootId: "boot-other" }, fields: { bootId: "boot-other" }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "f".repeat(64),
    })).toThrow(/目标身份/);
    expect(batch.facts).toHaveLength(1);
    expect(batch.facts[0]!.privatePayload.passwordHash).toBe("$secret");
    expect(batch.facts[0]!.modelPayload.passwordHash).toBe(true);
    expect(batch.facts[0]!.redactedFields).toContain("passwordHash");
    expect(store.getToolRun("CALL-1")).toMatchObject({ status: "SUCCEEDED", result: { factRefs: [batch.facts[0]!.factId] } });

    store.startToolRun({ toolCallId: "CALL-2", taskId: task.taskId, epochId: epoch.epochId, toolName: "enumerate", risk: "READ", replayPolicy: "SAFE_REOBSERVE", args: {} });
    expect(() => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "CALL-2", source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "CALL-2", collector: { name: "enumerate", version: "2.0.0" }, observations: [{ namespace: "account", identity: { uid: 1, username: "bad" }, fields: { uid: 1, username: "bad", invented: "x" }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "b".repeat(64), toolRun: { toolCallId: "CALL-2", status: "SUCCEEDED" },
    })).toThrow(/Manifest 外字段/);
    expect(store.listFacts(task.taskId, epoch.epochId)).toHaveLength(1);
    expect(store.getToolRun("CALL-2")?.status).toBe("STARTED");

    store.startToolRun({ toolCallId: "CALL-STALE-EPOCH", taskId: task.taskId, epochId: "EPOCH-STALE", toolName: "enumerate", risk: "READ", replayPolicy: "SAFE_REOBSERVE", args: {} });
    expect(() => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "CALL-STALE-EPOCH", source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "CALL-STALE-EPOCH", collector: { name: "enumerate", version: "3.0.0" }, observations: [], edges: [], gaps: [], wireDigest: "c".repeat(64),
      toolRun: { toolCallId: "CALL-STALE-EPOCH", status: "SUCCEEDED" },
    })).toThrow(/任务与 Epoch/);
    expect(store.getToolRun("CALL-STALE-EPOCH")?.status).toBe("STARTED");
  });

  it("受控 read 文本进入 Model Fact，但不会因 Manifest DENY 被静默丢弃", async () => {
    const { store, task, epoch } = await v2Store();
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "READ-1", source: { kind: "MODEL" },
      targetFingerprint: task.target.hostFingerprint, requestId: "READ-1", collector: { name: "read", version: "2.0.0" },
      observations: [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "2" }, fields: { mountId: "1", device: "1", inode: "2", path: "/etc/os-release", kind: "regular", size: 12, mode: 420, uid: 0, gid: 0, mtime: new Date().toISOString(), contentClass: "SAFE_TEXT", content: "NAME=Example" }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "d".repeat(64),
    });
    expect(batch.facts[0]!.privatePayload.content).toBe("NAME=Example");
    expect(batch.facts[0]!.modelPayload.content).toBe("NAME=Example");
  });

  it("query_facts 固化快照并强制 task+epoch 隔离，Cursor 不跳过事实", async () => {
    const { store, task, epoch } = await v2Store();
    for (let index = 0; index < 3; index += 1) store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `RUN-${index}`, source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: `RUN-${index}`, collector: { name: "enumerate", version: "2.0.0" }, observations: [{ namespace: "account", identity: { uid: index + 1000, username: `u${index}` }, fields: { uid: index + 1000, username: `u${index}` }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }], edges: [], gaps: [], wireDigest: String(index).repeat(64),
    });
    const first = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["factId", "factSeq", "payload"], limit: 2 });
    expect(first.rows).toHaveLength(2); expect(first.nextCursorRef).toMatch(/^QCUR-/);
    const cursorRef = first.nextCursorRef;
    if (!cursorRef) throw new Error("第一页应返回查询游标");
    const second = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["factId", "factSeq", "payload"], limit: 2, cursorRef });
    expect(second.rows).toHaveLength(1);
    expect(new Set([...first.rows, ...second.rows].map((row) => row.factId)).size).toBe(3);
    expect(() => store.queryFacts("TASK-OTHER", epoch.epochId, { view: "facts", select: ["factId"], limit: 2, cursorRef })).toThrow(/跨 task/);

    const customOrder = [{ field: "sourceRunId", direction: "desc" as const }];
    const customFirst = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["sourceRunId"], orderBy: customOrder, limit: 1 });
    expect(customFirst.rows).toEqual([{ sourceRunId: "RUN-2" }]);
    if (!customFirst.nextCursorRef) throw new Error("自定义排序第一页应返回游标");
    store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN-Z-NEW", source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "RUN-Z-NEW", collector: { name: "enumerate", version: "2.0.0" }, observations: [{ namespace: "account", identity: { uid: 1999, username: "new-after-snapshot" }, fields: { uid: 1999, username: "new-after-snapshot" }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: "f".repeat(64),
    });
    const customSecond = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["sourceRunId"], orderBy: customOrder, limit: 1, cursorRef: customFirst.nextCursorRef });
    expect(customSecond.rows).toEqual([{ sourceRunId: "RUN-1" }]);
    if (!customSecond.nextCursorRef) throw new Error("自定义排序第二页应返回游标");
    const customThird = store.queryFacts(task.taskId, epoch.epochId, { view: "facts", namespace: "account", select: ["sourceRunId"], orderBy: customOrder, limit: 10, cursorRef: customSecond.nextCursorRef });
    expect(customThird.rows).toEqual([{ sourceRunId: "RUN-0" }]);
  });

  it("INV-04/INV-12：query_facts 字节预算试算不落孤儿 QuerySnapshot 或 Cursor", async () => {
    const { store, task, epoch } = await v2Store();
    task.checks = ["backdoor_account"];
    store.saveTask(task);
    for (let index = 0; index < 10; index += 1) store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `QUERY-SIZE-${index}`, source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: `QUERY-SIZE-${index}`, collector: { name: "enumerate", version: "2.0.0" }, observations: [{ namespace: "account", identity: { uid: index + 2000, username: `sized-${index}` }, fields: { uid: index + 2000, username: `sized-${index}`, home: `/home/${"x".repeat(300)}` }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: String(index).repeat(64),
    });
    for (const [kind, limit] of [["LOCAL_QUERY_CALLS", 10], ["LOCAL_QUERY_ROWS", 100], ["LOCAL_QUERY_WALL_MS", 10_000]] as const) {
      store.initializeUsageCounter(task.taskId, epoch.epochId, kind, limit);
    }
    const grant: TaskGrant = { grantId: "GRANT-QUERY-SIZE", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "backdoor_account" }, createdAt: new Date().toISOString() };
    store.putTaskGrant(grant);
    const helper: HelperCapabilitiesV2 = { protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" }, namespaces: { account: { fields: ["uid", "username", "home"], relations: [], verbs: ["enumerate"] } }, matchers: [], probes: [], verbs: ["enumerate"], limits: { maxObjects: 10, maxOutputBytes: 4096, maxReadBytes: 1024, maxCollectBytes: 1024 } };
    const config = testConfig("/tmp/query-size");
    config.llmData.maxTextBytes = 1024;
    const tools = createV2SecurityTools({ task, epoch, config, store, executor: new FakeProtocolV2Executor(helper, async () => { throw new Error("本测试不应远程调用 helper"); }), evidence: new EvidenceStore("/tmp/query-size", store), capabilities: gateCapabilities(helper, [grant]), approvals: new ApprovalService(store), budgetOwner: "MODEL" });
    const query = tools.find((tool) => tool.name === "query_facts");
    if (!query) throw new Error("缺少 query_facts");

    await expect(query.execute("QUERY-INVALID-SELECT", { view: "facts", namespace: "account", select: ["path"], limit: 10 })).rejects.toThrow(/参数不符合工具 Schema/);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "LOCAL_QUERY_CALLS")).toBe(10);
    const result = await query.execute("QUERY-SIZE-CALL", { view: "facts", namespace: "account", limit: 10 });
    expect(Buffer.byteLength(JSON.stringify(result.details), "utf8")).toBeLessThanOrEqual(1024);
    expect(JSON.stringify(result.details)).toContain("payload");
    expect(store.listQuerySnapshots(task.taskId, epoch.epochId)).toHaveLength(1);
  });

  it("INV-06/INV-12：Edge/Evidence Meta/Assessment/Coverage 视图只读模型安全字段并保持快照分页", async () => {
    const { store, task, epoch } = await v2Store();
    const observedAt = new Date().toISOString();
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "EDGE-RUN", source: { kind: "MODEL" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "EDGE-RUN", collector: { name: "relate", version: "2.0.0" },
      observations: [
        { namespace: "process", identity: { bootId: "boot", pid: 10, startTicks: "1", exeInode: "10", exeSha256: "a".repeat(64) }, fields: { ppid: 1, uid: 0, username: "root", comm: "parent", exe: "/usr/bin/parent", state: "S" }, observedAt, consistency: "OBJECT_STABLE" },
        { namespace: "process", identity: { bootId: "boot", pid: 11, startTicks: "2", exeInode: "11", exeSha256: "b".repeat(64) }, fields: { ppid: 10, uid: 1000, username: "user", comm: "child", exe: "/tmp/child", state: "S" }, observedAt, consistency: "OBJECT_STABLE" },
      ],
      edges: [{ relation: "children", fromIdentity: { namespace: "process", identity: { bootId: "boot", pid: 10, startTicks: "1", exeInode: "10", exeSha256: "a".repeat(64) } }, toIdentity: { namespace: "process", identity: { bootId: "boot", pid: 11, startTicks: "2", exeInode: "11", exeSha256: "b".repeat(64) } }, observedAt }],
      gaps: [], wireDigest: "1".repeat(64),
    });
    store.putEvidence({ evidenceId: "EV-00000000-0000-4000-8000-000000000010", taskId: task.taskId, host: task.target.host, type: "collected_object", source: "/tmp/child", sha256: "c".repeat(64), collectedAt: observedAt, tool: "collect", toolCallId: "COLLECT-1", storagePath: "/private/spool/secret", metadata: { epochId: epoch.epochId, subjectRef: batch.facts[1]!.subjectRef, remoteSize: 123, complete: true, artifactToken: "must-not-leak" } });
    store.putAssessment({ assessmentId: "ASM-00000000-0000-4000-8000-000000000010", taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL", category: "linux_intrusion_triage", subjectRef: batch.facts[1]!.subjectRef, scope: "SUBJECT", verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.7, rationale: "临时目录进程", evidenceRefs: [], factRefs: [batch.facts[1]!.factId], queryRefs: [], createdAt: observedAt });
    const coverage = (id: string, category: "webshell" | "linux_intrusion_triage") => ({ coverageId: id, taskId: task.taskId, epochId: epoch.epochId, category, presetId: `${category}-baseline`, presetVersion: "2.0.0", status: "COMPLETE" as const, applicability: "APPLICABLE" as const, completedCriteria: ["baseline"], missingCriteria: [], createdAt: observedAt });
    store.putCoverageRun(coverage("COV-1", "webshell"));
    store.putCoverageRun(coverage("COV-2", "linux_intrusion_triage"));

    expect(store.queryFacts(task.taskId, epoch.epochId, { view: "edges", select: ["edgeId", "relation", "fromRef", "toRef"], limit: 10 }).rows).toEqual([expect.objectContaining({ relation: "children" })]);
    const evidenceRows = store.queryFacts(task.taskId, epoch.epochId, { view: "evidence_meta", select: ["evidenceId", "sha256", "size", "subjectRef", "complete"], limit: 10 }).rows;
    expect(evidenceRows).toEqual([expect.objectContaining({ size: 123, complete: true })]);
    expect(JSON.stringify(evidenceRows)).not.toContain("storagePath");
    expect(JSON.stringify(evidenceRows)).not.toContain("artifactToken");
    expect(store.queryFacts(task.taskId, epoch.epochId, { view: "assessments", category: "linux_intrusion_triage", select: ["assessmentId", "verdict", "subjectRef"], limit: 10 }).rows).toEqual([expect.objectContaining({ verdict: "SUSPICIOUS" })]);

    const first = store.queryFacts(task.taskId, epoch.epochId, { view: "coverage", select: ["coverageId", "category", "status"], orderBy: [{ field: "coverageId", direction: "asc" }], limit: 1 });
    expect(first.rows).toHaveLength(1);
    if (!first.nextCursorRef) throw new Error("Coverage 快照应有第二页");
    store.putCoverageRun(coverage("COV-3", "webshell"));
    const second = store.queryFacts(task.taskId, epoch.epochId, { view: "coverage", select: ["coverageId", "category", "status"], orderBy: [{ field: "coverageId", direction: "asc" }], limit: 10, cursorRef: first.nextCursorRef });
    expect(second.rows).toEqual([expect.objectContaining({ coverageId: "COV-2" })]);
    expect(JSON.stringify(second.rows)).not.toContain("COV-3");
    expect(() => store.queryFacts(task.taskId, epoch.epochId, { view: "evidence_meta", select: ["storagePath"], limit: 1 })).toThrow(/非法字段/);
  });

  it("预算必须先预留，超额实际成本被拒绝", async () => {
    const { store, task, epoch } = await v2Store();
    store.initializeBudget(task.taskId, epoch.epochId, "MODEL", { remoteCalls: 1, nodes: 10, bytes: 1000, wallTimeMs: 1000, probeCalls: 0 });
    store.reserveBudget("BRES-1", task.taskId, epoch.epochId, "MODEL", { remoteCalls: 1, nodes: 5, bytes: 500, wallTimeMs: 500, probeCalls: 0 });
    expect(() => store.reserveBudget("BRES-2", task.taskId, epoch.epochId, "MODEL", { remoteCalls: 1, nodes: 1, bytes: 1, wallTimeMs: 1, probeCalls: 0 })).toThrow(/预算不足/);
    expect(() => store.settleBudget("BRES-1", { remoteCalls: 1, nodes: 6, bytes: 500, wallTimeMs: 500, probeCalls: 0 })).toThrow(/超过预留/);
    expect(store.getBudgetAccount(task.taskId, epoch.epochId, "MODEL")).toMatchObject({
      used: { remoteCalls: 0, nodes: 0, bytes: 0, wallTimeMs: 0, probeCalls: 0 },
      reserved: { remoteCalls: 1, nodes: 5, bytes: 500, wallTimeMs: 500, probeCalls: 0 },
      remaining: { remoteCalls: 0, nodes: 5, bytes: 500, wallTimeMs: 500, probeCalls: 0 },
    });
    store.settleBudget("BRES-1", { remoteCalls: 1, nodes: 4, bytes: 400, wallTimeMs: 250, probeCalls: 0 });
    expect(store.getBudgetAccount(task.taskId, epoch.epochId, "MODEL")).toMatchObject({
      used: { remoteCalls: 1, nodes: 4, bytes: 400, wallTimeMs: 250, probeCalls: 0 },
      reserved: { remoteCalls: 0, nodes: 0, bytes: 0, wallTimeMs: 0, probeCalls: 0 },
      remaining: { remoteCalls: 0, nodes: 6, bytes: 600, wallTimeMs: 750, probeCalls: 0 },
    });
  });

  it("本地查询、内容和 Grant Request 使用独立持久预算，Pending Request 可过期", async () => {
    const { store, task, epoch } = await v2Store();
    store.initializeUsageCounter(task.taskId, epoch.epochId, "LOCAL_QUERY_ROWS", 2);
    store.initializeUsageCounter(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES", 8);
    store.consumeUsage(task.taskId, epoch.epochId, "LOCAL_QUERY_ROWS", 2);
    store.consumeUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES", 8);
    expect(() => store.consumeUsage(task.taskId, epoch.epochId, "LOCAL_QUERY_ROWS", 1)).toThrow(/预算不足/);
    expect(() => store.consumeUsage(task.taskId, epoch.epochId, "MODEL_CONTENT_BYTES", 1)).toThrow(/预算不足/);
    store.putGrantRequest({ requestId: "GRQ-1", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "SCOPE", status: "PENDING", bindingDigest: "a".repeat(64), binding: { namespace: "file", requestedRoot: "/srv/www" }, createdAt: new Date().toISOString() });
    expect(store.expirePendingGrantRequests(task.taskId)).toBe(1);
    expect(store.getGrantRequest("GRQ-1")?.status).toBe("EXPIRED");
  });

  it("EXTERNAL 只能丰富已由 SYSTEM 物化的 task_ioc，不能创建自由 IOC", async () => {
    const { store, task, epoch } = await v2Store();
    const identity = { kind: "ip", valueDigest: "e".repeat(64) };
    store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "IOC-SYSTEM", source: { kind: "SYSTEM" }, targetFingerprint: task.target.hostFingerprint, requestId: "IOC-SYSTEM", collector: { name: "task_ioc_materializer", version: "2.0.0" }, observations: [{ namespace: "task_ioc", identity, fields: { ...identity, value: "8.8.8.8", suppliedAt: new Date().toISOString() }, observedAt: new Date().toISOString(), consistency: "POINT_IN_TIME" }], edges: [], gaps: [], wireDigest: "e".repeat(64) });
    expect(() => store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "IOC-EXTERNAL", source: { kind: "EXTERNAL", externalProvider: "dbapp-ti" }, targetFingerprint: task.target.hostFingerprint, requestId: "IOC-EXTERNAL", collector: { name: "dbapp-ti", version: "2.0.0" }, observations: [{ namespace: "task_ioc", identity, fields: { ...identity, intelProvider: "dbapp-ti", intelMalicious: true, intelRiskLevel: "high", intelThreatTypes: ["c2"], intelQueriedAt: new Date().toISOString() }, observedAt: new Date().toISOString(), consistency: "EXTERNAL_BASELINE" }], edges: [], gaps: [], wireDigest: "f".repeat(64) })).not.toThrow();
    expect(() => store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "IOC-FREE", source: { kind: "EXTERNAL", externalProvider: "dbapp-ti" }, targetFingerprint: task.target.hostFingerprint, requestId: "IOC-FREE", collector: { name: "dbapp-ti", version: "2.0.0" }, observations: [{ namespace: "task_ioc", identity: { kind: "ip", valueDigest: "9".repeat(64) }, fields: { kind: "ip", valueDigest: "9".repeat(64), intelProvider: "dbapp-ti", intelRiskLevel: "unknown", intelThreatTypes: [], intelQueriedAt: new Date().toISOString() }, observedAt: new Date().toISOString(), consistency: "EXTERNAL_BASELINE" }], edges: [], gaps: [], wireDigest: "9".repeat(64) })).toThrow(/首次物化/);
  });

  it("外部情报按调用、去重 IOC 和实际墙钟时间分别计费，超额时固化 InvestigationGap", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-intel-budget-"));
    const { store, task, epoch } = await v2Store();
    task.checks = ["linux_intrusion_triage"];
    store.saveTask(task);
    store.putTaskGrant({ grantId: "GRANT-TI-BUDGET", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "linux_intrusion_triage" }, createdAt: new Date().toISOString() });
    const identity = { kind: "ip", valueDigest: "8".repeat(64) };
    const materialized = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "IOC-BUDGET-SYSTEM", source: { kind: "SYSTEM" },
      targetFingerprint: task.target.hostFingerprint, requestId: "IOC-BUDGET-SYSTEM", collector: { name: "task_ioc_materializer", version: "2.0.0" },
      observations: [{ namespace: "task_ioc", identity, fields: { ...identity, value: "8.8.8.8", suppliedAt: new Date().toISOString() }, observedAt: new Date().toISOString(), consistency: "POINT_IN_TIME" }],
      edges: [], gaps: [], wireDigest: "8".repeat(64),
    });
    store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_CALLS", 1);
    store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_IOCS", 1);
    store.initializeUsageCounter(task.taskId, epoch.epochId, "THREAT_INTEL_WALL_MS", 1_000);
    const threatIntel: ThreatIntelClient = {
      compromiseDetection: async (iocs) => ({
        provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, requestId: "REQ-v2-budget", queriedAt: new Date().toISOString(), warnings: [],
        verdicts: iocs.map((ioc) => ({ ioc, iocType: "ip", malicious: false, riskLevel: "info", confidence: 0.9, threatTypes: [], apt: false, hackerGroups: [], attackEvents: [], malwareFamilies: [], cached: false, source: DBAPP_THREAT_INTEL_SOURCE })),
      }),
      batchFileInfo: async () => { throw new Error("不应调用文件情报"); },
    };
    const config = testConfig(directory); config.threatIntel.enabled = true;
    const helper: HelperCapabilitiesV2 = { protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "helper", version: "3.0.0" }, namespaces: { process: { fields: ["pid"], relations: [], verbs: ["enumerate"] } }, matchers: [], probes: [], verbs: ["enumerate"], limits: { maxObjects: 1, maxOutputBytes: 1024, maxReadBytes: 1024, maxCollectBytes: 1024 } };
    const grants = store.listTaskGrants(task.taskId);
    const tools = createV2SecurityTools({ task, epoch, config, store, executor: new FakeProtocolV2Executor(helper, async () => { throw new Error("不应远程调用 helper"); }), evidence: new EvidenceStore(directory, store), capabilities: gateCapabilities(helper, grants), approvals: new ApprovalService(store), threatIntel, budgetOwner: "MODEL" });
    const tool = tools.find((candidate) => candidate.name === "enrich_threat_intel");
    if (!tool) throw new Error("应注册 v2 外部情报工具");

    await tool.execute("TI-BUDGET-1", { refs: [materialized.facts[0]!.subjectRef] });
    expect(store.remainingUsage(task.taskId, epoch.epochId, "THREAT_INTEL_CALLS")).toBe(0);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "THREAT_INTEL_IOCS")).toBe(0);
    expect(store.remainingUsage(task.taskId, epoch.epochId, "THREAT_INTEL_WALL_MS")).toBeLessThan(1_000);
    await expect(tool.execute("TI-BUDGET-2", { refs: [materialized.facts[0]!.subjectRef] })).rejects.toThrow(/预算不足/);
    expect(store.listInvestigationGaps(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([expect.objectContaining({ reasonCode: "THREAT_INTEL_IOCS" })]));
  });

  it("外部事实不能单独形成 CONFIRMED_MALICIOUS", async () => {
    const { store, task, epoch } = await v2Store();
    const batch = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "EXT-1", source: { kind: "EXTERNAL", externalProvider: "dbapp-ti" }, targetFingerprint: task.target.hostFingerprint, requestId: "EXT-1", collector: { name: "dbapp-ti", version: "1" }, observations: [{ namespace: "socket", identity: { protocol: "tcp", localAddress: "127.0.0.1", localPort: 1, remoteAddress: "8.8.8.8", remotePort: 443, inode: "1" }, fields: { protocol: "tcp", localAddress: "127.0.0.1", localPort: 1, remoteAddress: "8.8.8.8", remotePort: 443, inode: "1" }, observedAt: new Date().toISOString(), consistency: "EXTERNAL_BASELINE" }], edges: [], gaps: [], wireDigest: "c".repeat(64) });
    store.putEvidence({ evidenceId: "EV-00000000-0000-4000-8000-000000000001", taskId: task.taskId, host: task.target.host, type: "metadata", source: "external", tool: "intel", collectedAt: new Date().toISOString(), metadata: { complete: true } });
    const assessment: Assessment = { assessmentId: "ASM-00000000-0000-4000-8000-000000000001", taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL", category: "linux_intrusion_triage", subjectRef: batch.facts[0]!.subjectRef, scope: "SUBJECT", verdict: "CONFIRMED_MALICIOUS", severity: "CRITICAL", confidence: 0.9, rationale: "仅依据外部情报", evidenceRefs: ["EV-00000000-0000-4000-8000-000000000001"], factRefs: [batch.facts[0]!.factId], queryRefs: [], createdAt: new Date().toISOString() };
    expect(() => store.putAssessment(assessment)).toThrow(/完整 Evidence|主机信号/);
  });

  it("CONFIRMED_MALICIOUS 只接受当前 Epoch 且绑定被裁定对象的显式完整 Evidence", async () => {
    const { store, task, epoch } = await v2Store();
    const observedAt = new Date().toISOString();
    const commit = (runId: string, collector: string, inode: string, path: string) => store.commitFactBatch({
      taskId: task.taskId,
      epochId: epoch.epochId,
      sourceRunId: runId,
      source: { kind: "MODEL" },
      targetFingerprint: task.target.hostFingerprint,
      requestId: runId,
      collector: { name: collector, version: "2.1.0" },
      observations: [{
        namespace: "file",
        identity: { mountId: "1", device: "1", inode },
        fields: { mountId: "1", device: "1", inode, path, kind: "file", size: 10, contentClass: "SYSTEM_TEXT" },
        observedAt,
        consistency: "OBJECT_STABLE",
      }],
      edges: [],
      gaps: [],
      wireDigest: runId.padEnd(64, "0").slice(0, 64),
    }).facts[0]!;
    const first = commit("HOST-FACT-1", "enumerate", "10", "/tmp/suspect");
    const second = commit("HOST-FACT-2", "match", "10", "/tmp/suspect");
    const unrelated = commit("HOST-FACT-3", "enumerate", "11", "/tmp/unrelated");
    const incompleteEvidenceId = "EV-00000000-0000-4000-8000-000000000010";
    const unrelatedEvidenceId = "EV-00000000-0000-4000-8000-000000000011";
    const boundEvidenceId = "EV-00000000-0000-4000-8000-000000000012";
    const evidenceBase = { taskId: task.taskId, host: task.target.host, type: "metadata" as const, source: "host", tool: "collect", collectedAt: observedAt };
    store.putEvidence({ ...evidenceBase, evidenceId: incompleteEvidenceId, metadata: { epochId: epoch.epochId, subjectRef: first.subjectRef } });
    const completeMetadata = { complete: true, epochId: epoch.epochId, range: { start: 0, length: 10, complete: true }, artifactSize: 10, artifactDigest: "a".repeat(64), integrityStatus: "VERIFIED" };
    store.putEvidence({ ...evidenceBase, evidenceId: unrelatedEvidenceId, sha256: "a".repeat(64), metadata: { ...completeMetadata, subjectRef: unrelated.subjectRef } });
    store.putEvidence({ ...evidenceBase, evidenceId: boundEvidenceId, sha256: "a".repeat(64), metadata: { ...completeMetadata, subjectRef: first.subjectRef } });
    const assessment = (assessmentId: string, evidenceId: string): Assessment => ({
      assessmentId,
      taskId: task.taskId,
      epochId: epoch.epochId,
      authorType: "MODEL",
      category: "webshell",
      subjectRef: first.subjectRef,
      scope: "SUBJECT",
      verdict: "CONFIRMED_MALICIOUS",
      severity: "CRITICAL",
      confidence: 0.95,
      rationale: "两个主机采集器事实与完整证据共同确认",
      evidenceRefs: [evidenceId],
      factRefs: [first.factId, second.factId],
      queryRefs: [],
      createdAt: observedAt,
    });
    expect(() => store.putAssessment(assessment("ASM-00000000-0000-4000-8000-000000000010", incompleteEvidenceId))).toThrow(/完整 Evidence/);
    expect(() => store.putAssessment(assessment("ASM-00000000-0000-4000-8000-000000000011", unrelatedEvidenceId))).toThrow(/完整 Evidence/);
    expect(() => store.putAssessment(assessment("ASM-00000000-0000-4000-8000-000000000012", boundEvidenceId))).not.toThrow();
    expect(store.listAssessments(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([expect.objectContaining({ assessmentId: "ASM-00000000-0000-4000-8000-000000000012" })]));
  });

  it("JVM retransformation 证据仅能通过精确 loads_class 谱系支撑对应 Class", async () => {
    const { store, task, epoch } = await v2Store();
    const observedAt = new Date().toISOString();
    const jvmIdentity = { bootId: "boot-jvm", pid: 4242, startTicks: "100" };
    const classIdentity = { jvmDigest: "jvm-digest", className: "demo.SuspiciousFilter", loaderId: "loader-1" };
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "PROBE-DUMP-1",
      source: { kind: "MODEL", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "PROBE-DUMP-1", collector: { name: "probe", version: "3.0.0" },
      observations: [
        { namespace: "jvm", identity: jvmIdentity, fields: jvmIdentity, observedAt, consistency: "POINT_IN_TIME" },
        { namespace: "class", identity: classIdentity, fields: { ...classIdentity, bytecodeSha256: "a".repeat(64), modifiable: true }, observedAt, consistency: "POINT_IN_TIME" },
      ],
      edges: [{ relation: "loads_class", fromIdentity: { namespace: "jvm", identity: jvmIdentity }, toIdentity: { namespace: "class", identity: classIdentity }, observedAt }],
      gaps: [], wireDigest: "d".repeat(64),
    });
    const jvm = batch.facts.find((fact) => fact.namespace === "jvm")!;
    const loadedClass = batch.facts.find((fact) => fact.namespace === "class")!;
    const evidenceId = "EV-00000000-0000-4000-8000-000000000020";
    store.putEvidence({ evidenceId, taskId: task.taskId, host: task.target.host, type: "jvm_class_bytecode", source: "probe", tool: "probe", sha256: "a".repeat(64), collectedAt: observedAt, metadata: { complete: true, epochId: epoch.epochId, subjectRef: jvm.subjectRef, className: classIdentity.className, classLoaderId: classIdentity.loaderId, captureMethod: "JVM_RETRANSFORM", range: { start: 0, length: 10, complete: true }, artifactSize: 10, artifactDigest: "a".repeat(64), integrityStatus: "VERIFIED" } });
    const assessment: Assessment = { assessmentId: "ASM-00000000-0000-4000-8000-000000000020", taskId: task.taskId, epochId: epoch.epochId, authorType: "MODEL", category: "java_memory_shell", subjectRef: loadedClass.subjectRef, scope: "SUBJECT", verdict: "CONFIRMED_MALICIOUS", severity: "CRITICAL", confidence: 0.95, rationale: "精确 ClassLoader 的运行态字节码证据", evidenceRefs: [evidenceId], factRefs: [jvm.factId, loadedClass.factId], queryRefs: [], createdAt: observedAt };
    expect(() => store.putAssessment(assessment)).not.toThrow();

    const otherIdentity = { ...classIdentity, loaderId: "loader-2" };
    const other = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "PROBE-DUMP-2", source: { kind: "MODEL", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint, requestId: "PROBE-DUMP-2", collector: { name: "probe", version: "3.0.0" }, observations: [{ namespace: "class", identity: otherIdentity, fields: otherIdentity, observedAt, consistency: "POINT_IN_TIME" }], edges: [], gaps: [], wireDigest: "e".repeat(64) }).facts[0]!;
    expect(() => store.putAssessment({ ...assessment, assessmentId: "ASM-00000000-0000-4000-8000-000000000021", subjectRef: other.subjectRef, factRefs: [jvm.factId, other.factId] })).toThrow(/实测关系验证/);
  });

  it("INV-15：规则按目标观察来源增量消费，不信任控制面或模型文本", async () => {
    const { store, task, epoch } = await v2Store();
    task.checks = ["backdoor_account"]; store.saveTask(task);
    const put = (runId: string, username: string, uid: number) => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: `${runId}:account-db`,
      source: { kind: "PRESET", presetRunId: runId, presetId: "account-baseline", presetVersion: "2.0.0", stepId: "account-db" },
      targetFingerprint: task.target.hostFingerprint, requestId: `${runId}:account-db`, collector: { name: "enumerate", version: "2.0.0" },
      observations: [{ namespace: "account", identity: { uid, username }, fields: { uid, username, gid: uid, home: `/home/${username}`, shell: "/bin/bash", locked: false }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: String(uid).padStart(64, "0"),
    }).facts[0]!;
    const current = put("PRESET-RUN-1", "current-admin", 0);
    put("PRESET-RUN-10", "other-admin", 0);

    const assessments = new DeterministicRuleEngineV2(store).evaluate(task.taskId, epoch.epochId, "PRESET-RUN-1");
    expect(assessments).toHaveLength(1);
    expect(assessments[0]?.factRefs).toEqual([current.factId]);

    const observed = (runId: string, username: string, evidenceOrigin: "TARGET_OBSERVATION" | "CONTROL_PLANE_INPUT") => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: runId,
      source: { kind: "MODEL", evidenceOrigin }, targetFingerprint: task.target.hostFingerprint,
      requestId: runId, collector: { name: "enumerate", version: "2.1.0" },
      observations: [{ namespace: "account", identity: { uid: 0, username }, fields: { uid: 0, username, gid: 0, home: `/home/${username}`, shell: "/bin/bash", locked: false }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: runId.padEnd(64, "0").slice(0, 64),
    }).facts[0]!;
    const remoteModelRequested = observed("MODEL-REMOTE", "remote-admin", "TARGET_OBSERVATION");
    const controlPlane = observed("MODEL-TEXT", "fabricated-admin", "CONTROL_PLANE_INPUT");
    const incremental = new DeterministicRuleEngineV2(store).evaluateFactRefs(task.taskId, epoch.epochId, [remoteModelRequested.factId, controlPlane.factId]);
    expect(incremental).toHaveLength(1);
    expect(incremental[0]?.factRefs).toEqual([remoteModelRequested.factId]);
    expect(new DeterministicRuleEngineV2(store).evaluateFactRefs(task.taskId, epoch.epochId, [remoteModelRequested.factId])).toHaveLength(0);
  });

  it("INV-25：稳定身份强化只追加 Fact，不生成新 ObjectRef", async () => {
    const { store, task, epoch } = await v2Store();
    const commit = (runId: string, fields: Record<string, unknown>) => store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: runId, source: { kind: "SYSTEM" }, targetFingerprint: task.target.hostFingerprint,
      requestId: runId, collector: { name: "project", version: "2.0.0" },
      observations: [{ namespace: "account", identity: { uid: 1001, username: "analyst" }, fields: { uid: 1001, username: "analyst", ...fields }, observedAt: new Date().toISOString(), consistency: "OBJECT_STABLE" }],
      edges: [], gaps: [], wireDigest: runId.padEnd(64, "0").slice(0, 64),
    });
    const first = commit("IDENTITY-1", { gid: 1001 });
    const second = commit("IDENTITY-2", { gid: 1001, home: "/home/analyst", shell: "/bin/bash", locked: false });
    expect(second.facts[0]?.subjectRef).toBe(first.facts[0]?.subjectRef);
    expect(store.listObjectReferences(task.taskId, epoch.epochId, "account")).toHaveLength(1);
    expect(store.listFacts(task.taskId, epoch.epochId).filter((fact) => fact.namespace === "account")).toHaveLength(2);
  });

  it("INV-27：CoverageGap 与 InvestigationGap 代码空间不相交", () => {
    expect(COVERAGE_GAP_CODES.filter((code) => (INVESTIGATION_GAP_CODES as readonly string[]).includes(code))).toEqual([]);
  });
});
