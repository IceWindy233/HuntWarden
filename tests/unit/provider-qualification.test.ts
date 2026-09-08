import { describe, expect, it } from "vitest";
import type { AuditEvent, Evidence, ReportRecord, TaskContext } from "../../src/domain/types.js";
import { classifyProviderEndpoint, evaluateProviderQualification, isPublicProviderAddress, type ProviderQualificationInput, type ProviderQualificationStore } from "../../src/evaluation/provider-qualification.js";
import type { CompletionSnapshot, DiscoveryCheckpoint, InvestigationAction, InvestigationActionAttempt, InvestigationSession } from "../../src/investigation/types.js";
import type { Assessment, ScanEpoch } from "../../src/protocol-v2/types.js";
import type { ToolRunRecord } from "../../src/storage/runtime-store.js";

const now = "2026-09-08T00:00:00.000Z";
const provider = "real-vendor";
const model = "tool-model";
const commit = "c".repeat(40);
const helperSha256 = "e".repeat(64);
const reportPath = fileURLToPath(import.meta.url);
const reportSha256 = createHash("sha256").update(readFileSync(reportPath)).digest("hex");

function task(taskId: string, checks: TaskContext["checks"]): TaskContext {
  return {
    taskId, request: "发布资格验收", target: { host: "redacted", port: 22, username: "operator", hostFingerprint: "SHA256:redacted", privateKeyPath: "/redacted", knownHostsPath: "/redacted" },
    mode: "SCAN", status: "COMPLETED", modelProvider: provider, modelId: model, promptVersion: "release-v1", checks,
    profile: "DEEP", timeWindowHours: 168, iocs: {}, focus: { categories: checks, entryMode: "ZERO_IOC", iocKinds: [], priority: "VOLATILE_FIRST" },
    createdAt: now, updatedAt: now, turnCount: 3, toolCallCount: 6, protocolVersion: 2, activeEpochId: `${taskId}-EPOCH`,
  };
}

function epoch(taskId: string): ScanEpoch {
  return { epochId: `${taskId}-EPOCH`, taskId, targetFingerprint: "SHA256:redacted", protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", controllerCommit: commit, controllerTreeClean: true, controllerCommitAtFinish: commit, controllerTreeCleanAtFinish: true, helperSha256, reason: "INITIAL", status: "COMPLETED", startedAt: now, finishedAt: now };
}

function session(taskId: string): InvestigationSession {
  return { sessionId: `${taskId}-SESSION`, taskId, epochId: `${taskId}-EPOCH`, engineVersion: "1.0.0", playbookRegistryDigest: "p", ruleRegistryDigest: "r", authorizationVersion: "AUTH-1", executionStatus: "STOPPED", investigationStatus: "CLOSED_WITH_FINDINGS", revision: 1, completionSnapshotRef: `${taskId}-SNAPSHOT`, createdAt: now, updatedAt: now };
}

function action(taskId: string): InvestigationAction {
  return { actionId: `${taskId}-ACTION`, taskId, epochId: `${taskId}-EPOCH`, kind: "REMOTE_PRIMITIVE", requestedBy: "MODEL", obligationIds: [`${taskId}-OBL`], subjectRefs: [], entityVersionRefs: [], operationRef: "enumerate", replayPolicy: "SAFE_REOBSERVE", args: { namespace: "process", limit: 10 }, argsDigest: "a", dependsOn: [], authorizationVersion: "AUTH-1", observationRound: "MODEL:HYP:1", idempotencyKey: `${taskId}-IDEMPOTENT`, priority: 50, status: "SUCCEEDED", revision: 2, resultRefs: [], createdAt: now, updatedAt: now };
}

function attempt(taskId: string): InvestigationActionAttempt {
  return { attemptId: `${taskId}-ATTEMPT`, actionId: `${taskId}-ACTION`, taskId, epochId: `${taskId}-EPOCH`, attempt: 1, toolCallId: `${taskId}-ATTEMPT`, status: "SUCCEEDED", startedAt: now, finishedAt: now };
}

function assessment(taskId: string, category: Assessment["category"], evidenceRefs: string[] = []): Assessment {
  return { assessmentId: `${taskId}-${category}-ASM`, taskId, epochId: `${taskId}-EPOCH`, authorType: "MODEL", category, scope: "OBSERVED_CATEGORY", verdict: "NO_OBSERVED_FINDING", severity: "INFO", confidence: 0.9, rationale: "模型完成复核", evidenceRefs, factRefs: [], queryRefs: [], createdAt: now };
}

function toolRuns(taskId: string): ToolRunRecord[] {
  const run = (toolName: string, args: unknown): ToolRunRecord => ({ toolCallId: `${taskId}-${toolName}`, taskId, epochId: `${taskId}-EPOCH`, toolName, risk: "LOCAL", replayPolicy: "SAFE", args, status: "SUCCEEDED", startedAt: now, finishedAt: now });
  return [run("propose_hypothesis", { subjectRef: "OBJ-00000000-0000-4000-8000-000000000001" }), run("propose_actions", { actions: ["enumerate"] }), run("enumerate", { namespace: "process", limit: 10 })];
}

function httpAudit(taskId: string): AuditEvent[] {
  return [{ eventId: `${taskId}-AUDIT`, taskId, event: "model_provider_http_attempt", level: "debug", data: { epochId: `${taskId}-EPOCH`, provider, model, attempt: 1, durationMs: 10, status: 200, retryable: false }, createdAt: now }];
}

function buildStore() {
  const linuxId = "TASK-LINUX";
  const javaId = "TASK-JAVA";
  const tasks = new Map([[linuxId, task(linuxId, ["linux_intrusion_triage", "linux_persistence"])], [javaId, task(javaId, ["java_memory_shell"])]]);
  const epochs = new Map([...tasks].map(([id]) => [id, epoch(id)]));
  const sessions = new Map([...tasks].map(([id]) => [id, session(id)]));
  const actions = new Map([...tasks].map(([id]) => [id, [action(id)]]));
  const attempts = new Map([...tasks].map(([id]) => [id, [attempt(id)]]));
  const javaEvidenceId = "EV-00000000-0000-4000-8000-000000000001";
  const assessments = new Map<string, Assessment[]>([
    [linuxId, [assessment(linuxId, "linux_intrusion_triage"), assessment(linuxId, "linux_persistence")]],
    [javaId, [assessment(javaId, "java_memory_shell", [javaEvidenceId])]],
  ]);
  const evidence = new Map<string, Evidence[]>([
    [linuxId, []],
    [javaId, [{ evidenceId: javaEvidenceId, taskId: javaId, host: "redacted", type: "jvm_class_bytecode", source: "probe", sha256: "a".repeat(64), collectedAt: now, tool: "probe", metadata: { epochId: `${javaId}-EPOCH`, complete: true, integrityStatus: "VERIFIED" } }]],
  ]);
  const runs = new Map([...tasks].map(([id]) => [id, toolRuns(id)]));
  const audits = new Map([...tasks].map(([id]) => [id, httpAudit(id)]));
  const reports = new Map([...tasks].map(([id]) => [id, [{ reportId: `${id}-REPORT`, taskId: id, epochId: `${id}-EPOCH`, version: 1, path: reportPath, sha256: reportSha256, generationMode: "MODEL", validationErrors: [], createdAt: now } satisfies ReportRecord]]));
  const checkpoints = new Map([...tasks].map(([id]) => [id, [{ checkpointId: `${id}-CHECKPOINT`, taskId: id, epochId: `${id}-EPOCH`, namespace: "process", requestDigest: "digest", status: "COMPLETE", scannedCount: 10, matchedCount: 0, returnedCount: 10, createdAt: now, updatedAt: now } satisfies DiscoveryCheckpoint]]));
  const store: ProviderQualificationStore = {
    getTask: (id) => tasks.get(id),
    getScanEpoch: (id) => epochs.get(id),
    getInvestigationSession: (id) => sessions.get(id),
    getCompletionSnapshot: (id) => ({ snapshotRef: `${id}-SNAPSHOT`, taskId: id, epochId: `${id}-EPOCH`, investigationStatus: "CLOSED_WITH_FINDINGS", maxEventSeq: 1, openRequiredObligationIds: [], runningActionIds: [], limitedObligationIds: [], findingAssessmentIds: [], createdAt: now } satisfies CompletionSnapshot),
    listInvestigationActions: (id) => actions.get(id) ?? [],
    listInvestigationActionAttempts: (id) => attempts.get(id) ?? [],
    listDiscoveryCheckpoints: (id) => checkpoints.get(id) ?? [],
    listAssessments: (id) => assessments.get(id) ?? [],
    listEvidence: (id) => evidence.get(id) ?? [],
    listToolRuns: (id) => runs.get(id) ?? [],
    listAudit: (id) => audits.get(id) ?? [],
    listReports: (id) => reports.get(id) ?? [],
  };
  return { store, linuxId, javaId, evidence, runs, audits };
}

function input(): ProviderQualificationInput & ReturnType<typeof buildStore> {
  const fixture = buildStore();
  return {
    ...fixture,
    linuxTaskId: fixture.linuxId,
    javaTaskId: fixture.javaId,
    commit, manifestVersion: "3.0.0", provider, model, protocol: "openai-responses", endpoint: "https://api.vendor.example/v1",
    endpointResolution: { before: ["203.0.114.10"], after: ["203.0.114.10"] }, expectedHelperSha256: helperSha256,
    smoke: { toolCallVerified: true, usage: { input: 12, output: 3 } },
    faultContract: { sha256: "f".repeat(64), value: { schemaVersion: 1, status: "PASS", evaluationKind: "PROTOCOL_FIXTURE", endpointClass: "LOOPBACK", commit: "c".repeat(40), manifestVersion: "3.0.0", protocols: [{ protocol: "openai-completions", toolCallVerified: true, usage: { input: 1, output: 1 } }, { protocol: "openai-responses", toolCallVerified: true, usage: { input: 1, output: 1 } }], faults: { retry: { attempts: [{ status: 429 }, { status: 200 }] }, stall: { stopReason: "aborted", httpStatus: 200, runtimeClassification: "PROVIDER_FAILURE" }, empty: { rejected: true } } } },
  };
}

describe("真实 Provider 发布资格生成器", () => {
  it("从两个完整 RuntimeStore 任务和故障契约计算 PASS", () => {
    const value = input();
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("PASS");
    expect(result.failures).toEqual([]);
    expect(result.tasks.javaRuntime.javaEvidenceReferencedByModel).toBe(1);
    expect(result.faultContract.retryStatuses).toEqual([429, 200]);
  });

  it("远端端点、重复执行或 Java Evidence 未引用时失败关闭", () => {
    const value = input();
    value.endpoint = "http://127.0.0.1:8080/v1";
    value.runs.get(value.linuxId)!.push({ ...value.runs.get(value.linuxId)!.at(-1)!, toolCallId: "duplicate" });
    value.evidence.set(value.javaId, []);
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("FAIL");
    expect(result.failures).toEqual(expect.arrayContaining([
      expect.stringContaining("HTTPS 远端厂商端点"),
      expect.stringContaining("重复成功执行"),
      expect.stringContaining("类字节码 Evidence"),
    ]));
  });

  it("拒绝把旧 Epoch 的报告复用于当前发布资格", () => {
    const value = input();
    value.store.listReports = (taskId) => [{
      reportId: `${taskId}-STALE-REPORT`, taskId, epochId: `${taskId}-OLD-EPOCH`, version: 1,
      path: reportPath, sha256: reportSha256, generationMode: "MODEL", validationErrors: [], createdAt: now,
    }];
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("FAIL");
    expect(result.failures).toEqual(expect.arrayContaining([expect.stringContaining("绑定当前 Epoch")]));
  });

  it("拒绝数据库摘要与实际报告文件不一致的资格证据", () => {
    const value = input();
    value.store.listReports = (taskId) => [{
      reportId: `${taskId}-TAMPERED-REPORT`, taskId, epochId: `${taskId}-EPOCH`, version: 1,
      path: reportPath, sha256: "b".repeat(64), generationMode: "MODEL", validationErrors: [], createdAt: now,
    }];
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("FAIL");
    expect(result.failures).toEqual(expect.arrayContaining([expect.stringContaining("文件摘要一致")]));
  });

  it("接受最终投影已校验且摘要一致的确定性回退报告", () => {
    const value = input();
    value.store.listReports = (taskId) => [{
      reportId: `${taskId}-FALLBACK-REPORT`, taskId, epochId: `${taskId}-EPOCH`, version: 1,
      path: reportPath, sha256: reportSha256, generationMode: "FALLBACK",
      validationErrors: ["模型初稿缺少字段，已使用确定性模板"], createdAt: now,
    }];
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("PASS");
    expect(result.failures).toEqual([]);
  });

  it("拒绝把旧 Epoch 的 Provider 审计和 ToolRun 计入当前任务", () => {
    const value = input();
    for (const taskId of [value.linuxId, value.javaId]) {
      value.audits.set(taskId, value.audits.get(taskId)!.map((event) => ({ ...event, data: { ...event.data, epochId: `${taskId}-OLD-EPOCH` } })));
      value.runs.set(taskId, value.runs.get(taskId)!.map((run) => ({ ...run, epochId: `${taskId}-OLD-EPOCH` })));
    }
    const result = evaluateProviderQualification(value);
    expect(result.status).toBe("FAIL");
    expect(result.failures).toEqual(expect.arrayContaining([
      expect.stringContaining("当前 Epoch 未实际调用 propose_hypothesis"),
      expect.stringContaining("成功 HTTP 尝试审计"),
    ]));
  });

  it("只把公开 HTTPS 域名归类为发布端点", () => {
    expect(classifyProviderEndpoint("https://api.example.com/v1")).toBe("REMOTE_VENDOR");
    expect(classifyProviderEndpoint("https://172.20.1.2/v1")).toBe("NON_RELEASE_ENDPOINT");
    expect(classifyProviderEndpoint("https://[fd00::1]/v1")).toBe("NON_RELEASE_ENDPOINT");
    expect(classifyProviderEndpoint("http://api.example.com/v1")).toBe("NON_RELEASE_ENDPOINT");
    expect(classifyProviderEndpoint("https://api.example.com/v1", ["10.0.0.1"])).toBe("NON_RELEASE_ENDPOINT");
    expect(isPublicProviderAddress("8.8.8.8")).toBe(true);
    expect(isPublicProviderAddress("100.64.0.1")).toBe(false);
    expect(isPublicProviderAddress("::ffff:10.0.0.1")).toBe(false);
    expect(isPublicProviderAddress("2606:4700:4700::1111")).toBe(true);
  });
});
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
