import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createModels } from "@earendil-works/pi-ai";
import { fauxProvider } from "@earendil-works/pi-ai/providers/faux";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeProtocolV2Executor } from "../../src/executor/fake-executor.js";
import { categoryGrantAllowsNamespace, gateCapabilities } from "../../src/protocol-v2/capability.js";
import type { HelperCapabilitiesV2, ScanEpoch, TaskGrant } from "../../src/protocol-v2/types.js";
import { Application } from "../../src/runtime/application.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createV2SecurityTools } from "../../src/tools/v2/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("v2 HUMAN Assessment 与 Grant 撤销", () => {
  it("人工裁定只追加账本关系，Grant 撤销后既持久化又立即阻断已有工具闭包", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-v2-human-grant-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const models = createModels(); const faux = fauxProvider({ tokensPerSecond: 0 }); models.setProvider(faux.provider);
    const application = new Application(testConfig(directory), store, models, faux.getModel());
    const task = application.createTask({ request: "复核 v2 人工裁定", mode: "SCAN", checks: ["webshell"], target: testTask().target });
    const epoch: ScanEpoch = { epochId: "EPOCH-00000000-0000-4000-8000-000000000099", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "2.0.0", helperVersion: "2.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() };
    store.createScanEpoch(epoch); task.activeEpochId = epoch.epochId; store.saveTask(task);
    const observedAt = new Date().toISOString();
    const facts = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "HUMAN-FACT", source: { kind: "SYSTEM" }, targetFingerprint: task.target.hostFingerprint, requestId: "HUMAN-FACT", collector: { name: "test", version: "2.0.0" }, observations: [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "99" }, fields: { mountId: "1", device: "1", inode: "99", path: "/srv/www/x.php", kind: "regular", size: 12, mode: 420, uid: 33, gid: 33, mtime: observedAt }, observedAt, consistency: "OBJECT_STABLE" }], edges: [], gaps: [], wireDigest: "9".repeat(64) });
    store.putAssessment({ assessmentId: "ASM-00000000-0000-4000-8000-000000000099", taskId: task.taskId, epochId: epoch.epochId, authorType: "RULE", category: "webshell", subjectRef: facts.facts[0]!.subjectRef, scope: "SUBJECT", verdict: "SUSPICIOUS", severity: "MEDIUM", confidence: 0.7, rationale: "规则命中", evidenceRefs: [], factRefs: [facts.facts[0]!.factId], queryRefs: [], createdAt: observedAt });

    const human = application.recordHumanAssessment({ taskId: task.taskId, targetAssessmentId: "ASM-00000000-0000-4000-8000-000000000099", verdict: "BENIGN", rationale: "分析师已核对部署记录" });
    expect(human).toMatchObject({ authorType: "HUMAN", verdict: "BENIGN", confidence: 1 });
    expect(store.listAssessments(task.taskId, epoch.epochId)).toHaveLength(2);
    expect(store.listAssessmentRelations(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ kind: "ADJUDICATES", fromAssessmentId: human.assessmentId, toAssessmentId: "ASM-00000000-0000-4000-8000-000000000099" })]);

    const grant: TaskGrant = { grantId: "GRANT-REVOKE", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "CATEGORY", status: "ACTIVE", binding: { category: "webshell" }, createdAt: observedAt };
    store.putTaskGrant(grant);
    const helper: HelperCapabilitiesV2 = { protocolVersion: 2, manifestVersion: "2.0.0", helper: { name: "helper", version: "2.0.0" }, namespaces: { file: { fields: ["path"], relations: [], verbs: ["enumerate"] }, account: { fields: ["uid"], relations: [], verbs: ["enumerate"] } }, matchers: [], probes: [], verbs: ["enumerate"], limits: { maxObjects: 10, maxOutputBytes: 4096, maxReadBytes: 1024, maxCollectBytes: 1024 } };
    const capabilities = gateCapabilities(helper, [grant]);
    expect(capabilities.namespaces.file).toBeDefined(); expect(capabilities.namespaces.account).toBeUndefined();
    const executor = new FakeProtocolV2Executor(helper, async () => { throw new Error("撤销后不应到达 helper"); });
    const tools = createV2SecurityTools({ task, epoch, config: testConfig(directory), store, executor, evidence: new EvidenceStore(directory, store), capabilities, approvals: new ApprovalService(store), budgetOwner: "MODEL" });
    const enumerate = tools.find((tool) => tool.name === "enumerate"); if (!enumerate) throw new Error("缺少 enumerate");

    application.revokeTaskGrant(task.taskId, grant.grantId, "调查范围已由分析师收回");
    expect(store.listTaskGrants(task.taskId)).toEqual(expect.arrayContaining([expect.objectContaining({ grantId: grant.grantId, status: "REVOKED", revocationReason: "调查范围已由分析师收回" })]));
    expect(categoryGrantAllowsNamespace(store.listTaskGrants(task.taskId), "file")).toBe(false);
    await expect(enumerate.execute("ENUM-AFTER-REVOKE", { namespace: "file", fields: ["path"], limit: 1 })).rejects.toThrow(/Category Grant 已失效或被撤销/);
    expect(executor.calls).toHaveLength(0);

    store.putGrantRequest({ requestId: "GRQ-DENY", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, kind: "SCOPE", status: "PENDING", bindingDigest: "d".repeat(64), binding: { namespace: "file", requestedRoot: "/srv/other" }, createdAt: observedAt });
    await application.decideGrantRequest("GRQ-DENY", false);
    expect(store.getGrantRequest("GRQ-DENY")?.status).toBe("DENIED");
    expect(store.listInvestigationGaps(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([expect.objectContaining({ code: "GRANT_DENIED", reasonCode: "SCOPE" })]));
    await application.close();
  });
});
