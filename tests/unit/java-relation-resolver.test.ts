import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import { JavaRelationResolver } from "../../src/investigation/java-relation-resolver.js";
import type { InvestigationSession } from "../../src/investigation/types.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const stores: RuntimeStore[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("Java 精确关系解析器", () => {
  it("仅在 JVM、类名与 ClassLoader 都一致时关联组件，并绑定精确代码来源文件", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-java-relations-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db"); stores.push(store);
    const task = testTask(); task.protocolVersion = 2; task.checks = ["java_memory_shell"]; store.createTask(task);
    const epoch: ScanEpoch = { epochId: "EPOCH-JAVA-RELATIONS", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() };
    store.createScanEpoch(epoch); task.activeEpochId = epoch.epochId; store.saveTask(task);
    const observedAt = new Date().toISOString();
    const jvm = { bootId: "boot", pid: 42, startTicks: "100" };
    const component = { jvmDigest: "a".repeat(64), context: "/app", componentKind: "filter", name: "Marker", className: "lab.Marker", classLoaderId: "loader-A" };
    const exactClass = { jvmDigest: "a".repeat(64), className: "lab.Marker", loaderId: "loader-A" };
    const otherClass = { jvmDigest: "a".repeat(64), className: "lab.Marker", loaderId: "loader-B" };
    const source = { mountId: "1", device: "1", inode: "900" };
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "PROBE-JAVA", source: { kind: "SYSTEM", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint, requestId: "PROBE-JAVA", collector: { name: "probe", version: "3.0.0" },
      observations: [
        { namespace: "jvm", identity: jvm, fields: { ...jvm, attachSupported: true }, observedAt, consistency: "POINT_IN_TIME" },
        { namespace: "java_component", identity: component, fields: component, observedAt, consistency: "POINT_IN_TIME" },
        { namespace: "class", identity: exactClass, fields: { ...exactClass, codeSource: "file:/opt/app/marker.jar", modifiable: true }, observedAt, consistency: "POINT_IN_TIME" },
        { namespace: "class", identity: otherClass, fields: { ...otherClass, codeSource: "file:/opt/app/other.jar", modifiable: true }, observedAt, consistency: "POINT_IN_TIME" },
        { namespace: "file", identity: source, fields: { ...source, path: "/opt/app/marker.jar", kind: "regular", size: 10, mtime: observedAt, contentClass: "SENSITIVE_TEXT" }, observedAt, consistency: "OBJECT_STABLE" },
      ],
      edges: [
        { relation: "hosts_component", fromIdentity: { namespace: "jvm", identity: jvm }, toIdentity: { namespace: "java_component", identity: component }, observedAt },
        { relation: "loads_class", fromIdentity: { namespace: "jvm", identity: jvm }, toIdentity: { namespace: "class", identity: exactClass }, observedAt },
        { relation: "loads_class", fromIdentity: { namespace: "jvm", identity: jvm }, toIdentity: { namespace: "class", identity: otherClass }, observedAt },
      ], gaps: [], wireDigest: "b".repeat(64),
    });

    const resolver = new JavaRelationResolver(store);
    expect(resolver.resolve(task.taskId, epoch.epochId)).toHaveLength(2);
    expect(resolver.resolve(task.taskId, epoch.epochId)).toEqual([]);
    const refs = new Map(batch.facts.map((fact) => [fact.namespace === "class" ? `${fact.namespace}:${fact.privatePayload.loaderId}` : fact.namespace, fact.subjectRef]));
    expect(store.listEdges(task.taskId, epoch.epochId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ relation: "implemented_by", fromRef: refs.get("java_component"), toRef: refs.get("class:loader-A") }),
      expect.objectContaining({ relation: "defined_in", fromRef: refs.get("class:loader-A"), toRef: refs.get("file") }),
    ]));
    const derived = store.listRelationProvenance(task.taskId, epoch.epochId).filter((item) => item.derivation === "DERIVED");
    expect(derived).toHaveLength(2);
    expect(derived.every((item) => item.sourceRefs.length === 2 && item.resolverVersion === "java-runtime-relations@1.0.0")).toBe(true);

    const session: InvestigationSession = { sessionId: "ISESS-JAVA", taskId: task.taskId, epochId: epoch.epochId, engineVersion: "1.0.0", playbookRegistryDigest: "a".repeat(64), ruleRegistryDigest: "b".repeat(64), authorizationVersion: "AUTH-JAVA", executionStatus: "RUNNING", investigationStatus: "OPEN", revision: 0, createdAt: observedAt, updatedAt: observedAt };
    store.createInvestigationSession(session);
    store.putCoverageRun({ coverageId: "COV-JAVA", taskId: task.taskId, epochId: epoch.epochId, category: "java_memory_shell", presetId: "java-memory-baseline", presetVersion: "2.2.0", status: "COMPLETE", applicability: "APPLICABLE", completedCriteria: ["exact_class"], missingCriteria: [], createdAt: observedAt });
    const evidenceId = "EV-JAVA-BYTECODE";
    store.putEvidence({ evidenceId, taskId: task.taskId, host: task.target.host, type: "jvm_class_bytecode", source: "lab.Marker", sha256: "c".repeat(64), tool: "probe", collectedAt: observedAt, metadata: { epochId: epoch.epochId, subjectRef: refs.get("jvm"), artifactSubjectRef: refs.get("class:loader-A"), complete: true, integrityStatus: "VERIFIED", range: { start: 0, length: 1, complete: true }, artifactSize: 1, artifactDigest: "c".repeat(64) } });
    store.putInvestigationObligation({ obligationId: "OBL-JAVA-BYTECODE", taskId: task.taskId, epochId: epoch.epochId, obligationKind: "JAVA_PRESERVE_BYTECODE", dedupeKey: "JAVA_PRESERVE_BYTECODE:component", subjectRefs: [refs.get("java_component")!], required: true, status: "SATISFIED", resultRefs: [evidenceId], gapRefs: [], createdAt: observedAt, updatedAt: observedAt });
    expect(new InvestigationCompletionValidator(store).freeze(task.taskId, epoch.epochId).investigationStatus).toBe("CLOSED_NO_OBSERVED_FINDING");
  });
});
