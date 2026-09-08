import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DerivedObjectResolver } from "../../src/investigation/derived-object-resolver.js";
import type { AuthorizationEnvelope } from "../../src/investigation/types.js";
import type { ScanEpoch } from "../../src/protocol-v2/types.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("白名单派生对象解析器", () => {
  it("只从当前 Epoch 的来源 Fact 与已授权关系解析对象并记录 DERIVED 谱系", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-derived-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = { ...testTask(), protocolVersion: 2 as const };
    store.createTask(task);
    const epoch: ScanEpoch = { epochId: "EPOCH-DERIVED", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: "2026-01-01T00:00:00.000Z" };
    store.createScanEpoch(epoch);
    const batch = store.commitFactBatch({
      taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN-DERIVED", source: { kind: "SYSTEM", evidenceOrigin: "TARGET_OBSERVATION" }, targetFingerprint: task.target.hostFingerprint,
      requestId: "REQ-DERIVED", collector: { name: "test", version: "1" }, gaps: [], edges: [], wireDigest: "a".repeat(64),
      observations: [
        { namespace: "process", identity: { bootId: "boot", pid: 42, startTicks: "100" }, fields: { bootId: "boot", pid: 42, startTicks: "100", ppid: 1 }, observedAt: "2026-01-01T00:00:01.000Z", consistency: "CURSOR_BEST_EFFORT" },
        { namespace: "socket", identity: { protocol: "tcp", localAddress: "127.0.0.1", localPort: 1234, remoteAddress: "203.0.113.1", remotePort: 443, inode: "9" }, fields: { protocol: "tcp", localAddress: "127.0.0.1", localPort: 1234, remoteAddress: "203.0.113.1", remotePort: 443, inode: "9", pid: 42 }, observedAt: "2026-01-01T00:00:02.000Z", consistency: "CURSOR_BEST_EFFORT" },
      ],
    });
    const socket = batch.facts.find((fact) => fact.namespace === "socket")!;
    const process = batch.facts.find((fact) => fact.namespace === "process")!;
    const authorization: AuthorizationEnvelope = { version: "AUTH", targetFingerprint: task.target.hostFingerprint, namespaces: ["socket", "process"], scopeRefs: [], derivedRelations: ["owned_by"], sensitiveRead: false, collectEvidence: true, probes: [], budget: { remoteCalls: 1, nodes: 1, bytes: 1, wallTimeMs: 1 } };
    const result = new DerivedObjectResolver(store).resolve({ requestId: "DERIVE-1", taskId: task.taskId, epochId: epoch.epochId, resolverRef: "socket.owner_by_pid@1.0.0", sourceFactRef: socket.factId }, authorization);
    expect(result).toMatchObject({ status: "RESOLVED", objectRefs: [process.subjectRef] });
    expect(store.listEdges(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ relation: "owned_by", fromRef: socket.subjectRef, toRef: process.subjectRef })]);
    expect(store.listRelationProvenance(task.taskId, epoch.epochId)).toEqual([expect.objectContaining({ derivation: "DERIVED", sourceRefs: expect.arrayContaining([socket.factId, process.factId]), resolverVersion: "socket.owner_by_pid@1.0.0", timeErrorMs: 1000 })]);
    store.close();
  });

  it("未授权关系被拒绝，来源文本不能作为路径或对象自授权", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-derived-denied-")); directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = { ...testTask(), protocolVersion: 2 as const }; store.createTask(task);
    const epoch: ScanEpoch = { epochId: "EPOCH-DERIVED-DENY", taskId: task.taskId, targetFingerprint: task.target.hostFingerprint, protocolVersion: 2, manifestVersion: "3.0.0", helperVersion: "3.0.0", reason: "INITIAL", status: "RUNNING", startedAt: new Date().toISOString() }; store.createScanEpoch(epoch);
    const batch = store.commitFactBatch({ taskId: task.taskId, epochId: epoch.epochId, sourceRunId: "RUN", source: { kind: "SYSTEM" }, targetFingerprint: task.target.hostFingerprint, requestId: "REQ", collector: { name: "test", version: "1" }, gaps: [], edges: [], wireDigest: "b".repeat(64), observations: [{ namespace: "socket", identity: { protocol: "tcp", localAddress: "x", localPort: 1, remoteAddress: "y", remotePort: 2, inode: "1" }, fields: { protocol: "tcp", localAddress: "x", localPort: 1, remoteAddress: "y", remotePort: 2, inode: "1", pid: 42 }, observedAt: new Date().toISOString(), consistency: "CURSOR_BEST_EFFORT" }] });
    const authorization: AuthorizationEnvelope = { version: "AUTH", targetFingerprint: task.target.hostFingerprint, namespaces: ["socket", "process"], scopeRefs: [], derivedRelations: [], sensitiveRead: false, collectEvidence: false, probes: [], budget: { remoteCalls: 0, nodes: 0, bytes: 0, wallTimeMs: 0 } };
    expect(() => new DerivedObjectResolver(store).resolve({ requestId: "DERIVE-DENY", taskId: task.taskId, epochId: epoch.epochId, resolverRef: "socket.owner_by_pid@1.0.0", sourceFactRef: batch.facts[0]!.factId }, authorization)).toThrow(/不在当前授权包络/);
    expect(store.listEdges(task.taskId, epoch.epochId)).toEqual([]);
    store.close();
  });
});
