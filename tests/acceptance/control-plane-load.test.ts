import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { TargetConfig } from "../../src/domain/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import type { WireCost } from "../../src/protocol-v2/types.js";
import { bootstrapProtocolV2 } from "../../src/runtime/v2-bootstrap.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testConfig, testTask } from "../helpers.js";

const enabled = process.env.HUNTWARDEN_CONTROL_LOAD_TESTS === "1";
const stateDir = resolve("acceptance/load/.state");

function costIsZero(cost: WireCost): boolean {
  return cost.remoteCalls === 0 && cost.nodes === 0 && cost.bytes === 0 && cost.wallTimeMs === 0 && (cost.probeCalls ?? 0) === 0;
}

describe.skipIf(!enabled)("真实 Helper 控制端规模调查", () => {
  let executor: SSHExecutor;
  let target: TargetConfig;
  beforeAll(async () => {
    const knownHostsPath = resolve(stateDir, "known_hosts");
    const knownHosts = await readFile(knownHostsPath, "utf8");
    const fingerprint = knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2300/)?.[1];
    if (!fingerprint) throw new Error("负载 known_hosts 缺少 2300 指纹");
    target = {
      host: "127.0.0.1", port: 2300, username: "secagent", hostFingerprint: fingerprint,
      privateKeyPath: resolve(stateDir, "operator_ed25519"), knownHostsPath,
    };
    executor = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 120_000);
  });
  afterAll(async () => await executor?.close());

  it("首屏异常进程先保全，并耗尽 1千/1万进程分页后记录资源与预算", async () => {
    const processCount = Number(process.env.HUNTWARDEN_LOAD_PROCESS_COUNT ?? "1000");
    if (!Number.isInteger(processCount) || processCount < 1 || processCount > 10_000) throw new Error("HUNTWARDEN_LOAD_PROCESS_COUNT 无效");
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-control-load-"));
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("SCAN");
    task.taskId = `TASK-CONTROL-LOAD-${processCount}`;
    task.protocolVersion = 2;
    task.target = target;
    task.checks = ["linux_intrusion_triage"];
    task.profile = "DEEP";
    store.createTask(task);
    const config = testConfig(directory);
    const generous = { remoteCalls: 1_000, nodes: 500_000, bytes: 768 * 1024 * 1024, wallTimeMs: 7_200_000, probeCalls: 0 };
    config.protocolV2.remoteBudget.preset = generous;
    config.protocolV2.remoteBudget.model = generous;
    config.protocolV2.dataPolicy.evidenceBytes = 512 * 1024 * 1024;

    const started = performance.now();
    const initialCpu = process.cpuUsage();
    let firstLeadMs: number | undefined;
    let firstEvidenceMs: number | undefined;
    const samples: Array<{ elapsedMs: number; rssBytes: number; heapUsedBytes: number }> = [];
    const sample = () => {
      const memory = process.memoryUsage();
      const elapsedMs = Math.round(performance.now() - started);
      samples.push({ elapsedMs, rssBytes: memory.rss, heapUsedBytes: memory.heapUsed });
      const epochId = store.getTask(task.taskId)?.activeEpochId;
      if (!epochId) return;
      if (firstLeadMs === undefined && store.listInvestigationLeads(task.taskId, epochId).length > 0) firstLeadMs = elapsedMs;
      if (firstEvidenceMs === undefined && store.listEvidence(task.taskId).length > 0) firstEvidenceMs = elapsedMs;
    };
    sample();
    const timer = setInterval(sample, 50);
    try {
      const result = await bootstrapProtocolV2({
        task, config, store, executor, evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store),
      });
      sample();
      const elapsedMs = Math.round(performance.now() - started);
      const cpu = process.cpuUsage(initialCpu);
      const facts = store.listFacts(task.taskId, result.epoch.epochId);
      const fixtureProcesses = facts.filter((fact) => fact.namespace === "process" && fact.privatePayload.exe === "/usr/local/bin/huntwarden-process-fixture");
      const uniqueFixtureSubjects = new Set(fixtureProcesses.map((fact) => fact.subjectRef));
      const beacon = facts.find((fact) => fact.namespace === "process" && fact.privatePayload.exe === "/var/tmp/.huntwarden-load-beacon");
      if (!beacon) throw new Error("控制端未发现首屏异常进程");
      const evidence = store.listEvidence(task.taskId).find((item) => item.metadata?.subjectRef === beacon.subjectRef);
      const actions = store.listInvestigationActions(task.taskId, result.epoch.epochId);
      const activeActions = actions.filter((action) => ["READY", "RUNNING"].includes(action.status));
      const events = store.listInvestigationEvents(task.taskId, result.epoch.epochId, 0, 5_000);
      const firstCollect = events.find((event) => event.eventType === "ACTION_CREATED" && event.payload.operationRef === "collect");
      const beaconBatch = events.find((event) => event.eventType === "FACT_BATCH_COMMITTED"
        && Array.isArray(event.payload.factRefs) && event.payload.factRefs.includes(beacon.factId));
      const processPageFacts = facts.filter((fact) => fact.namespace === "process" && fact.source.kind === "PRESET" && fact.source.stepId === "process-snapshot");
      const lastProcessPageRun = processPageFacts.toSorted((left, right) => left.factSeq - right.factSeq).at(-1)?.sourceRunId;
      const lastProcessPageBatch = events.find((event) => event.eventType === "FACT_BATCH_COMMITTED" && event.payload.sourceRunId === lastProcessPageRun);
      const budgets = (["PRESET", "DISCOVERY", "MODEL"] as const).map((owner) => store.getBudgetAccount(task.taskId, result.epoch.epochId, owner));
      const completion = new InvestigationCompletionValidator(store).evaluate(task.taskId, result.epoch.epochId);

      expect(uniqueFixtureSubjects.size).toBe(processCount + 1);
      expect(evidence?.metadata).toMatchObject({ complete: true, integrityStatus: "VERIFIED" });
      expect(firstLeadMs).toBeDefined(); expect(firstEvidenceMs).toBeDefined();
      expect(firstCollect).toBeDefined(); expect(beaconBatch).toBeDefined(); expect(lastProcessPageBatch).toBeDefined();
      expect(firstCollect!.eventSeq).toBeLessThan(lastProcessPageBatch!.eventSeq);
      expect(Date.parse(evidence!.collectedAt) - Date.parse(beaconBatch!.createdAt)).toBeGreaterThanOrEqual(0);
      expect(activeActions).toEqual([]);
      expect(budgets.every((budget) => budget && costIsZero(budget.reserved))).toBe(true);

      const report = {
        status: "PASS",
        environment: { target: "ubuntu:22.04 Docker over SSH", architecture: process.arch, processFixtureCount: processCount },
        latencyMs: {
          firstLead: firstLeadMs,
          firstEvidence: firstEvidenceMs,
          observationCommitToEvidence: Date.parse(evidence!.collectedAt) - Date.parse(beaconBatch!.createdAt),
          bootstrapComplete: elapsedMs,
        },
        counts: {
          processFacts: facts.filter((fact) => fact.namespace === "process").length,
          uniqueFixtureProcesses: uniqueFixtureSubjects.size,
          leads: store.listInvestigationLeads(task.taskId, result.epoch.epochId).length,
          evidence: store.listEvidence(task.taskId).length,
          actions: actions.length,
          attempts: store.listInvestigationActionAttempts(task.taskId, result.epoch.epochId).length,
        },
        ordering: { firstCollectEventSeq: firstCollect!.eventSeq, lastProcessPageEventSeq: lastProcessPageBatch!.eventSeq },
        controllerResources: {
          sampleCount: samples.length,
          maxSampledRssBytes: Math.max(...samples.map((item) => item.rssBytes)),
          maxSampledHeapUsedBytes: Math.max(...samples.map((item) => item.heapUsedBytes)),
          cpuUserMicros: cpu.user,
          cpuSystemMicros: cpu.system,
          samples,
        },
        budgets,
        completion: { canClose: completion.canClose, investigationStatus: completion.status, reasons: completion.reasons },
      };
      const output = process.env.HUNTWARDEN_LOAD_CONTROL_RESULT;
      if (output) await writeFile(resolve(output), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    } finally {
      clearInterval(timer);
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }, 900_000);
});
