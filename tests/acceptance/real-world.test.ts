import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { TargetConfig } from "../../src/domain/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import { bootstrapProtocolV2 } from "../../src/runtime/v2-bootstrap.js";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { DockerV2Remote } from "../docker/v2-remote.js";
import { testConfig, testTask } from "../helpers.js";

const enabled = process.env.HUNTWARDEN_REAL_WORLD_TESTS === "1";
const run = promisify(execFile);
const stateDir = resolve("acceptance/real-world/.state");
const container = "huntwarden-real-world-target";

interface ScenarioManifest { scenarioId: string; account: string; webRoot: string; webPath: string; artifactPath: string; artifactSha256: string; beaconPath: string; deletedPath: string; cronPath: string; deletedPid: number }

describe.skipIf(!enabled)("Debian 12 动态真实攻击链 v2 验收", () => {
  let remote: SSHExecutor; let client: DockerV2Remote; let manifest: ScenarioManifest; let target: TargetConfig;
  beforeAll(async () => {
    const knownHostsPath = resolve(stateDir, "known_hosts"); const knownHosts = await readFile(knownHostsPath, "utf8");
    const fingerprint = knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2299/)?.[1]; if (!fingerprint) throw new Error("真实场景 known_hosts 缺少 2299 指纹");
    target = { host: "127.0.0.1", port: 2299, username: "secagent", hostFingerprint: fingerprint, privateKeyPath: resolve(stateDir, "operator_ed25519"), knownHostsPath };
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 60_000); client = new DockerV2Remote(remote);
    const output = await run("docker", ["exec", container, "python3", "-c", "import json; print(json.dumps(json.load(open('/run/huntwarden-acceptance.json'))))"], { timeout: 10_000 });
    manifest = JSON.parse(output.stdout) as ScenarioManifest;
  });
  afterAll(async () => await remote?.close());

  it("在官方 Debian 目标完成 v2 Capability 与主机事实协商", async () => {
    const capabilities = await remote.getCapabilitiesV2();
    expect(capabilities).toMatchObject({ protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "huntwarden-helper-v2" } });
    expect(Object.keys(capabilities.namespaces)).toEqual(expect.arrayContaining(["web_root", "process", "account", "cron_entry", "auth_event", "exec_event"]));
    const hosts = await client.enumerate("host", ["hostname", "os", "distribution", "distributionVersion", "release", "architecture", "timezone", "initSystem", "selinuxMode"]);
    expect(hosts[0]?.fields).toMatchObject({ os: "Linux", distribution: "debian", architecture: expect.any(String), timezone: expect.any(String), initSystem: expect.any(String), selinuxMode: expect.any(String) });
  });

  it("关联动态 Web 落地文件、版本化 YARA 与 Evidence artifact", async () => {
    const roots = await client.enumerate("web_root", ["path", "server", "effective"]);
    expect(roots.some((item) => item.fields.path === manifest.webRoot)).toBe(true);
    const files = await client.enumerate("file", ["path", "size", "mtime", "contentClass"], { scope: { namespace: "file", canonicalRoot: manifest.webRoot }, predicate: { op: "eq", field: "path", value: manifest.webPath } });
    const candidate = files[0]; if (!candidate) throw new Error("动态 Web 文件未进入 v2 file namespace");
    const binding = { namespace: "file", identity: candidate.identity, locator: { path: manifest.webPath } };
    const literal = await client.invoke("match", { objects: [binding], matcher: { engine: "literal", pattern: "system(" }, maxHits: 20, includeContext: false });
    expect(literal.objects.length).toBeGreaterThan(0);
    if ((await remote.getCapabilitiesV2()).matchers.includes("yara")) {
      const yara = await client.invoke("match", { objects: [binding], matcher: { engine: "yara", ruleSetRef: "RULESET-WEBSHELL-BUILTIN-2" }, maxHits: 20, includeContext: false });
      expect(String(yara.objects[0]?.fields.content)).toContain("YARA_MATCH:");
    }
    const collected = await client.invoke("collect", { ...binding, maxBytes: 10 * 1024 * 1024, purpose: "REAL_WORLD_WEB" }, { remoteCalls: 1, nodes: 1, bytes: 10 * 1024 * 1024, wallTimeMs: 60_000, probeCalls: 0 });
    expect(collected.artifact?.complete).toBe(true); await client.maintenance("artifact_release", { artifactToken: collected.artifact!.token });
  }, 180_000);

  it("以固定分块流式传输 100 MiB Evidence，并核对端到端摘要", async () => {
    const files = await client.enumerate("file", ["path", "size"], {
      scope: { namespace: "file", canonicalRoot: manifest.webRoot }, predicate: { op: "eq", field: "path", value: manifest.artifactPath },
    });
    const artifactFile = files[0]; if (!artifactFile) throw new Error("负载 Artifact 未进入 v2 file namespace");
    expect(artifactFile.fields.size).toBe(100 * 1024 * 1024);
    const collected = await client.invoke("collect", {
      namespace: "file", identity: artifactFile.identity, locator: { path: manifest.artifactPath }, maxBytes: 100 * 1024 * 1024, purpose: "ACCEPTANCE_100_MIB_STREAM",
    }, { remoteCalls: 1, nodes: 1, bytes: 100 * 1024 * 1024, wallTimeMs: 60_000, probeCalls: 0 });
    expect(collected.artifact).toMatchObject({ size: 100 * 1024 * 1024, sha256: manifest.artifactSha256, complete: true });
    let chunks = 0; let bytes = 0;
    const transferred = await remote.downloadArtifact({ artifactToken: collected.artifact!.token, sha256: collected.artifact!.sha256, size: collected.artifact!.size, expiresAt: collected.artifact!.expiresAt }, (chunk) => {
      chunks += 1; bytes += chunk.length;
    }, undefined, 120_000);
    expect(transferred).toEqual({ size: 100 * 1024 * 1024, sha256: manifest.artifactSha256 });
    expect(bytes).toBe(100 * 1024 * 1024);
    expect(chunks).toBe(400);
  }, 180_000);

  it("账户、SSH trust 与 Cron 通过独立 namespace 关联且不泄露公钥", async () => {
    const accounts = await client.enumerate("account", ["uid", "username", "gid", "home", "shell", "groups", "locked"]);
    expect(accounts.some((item) => item.fields.username === manifest.account && item.fields.uid === 0)).toBe(true);
    const keys = await client.enumerate("ssh_key", ["fingerprint", "ownerUid", "type", "comment", "sourceFile"]);
    expect(keys.some((item) => typeof item.fields.fingerprint === "string")).toBe(true); expect(JSON.stringify(keys)).not.toContain("ssh-ed25519 AAAA");
    const cron = await client.enumerate("cron_entry", ["source", "schedule", "user", "command"]);
    expect(cron.some((item) => item.fields.source === manifest.cronPath && String(item.fields.command).includes(manifest.beaconPath))).toBe(true);
  }, 180_000);

  it("删除后运行与隐藏 Beacon 可由 process identity、relate、collect 复核", async () => {
    const processes = await client.enumerate("process", ["pid", "ppid", "uid", "comm", "exe", "exeInode", "exeSha256", "command", "state"]);
    const deleted = processes.find((item) => item.fields.pid === manifest.deletedPid && item.fields.exe === manifest.deletedPath); if (!deleted) throw new Error("缺少删除后运行进程");
    const beacon = processes.find((item) => String(item.fields.command).includes(manifest.beaconPath)); if (!beacon) throw new Error("缺少 Beacon 进程");
    const connections = await client.invoke("relate", { namespace: "process", identity: beacon.identity, locator: { exeInode: beacon.fields.exeInode, exeSha256: beacon.fields.exeSha256 }, relation: "connects", limit: 500 });
    expect(connections.objects.some((item) => item.fields.remotePort === 18771 && item.fields.state === "ESTABLISHED")).toBe(true);
    const collected = await client.invoke("collect", { namespace: "process", identity: deleted.identity, locator: { exeInode: deleted.fields.exeInode, exeSha256: deleted.fields.exeSha256 }, maxBytes: 10 * 1024 * 1024, purpose: "DELETED_EXECUTABLE" }, { remoteCalls: 1, nodes: 1, bytes: 10 * 1024 * 1024, wallTimeMs: 60_000, probeCalls: 0 });
    expect(collected.artifact?.sha256).toBe(deleted.fields.exeSha256); await client.maintenance("artifact_release", { artifactToken: collected.artifact!.token });
  }, 180_000);

  it("正式 v2 Preset + RULE Assessment 在动态目标上形成 Coverage 与规则账本", async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-real-world-v2-"));
    const store = await RuntimeStore.open(directory, "runtime.db");
    try {
      const task = testTask("SCAN"); task.protocolVersion = 2; task.target = target; task.checks = ["webshell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"]; store.createTask(task);
      const config = testConfig(directory);
      const result = await bootstrapProtocolV2({ task, config, store, executor: remote, evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store) });
      expect(result.epoch.protocolVersion).toBe(2);
      const coverage = store.listCoverageRuns(task.taskId, result.epoch.epochId);
      expect(coverage.map((item) => item.category)).toEqual(expect.arrayContaining(task.checks));
      expect(coverage.some((item) => item.status === "ERROR" && item.applicability !== "UNKNOWN")).toBe(false);
      const facts = store.listFacts(task.taskId, result.epoch.epochId);
      expect(facts.some((fact) => fact.namespace === "web_root" && fact.privatePayload.effective === true)).toBe(true);
      expect(facts.some((fact) => fact.namespace === "delegation_rule" && String(fact.privatePayload.statement).includes("huntwarden-helper"))).toBe(true);
      expect(facts.some((fact) => fact.namespace === "ssh_trust_config" && fact.privatePayload.effective === true)).toBe(true);
      expect(facts.some((fact) => fact.namespace === "file" && fact.privatePayload.baseline === "package_db")).toBe(true);
      const assessments = store.listAssessments(task.taskId, result.epoch.epochId);
      expect(assessments).toEqual(expect.arrayContaining([expect.objectContaining({ authorType: "RULE", category: "backdoor_account", verdict: "SUSPICIOUS" })]));
      const leads = store.listInvestigationLeads(task.taskId, result.epoch.epochId);
      const actions = store.listInvestigationActions(task.taskId, result.epoch.epochId);
      const attempts = store.listInvestigationActionAttempts(task.taskId, result.epoch.epochId);
      const edges = store.listEdges(task.taskId, result.epoch.epochId);
      expect(result.investigationSession.authorizationEnvelope).toMatchObject({ targetFingerprint: target.hostFingerprint, collectEvidence: true, namespaces: expect.arrayContaining(["process", "socket", "file"]) });
      expect(leads.length).toBeGreaterThan(0);
      expect(actions.some((item) => item.requestedBy === "DISCOVERY" && item.operationRef === "collect" && ["SUCCEEDED", "PARTIAL"].includes(item.status))).toBe(true);
      expect(attempts.length).toBeGreaterThan(0);
      // Bootstrap 必须先让 process/socket 前导事实触发易失保全，再进入完整 Preset 的
      // Web/包/JVM 分支；只检查最终均存在无法证明易失对象没有被后续大扫描挤占。
      const preludeFacts = facts.filter((fact) => fact.source.kind === "PRESET" && ["process-snapshot", "socket-snapshot"].includes(String(fact.source.stepId)));
      const fullPresetFact = facts.find((fact) => fact.namespace === "web_root");
      const events = store.listInvestigationEvents(task.taskId, result.epoch.epochId, 0, 5_000);
      const firstDiscoveryAction = events.find((event) => event.eventType === "ACTION_CREATED"
        && event.payload.operationRef === "collect");
      const fullPresetBatch = fullPresetFact && events.find((event) => event.eventType === "FACT_BATCH_COMMITTED"
        && event.payload.sourceRunId === fullPresetFact.sourceRunId);
      expect(preludeFacts.length).toBeGreaterThan(0);
      expect(firstDiscoveryAction).toBeDefined();
      expect(fullPresetBatch).toBeDefined();
      expect(firstDiscoveryAction!.eventSeq).toBeLessThan(fullPresetBatch!.eventSeq);
      expect(edges.some((edge) => edge.relation === "command_file"
        && store.getObjectReference(task.taskId, result.epoch.epochId, edge.toRef)?.namespace === "file"
        && store.listFacts(task.taskId, result.epoch.epochId).some((fact) => fact.subjectRef === edge.toRef && fact.privatePayload.path === manifest.beaconPath))).toBe(true);
      expect(edges.some((edge) => edge.relation === "started_by"
        && ["cron_entry", "unit", "persistence"].includes(store.getObjectReference(task.taskId, result.epoch.epochId, edge.toRef)?.namespace ?? ""))).toBe(true);
      expect(actions.some((item) => item.operationRef === "verify" && item.obligationIds.some((id) => store.listInvestigationObligations(task.taskId, result.epoch.epochId).find((obligation) => obligation.obligationId === id)?.obligationKind === "PROCESS_FILE_PACKAGE_COUNTERCHECK"))).toBe(true);
      const processEvidence = store.listEvidence(task.taskId).find((item) => item.type === "collected_object" && typeof item.metadata?.subjectRef === "string" && store.getObjectReference(task.taskId, result.epoch.epochId, item.metadata.subjectRef)?.namespace === "process");
      expect(processEvidence?.metadata).toMatchObject({ epochId: result.epoch.epochId, complete: true, integrityStatus: "VERIFIED", range: { start: 0, complete: true } });
      const scriptFact = facts.find((fact) => fact.namespace === "file" && fact.privatePayload.path === manifest.beaconPath);
      expect(scriptFact).toBeDefined();
      expect(store.listEvidence(task.taskId).some((item) => item.metadata?.subjectRef === scriptFact?.subjectRef && item.metadata?.complete === true && item.metadata?.integrityStatus === "VERIFIED")).toBe(true);
      const validator = new InvestigationCompletionValidator(store);
      const evaluated = validator.evaluate(task.taskId, result.epoch.epochId);
      expect(evaluated.canClose, JSON.stringify({
        evaluated,
        checkpoints: store.listDiscoveryCheckpoints(task.taskId, result.epoch.epochId),
        openObligations: store.listInvestigationObligations(task.taskId, result.epoch.epochId)
          .filter((item) => item.required && ["OPEN", "QUEUED"].includes(item.status)),
        activeActions: store.listInvestigationActions(task.taskId, result.epoch.epochId)
          .filter((item) => ["READY", "RUNNING"].includes(item.status)),
      })).toBe(true);
      expect(evaluated.findingAssessmentIds.length).toBeGreaterThan(0);
      const completion = validator.freeze(task.taskId, result.epoch.epochId);
      expect(["CLOSED_WITH_FINDINGS", "LIMITED"]).toContain(completion.investigationStatus);
      if (completion.investigationStatus === "LIMITED") expect(completion.limitedObligationIds.length).toBeGreaterThan(0);
    } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
  }, 300_000);
});
