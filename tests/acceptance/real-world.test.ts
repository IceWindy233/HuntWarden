import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { ScanPlanner } from "../../src/checks/scan-planner.js";
import type { TargetConfig } from "../../src/domain/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import type { StableProcessIdentity } from "../../src/executor/operations.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createSecurityTools } from "../../src/tools/index.js";
import { testConfig, testTask } from "../helpers.js";

const enabled = process.env.HUNTWARDEN_REAL_WORLD_TESTS === "1";
const run = promisify(execFile);
const stateDir = resolve("acceptance/real-world/.state");
const container = "huntwarden-real-world-target";

interface ScenarioManifest {
  scenarioId: string;
  account: string;
  webRoot: string;
  webPath: string;
  beaconPath: string;
  deletedPath: string;
  cronPath: string;
  deletedPid: number;
}

function identity(value: Record<string, unknown>): StableProcessIdentity {
  return {
    bootId: String(value.bootId),
    pid: Number(value.pid),
    startTicks: String(value.startTicks),
    exeInode: String(value.exeInode),
    exeSha256: String(value.exeSha256),
  };
}

describe.skipIf(!enabled)("Debian 12 动态真实攻击链验收", () => {
  let remote: SSHExecutor;
  let manifest: ScenarioManifest;
  let target: TargetConfig;

  beforeAll(async () => {
    const knownHostsPath = resolve(stateDir, "known_hosts");
    const knownHosts = await readFile(knownHostsPath, "utf8");
    const fingerprint = knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2299/)?.[1];
    if (!fingerprint) throw new Error("真实场景 known_hosts 缺少 2299 指纹");
    target = {
      host: "127.0.0.1",
      port: 2299,
      username: "secagent",
      hostFingerprint: fingerprint,
      privateKeyPath: resolve(stateDir, "operator_ed25519"),
      knownHostsPath,
    };
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 45_000);
    const output = await run("docker", ["exec", container, "python3", "-c",
      "import json; print(json.dumps(json.load(open('/run/huntwarden-acceptance.json'))))"], { timeout: 10_000 });
    manifest = JSON.parse(output.stdout) as ScenarioManifest;
  });

  afterAll(async () => remote?.close());

  it("在非 Lab 官方发行版上完成能力协商和降级标识", async () => {
    const capabilities = await remote.invoke({ operation: "get_capabilities", params: {} });
    expect(capabilities.platform).toMatchObject({
      system: "Linux",
      architecture: expect.any(String),
      distribution: { id: "debian", versionId: "12", prettyName: expect.stringContaining("Debian GNU/Linux 12") },
    });
    expect(capabilities.operations).toEqual(expect.arrayContaining([
      "discover_effective_web_roots",
      "list_suspicious_processes",
      "list_cron_entries",
      "list_privileged_accounts",
    ]));
  });

  it("关联动态 Web 落地文件、行为特征、YARA 与访问请求", async () => {
    const roots = await remote.invoke({ operation: "discover_effective_web_roots", params: {} });
    expect(roots.items).toEqual(expect.arrayContaining([expect.objectContaining({ path: manifest.webRoot })]));

    const recent = await remote.invoke({ operation: "list_recent_web_artifacts", params: {
      roots: [manifest.webRoot], modifiedWithinHours: 24, maxFiles: 500, maxFileSizeBytes: 10 * 1024 * 1024,
    } });
    const candidate = recent.items.find((item) => item.path === manifest.webPath);
    expect(candidate).toMatchObject({ sha256: expect.stringMatching(/^[0-9a-f]{64}$/), extension: ".php" });

    const inspection = await remote.invoke({ operation: "inspect_script_file", params: { path: manifest.webPath, maxBytes: 65_536 } });
    expect(inspection.features).toMatchObject({ commandExecution: 1, dynamicEvaluation: 1 });
    const yara = await remote.invoke({ operation: "yara_scan_files", params: {
      paths: [manifest.webPath], rulePath: "/opt/huntwarden/rules/webshell.yar",
    } });
    expect(yara[0]?.matches).toEqual(expect.arrayContaining([
      "HuntWarden_Suspicious_Server_Script_Combination",
      "HuntWarden_PHP_Request_To_Command_Chain",
    ]));

    const requests = await remote.invoke({ operation: "correlate_web_requests", params: {
      path: manifest.webPath, expectedSha256: String(candidate!.sha256), maxEvents: 100,
    } });
    expect(requests.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ sourceIp: "198.51.100.42", method: "POST", uri: expect.stringContaining("token=[REDACTED]") }),
      expect.objectContaining({ sourceIp: "198.51.100.42", method: "GET" }),
    ]));
  });

  it("从动态账户和 Cron 中恢复持久化上下文，且不泄露 SSH 公钥", async () => {
    const accounts = await remote.invoke({ operation: "list_privileged_accounts", params: {} });
    expect(accounts).toEqual(expect.arrayContaining([
      expect.objectContaining({ username: manifest.account, uid: 0, accountSource: "local" }),
    ]));
    const keys = await remote.invoke({ operation: "inspect_authorized_keys", params: { username: manifest.account } });
    expect(keys).toEqual([expect.objectContaining({ fingerprint: expect.stringMatching(/^SHA256:/) })]);
    expect(JSON.stringify(keys)).not.toContain("ssh-ed25519 AAAA");

    const cron = await remote.invoke({ operation: "list_cron_entries", params: { maxItems: 500, includeUserScope: true } });
    expect(cron.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: manifest.cronPath, username: "root", commandSummary: expect.stringContaining(manifest.beaconPath) }),
      expect.objectContaining({ path: "/etc/cron.d/backup-retention", username: "root" }),
    ]));
  });

  it("识别删除后运行和隐藏 Beacon，并完成稳定进程到 Socket 关联", async () => {
    const suspicious = await remote.invoke({ operation: "list_suspicious_processes", params: { maxProcesses: 2000 } });
    const deleted = suspicious.items.find((item) => item.exePath === manifest.deletedPath);
    expect(deleted).toMatchObject({
      pid: manifest.deletedPid,
      exeDeleted: true,
      signals: expect.arrayContaining(["deleted_executable", "temporary_executable", "hidden_executable"]),
    });

    const beacon = suspicious.items.find((item) => item.launcherPath === manifest.beaconPath);
    expect(beacon).toMatchObject({ signals: expect.arrayContaining(["temporary_executable", "hidden_executable"]) });
    const connections = await remote.invoke({ operation: "list_process_connections", params: {
      ...identity(beacon!), maxConnections: 500,
    } });
    expect(connections.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ remote: expect.stringMatching(/:18771$/), state: "ESTABLISHED" }),
    ]));
  });

  it("将认证与提权痕迹纳入事件时间线", async () => {
    const auth = await remote.invoke({ operation: "query_auth_events", params: { sinceHours: 24, maxEvents: 500 } });
    expect(auth.items).toEqual(expect.arrayContaining([
      expect.objectContaining({ username: manifest.account, sourceIp: "198.51.100.42", eventType: "authentication_success" }),
      expect.objectContaining({ username: manifest.account, eventType: "privilege_use" }),
    ]));
    const timeline = await remote.invoke({ operation: "build_incident_timeline", params: { sinceHours: 24, maxEvents: 2000 } });
    expect(timeline.items.some((item) => item.timelineSource === "auth" && item.username === manifest.account)).toBe(true);
  });

  it("通过正式工具注册表和最低扫描图固化动态规则结论与降级", async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-real-world-planner-"));
    const store = await RuntimeStore.open(directory, "runtime.db");
    try {
      const task = testTask("SCAN");
      task.target = target;
      task.checks = ["webshell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"];
      store.createTask(task);
      const config = testConfig(directory);
      const approvals = new ApprovalService(store);
      const evidence = new EvidenceStore(directory, store);
      const tools = createSecurityTools({ task, config, store, executor: remote, approvals, evidence });
      const result = await new ScanPlanner({
        task, store, tools, maxLlmBytes: config.llmData.maxTextBytes,
        accountChecks: config.account,
        threatIntelChecks: { enabled: false, autoEnrichConnections: false },
      }).run();

      expect(result.outcomes).toEqual(expect.arrayContaining([
        expect.objectContaining({ stepId: "web-candidates", status: "success" }),
        expect.objectContaining({ stepId: "privileged-accounts", status: "success" }),
        expect.objectContaining({ stepId: "suspicious-processes", status: "partial" }),
      ]));
      expect(result.deterministicFindings).toEqual(expect.arrayContaining([
        expect.objectContaining({ category: "backdoor_account", status: "SUSPICIOUS", title: "发现非 root 名称的 UID 0 账户" }),
        expect.objectContaining({ category: "linux_intrusion_triage", status: "SUSPICIOUS", title: "发现具有固定结构异常信号的运行进程" }),
      ]));
      expect(store.listFindings(task.taskId)).toEqual(expect.arrayContaining([
        expect.objectContaining({ category: "linux_persistence", status: "ERROR" }),
      ]));
      expect(store.listFindings(task.taskId).some((finding) => finding.category === "linux_persistence" && finding.status === "NO_FINDING")).toBe(false);
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }, 180_000);
});
