import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import { createId } from "../../src/common/ids.js";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import type { CollectedArtifactOutput } from "../../src/executor/operations.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createReference } from "../../src/tools/reference-utils.js";
import { createRemediationTools } from "../../src/tools/remediation/tools.js";
import { testConfig, testTask } from "../helpers.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";
const stateDir = resolve("labs/.lab-state");
const knownHostsPath = resolve(stateDir, "known_hosts");
const privateKeyPath = resolve(stateDir, "id_ed25519");
const helperPath = "/usr/local/libexec/huntwarden-helper";

describe.skipIf(!enabled)("Docker Lab 真实 SSH Tool Chain", () => {
  const executors: SSHExecutor[] = [];
  const temporaryDirectories: string[] = [];
  let knownHosts = "";

  beforeAll(async () => { knownHosts = await readFile(knownHostsPath, "utf8"); });
  afterAll(async () => {
    await Promise.all(executors.map((executor) => executor.close()));
    await Promise.all(temporaryDirectories.map((path) => rm(path, { recursive: true, force: true })));
  });

  function executor(port: number): SSHExecutor {
    const fingerprint = knownHosts.match(new RegExp(`# (SHA256:[A-Za-z0-9+/]+) port=${port}`))?.[1];
    if (!fingerprint) throw new Error(`known_hosts 缺少 ${port} 的指纹`);
    const target: TargetConfig = {
      host: "127.0.0.1", port, username: "secagent", hostFingerprint: fingerprint,
      privateKeyPath, knownHostsPath,
    };
    const value = new SSHExecutor(target, helperPath, 30_000);
    executors.push(value);
    return value;
  }

  async function artifactBytes(remote: SSHExecutor, output: CollectedArtifactOutput): Promise<Buffer> {
    if (output.artifact) {
      const chunks: Buffer[] = [];
      await remote.downloadArtifact(output.artifact, (chunk) => { chunks.push(Buffer.from(chunk)); });
      return Buffer.concat(chunks);
    }
    if (typeof output.dataBase64 === "string") return Buffer.from(output.dataBase64, "base64");
    throw new Error("采集结果没有 Artifact Token 或兼容字节数据");
  }

  it("Lab-Web 完成候选、YARA、特征和采集链", async () => {
    const remote = executor(2222);
    const capabilities = await remote.invoke({ operation: "get_capabilities", params: {} });
    expect(capabilities).toMatchObject({ protocolVersion: 1, artifactTransfer: { supported: true, protocolVersion: 1 } });
    expect(capabilities.operations).toContain("collect_file");
    const roots = await remote.invoke({ operation: "discover_web_roots", params: {} });
    expect(roots.some((item) => item.path === "/var/www/html")).toBe(true);
    const files = await remote.invoke({ operation: "find_recent_web_files", params: {
      roots: ["/var/www/html"], modifiedWithinHours: 168, maxFiles: 500, maxFileSizeBytes: 10 * 1024 * 1024,
    } });
    const sample = files.find((item) => item.path === "/var/www/html/lab-webshell.php");
    expect(sample).toBeTruthy();
    const yara = await remote.invoke({ operation: "yara_scan_files", params: {
      paths: [String(sample!.path)], rulePath: "/opt/huntwarden/rules/webshell.yar",
    } });
    expect(yara[0]?.matches).toContain("HuntWarden_Lab_WebShell_Marker");
    const inspection = await remote.invoke({ operation: "inspect_script_file", params: { path: String(sample!.path), maxBytes: 65_536 } });
    expect(inspection.sha256).toBe(sample!.sha256);
    const evidence = await remote.invoke({ operation: "collect_file", params: { path: String(sample!.path), maxBytes: 10 * 1024 * 1024 } });
    expect(evidence.sha256).toBe(sample!.sha256);
    expect((await artifactBytes(remote, evidence)).length).toBe(evidence.size);

    const large = await remote.invoke({ operation: "collect_file", params: { path: "/usr/bin/python3", maxBytes: 10 * 1024 * 1024 } });
    expect(large.artifact).toBeTruthy();
    let chunks = 0;
    let transferred = 0;
    await remote.downloadArtifact(large.artifact!, (chunk) => { chunks += 1; transferred += chunk.length; });
    expect(transferred).toBe(large.size);
    expect(chunks).toBeGreaterThan(1);
  });

  it("Lab-Tomcat 枚举动态 Filter 并完成 Class Dump", async () => {
    const remote = executor(2223);
    const processes = await remote.invoke({ operation: "list_java_processes", params: {} });
    const tomcatProcess = processes.find((item) => String(item.command).toLowerCase().includes("catalina"));
    expect(tomcatProcess).toBeTruthy();
    const pid = Number(tomcatProcess!.pid);
    const container = await remote.invoke({ operation: "detect_java_container", params: { pid } });
    expect(container).toMatchObject({ container: "tomcat", supported: true });
    const components = await remote.invoke({ operation: "run_tomcat_probe", params: { pid, command: "list_components" }, timeoutMs: 60_000 });
    const filter = (components.components as Record<string, unknown>[]).find((item) => item.className === "lab.DynamicMarkerFilter");
    expect(filter).toMatchObject({ type: "filter" });
    const inspected = await remote.invoke({ operation: "run_tomcat_probe", params: { pid, command: "inspect_class", className: "lab.DynamicMarkerFilter" }, timeoutMs: 60_000 });
    expect(inspected).toMatchObject({ loaded: true, partial: false });
    const disk = await remote.invoke({ operation: "search_class_on_disk", params: { pid, className: "lab.DynamicMarkerFilter" } });
    expect(disk.found).toBe(false);
    const dumped = await remote.invoke({ operation: "run_tomcat_probe", params: { pid, command: "dump_class", className: "lab.DynamicMarkerFilter" }, timeoutMs: 60_000 });
    expect(dumped.partial).toBe(false);
    const dumpedBytes = await artifactBytes(remote, dumped as CollectedArtifactOutput);
    expect(dumpedBytes.subarray(0, 4).toString("hex")).toBe("cafebabe");
  }, 120_000);

  it("Lab-Account 识别 UID 0 测试账户和未知 Key 指纹", async () => {
    const remote = executor(2224);
    const accounts = await remote.invoke({ operation: "list_privileged_accounts", params: {} });
    const account = accounts.find((item) => item.username === "labroot");
    expect(account).toMatchObject({ uid: 0 });
    const detail = await remote.invoke({ operation: "inspect_account", params: { username: "labroot" } });
    expect(detail).toMatchObject({ username: "labroot", uid: 0 });
    const keys = await remote.invoke({ operation: "inspect_authorized_keys", params: { username: "labroot" } });
    expect(keys).toHaveLength(1);
    expect(keys[0]?.fingerprint).toMatch(/^SHA256:/);
    expect(keys[0]).not.toHaveProperty("key");
  });

  it("Lab-Persistence 完成 Cron、systemd、SSH、Shell 与进程网络关联链", async () => {
    const remote = executor(2225);
    const request = { maxItems: 500, includeUserScope: true };
    const cron = await remote.invoke({ operation: "list_cron_entries", params: request });
    const cronMarker = cron.items.find((item) => item.path === "/etc/cron.d/huntwarden-lab");
    expect(cronMarker).toMatchObject({ kind: "cron", username: "persistuser" });
    const limitedCron = await remote.invoke({ operation: "list_cron_entries", params: { maxItems: 1, includeUserScope: true } });
    expect(limitedCron).toMatchObject({ partial: true });
    expect(limitedCron.items).toHaveLength(1);

    const systemd = await remote.invoke({ operation: "list_systemd_units", params: request });
    const unit = systemd.items.find((item) => item.unit === "huntwarden-lab.service");
    expect(unit).toMatchObject({ kind: "systemd", enabled: true, runAs: "persistuser" });
    expect(systemd).toMatchObject({ partial: true });
    expect(systemd.warnings.join(" ")).toContain("管理器未运行");

    const ssh = await remote.invoke({ operation: "list_ssh_persistence", params: request });
    const unknown = ssh.items.find((item) => item.username === "persistuser");
    expect(unknown?.fingerprint).toMatch(/^SHA256:/);
    expect(JSON.stringify(ssh)).not.toContain("ssh-ed25519 AAAA");
    expect(unknown).not.toHaveProperty("key");

    const shell = await remote.invoke({ operation: "list_shell_startup_files", params: request });
    const startup = shell.items.find((item) => item.path === "/home/persistuser/.bashrc");
    expect(startup).toMatchObject({ kind: "shell" });
    expect(startup?.features).toContain("interpreter_execution");

    const inspected = await remote.invoke({ operation: "inspect_persistence_item", params: {
      kind: String(unit!.kind), path: String(unit!.path), expectedSha256: String(unit!.sha256),
    } });
    expect(inspected.sha256).toBe(unit!.sha256);

    const processes = await remote.invoke({ operation: "find_related_processes", params: {
      kind: String(unit!.kind), path: String(unit!.path), expectedSha256: String(unit!.sha256),
      commandHint: (unit!.execStart as string[]).join(" "), maxProcesses: 500,
    } });
    const listener = processes.find((item) => String(item.command).includes("listener.py") && String(item.executable).includes("python"));
    expect(listener).toBeTruthy();
    const connections = await remote.invoke({ operation: "list_process_connections", params: { pid: Number(listener!.pid), maxConnections: 500 } });
    expect(connections.items.some((item) => String(item.local).endsWith(":45555") && item.state === "LISTEN")).toBe(true);

    const artifact = await remote.invoke({ operation: "collect_persistence_artifact", params: {
      kind: String(unit!.kind), path: String(unit!.path), expectedSha256: String(unit!.sha256), maxBytes: 1024 * 1024,
    } });
    expect(artifact.sha256).toBe(unit!.sha256);
    expect((await artifactBytes(remote, artifact)).length).toBe(artifact.size);

    await expect(remote.invoke({ operation: "inspect_persistence_item", params: {
      kind: "shell", path: "/etc/passwd", expectedSha256: "0".repeat(64),
    } })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(remote.invoke({ operation: "inspect_persistence_item", params: {
      kind: "shell", path: "/home/persistuser/../persistuser/.bashrc", expectedSha256: String(startup!.sha256),
    } })).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("未知 Host Key 在连接前失败", async () => {
    const target: TargetConfig = {
      host: "127.0.0.1", port: 2222, username: "secagent", hostFingerprint: "SHA256:not-known",
      privateKeyPath, knownHostsPath,
    };
    const remote = new SSHExecutor(target, helperPath, 5_000);
    executors.push(remote);
    await expect(remote.invoke({ operation: "get_host_info", params: {} })).rejects.toMatchObject({ code: "INVALID_TARGET" });
  });

  it("Lab-Web 写工具无票据和拒绝审批均为零写入，批准后原子隔离并记录回执", async () => {
    const remote = executor(2222);
    const source = "/var/www/html/lab-webshell.php";
    const collected = await remote.invoke({ operation: "collect_file", params: { path: source, maxBytes: 10 * 1024 * 1024 } });
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-docker-quarantine-"));
    temporaryDirectories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.target = {
      host: "127.0.0.1", port: 2222, username: "secagent",
      hostFingerprint: knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2222/)![1]!,
      privateKeyPath, knownHostsPath,
    };
    store.createTask(task);
    const approvals = new ApprovalService(store);
    const evidence = new EvidenceStore(directory, store);
    const stored = await evidence.putBuffer({
      taskId: task.taskId, host: task.target.host, type: "file", source, tool: "collect_file",
      toolCallId: "call-collect-webshell", data: await artifactBytes(remote, collected),
    });
    expect(stored.sha256).toBe(collected.sha256);
    const config = testConfig(directory);
    config.remediation.quarantineRoot = "/var/lib/huntwarden/quarantine";
    const tool = createRemediationTools({ task, config, store, approvals, executor: remote, evidence })
      .find((item) => item.name === "quarantine_file")!;
    const args = { evidenceRef: stored.evidenceId };

    await expect(tool.execute("call-quarantine-without-approval", args, undefined)).rejects.toThrow(/授权票据/);
    expect((await remote.invoke({ operation: "inspect_script_file", params: { path: source, maxBytes: 65_536 } })).sha256).toBe(stored.sha256);

    const denied = approvals.request(task, tool.name, args);
    approvals.decide(denied.approvalId, false);
    await expect(tool.execute("call-quarantine-denied", args, undefined)).rejects.toThrow(/授权票据/);
    expect((await remote.invoke({ operation: "get_action_receipt", params: { actionId: denied.actionId }, actionId: denied.actionId })).status).toBe("UNKNOWN");
    expect((await remote.invoke({ operation: "inspect_script_file", params: { path: source, maxBytes: 65_536 } })).sha256).toBe(stored.sha256);

    const approved = approvals.request(task, tool.name, args);
    approvals.decide(approved.approvalId, true);
    await tool.execute("call-quarantine-approved", args, undefined);
    const localReceipt = store.getActionReceipt(approved.actionId);
    expect(localReceipt?.status).toBe("SUCCEEDED");
    expect(store.findLatestApproval(task.taskId, tool.name, approvals.getArgsDigest(args))?.status).toBe("CONSUMED");
    const remoteReceipt = await remote.invoke({ operation: "get_action_receipt", params: { actionId: approved.actionId }, actionId: approved.actionId });
    expect(remoteReceipt).toMatchObject({ status: "SUCCEEDED", result: { verifiedMissing: true, verifiedMode000: true, quarantineMode: 0 } });
    const remaining = await remote.invoke({ operation: "find_recent_web_files", params: {
      roots: ["/var/www/html"], modifiedWithinHours: 168, maxFiles: 500, maxFileSizeBytes: 10 * 1024 * 1024,
    } });
    expect(remaining.some((item) => item.path === source)).toBe(false);
    await expect(tool.execute("call-quarantine-reuse-consumed-ticket", args, undefined)).rejects.toThrow(/授权票据/);
    store.close();
  });

  it("Lab-Account 写工具无票据为零成功，单次批准后真实禁用并记录回执", async () => {
    const remote = executor(2224);
    const directory = await mkdtemp(resolve(tmpdir(), "huntwarden-docker-write-"));
    temporaryDirectories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.target = {
      host: "127.0.0.1", port: 2224, username: "secagent",
      hostFingerprint: knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2224/)![1]!,
      privateKeyPath, knownHostsPath,
    };
    store.createTask(task);
    const approvals = new ApprovalService(store);
    const reference = createReference(store, task.taskId, "account", "account", { username: "labroot", uid: 0 });
    const config = testConfig(directory);
    const tool = createRemediationTools({
      task, config, store, approvals, executor: remote, evidence: new EvidenceStore(directory, store),
    }).find((item) => item.name === "disable_account")!;
    const args = { accountRef: reference.ref };
    await expect(tool.execute("call-without-approval", args, undefined)).rejects.toThrow(/授权票据/);
    expect(store.listPendingApprovals(task.taskId)).toHaveLength(0);
    const ticket = approvals.request(task, tool.name, args);
    approvals.decide(ticket.approvalId, true);
    await tool.execute("call-with-approval", args, undefined);
    expect(store.getActionReceipt(ticket.actionId)?.status).toBe("SUCCEEDED");
    expect(store.findLatestApproval(task.taskId, tool.name, approvals.getArgsDigest(args))?.status).toBe("CONSUMED");
    const after = await remote.invoke({ operation: "inspect_account", params: { username: "labroot" } });
    expect(after.passwordLocked).toBe(true);
    expect(String(after.accountExpireDays)).not.toBe("-1");
    store.close();
  });

  it("Lab-Account 永久拒绝禁用 root 和当前 SSH 执行账户", async () => {
    const remote = executor(2224);
    for (const username of ["root", "secagent"]) {
      const actionId = createId("action");
      await expect(remote.invoke({
        operation: "disable_account",
        params: { actionId, username, executorUsername: "secagent" },
        actionId,
      })).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
      expect((await remote.invoke({ operation: "get_action_receipt", params: { actionId }, actionId })).status).toBe("UNKNOWN");
    }
  });
});
