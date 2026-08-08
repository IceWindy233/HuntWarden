import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
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

  it("Lab-Web 完成候选、YARA、特征和采集链", async () => {
    const remote = executor(2222);
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
    expect(Buffer.from(evidence.dataBase64, "base64").length).toBe(evidence.size);
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
    expect(Buffer.from(String(dumped.dataBase64), "base64").subarray(0, 4).toString("hex")).toBe("cafebabe");
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

  it("未知 Host Key 在连接前失败", async () => {
    const target: TargetConfig = {
      host: "127.0.0.1", port: 2222, username: "secagent", hostFingerprint: "SHA256:not-known",
      privateKeyPath, knownHostsPath,
    };
    const remote = new SSHExecutor(target, helperPath, 5_000);
    executors.push(remote);
    await expect(remote.invoke({ operation: "get_host_info", params: {} })).rejects.toMatchObject({ code: "INVALID_TARGET" });
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
});
