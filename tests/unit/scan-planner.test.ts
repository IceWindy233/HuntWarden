import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { ScanPlanner } from "../../src/checks/scan-planner.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createSecurityTools } from "../../src/tools/index.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function capabilities() {
  return {
    protocolVersion: 1,
    helper: { name: "huntwarden-helper", version: "test" },
    platform: { system: "Linux", release: "test", architecture: "x64", python: "3.11" },
    operations: ["get_capabilities", "get_host_info", "discover_web_roots", "find_recent_web_files"],
    artifactTransfer: { supported: true, protocolVersion: 1, maxBytes: 10 * 1024 * 1024 },
    features: { yara: true, javaAttach: false, tomcatProbe: false },
    partial: false,
    warnings: [],
  };
}

describe("ScanPlanner 确定性最低执行图", () => {
  it("先执行 Web 预检、Root 和候选步骤，并按稳定 toolCallId 复用成功结果", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-scan-plan-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const executor = new FakeExecutor({
      get_capabilities: () => capabilities(),
      get_host_info: () => ({ hostname: "target", note: "token=super-secret" }),
      discover_web_roots: () => [{ path: "/var/www/html", server: "nginx" }],
      find_recent_web_files: () => [{ path: "/var/www/html/index.php", size: 10, mtime: "2026-01-01T00:00:00Z", sha256: "a".repeat(64) }],
    });
    const config = testConfig(directory);
    const tools = createSecurityTools({
      task,
      config,
      store,
      executor,
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });
    const planner = new ScanPlanner({ task, store, tools, maxLlmBytes: config.llmData.maxTextBytes });

    const first = await planner.run();
    const callsAfterFirstRun = executor.calls.length;
    const second = await planner.run();

    expect(executor.calls.map((call) => call.operation)).toEqual([
      "get_capabilities", "get_host_info", "discover_web_roots", "find_recent_web_files",
    ]);
    expect(executor.calls).toHaveLength(callsAfterFirstRun);
    expect(store.listToolRuns(task.taskId)).toHaveLength(4);
    expect(store.getTask(task.taskId)?.toolCallCount).toBe(4);
    expect(first.minimumToolNames).toEqual(new Set(["get_capabilities", "get_host_info", "discover_web_roots", "find_recent_web_files"]));
    expect(first.promptContext).toContain("candidateRef");
    expect(first.promptContext).not.toContain("super-secret");
    expect(first.promptContext).toContain("[REDACTED]");
    expect(second.outcomes.every((outcome) => outcome.status === "not_applicable" || outcome.reused)).toBe(true);
    const completedAudit = store.listAudit(task.taskId).find((event) => event.event === "deterministic_scan_completed");
    expect(completedAudit?.data.summary).toContain("candidateRef");
    expect(completedAudit?.data.summary).not.toContain("super-secret");
    store.close();
  });

  it("共享能力中与当前类别无关的 PARTIAL 不会生成 ERROR Finding", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-scan-plan-unrelated-partial-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const executor = new FakeExecutor({
      get_capabilities: () => ({ ...capabilities(), partial: true, warnings: ["Tomcat 探针不可用"] }),
      get_host_info: () => ({ hostname: "target" }),
      discover_web_roots: () => [{ path: "/var/www/html", server: "nginx" }],
      find_recent_web_files: () => [],
    });
    const config = testConfig(directory);
    const tools = createSecurityTools({
      task,
      config,
      store,
      executor,
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });

    const result = await new ScanPlanner({ task, store, tools, maxLlmBytes: config.llmData.maxTextBytes }).run();

    expect(result.outcomes).toEqual(expect.arrayContaining([
      expect.objectContaining({ stepId: "capabilities", status: "partial" }),
      expect.objectContaining({ stepId: "web-candidates", status: "success" }),
    ]));
    expect(store.listFindings(task.taskId).some((finding) => finding.status === "ERROR")).toBe(false);
    expect(store.listFindings(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: "webshell", status: "NO_FINDING" }),
    ]));
    store.close();
  });

  it("最低只读工具失败时固化 ERROR Finding，不会把失败解释为安全", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-scan-plan-error-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["backdoor_account"];
    store.createTask(task);
    const executor = new FakeExecutor({
      get_capabilities: () => capabilities(),
      get_host_info: () => ({ hostname: "target" }),
      list_privileged_accounts: () => { throw new Error("permission denied"); },
    });
    const config = testConfig(directory);
    const tools = createSecurityTools({
      task,
      config,
      store,
      executor,
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });

    const result = await new ScanPlanner({ task, store, tools, maxLlmBytes: config.llmData.maxTextBytes }).run();

    expect(result.outcomes).toEqual(expect.arrayContaining([
      expect.objectContaining({ toolName: "list_privileged_accounts", status: "error" }),
    ]));
    expect(store.listFindings(task.taskId)).toMatchObject([
      { category: "backdoor_account", status: "ERROR" },
    ]);
    expect(store.getTask(task.taskId)?.coverage.backdoor_account).toBe("ERROR");
    store.close();
  });

  it("最低账户图完成后立即固化规则 Finding，重复运行不会重复写入", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-scan-plan-rule-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["backdoor_account"];
    store.createTask(task);
    const executor = new FakeExecutor({
      get_capabilities: () => capabilities(),
      get_host_info: () => ({ hostname: "target" }),
      list_privileged_accounts: () => [
        { username: "root", uid: 0, gid: 0, shell: "/bin/bash", home: "/root", sudo: true, interactive: true },
        { username: "backup-root", uid: 0, gid: 0, shell: "/bin/bash", home: "/srv/backup", sudo: false, interactive: true },
      ],
      inspect_privilege_delegation: () => ({ items: [], partial: false, warnings: [] }),
      inspect_ssh_trust_configuration: () => ({ items: [], effective: { available: true }, trustFiles: [], partial: false, warnings: [] }),
      inspect_account: (params) => ({ ...(params as { username: string }), uid: 0, groups: [] }),
      inspect_authorized_keys: () => [],
      get_login_history: () => [],
    });
    const config = testConfig(directory);
    const tools = createSecurityTools({
      task,
      config,
      store,
      executor,
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });
    const planner = new ScanPlanner({ task, store, tools, maxLlmBytes: config.llmData.maxTextBytes });

    const first = await planner.run();
    const second = await planner.run();

    expect(first.deterministicFindings).toMatchObject([
      { category: "backdoor_account", status: "SUSPICIOUS", severity: "MEDIUM" },
    ]);
    expect(second.deterministicFindings[0]?.findingId).toBe(first.deterministicFindings[0]?.findingId);
    expect(store.listFindings(task.taskId)).toHaveLength(1);
    expect(first.promptContext).toContain("HW-ACCOUNT-UID0-001@1.0.0");
    expect(store.getTask(task.taskId)?.coverage.backdoor_account).toBe("SUSPICIOUS");
    store.close();
  });
});
