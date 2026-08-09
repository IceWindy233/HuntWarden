import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createSecurityTools } from "../../src/tools/index.js";
import { createRecordFindingTool } from "../../src/tools/local/record-finding.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("任务检测包边界", () => {
  it("将 SecurityTool timeoutMs 传播到 HostExecutor", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-tool-timeout-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("SCAN");
    task.checks = ["webshell"];
    store.createTask(task);
    const executor = new FakeExecutor({
      get_capabilities: () => ({
        protocolVersion: 1, helper: { name: "huntwarden-helper", version: "test" },
        platform: { system: "Linux", release: "test", architecture: "x64", python: "3" },
        operations: ["get_capabilities"], artifactTransfer: { supported: true, protocolVersion: 1, maxBytes: 1024 },
        features: { yara: true, javaAttach: true, tomcatProbe: true }, partial: false, warnings: [],
      }),
    });
    const tool = createSecurityTools({ task, config: testConfig(directory), store, executor, approvals: new ApprovalService(store), evidence: new EvidenceStore(directory, store) })
      .find((item) => item.name === "get_capabilities")!;

    await tool.execute("call-capabilities-timeout", {}, undefined);

    expect(executor.calls).toContainEqual({ operation: "get_capabilities", params: {} });
    expect(executor.effectiveTimeouts).toEqual([15_000]);
    store.close();
  });

  it("只注册任务选中的检测包，SCAN 模式不暴露写工具", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-tool-scope-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("SCAN");
    task.checks = ["webshell"];
    store.createTask(task);
    const executor = new FakeExecutor();
    const tools = createSecurityTools({
      task,
      config: testConfig(directory),
      store,
      executor,
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });
    const names = tools.map((tool) => tool.name);

    expect(names).toEqual(expect.arrayContaining([
      "get_host_info", "list_processes", "discover_web_roots", "find_recent_web_files", "record_finding",
    ]));
    expect(names).not.toEqual(expect.arrayContaining([
      "list_java_processes", "list_privileged_accounts", "list_cron_entries", "quarantine_file", "disable_account",
    ]));
    store.close();
  });

  it("REMEDIATE 模式也只暴露所选检测包对应的写工具", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-write-tool-scope-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("REMEDIATE");
    task.checks = ["backdoor_account"];
    store.createTask(task);
    const tools = createSecurityTools({
      task,
      config: testConfig(directory),
      store,
      executor: new FakeExecutor(),
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });
    const names = tools.map((tool) => tool.name);

    expect(names).toContain("list_privileged_accounts");
    expect(names).toContain("disable_account");
    expect(names).not.toContain("quarantine_file");
    expect(names).not.toContain("discover_web_roots");
    store.close();
  });

  it("record_finding 拒绝写入任务未选择的类别", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-finding-scope-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const tool = createRecordFindingTool({
      task,
      config: testConfig(directory),
      store,
      executor: new FakeExecutor(),
      approvals: new ApprovalService(store),
      evidence: new EvidenceStore(directory, store),
    });

    await expect(tool.execute("call-out-of-scope", {
      category: "java_memory_shell",
      severity: "INFO",
      confidence: 1,
      status: "NO_FINDING",
      title: "越界 Finding",
      summary: "不应被保存",
      evidenceRefs: [],
    })).rejects.toThrow(/未选择的检测类别/);
    expect(store.listFindings(task.taskId)).toHaveLength(0);
    expect(store.getTask(task.taskId)?.coverage).toEqual({});
    store.close();
  });
});
