import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ScanStepOutcome } from "../../src/checks/scan-planner.js";
import type { Evidence, Finding, SecurityToolResult } from "../../src/domain/types.js";
import { DeterministicRuleEngine } from "../../src/rules/deterministic-rule-engine.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { testTask } from "../helpers.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function outcome(
  stepId: string,
  items: Record<string, unknown>[] = [],
  artifactRefs: string[] = [],
  status: "success" | "partial" = "success",
): ScanStepOutcome {
  const details: SecurityToolResult = { status, summary: { count: items.length }, items, artifactRefs, warnings: [] };
  return { stepId, toolName: `tool_${stepId}`, invocation: 0, status, reused: false, details };
}

function preflight(): ScanStepOutcome[] {
  return [outcome("capabilities"), outcome("host-info")];
}

function putEvidence(store: RuntimeStore, evidenceId: string, taskId: string): Evidence {
  const evidence: Evidence = {
    evidenceId,
    taskId,
    host: "127.0.0.1",
    type: "rule-test",
    source: "fixed-scope",
    collectedAt: new Date().toISOString(),
    tool: "rule-test",
  };
  store.putEvidence(evidence);
  return evidence;
}

function existingFinding(taskId: string, status: Finding["status"]): Finding {
  return {
    findingId: `FIND-existing-${status}`,
    taskId,
    host: "127.0.0.1",
    category: "backdoor_account",
    severity: "HIGH",
    confidence: 0.95,
    status,
    title: "分析师已确认的高风险结论",
    summary: "来自更完整的人工或模型事实链。",
    evidenceRefs: [],
    createdAt: new Date().toISOString(),
    toolCallId: `existing-${status}`,
  };
}

describe("DeterministicRuleEngine", () => {
  it("对额外 UID 0 账户生成有 Evidence 的 SUSPICIOUS Finding，同一输入幂等且不降低已有高风险", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-account-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["backdoor_account"];
    store.createTask(task);
    const evidenceId = "EV-rule-account";
    putEvidence(store, evidenceId, task.taskId);
    const engine = new DeterministicRuleEngine(store);
    const suspiciousInput = [
      ...preflight(),
      outcome("privileged-accounts", [
        { accountRef: "ACCT-root", username: "root", uid: 0 },
        { accountRef: "ACCT-labroot", username: "labroot", uid: 0 },
      ], [evidenceId]),
    ];

    const first = engine.evaluate(task, suspiciousInput);
    const second = engine.evaluate(task, suspiciousInput);

    expect(first).toMatchObject([{ category: "backdoor_account", status: "SUSPICIOUS", evidenceRefs: [evidenceId] }]);
    expect(second[0]?.findingId).toBe(first[0]?.findingId);
    expect(store.listFindings(task.taskId)).toHaveLength(1);
    expect(first[0]?.summary).toContain("HW-ACCOUNT-UID0-001@1.0.0");
    expect(first[0]?.summary).toContain("反证与限制");
    expect(first[0]?.toolCallId).toMatch(/HW-ACCOUNT-UID0-001:1\.0\.0:[a-f0-9]{64}$/);

    store.putFinding(existingFinding(task.taskId, "CONFIRMED"));
    engine.evaluate(task, [
      ...preflight(),
      outcome("privileged-accounts", [{ accountRef: "ACCT-root", username: "root", uid: 0 }], [evidenceId]),
    ]);
    expect(store.listFindings(task.taskId)).toHaveLength(3);
    expect(store.getTask(task.taskId)?.coverage.backdoor_account).toBe("CONFIRMED");
    expect(store.listAudit(task.taskId).find((event) => event.event === "deterministic_rule_evaluated")?.data).toMatchObject({
      ruleId: "HW-ACCOUNT-UID0-001",
      ruleVersion: "1.0.0",
    });
    store.close();
  });

  it("任一持久化源为 PARTIAL 时不产生 NO_FINDING", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-partial-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["linux_persistence"];
    store.createTask(task);

    const result = new DeterministicRuleEngine(store).evaluate(task, [
      ...preflight(),
      outcome("cron"),
      outcome("systemd", [], [], "partial"),
      outcome("ssh-persistence"),
      outcome("shell-startup"),
    ]);

    expect(result).toEqual([]);
    expect(store.listFindings(task.taskId)).toEqual([]);
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "deterministic_rule_skipped_incomplete" }),
    ]));
    store.close();
  });

  it("普通解释器关键词单独出现只形成 NO_FINDING，强上下文组合最多形成 SUSPICIOUS", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-persistence-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["linux_persistence"];
    store.createTask(task);
    const evidenceId = "EV-rule-persistence";
    putEvidence(store, evidenceId, task.taskId);
    const engine = new DeterministicRuleEngine(store);
    const base = [...preflight(), outcome("systemd", [], [evidenceId]), outcome("ssh-persistence", [], [evidenceId]), outcome("shell-startup", [], [evidenceId])];

    const keywordOnly = engine.evaluate(task, [
      ...base,
      outcome("cron", [{ persistenceRef: "PERSIST-benign", path: "/etc/cron.d/backup", features: ["interpreter_execution"] }], [evidenceId]),
    ]);
    const strongContext = engine.evaluate(task, [
      ...base,
      outcome("cron", [{ persistenceRef: "PERSIST-risk", path: "/etc/cron.d/update", features: ["interpreter_execution", "temporary_execution"] }], [evidenceId]),
    ]);

    expect(keywordOnly).toMatchObject([{ status: "NO_FINDING", severity: "INFO" }]);
    expect(strongContext).toMatchObject([{ status: "SUSPICIOUS", severity: "MEDIUM", evidenceRefs: [evidenceId] }]);
    expect(store.getTask(task.taskId)?.coverage.linux_persistence).toBe("SUSPICIOUS");
    store.close();
  });

  it("有近期 Web 候选时不靠文件名定性；无候选且完整覆盖时才形成保守 NO_FINDING", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-web-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["webshell"];
    store.createTask(task);
    const engine = new DeterministicRuleEngine(store);
    const roots = outcome("web-roots", [{ webRootRef: "CAND-root", path: "/var/www/html" }]);

    expect(engine.evaluate(task, [
      ...preflight(), roots,
      outcome("web-candidates", [{ candidateRef: "CAND-shell", path: "/var/www/html/cmd.php" }]),
    ])).toEqual([]);
    expect(engine.evaluate(task, [...preflight(), roots, outcome("web-candidates")])).toMatchObject([
      { category: "webshell", status: "NO_FINDING" },
    ]);
    store.close();
  });

  it("结构异常进程缺少真实 Evidence 时抑制 SUSPICIOUS", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-triage-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["linux_intrusion_triage"];
    store.createTask(task);
    const engine = new DeterministicRuleEngine(store);
    const process = { processRef: "PROC-risk", pid: 8123, exePath: "/tmp/.hidden", signals: ["temporary_executable"] };

    expect(engine.evaluate(task, [...preflight(), outcome("suspicious-processes", [process], ["EV-missing"])] )).toEqual([]);
    expect(store.listAudit(task.taskId)).toEqual(expect.arrayContaining([
      expect.objectContaining({ event: "deterministic_rule_suppressed" }),
    ]));
    store.close();
  });

  it("安恒情报命中只形成需主机事实佐证的 SUSPICIOUS，不单独确认为失陷", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-rule-ti-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    task.checks = ["linux_intrusion_triage"];
    store.createTask(task);
    const evidenceId = "EV-rule-dbapp-ti";
    putEvidence(store, evidenceId, task.taskId);

    const result = new DeterministicRuleEngine(store).evaluate(task, [
      ...preflight(),
      outcome("network-threat-intel", [{
        ioc: "8.8.8.8", malicious: true, riskLevel: "high", threatTypes: ["botnet"], connectionRefs: ["SOCK-test"],
      }], [evidenceId]),
    ]);

    expect(result).toMatchObject([{
      category: "linux_intrusion_triage", status: "SUSPICIOUS", severity: "MEDIUM", evidenceRefs: [evidenceId],
    }]);
    expect(result[0]?.summary).toContain("外部情报是关联证据而非主机失陷的单独定论");
    expect(result[0]?.status).not.toBe("CONFIRMED");
    store.close();
  });
});
