import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import type { SecurityError } from "../../src/common/errors.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { assertCompatibleHelper, REQUIRED_HELPER_PROTOCOL_VERSION, type HostCapabilities } from "../../src/executor/operations.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createHostTools } from "../../src/tools/host/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function capabilities(overrides: Partial<HostCapabilities> = {}): HostCapabilities {
  return {
    protocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION,
    helper: { name: "huntwarden-helper", version: "0.4.0" },
    platform: { system: "Linux", release: "test", architecture: "x64", python: "3.11" },
    timezone: "Asia/Shanghai",
    utcOffsetSeconds: 28_800,
    hostTimeUtc: new Date().toISOString(),
    operations: ["get_capabilities"],
    artifactTransfer: { supported: true, protocolVersion: 1, maxBytes: 10 * 1024 * 1024 },
    features: { yara: true, javaAttach: false, tomcatProbe: false },
    partial: false,
    warnings: [],
    ...overrides,
  };
}

async function capabilityTool(capability: HostCapabilities) {
  const directory = await mkdtemp(join(tmpdir(), "huntwarden-capabilities-"));
  directories.push(directory);
  const store = await RuntimeStore.open(directory, "runtime.db");
  const task = testTask("SCAN");
  task.checks = ["webshell"];
  store.createTask(task);
  const executor = new FakeExecutor({ get_capabilities: () => capability });
  const tool = createHostTools({
    task, config: testConfig(directory), store, executor,
    approvals: new ApprovalService(store), evidence: new EvidenceStore(directory, store),
  }).find((item) => item.name === "get_capabilities")!;
  return { store, task, tool };
}

describe("Helper 协议兼容闸门", () => {
  it("接受与控制端一致的协议版本", () => {
    expect(() => assertCompatibleHelper(capabilities())).not.toThrow();
  });

  it("协议版本不一致时拒绝任务并给出升级指引", () => {
    const drifted = capabilities({ protocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION + 1 });
    let error: SecurityError | undefined;
    try {
      assertCompatibleHelper(drifted);
    } catch (thrown) {
      error = thrown as SecurityError;
    }
    expect(error?.code).toBe("UNSUPPORTED_ENVIRONMENT");
    expect(error?.message).toContain(`实际 ${REQUIRED_HELPER_PROTOCOL_VERSION + 1}`);
    expect(error?.message).toContain(`期望 ${REQUIRED_HELPER_PROTOCOL_VERSION}`);
    expect(error?.message).toContain("install-helper.sh");
    expect(error?.details).toMatchObject({
      actualProtocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION + 1,
      expectedProtocolVersion: REQUIRED_HELPER_PROTOCOL_VERSION,
    });
  });

  it("协议版本缺失或非整数视为不兼容", () => {
    const missing = capabilities({ protocolVersion: undefined as unknown as number });
    const fractional = capabilities({ protocolVersion: 1.5 });
    expect(() => assertCompatibleHelper(missing)).toThrow(/未上报有效的协议版本/);
    expect(() => assertCompatibleHelper(fractional)).toThrow(/未上报有效的协议版本/);
  });

  it("helper 版本缺失或空串视为不兼容", () => {
    const missing = capabilities({ helper: { name: "huntwarden-helper" } as unknown as HostCapabilities["helper"] });
    const blank = capabilities({ helper: { name: "huntwarden-helper", version: "   " } });
    expect(() => assertCompatibleHelper(missing)).toThrow(/未上报版本号/);
    expect(() => assertCompatibleHelper(blank)).toThrow(/未上报版本号/);
  });

  it("get_capabilities 工具在协议不兼容时直接失败，不产出能力结论", async () => {
    const { store, task, tool } = await capabilityTool(capabilities({ protocolVersion: 2 }));
    await expect(tool.execute("call-capabilities-drift", {}, undefined)).rejects.toMatchObject({ code: "UNSUPPORTED_ENVIRONMENT" });
    expect(store.listEvidence(task.taskId)).toHaveLength(0);
    store.close();
  });
});

describe("控制端与目标端时间偏差", () => {
  it("偏差在阈值内时不告警，并把时区事实固化进 summary 与 Evidence", async () => {
    const { store, task, tool } = await capabilityTool(capabilities());
    const result = await tool.execute("call-capabilities-in-sync", {}, undefined);
    const details = result.details as {
      status: string;
      warnings: string[];
      summary: { hostTime: { timezone: string; utcOffsetSeconds: number; skewSeconds: number }; evidenceId: string };
    };

    expect(details.status).toBe("success");
    expect(details.warnings).toEqual([]);
    expect(details.summary.hostTime).toMatchObject({ timezone: "Asia/Shanghai", utcOffsetSeconds: 28_800 });
    expect(Math.abs(details.summary.hostTime.skewSeconds)).toBeLessThanOrEqual(1);
    const evidence = store.getEvidence(task.taskId, details.summary.evidenceId);
    expect(evidence?.type).toBe("host_capabilities");
    expect(evidence?.metadata).toMatchObject({ hostTime: { timezone: "Asia/Shanghai", utcOffsetSeconds: 28_800 } });
    store.close();
  });

  it("偏差超过 300 秒时追加时间线可信度告警", async () => {
    const behind = new Date(Date.now() - 3_600_000).toISOString();
    const { store, tool } = await capabilityTool(capabilities({ hostTimeUtc: behind }));
    const result = await tool.execute("call-capabilities-skewed", {}, undefined);
    const details = result.details as { status: string; warnings: string[]; summary: { hostTime: { skewSeconds: number } } };

    expect(details.summary.hostTime.skewSeconds).toBeGreaterThanOrEqual(3_599);
    expect(details.warnings.some((warning) => warning.includes("时间线关联的可信度下降"))).toBe(true);
    expect(details.warnings.some((warning) => warning.includes("NTP"))).toBe(true);
    store.close();
  });

  it("目标端未上报主机时间时告警但不降级为 PARTIAL", async () => {
    const { store, tool } = await capabilityTool(capabilities({ hostTimeUtc: "", timezone: "" }));
    const result = await tool.execute("call-capabilities-no-time", {}, undefined);
    const details = result.details as {
      status: string;
      warnings: string[];
      summary: { hostTime: { timezone: string | null; hostTimeUtc: string | null; skewSeconds: number | null } };
    };

    expect(details.status).toBe("success");
    expect(details.summary.hostTime).toMatchObject({ timezone: null, hostTimeUtc: null, skewSeconds: null });
    expect(details.warnings.some((warning) => warning.includes("无法评估控制端与目标主机的时间偏差"))).toBe(true);
    store.close();
  });
});
