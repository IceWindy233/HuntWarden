import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { DbappThreatIntelClient } from "../../src/threat-intel/dbapp-client.js";
import { attachConnectionReferences, isPublicThreatIntelIp } from "../../src/threat-intel/network-ioc.js";
import { DBAPP_THREAT_INTEL_SOURCE, type ThreatIntelClient } from "../../src/threat-intel/types.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { FakeExecutor } from "../../src/executor/fake-executor.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { createThreatIntelTools } from "../../src/tools/threat-intel/tools.js";
import { testConfig, testTask } from "../helpers.js";

const directories: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("安恒威胁情报接入", () => {
  it("使用官方端点和 X-API-Key，并在本地缓存相同 IOC", async () => {
    const fetcher = vi.fn(async (_input: unknown, init?: RequestInit) => {
      expect(String(_input)).toBe("https://ti.dbappsecurity.com.cn/oapi/v1/compromise-detection");
      expect(new Headers(init?.headers).get("X-API-Key")).toBe("nti-test_key_1234567890");
      expect(JSON.parse(String(init?.body))).toEqual({ iocs: "8.8.8.8" });
      return new Response(JSON.stringify({
        code: 0,
        request_id: "REQ-test",
        data: { results: [{ ip: "8.8.8.8", is_malicious: true, risk_level: "high", threat_type: ["botnet"] }] },
      }), { status: 200, headers: { "content-type": "application/json" } });
    });
    const config = testConfig("/tmp/huntwarden-ti-client").threatIntel;
    const client = new DbappThreatIntelClient(config, async () => "nti-test_key_1234567890", fetcher as unknown as typeof fetch);

    const first = await client.compromiseDetection(["8.8.8.8"]);
    const second = await client.compromiseDetection(["8.8.8.8"]);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(first).toMatchObject({ provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, requestId: "REQ-test" });
    expect(first.verdicts[0]).toMatchObject({ ioc: "8.8.8.8", malicious: true, riskLevel: "high", cached: false });
    expect(second.verdicts[0]?.cached).toBe(true);
  });

  it("只为公网远端连接创建任务内 SOCK 引用", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-ti-refs-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask();
    store.createTask(task);

    const result = attachConnectionReferences(store, task.taskId, [
      { protocol: "tcp", local: "10.0.0.2:50000", remote: "8.8.8.8:443", state: "ESTABLISHED", processRef: "PROC-test" },
      { protocol: "tcp", local: "10.0.0.2:50001", remote: "127.0.0.1:8080", state: "ESTABLISHED" },
      { protocol: "tcp", local: "0.0.0.0:22", remote: "0.0.0.0:0", state: "LISTEN" },
    ]);

    expect(result.refs).toHaveLength(1);
    expect(result.refs[0]).toMatch(/^SOCK-/);
    expect(result.items[0]).toMatchObject({ remoteIp: "8.8.8.8", threatIntelEligible: true });
    expect(result.items[1]).toMatchObject({ threatIntelEligible: false });
    expect(isPublicThreatIntelIp("10.0.0.1")).toBe(false);
    expect(isPublicThreatIntelIp("2001:db8::1")).toBe(false);
    expect(isPublicThreatIntelIp("::ffff:127.0.0.1")).toBe(false);
    expect(isPublicThreatIntelIp("1.1.1.1")).toBe(true);
    store.close();
  });

  it("情报工具只查询任务内引用并固化来源 Evidence", async () => {
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-ti-tool-"));
    directories.push(directory);
    const store = await RuntimeStore.open(directory, "runtime.db");
    const task = testTask("SCAN");
    task.checks = ["linux_intrusion_triage"];
    store.createTask(task);
    const config = testConfig(directory);
    config.threatIntel.enabled = true;
    const references = attachConnectionReferences(store, task.taskId, [
      { protocol: "tcp", local: "10.0.0.2:50000", remote: "8.8.8.8:443", state: "ESTABLISHED" },
    ]);
    const queried: string[][] = [];
    const threatIntel: ThreatIntelClient = {
      compromiseDetection: async (iocs) => {
        queried.push([...iocs]);
        return { provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, requestId: "REQ-tool", queriedAt: new Date().toISOString(), warnings: [], verdicts: iocs.map((ioc) => ({
          ioc, iocType: "ip", malicious: true, riskLevel: "high", confidence: 0.9, threatTypes: ["botnet"], apt: false,
          hackerGroups: [], attackEvents: [], malwareFamilies: [], cached: false, source: DBAPP_THREAT_INTEL_SOURCE,
        })) };
      },
      batchFileInfo: async () => { throw new Error("不应调用"); },
    };
    const tools = createThreatIntelTools({ task, config, store, executor: new FakeExecutor(), approvals: new ApprovalService(store), evidence: new EvidenceStore(directory, store), threatIntel });
    const tool = tools.find((candidate) => candidate.name === "enrich_observed_network_iocs")!;

    const result = await tool.execute("call-ti-network", { connectionRefs: references.refs });

    expect(queried).toEqual([["8.8.8.8"]]);
    expect(result.details).toMatchObject({ status: "success", summary: { source: DBAPP_THREAT_INTEL_SOURCE, malicious: 1 } });
    const evidence = store.listEvidence(task.taskId);
    expect(evidence).toHaveLength(1);
    expect(evidence[0]).toMatchObject({ type: "dbapp_network_threat_intel", source: DBAPP_THREAT_INTEL_SOURCE });
    expect(JSON.stringify(result)).not.toContain("nti-");
    store.close();
  });
});
