import { afterEach, describe, expect, it, vi } from "vitest";
import { DbappThreatIntelClient } from "../../src/threat-intel/dbapp-client.js";
import { isPublicThreatIntelIp, parseNetworkEndpoint } from "../../src/threat-intel/network-ioc.js";
import { DBAPP_THREAT_INTEL_SOURCE } from "../../src/threat-intel/types.js";
import { testConfig } from "../helpers.js";

afterEach(() => vi.restoreAllMocks());

describe("安恒威胁情报接入", () => {
  it("使用官方端点和 X-API-Key，并在本地缓存相同 IOC", async () => {
    const fetcher = vi.fn(async (_input: unknown, init?: RequestInit) => {
      expect(String(_input)).toBe("https://ti.dbappsecurity.com.cn/oapi/v1/compromise-detection");
      expect(new Headers(init?.headers).get("X-API-Key")).toBe("nti-test_key_1234567890");
      expect(JSON.parse(String(init?.body))).toEqual({ iocs: "8.8.8.8" });
      return new Response(JSON.stringify({ code: 0, request_id: "REQ-test", data: { results: [{ ip: "8.8.8.8", is_malicious: true, risk_level: "high", threat_type: ["botnet"] }] } }), { status: 200, headers: { "content-type": "application/json" } });
    });
    const client = new DbappThreatIntelClient(testConfig("/tmp/huntwarden-ti-client").threatIntel, async () => "nti-test_key_1234567890", fetcher as unknown as typeof fetch);

    const first = await client.compromiseDetection(["8.8.8.8"]);
    const second = await client.compromiseDetection(["8.8.8.8"]);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(first).toMatchObject({ provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, requestId: "REQ-test" });
    expect(first.verdicts[0]).toMatchObject({ ioc: "8.8.8.8", malicious: true, riskLevel: "high", cached: false });
    expect(second.verdicts[0]?.cached).toBe(true);
  });

  it("只允许公网 IP 进入外部情报，并安全解析网络端点", () => {
    for (const address of ["10.0.0.1", "127.0.0.1", "2001:db8::1", "::ffff:127.0.0.1"]) expect(isPublicThreatIntelIp(address)).toBe(false);
    expect(isPublicThreatIntelIp("1.1.1.1")).toBe(true);
    expect(parseNetworkEndpoint("8.8.8.8:443")).toEqual({ ip: "8.8.8.8", port: 443 });
    expect(parseNetworkEndpoint("not-an-endpoint")).toBeUndefined();
  });
});
