import { describe, expect, it, vi } from "vitest";
import { parseBusinessJvmQualificationManifest, runBusinessJvmQualification, type BusinessJvmQualificationManifest, type BusinessJvmRemote } from "../../src/evaluation/business-jvm-qualification.js";
import type { WireSuccess } from "../../src/protocol-v2/types.js";

const helperSha256 = "e".repeat(64);

function manifest(): BusinessJvmQualificationManifest {
  return parseBusinessJvmQualificationManifest({
    schemaVersion: 1,
    suiteId: "business-jvm-release",
    hostKeyOutOfBandVerified: true,
    workload: { fixture: false, workloadKind: "BUSINESS_APPLICATION", attestor: "application-owner", attestedAt: "2026-09-08T00:00:00.000Z", declarationSha256: "d".repeat(64) },
    jvmSelector: { commandContains: "business-application.jar" },
    traffic: {
      endpoints: [{ url: "https://service.example/health", expectedStatus: 200 }], concurrency: 4, baselineRequests: 20, minLoadedRequests: 100,
      requestTimeoutMs: 1_000, pauseMs: 0, maxResponseBytes: 1_024, maxFailureRate: 0, maxLoadedP95Ms: 1_000, maxP95RegressionRatio: 10,
    },
    attach: { attempts: 12, maxWallTimeMs: 5_000, requiredComponents: [{ componentKind: "spring_controller", className: "com.example.HealthController", mappingContains: "/health" }] },
  });
}

function success(requestId: string, objects: WireSuccess["objects"], probe = false): WireSuccess {
  return { protocolVersion: 2, requestId, status: "SUCCESS", objects, edges: [], cost: { remoteCalls: 1, nodes: objects.length, bytes: 100, wallTimeMs: 1, probeCalls: probe ? 1 : 0 }, gaps: [] };
}

function remote(component = true): BusinessJvmRemote {
  return {
    getCapabilitiesV2: async () => ({ protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "huntwarden-helper-v2", version: "3.0.0", sha256: helperSha256 }, namespaces: {}, matchers: ["literal"], probes: ["jvm.tomcat.inventory"], verbs: ["enumerate", "probe"], limits: { maxObjects: 500, maxOutputBytes: 1_000_000, maxReadBytes: 1_000_000, maxCollectBytes: 1_000_000 } }),
    invokeV2: async (verb, request) => verb === "enumerate"
      ? success(request.requestId, [{ namespace: "jvm", identity: { bootId: "boot", pid: 100, startTicks: "10" }, fields: { command: "java -jar business-application.jar", attachSupported: true }, observedAt: "2026-09-08T00:00:00.000Z", consistency: "OBJECT_STABLE" }])
      : success(request.requestId, component ? [{ namespace: "java_component", identity: { id: "health" }, fields: { componentKind: "spring_controller", className: "com.example.HealthController", mappings: ["mapping:GET /health"] }, observedAt: "2026-09-08T00:00:00.000Z", consistency: "OBJECT_STABLE" }] : [], true),
  };
}

describe("真实业务 JVM 验收执行器", () => {
  it("在业务流量下完成至少 12 次 Attach、组件和身份核验", async () => {
    const result = await runBusinessJvmQualification({
      manifest: manifest(), manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: remote(), commit: "c".repeat(40),
      fetch: async () => new Response("ok", { status: 200 }), env: {}, evaluatedAt: "2026-09-08T01:00:00.000Z",
    });
    expect(result.status, result.failures.join("\n")).toBe("PASS");
    expect(result.attach).toMatchObject({ attempts: 12, componentMisses: 0, invalidProbeCosts: 0, incompleteInventories: 0 });
    expect(result.traffic.loadedRequests).toBeGreaterThanOrEqual(100);
    expect(result.identityStable).toBe(true);
  });

  it("相同排队业务在基线和 Attach 流量下不产生虚假的延迟退化", async () => {
    vi.useFakeTimers({ toFake: ["Date", "performance", "setTimeout", "clearTimeout", "setImmediate", "clearImmediate"] });
    try {
      const input = manifest();
      input.traffic.baselineRequests = 21;
      input.traffic.pauseMs = 5;
      input.traffic.maxP95RegressionRatio = 2;
      let serviceAvailableAt = 0;
      const pending = runBusinessJvmQualification({
        manifest: input, manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: remote(), commit: "c".repeat(40), env: {},
        fetch: async () => {
          const startedAt = performance.now();
          serviceAvailableAt = Math.max(startedAt, serviceAvailableAt) + 5;
          const { promise, resolve } = Promise.withResolvers<void>();
          setTimeout(resolve, serviceAvailableAt - startedAt);
          await promise;
          return new Response(null, { status: 200 });
        },
      });
      await vi.runAllTimersAsync();
      const result = await pending;
      expect(result.status, result.failures.join("\n")).toBe("PASS");
      expect(result.traffic.baselineRequests).toBe(21);
    } finally {
      vi.useRealTimers();
    }
  });

  it("组件漏报会失败关闭", async () => {
    const result = await runBusinessJvmQualification({
      manifest: manifest(), manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: remote(false), commit: "c".repeat(40),
      fetch: async () => new Response("ok", { status: 200 }), env: {},
    });
    expect(result.status).toBe("FAIL");
    expect(result.attach.componentMisses).toBe(12);
  });

  it("HTTP 200 中的业务认证错误不能通过流量验收", async () => {
    const input = manifest();
    input.traffic.endpoints[0]!.expectedJson = [{ path: ["code"], equals: 200 }, { path: ["rows"], minItems: 1 }];
    const result = await runBusinessJvmQualification({
      manifest: input, manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: remote(), commit: "c".repeat(40),
      fetch: async () => Response.json({ code: 401, rows: [{ userName: "operator" }] }), env: {},
    });
    expect(result.status).toBe("FAIL");
    expect(result.traffic.failureRate).toBe(1);
    expect(result.traffic.postAttachHealthVerified).toBe(false);
  });

  it("选择器命中多个 JVM 时不尝试任意目标的 Attach", async () => {
    const ambiguous = remote();
    const invoke = ambiguous.invokeV2;
    ambiguous.invokeV2 = async (verb, request) => {
      const response = await invoke(verb, request);
      if (verb === "enumerate" && response.status !== "ERROR") {
        response.objects.push({ ...response.objects[0]!, identity: { bootId: "boot", pid: 101, startTicks: "11" } });
      }
      return response;
    };
    const result = await runBusinessJvmQualification({
      manifest: manifest(), manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: ambiguous, commit: "c".repeat(40),
      fetch: async () => new Response(null, { status: 200 }), env: {},
    });
    expect(result.status).toBe("FAIL");
    expect(result.attach.attempts).toBe(0);
    expect(result.identityStable).toBe(false);
  });

  it("大请求总体仍能生成完整延迟统计", async () => {
    const input = manifest();
    input.traffic.minLoadedRequests = 200_000;
    const result = await runBusinessJvmQualification({
      manifest: input, manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, remote: remote(), commit: "c".repeat(40),
      fetch: async () => new Response(null, { status: 200 }), env: {},
    });
    expect(result.traffic.loadedRequests).toBeGreaterThanOrEqual(200_000);
    expect(Number.isFinite(result.traffic.loadedMaxMs)).toBe(true);
    expect(result.traffic.loadedMaxMs!).toBeGreaterThanOrEqual(result.traffic.loadedP95Ms!);
    expect(result.traffic.failureRate).toBe(0);
  }, 15_000);

  it("拒绝 URL 内嵌凭据", () => {
    const value = manifest();
    value.traffic.endpoints[0]!.url = "https://user:secret@service.example/health";
    expect(() => parseBusinessJvmQualificationManifest(value)).toThrow(/不能内嵌凭据/);
  });
});
