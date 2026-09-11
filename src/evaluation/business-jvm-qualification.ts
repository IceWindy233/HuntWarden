import { randomUUID } from "node:crypto";
import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import { digestObject } from "../common/json.js";
import type { ForensicVerb } from "../executor/protocol-v2-executor.js";
import { MANIFEST_VERSION, type HelperCapabilitiesV2, type WireRequest, type WireResponse, type WireSuccess } from "../protocol-v2/types.js";

const Strict = { additionalProperties: false } as const;
const EndpointSchema = Type.Object({
  method: Type.Optional(Type.Literal("GET")),
  url: Type.String({ minLength: 8, maxLength: 4096 }),
  expectedStatus: Type.Integer({ minimum: 100, maximum: 599 }),
  headersFromEnv: Type.Optional(Type.Record(Type.String({ minLength: 1, maxLength: 128 }), Type.String({ pattern: "^[A-Z][A-Z0-9_]{1,127}$" }))),
}, Strict);
export const BusinessJvmQualificationManifestSchema = Type.Object({
  schemaVersion: Type.Literal(1),
  suiteId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
  hostKeyOutOfBandVerified: Type.Literal(true),
  workload: Type.Object({
    fixture: Type.Literal(false),
    workloadKind: Type.Literal("BUSINESS_APPLICATION"),
    attestor: Type.String({ minLength: 1, maxLength: 256 }),
    attestedAt: Type.String({ minLength: 20, maxLength: 64 }),
    declarationSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
  }, Strict),
  jvmSelector: Type.Object({ commandContains: Type.String({ minLength: 1, maxLength: 512 }) }, Strict),
  traffic: Type.Object({
    endpoints: Type.Array(EndpointSchema, { minItems: 1, maxItems: 32 }),
    concurrency: Type.Integer({ minimum: 1, maximum: 64 }),
    baselineRequests: Type.Integer({ minimum: 20, maximum: 10_000 }),
    minLoadedRequests: Type.Integer({ minimum: 100, maximum: 1_000_000 }),
    requestTimeoutMs: Type.Integer({ minimum: 100, maximum: 120_000 }),
    pauseMs: Type.Integer({ minimum: 0, maximum: 10_000 }),
    maxResponseBytes: Type.Integer({ minimum: 1, maximum: 16_777_216 }),
    maxFailureRate: Type.Number({ minimum: 0, maximum: 0.01 }),
    maxLoadedP95Ms: Type.Integer({ minimum: 1, maximum: 120_000 }),
    maxP95RegressionRatio: Type.Number({ minimum: 1, maximum: 100 }),
  }, Strict),
  attach: Type.Object({
    attempts: Type.Integer({ minimum: 12, maximum: 100 }),
    maxWallTimeMs: Type.Integer({ minimum: 1_000, maximum: 600_000 }),
    requiredComponents: Type.Array(Type.Object({
      componentKind: Type.String({ minLength: 1, maxLength: 128 }),
      className: Type.String({ minLength: 1, maxLength: 512 }),
      mappingContains: Type.Optional(Type.String({ minLength: 1, maxLength: 512 })),
    }, Strict), { minItems: 1, maxItems: 100 }),
  }, Strict),
}, Strict);

export type BusinessJvmQualificationManifest = Static<typeof BusinessJvmQualificationManifestSchema>;

export interface BusinessJvmRemote {
  getCapabilitiesV2(): Promise<HelperCapabilitiesV2>;
  invokeV2(verb: ForensicVerb, request: WireRequest): Promise<WireResponse>;
}

export interface BusinessJvmQualificationInput {
  manifest: BusinessJvmQualificationManifest;
  manifestSha256: string;
  remote: BusinessJvmRemote;
  commit: string;
  expectedHelperSha256: string;
  fetch?: typeof globalThis.fetch;
  env?: NodeJS.ProcessEnv;
  evaluatedAt?: string;
}

export interface BusinessJvmQualificationResult {
  schemaVersion: 2;
  status: "PASS" | "FAIL";
  commit: string;
  manifestVersion: string;
  evaluatedAt: string;
  sourceManifestSha256: string;
  helperSha256: string | null;
  hostKeyOutOfBandVerified: true;
  environment: { fixture: false; workloadKind: "BUSINESS_APPLICATION"; workloadDeclarationSha256: string; attestorDigest: string };
  traffic: {
    concurrency: number;
    baselineRequests: number;
    loadedRequests: number;
    failures: string[];
    failureRate: number;
    baselineP95Ms: number | null;
    loadedP95Ms: number | null;
    loadedMaxMs: number | null;
    postAttachHealthVerified: boolean;
  };
  attach: {
    attempts: number;
    componentMisses: number;
    invalidProbeCosts: number;
    incompleteInventories: number;
    requiredComponentDigests: string[];
    wallTimeMs: number[];
    maxWallTimeMs: number | null;
  };
  identityStable: boolean;
  failures: string[];
}

export function parseBusinessJvmQualificationManifest(value: unknown): BusinessJvmQualificationManifest {
  const errors = [...Value.Errors(BusinessJvmQualificationManifestSchema, value)];
  if (errors.length > 0) throw new Error(`真实业务 JVM 验收清单无效:\n${errors.map((item) => `${item.instancePath || "/"}: ${item.message}`).join("\n")}`);
  const manifest = structuredClone(value) as BusinessJvmQualificationManifest;
  if (!Number.isFinite(Date.parse(manifest.workload.attestedAt))) throw new Error("真实业务 JVM 工作负载 attestedAt 不是有效时间");
  for (const endpoint of manifest.traffic.endpoints) {
    let parsed: URL;
    try { parsed = new URL(endpoint.url); } catch { throw new Error("真实业务 JVM 流量端点 URL 无效"); }
    if (!(["http:", "https:"] as string[]).includes(parsed.protocol)) throw new Error("真实业务 JVM 流量端点只允许 HTTP/HTTPS");
    if (parsed.username || parsed.password) throw new Error("流量端点 URL 不能内嵌凭据；请使用 headersFromEnv");
  }
  return manifest;
}

function percentile95(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)] ?? 0);
}

async function boundedBody(response: Response, maximum: number): Promise<void> {
  if (!response.body) return;
  const reader = response.body.getReader();
  let bytes = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) return;
      bytes += next.value.byteLength;
      if (bytes > maximum) throw new Error("RESPONSE_TOO_LARGE");
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

function failureCode(error: unknown): string {
  if (error instanceof DOMException && error.name === "TimeoutError") return "REQUEST_TIMEOUT";
  if (error instanceof Error && error.message === "RESPONSE_TOO_LARGE") return error.message;
  return `REQUEST_${error instanceof Error && /^[A-Za-z][A-Za-z0-9]*$/.test(error.name) ? error.name.toUpperCase() : "FAILED"}`;
}

function componentMatches(object: WireSuccess["objects"][number], required: BusinessJvmQualificationManifest["attach"]["requiredComponents"][number]): boolean {
  if (object.namespace !== "java_component" || object.fields.componentKind !== required.componentKind || object.fields.className !== required.className) return false;
  if (!required.mappingContains) return true;
  const values = [object.fields.name, ...(Array.isArray(object.fields.mappings) ? object.fields.mappings : [])].map(String);
  return values.some((value) => value.includes(required.mappingContains!));
}

export async function runBusinessJvmQualification(input: BusinessJvmQualificationInput): Promise<BusinessJvmQualificationResult> {
  const failures: string[] = [];
  const manifest = input.manifest;
  const fetchImpl = input.fetch ?? globalThis.fetch;
  const env = input.env ?? process.env;
  const capabilities = await input.remote.getCapabilitiesV2();
  if (!/^[a-f0-9]{40}$/.test(input.commit)) failures.push("提交不是完整 40 位 Git SHA-1");
  if (!/^[a-f0-9]{64}$/.test(input.manifestSha256)) failures.push("验收清单 SHA-256 无效");
  if (capabilities.manifestVersion !== MANIFEST_VERSION) failures.push(`Helper Manifest 版本不一致: ${capabilities.manifestVersion}`);
  if (capabilities.helper.version !== MANIFEST_VERSION) failures.push(`Helper 版本不一致: ${capabilities.helper.version}`);
  if (!/^[a-f0-9]{64}$/.test(input.expectedHelperSha256) || capabilities.helper.sha256 !== input.expectedHelperSha256) failures.push("目标 Helper 摘要与当前源码不一致");
  if (!capabilities.probes.includes("jvm.tomcat.inventory")) failures.push("目标 Helper 不支持 jvm.tomcat.inventory");
  let sequence = 0;
  const invoke = async (verb: ForensicVerb, params: Record<string, unknown>, probeCalls = 0): Promise<WireSuccess> => {
    const requestId = `BIZJVM-${randomUUID()}-${++sequence}`;
    const response = await input.remote.invokeV2(verb, {
      protocolVersion: 2,
      requestId,
      epochId: `EPOCH-BIZJVM-${input.commit.slice(0, 12)}`,
      deadlineMs: manifest.attach.maxWallTimeMs,
      reservation: { reservationId: `BRES-${requestId}`, estimate: { remoteCalls: 1, nodes: 10_000, bytes: 8 * 1024 * 1024, wallTimeMs: manifest.attach.maxWallTimeMs, probeCalls } },
      params,
    });
    if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message ?? "未提供详情"}`);
    return response;
  };
  const enumerateJvms = async (): Promise<WireSuccess["objects"]> => {
    const objects: WireSuccess["objects"] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 100; page += 1) {
      const result = await invoke("enumerate", { namespace: "jvm", fields: ["pid", "command", "attachSupported", "container"], limit: 500, ...(cursor ? { cursor } : {}) });
      objects.push(...result.objects);
      cursor = result.cursor;
      if (!cursor) return objects;
    }
    throw new Error("JVM 枚举超过 100 页安全上限");
  };
  const before = await enumerateJvms();
  const selected = before.filter((item) => item.namespace === "jvm" && String(item.fields.command ?? "").includes(manifest.jvmSelector.commandContains));
  if (selected.length !== 1) failures.push(`JVM selector 必须唯一命中，实际 ${selected.length}`);
  const jvm = selected[0];
  if (jvm?.fields.attachSupported !== true) failures.push("目标 JVM 不支持 Attach");
  const binding = jvm ? { namespace: "jvm", identity: jvm.identity, locator: {} } : undefined;

  let endpointIndex = 0;
  const baselineLatencies: number[] = [];
  const loadedLatencies: number[] = [];
  const trafficFailures: string[] = [];
  const requestOnce = async (target: number[]) => {
    const endpoint = manifest.traffic.endpoints[endpointIndex++ % manifest.traffic.endpoints.length]!;
    const headers = new Headers();
    for (const [header, envName] of Object.entries(endpoint.headersFromEnv ?? {})) {
      const secret = env[envName];
      if (!secret) { trafficFailures.push(`MISSING_HEADER_ENV:${envName}`); return; }
      headers.set(header, secret);
    }
    const startedAt = performance.now();
    try {
      const response = await fetchImpl(endpoint.url, { method: endpoint.method ?? "GET", headers, redirect: "error", signal: AbortSignal.timeout(manifest.traffic.requestTimeoutMs) });
      await boundedBody(response, manifest.traffic.maxResponseBytes);
      if (response.status !== endpoint.expectedStatus) trafficFailures.push(`HTTP_STATUS_${response.status}`);
    } catch (error) {
      trafficFailures.push(failureCode(error));
    } finally {
      target.push(performance.now() - startedAt);
    }
  };
  for (let index = 0; index < manifest.traffic.baselineRequests; index += 1) await requestOnce(baselineLatencies);

  let running = true;
  const workers = Array.from({ length: manifest.traffic.concurrency }, async () => {
    while (running) {
      await requestOnce(loadedLatencies);
      if (manifest.traffic.pauseMs > 0) await new Promise((resolve) => setTimeout(resolve, manifest.traffic.pauseMs));
      else await new Promise<void>((resolve) => setImmediate(resolve));
    }
  });
  let componentMisses = 0;
  let invalidProbeCosts = 0;
  let incompleteInventories = 0;
  const wallTimeMs: number[] = [];
  try {
    if (binding) {
      for (let attempt = 0; attempt < manifest.attach.attempts; attempt += 1) {
        const startedAt = performance.now();
        try {
          const inventory = await invoke("probe", { ...binding, probeKind: "jvm.tomcat.inventory", parameters: {} }, 1);
          if (inventory.cost.probeCalls !== 1 || inventory.cost.remoteCalls !== 1) invalidProbeCosts += 1;
          if (inventory.gaps.length > 0) incompleteInventories += 1;
          for (const required of manifest.attach.requiredComponents) if (!inventory.objects.some((item) => componentMatches(item, required))) componentMisses += 1;
        } catch {
          componentMisses += manifest.attach.requiredComponents.length;
          incompleteInventories += 1;
          failures.push(`Attach ${attempt + 1} 执行失败`);
        } finally {
          wallTimeMs.push(Math.round(performance.now() - startedAt));
        }
      }
    }
    const loadDeadline = Date.now() + Math.max(30_000, manifest.traffic.requestTimeoutMs * 2);
    while (loadedLatencies.length < manifest.traffic.minLoadedRequests && Date.now() < loadDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  } finally {
    running = false;
    await Promise.all(workers);
  }
  await requestOnce(loadedLatencies);
  const after = await enumerateJvms();
  const identityStable = Boolean(jvm && after.some((item) => item.namespace === "jvm" && digestObject(item.identity) === digestObject(jvm.identity)));
  const baselineP95 = percentile95(baselineLatencies);
  const loadedP95 = percentile95(loadedLatencies);
  const loadedMax = loadedLatencies.length > 0 ? Math.round(Math.max(...loadedLatencies)) : null;
  const failureRate = trafficFailures.length / Math.max(1, baselineLatencies.length + loadedLatencies.length);
  if (loadedLatencies.length < manifest.traffic.minLoadedRequests) failures.push(`业务负载请求不足: ${loadedLatencies.length}/${manifest.traffic.minLoadedRequests}`);
  if (failureRate > manifest.traffic.maxFailureRate) failures.push(`业务请求失败率超限: ${failureRate}/${manifest.traffic.maxFailureRate}`);
  if (loadedP95 === null || loadedP95 > manifest.traffic.maxLoadedP95Ms) failures.push(`负载 P95 超限: ${loadedP95 ?? "N/A"}/${manifest.traffic.maxLoadedP95Ms}`);
  if (baselineP95 === null || loadedP95 === null || loadedP95 > Math.max(1, baselineP95) * manifest.traffic.maxP95RegressionRatio) failures.push("负载 P95 相对基线退化超限");
  if (wallTimeMs.some((value) => value > manifest.attach.maxWallTimeMs)) failures.push("至少一次 Attach 超过冻结耗时门槛");
  if (componentMisses > 0) failures.push(`组件漏报 ${componentMisses} 次`);
  if (invalidProbeCosts > 0) failures.push(`Probe 成本结算无效 ${invalidProbeCosts} 次`);
  if (incompleteInventories > 0) failures.push(`Attach inventory 存在 ${incompleteInventories} 次 Gap`);
  if (!identityStable) failures.push("Attach 前后 JVM 稳定身份不一致");
  const postAttachHealthVerified = trafficFailures.length === 0 && loadedLatencies.length > 0;
  return {
    schemaVersion: 2,
    status: failures.length === 0 ? "PASS" : "FAIL",
    commit: input.commit,
    manifestVersion: capabilities.manifestVersion,
    evaluatedAt: input.evaluatedAt ?? new Date().toISOString(),
    sourceManifestSha256: input.manifestSha256,
    helperSha256: capabilities.helper.sha256 ?? null,
    hostKeyOutOfBandVerified: true,
    environment: { fixture: false, workloadKind: "BUSINESS_APPLICATION", workloadDeclarationSha256: manifest.workload.declarationSha256, attestorDigest: digestObject(manifest.workload.attestor) },
    traffic: { concurrency: manifest.traffic.concurrency, baselineRequests: baselineLatencies.length, loadedRequests: loadedLatencies.length, failures: trafficFailures.slice(0, 100), failureRate, baselineP95Ms: baselineP95, loadedP95Ms: loadedP95, loadedMaxMs: loadedMax, postAttachHealthVerified },
    attach: { attempts: wallTimeMs.length, componentMisses, invalidProbeCosts, incompleteInventories, requiredComponentDigests: manifest.attach.requiredComponents.map(digestObject), wallTimeMs, maxWallTimeMs: wallTimeMs.length > 0 ? Math.max(...wallTimeMs) : null },
    identityStable,
    failures,
  };
}
