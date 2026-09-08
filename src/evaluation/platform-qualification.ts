import { createHash, randomUUID } from "node:crypto";
import { dirname } from "node:path";
import { Type, type Static } from "typebox";
import { Value } from "typebox/value";
import { digestObject } from "../common/json.js";
import type { ProtocolV2Executor } from "../executor/protocol-v2-executor.js";
import { MANIFEST_VERSION, type HelperCapabilitiesV2, type WireRequest, type WireSuccess } from "../protocol-v2/types.js";

export const PLATFORM_IDS = [
  "ubuntu-24.04-arm64",
  "ubuntu-24.04-x86_64",
  "debian-12-systemd-x86_64",
  "rocky-or-alma-9-x86_64-selinux-enforcing",
  "amazon-linux-2023-x86_64",
] as const;
export type PlatformId = typeof PLATFORM_IDS[number];
const Strict = { additionalProperties: false } as const;
export const PlatformQualificationManifestSchema = Type.Object({
  schemaVersion: Type.Literal(1),
  suiteId: Type.String({ minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9._-]+$" }),
  platformId: Type.Union([
    Type.Literal("ubuntu-24.04-arm64"),
    Type.Literal("ubuntu-24.04-x86_64"),
    Type.Literal("debian-12-systemd-x86_64"),
    Type.Literal("rocky-or-alma-9-x86_64-selinux-enforcing"),
    Type.Literal("amazon-linux-2023-x86_64"),
  ]),
  hostKeyOutOfBandVerified: Type.Literal(true),
  officialImage: Type.Object({
    official: Type.Literal(true),
    source: Type.String({ minLength: 1, maxLength: 1024 }),
    imageId: Type.String({ minLength: 1, maxLength: 1024 }),
    imageDigest: Type.String({ pattern: "^[a-f0-9]{64}$" }),
    attestor: Type.String({ minLength: 1, maxLength: 256 }),
    attestedAt: Type.String({ minLength: 20, maxLength: 64 }),
  }, Strict),
  evidenceCandidates: Type.Array(Type.String({ pattern: "^/[A-Za-z0-9_./+-]+$", maxLength: 4096 }), { minItems: 1, maxItems: 16, uniqueItems: true }),
  maxEvidenceBytes: Type.Integer({ minimum: 1, maximum: 16_777_216 }),
}, Strict);
export type PlatformQualificationManifest = Static<typeof PlatformQualificationManifestSchema>;

export interface PlatformQualificationInput {
  manifest: PlatformQualificationManifest;
  manifestSha256: string;
  commit: string;
  expectedHelperSha256: string;
  createRemote(): Promise<ProtocolV2Executor> | ProtocolV2Executor;
  evaluatedAt?: string;
}

export interface PlatformQualificationResult {
  schemaVersion: 2;
  status: "PASS" | "FAIL";
  commit: string;
  manifestVersion: string;
  evaluatedAt: string;
  sourceManifestSha256: string;
  helperSha256: string | null;
  hostKeyOutOfBandVerified: true;
  environment: {
    platformId: PlatformId;
    distribution: string;
    version: string;
    architecture: string;
    kernel: string;
    timezone: string;
    init: string;
    selinux: string;
    officialImageDigest: string;
    imageIdentityDigest: string;
    imageAttestorDigest: string;
  };
  capabilities: { verified: boolean; digest: string; namespaces: number; verbs: number; matchers: string[]; probes: string[] };
  evidence: { verified: boolean; bytes: number; sha256: string | null; sourceIdentityDigest: string | null };
  recovery: { verified: boolean; reconnects: number; hostIdentityStable: boolean; capabilitiesStable: boolean };
  cleanup: { verified: boolean; releaseRequiredAfterDownload: boolean; finalAbsent: boolean };
  failures: string[];
}

interface ExpectedPlatform { distributions: string[]; versionPrefix: string; architectures: string[]; init: "systemd"; selinux?: "Enforcing" }
const expected: Record<PlatformId, ExpectedPlatform> = {
  "ubuntu-24.04-arm64": { distributions: ["ubuntu"], versionPrefix: "24.04", architectures: ["aarch64", "arm64"], init: "systemd" },
  "ubuntu-24.04-x86_64": { distributions: ["ubuntu"], versionPrefix: "24.04", architectures: ["x86_64", "amd64"], init: "systemd" },
  "debian-12-systemd-x86_64": { distributions: ["debian"], versionPrefix: "12", architectures: ["x86_64", "amd64"], init: "systemd" },
  "rocky-or-alma-9-x86_64-selinux-enforcing": { distributions: ["rocky", "almalinux"], versionPrefix: "9", architectures: ["x86_64", "amd64"], init: "systemd", selinux: "Enforcing" },
  "amazon-linux-2023-x86_64": { distributions: ["amzn"], versionPrefix: "2023", architectures: ["x86_64", "amd64"], init: "systemd" },
};

export function parsePlatformQualificationManifest(value: unknown): PlatformQualificationManifest {
  const errors = [...Value.Errors(PlatformQualificationManifestSchema, value)];
  if (errors.length > 0) throw new Error(`平台验收清单无效:\n${errors.map((item) => `${item.instancePath || "/"}: ${item.message}`).join("\n")}`);
  const manifest = structuredClone(value) as PlatformQualificationManifest;
  if (!Number.isFinite(Date.parse(manifest.officialImage.attestedAt))) throw new Error("官方镜像 attestedAt 不是有效时间");
  for (const candidate of manifest.evidenceCandidates) {
    if (candidate.includes("/../") || candidate.endsWith("/..") || candidate.includes("//")) throw new Error("Evidence 候选路径不能包含目录穿越或空段");
  }
  return manifest;
}

function addFailure(condition: unknown, failures: string[], message: string): boolean {
  if (!condition) failures.push(message);
  return Boolean(condition);
}

async function invoke(remote: ProtocolV2Executor, verb: "enumerate" | "collect", params: Record<string, unknown>, commit: string, sequence: number): Promise<WireSuccess> {
  const requestId = `PLATFORM-${randomUUID()}-${sequence}`;
  const request: WireRequest = {
    protocolVersion: 2,
    requestId,
    epochId: `EPOCH-PLATFORM-${commit.slice(0, 12)}`,
    deadlineMs: 60_000,
    reservation: { reservationId: `BRES-${requestId}`, estimate: { remoteCalls: 1, nodes: 5_000, bytes: 16_777_216, wallTimeMs: 60_000, probeCalls: 0 } },
    params,
  };
  const response = await remote.invokeV2(verb, request);
  if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message ?? "未提供详情"}`);
  return response;
}

async function readHost(remote: ProtocolV2Executor, commit: string, sequence: number): Promise<WireSuccess["objects"][number] | undefined> {
  const response = await invoke(remote, "enumerate", { namespace: "host", fields: ["bootId", "distribution", "distributionVersion", "release", "architecture", "timezone", "initSystem", "selinuxMode"], limit: 1 }, commit, sequence);
  return response.status === "SUCCESS" && response.gaps.length === 0 ? response.objects[0] : undefined;
}

export async function runPlatformQualification(input: PlatformQualificationInput): Promise<PlatformQualificationResult> {
  const failures: string[] = [];
  const manifest = input.manifest;
  addFailure(/^[a-f0-9]{40}$/.test(input.commit), failures, "提交不是完整 40 位 Git SHA-1");
  addFailure(/^[a-f0-9]{64}$/.test(input.manifestSha256), failures, "平台验收清单 SHA-256 无效");
  const first = await input.createRemote();
  let second: ProtocolV2Executor | undefined;
  let capabilities: HelperCapabilitiesV2 | undefined;
  let host: WireSuccess["objects"][number] | undefined;
  let transferBytes = 0;
  let transferSha: string | null = null;
  let sourceIdentityDigest: string | null = null;
  let releaseRequiredAfterDownload = false;
  let finalAbsent = false;
  let reconnectHost: WireSuccess["objects"][number] | undefined;
  let reconnectCapabilities: HelperCapabilitiesV2 | undefined;
  try {
    capabilities = await first.getCapabilitiesV2();
    addFailure(capabilities.manifestVersion === MANIFEST_VERSION && capabilities.helper.version === MANIFEST_VERSION, failures, "Helper/Manifest 版本不一致");
    addFailure(/^[a-f0-9]{64}$/.test(input.expectedHelperSha256) && capabilities.helper.sha256 === input.expectedHelperSha256, failures, "目标 Helper 摘要与当前源码不一致");
    addFailure(PLATFORM_IDS.includes(manifest.platformId), failures, "平台 ID 不受支持");
    host = await readHost(first, input.commit, 1);
    addFailure(Boolean(host), failures, "host 观测缺失或不完整");
    const observed = host?.fields ?? {};
    const wanted = expected[manifest.platformId];
    addFailure(wanted.distributions.includes(String(observed.distribution).toLowerCase()), failures, "目标发行版与平台 ID 不一致");
    addFailure(String(observed.distributionVersion).startsWith(wanted.versionPrefix), failures, "目标发行版版本与平台 ID 不一致");
    addFailure(wanted.architectures.includes(String(observed.architecture).toLowerCase()), failures, "目标架构与平台 ID 不一致");
    addFailure(observed.initSystem === wanted.init, failures, "目标 PID 1 不是 systemd");
    if (wanted.selinux) addFailure(observed.selinuxMode === wanted.selinux, failures, "目标 SELinux 不是 Enforcing");
    addFailure(typeof observed.timezone === "string" && observed.timezone.length > 0, failures, "目标时区未观测");

    let source: WireSuccess["objects"][number] | undefined;
    for (const path of manifest.evidenceCandidates) {
      const inventory = await invoke(first, "enumerate", { namespace: "file", scope: { namespace: "file", canonicalRoot: dirname(path) }, fields: ["path", "size", "contentClass"], predicate: { op: "eq", field: "path", value: path }, limit: 1 }, input.commit, 2);
      if (inventory.status === "SUCCESS" && inventory.gaps.length === 0 && inventory.objects[0]) { source = inventory.objects[0]; break; }
    }
    addFailure(Boolean(source), failures, "未找到可完整采集的 Evidence 候选文件");
    if (source) {
      sourceIdentityDigest = digestObject(source.identity);
      const path = String(source.fields.path);
      const collected = await invoke(first, "collect", { namespace: "file", identity: source.identity, locator: { path }, maxBytes: manifest.maxEvidenceBytes, purpose: "PLATFORM_QUALIFICATION" }, input.commit, 3);
      const artifact = collected.artifact;
      addFailure(collected.status === "SUCCESS" && collected.gaps.length === 0 && artifact?.complete === true && Boolean(artifact), failures, "平台 Evidence collect 不完整");
      if (artifact) {
        const localDigest = createHash("sha256");
        const transfer = await first.downloadArtifact({ artifactToken: artifact.token, sha256: artifact.sha256, size: artifact.size, expiresAt: artifact.expiresAt }, (chunk) => { transferBytes += chunk.length; localDigest.update(chunk); });
        transferSha = localDigest.digest("hex");
        addFailure(transfer.size === artifact.size && transfer.sha256 === artifact.sha256 && transferBytes === artifact.size && transferSha === artifact.sha256, failures, "平台 Evidence 传输摘要或字节数不一致");
        const releaseRequest = (index: number): WireRequest => ({ protocolVersion: 2, requestId: `PLATFORM-RELEASE-${randomUUID()}-${index}`, epochId: "MAINTENANCE", deadlineMs: 10_000, reservation: { reservationId: `PLATFORM-RELEASE-${index}`, estimate: { remoteCalls: 1, nodes: 1, bytes: 1024, wallTimeMs: 10_000, probeCalls: 0 } }, params: { artifactToken: artifact.token } });
        const firstRelease = await first.invokeMaintenanceV2("artifact_release", releaseRequest(1));
        const secondRelease = await first.invokeMaintenanceV2("artifact_release", releaseRequest(2));
        releaseRequiredAfterDownload = firstRelease.released === true;
        finalAbsent = secondRelease.released === false;
        addFailure(finalAbsent, failures, "Artifact 清理后仍存在");
      }
    }
    await first.close();
    second = await input.createRemote();
    reconnectCapabilities = await second.getCapabilitiesV2();
    reconnectHost = await readHost(second, input.commit, 4);
  } finally {
    await first.close().catch(() => undefined);
    await second?.close().catch(() => undefined);
  }
  const hostIdentityStable = Boolean(host && reconnectHost && digestObject(host.identity) === digestObject(reconnectHost.identity));
  const capabilitiesStable = Boolean(capabilities && reconnectCapabilities && digestObject(capabilities) === digestObject(reconnectCapabilities));
  addFailure(hostIdentityStable, failures, "SSH 重连后 Host 稳定身份不一致");
  addFailure(capabilitiesStable, failures, "SSH 重连后 Helper 能力发生变化");
  const fields = host?.fields ?? {};
  const capabilityVerified = Boolean(capabilities && capabilities.protocolVersion === 2 && capabilities.manifestVersion === MANIFEST_VERSION
    && ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"].every((verb) => capabilities!.verbs.includes(verb as never)));
  addFailure(capabilityVerified, failures, "八个取证原语能力不完整");
  return {
    schemaVersion: 2,
    status: failures.length === 0 ? "PASS" : "FAIL",
    commit: input.commit,
    manifestVersion: capabilities?.manifestVersion ?? "unknown",
    evaluatedAt: input.evaluatedAt ?? new Date().toISOString(),
    sourceManifestSha256: input.manifestSha256,
    helperSha256: capabilities?.helper.sha256 ?? null,
    hostKeyOutOfBandVerified: true,
    environment: {
      platformId: manifest.platformId,
      distribution: String(fields.distribution ?? "unknown"),
      version: String(fields.distributionVersion ?? "unknown"),
      architecture: String(fields.architecture ?? "unknown"),
      kernel: String(fields.release ?? "unknown"),
      timezone: String(fields.timezone ?? "unknown"),
      init: String(fields.initSystem ?? "unknown"),
      selinux: String(fields.selinuxMode ?? "unknown"),
      officialImageDigest: manifest.officialImage.imageDigest,
      imageIdentityDigest: digestObject({ source: manifest.officialImage.source, imageId: manifest.officialImage.imageId }),
      imageAttestorDigest: digestObject(manifest.officialImage.attestor),
    },
    capabilities: { verified: capabilityVerified, digest: capabilities ? digestObject(capabilities) : digestObject(null), namespaces: capabilities ? Object.keys(capabilities.namespaces).length : 0, verbs: capabilities?.verbs.length ?? 0, matchers: capabilities?.matchers ?? [], probes: capabilities?.probes ?? [] },
    evidence: { verified: Boolean(transferSha && transferBytes > 0), bytes: transferBytes, sha256: transferSha, sourceIdentityDigest },
    recovery: { verified: hostIdentityStable && capabilitiesStable, reconnects: second ? 1 : 0, hostIdentityStable, capabilitiesStable },
    cleanup: { verified: finalAbsent, releaseRequiredAfterDownload, finalAbsent },
    failures,
  };
}
