import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { ProtocolV2Executor } from "../../src/executor/protocol-v2-executor.js";
import { parsePlatformQualificationManifest, runPlatformQualification, type PlatformQualificationManifest } from "../../src/evaluation/platform-qualification.js";
import type { RemoteArtifact } from "../../src/executor/artifacts.js";
import type { WireRequest, WireResponse, WireSuccess } from "../../src/protocol-v2/types.js";

const payload = Buffer.from("platform-evidence");
const payloadSha = createHash("sha256").update(payload).digest("hex");
const helperSha256 = "e".repeat(64);

function manifest(platformId: PlatformQualificationManifest["platformId"] = "ubuntu-24.04-x86_64"): PlatformQualificationManifest {
  return parsePlatformQualificationManifest({
    schemaVersion: 1, suiteId: "platform-release", platformId, hostKeyOutOfBandVerified: true,
    officialImage: { official: true, source: "official-cloud-catalog", imageId: "ubuntu-24.04-20260908", imageDigest: "d".repeat(64), attestor: "platform-owner", attestedAt: "2026-09-08T00:00:00.000Z" },
    evidenceCandidates: ["/etc/hostname"], maxEvidenceBytes: 4096,
  });
}

function response(requestId: string, objects: WireSuccess["objects"], artifact?: WireSuccess["artifact"]): WireSuccess {
  return { protocolVersion: 2, requestId, status: "SUCCESS", objects, edges: [], ...(artifact ? { artifact } : {}), cost: { remoteCalls: 1, nodes: objects.length, bytes: payload.length, wallTimeMs: 1, probeCalls: 0 }, gaps: [] };
}

function remote(selinuxMode = "Unavailable"): ProtocolV2Executor {
  let artifactExists = false;
  return {
    getCapabilitiesV2: async () => ({ protocolVersion: 2, manifestVersion: "3.0.0", helper: { name: "huntwarden-helper-v2", version: "3.0.0", sha256: helperSha256 }, namespaces: { host: { fields: [], relations: [] }, file: { fields: [], relations: [] } }, matchers: ["literal", "re2"], probes: ["jvm.tomcat.inventory", "jvm.class.inspect", "jvm.class.dump"], verbs: ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"], limits: { maxObjects: 500, maxOutputBytes: 1_000_000, maxReadBytes: 1_000_000, maxCollectBytes: 1_000_000 } }),
    invokeV2: async (verb: string, request: WireRequest): Promise<WireResponse> => {
      if (verb === "collect") {
        artifactExists = true;
        return response(request.requestId, [], { token: "a".repeat(64), sha256: payloadSha, size: payload.length, complete: true, expiresAt: "2026-09-08T01:00:00.000Z" });
      }
      const namespace = request.params.namespace;
      if (namespace === "host") return response(request.requestId, [{ namespace: "host", identity: { bootId: "boot-1" }, fields: { distribution: "ubuntu", distributionVersion: "24.04", release: "6.8.0", architecture: "x86_64", timezone: "UTC", initSystem: "systemd", selinuxMode }, observedAt: "2026-09-08T00:00:00.000Z", consistency: "OBJECT_STABLE" }]);
      return response(request.requestId, [{ namespace: "file", identity: { mountId: "1", device: "1", inode: "1" }, fields: { path: "/etc/hostname", size: payload.length, contentClass: "SAFE_TEXT" }, observedAt: "2026-09-08T00:00:00.000Z", consistency: "OBJECT_STABLE" }]);
    },
    invokeMaintenanceV2: async (_verb, request) => {
      const released = artifactExists;
      artifactExists = false;
      return { released, requestId: request.requestId };
    },
    downloadArtifact: async (_artifact: RemoteArtifact, onChunk) => {
      await onChunk(payload);
      artifactExists = false;
      return { size: payload.length, sha256: payloadSha };
    },
    close: async () => undefined,
  };
}

describe("目标平台发布资格执行器", () => {
  it("从 Helper 主机事实、Evidence、清理和 SSH 重连生成 PASS", async () => {
    const result = await runPlatformQualification({ manifest: manifest(), manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, commit: "c".repeat(40), createRemote: () => remote(), evaluatedAt: "2026-09-08T01:00:00.000Z" });
    expect(result.status, result.failures.join("\n")).toBe("PASS");
    expect(result.environment).toMatchObject({ distribution: "ubuntu", version: "24.04", architecture: "x86_64", init: "systemd" });
    expect(result.evidence).toMatchObject({ verified: true, bytes: payload.length, sha256: payloadSha });
    expect(result.recovery).toMatchObject({ verified: true, reconnects: 1, hostIdentityStable: true, capabilitiesStable: true });
    expect(result.cleanup).toMatchObject({ verified: true, finalAbsent: true });
  });

  it("Rocky/Alma 平台在 SELinux 非 Enforcing 时失败关闭", async () => {
    const value = manifest("rocky-or-alma-9-x86_64-selinux-enforcing");
    const base = remote("Permissive");
    const original = base.invokeV2.bind(base);
    base.invokeV2 = async (verb, request, signal) => {
      const result = await original(verb, request, signal);
      if (result.status !== "ERROR" && request.params.namespace === "host") result.objects[0]!.fields = { ...result.objects[0]!.fields, distribution: "rocky", distributionVersion: "9.6" };
      return result;
    };
    const result = await runPlatformQualification({ manifest: value, manifestSha256: "a".repeat(64), expectedHelperSha256: helperSha256, commit: "c".repeat(40), createRemote: () => base });
    expect(result.status).toBe("FAIL");
    expect(result.failures).toContain("目标 SELinux 不是 Enforcing");
  });
});
