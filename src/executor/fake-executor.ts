import { createHash } from "node:crypto";
import type { ArtifactTransferResult, RemoteArtifact } from "./artifacts.js";
import type { ForensicVerb, MaintenanceVerb, ProtocolV2Executor } from "./protocol-v2-executor.js";
import type { HelperCapabilitiesV2, WireRequest, WireResponse } from "../protocol-v2/types.js";

export class FakeProtocolV2Executor implements ProtocolV2Executor {
  readonly calls: Array<{ verb: ForensicVerb; request: WireRequest }> = [];
  readonly maintenanceCalls: Array<{ verb: MaintenanceVerb; request: WireRequest }> = [];
  constructor(
    readonly capabilities: HelperCapabilitiesV2,
    private readonly handler: (verb: ForensicVerb, request: WireRequest) => WireResponse | Promise<WireResponse>,
    private readonly artifacts: Record<string, Buffer> = {},
    private readonly maintenanceHandler?: (verb: MaintenanceVerb, request: WireRequest) => Record<string, unknown> | Promise<Record<string, unknown>>,
  ) {}
  async getCapabilitiesV2(): Promise<HelperCapabilitiesV2> { return structuredClone(this.capabilities); }
  async invokeV2(verb: ForensicVerb, request: WireRequest, signal?: AbortSignal): Promise<WireResponse> {
    signal?.throwIfAborted(); this.calls.push({ verb, request: structuredClone(request) }); return await this.handler(verb, request);
  }
  async invokeMaintenanceV2(verb: MaintenanceVerb, request: WireRequest, signal?: AbortSignal): Promise<Record<string, unknown>> {
    signal?.throwIfAborted(); this.maintenanceCalls.push({ verb, request: structuredClone(request) });
    if (!this.maintenanceHandler) throw new Error(`No fake maintenance handler for ${verb}`);
    return await this.maintenanceHandler(verb, request);
  }
  async downloadArtifact(artifact: RemoteArtifact, onChunk: (chunk: Buffer) => void | Promise<void>): Promise<ArtifactTransferResult> {
    const value = this.artifacts[artifact.artifactToken];
    if (!value) throw new Error(`No fake artifact payload for ${artifact.artifactToken}`);
    await onChunk(value);
    return { sha256: createHash("sha256").update(value).digest("hex"), size: value.length };
  }
  async close(): Promise<void> {}
}
