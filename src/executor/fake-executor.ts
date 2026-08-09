import { createHash } from "node:crypto";
import type { ArtifactTransferResult, HostExecutor, HostOperation, HostOperationOutput, HostOperationRequest, RemoteArtifact } from "./operations.js";
import { effectiveHostOperationTimeout } from "./timeout-context.js";

export type FakeHandler = (params: unknown) => unknown | Promise<unknown>;

export class FakeExecutor implements HostExecutor {
  readonly calls: { operation: HostOperation; params: unknown }[] = [];
  readonly effectiveTimeouts: number[] = [];
  constructor(
    private readonly handlers: Partial<Record<HostOperation, FakeHandler>> = {},
    private readonly artifacts: Record<string, Buffer> = {},
  ) {}

  async invoke<T extends HostOperation>(request: HostOperationRequest<T>, signal?: AbortSignal): Promise<HostOperationOutput<T>> {
    if (signal?.aborted) throw signal.reason;
    this.calls.push({ operation: request.operation, params: request.params });
    this.effectiveTimeouts.push(effectiveHostOperationTimeout(request.timeoutMs, 30_000));
    const handler = this.handlers[request.operation];
    if (!handler) throw new Error(`No fake handler for ${request.operation}`);
    return await handler(request.params) as HostOperationOutput<T>;
  }

  async downloadArtifact(artifact: RemoteArtifact, onChunk: (chunk: Buffer) => void | Promise<void>, signal?: AbortSignal): Promise<ArtifactTransferResult> {
    signal?.throwIfAborted();
    const value = this.artifacts[artifact.artifactToken];
    if (!value) throw new Error(`No fake artifact payload for ${artifact.artifactToken}`);
    await onChunk(value);
    return { sha256: createHash("sha256").update(value).digest("hex"), size: value.length };
  }

  async close(): Promise<void> {}
}
