import type { HostExecutor, HostOperation, HostOperationOutput, HostOperationRequest } from "./operations.js";

export type FakeHandler = (params: unknown) => unknown | Promise<unknown>;

export class FakeExecutor implements HostExecutor {
  readonly calls: { operation: HostOperation; params: unknown }[] = [];
  constructor(private readonly handlers: Partial<Record<HostOperation, FakeHandler>> = {}) {}

  async invoke<T extends HostOperation>(request: HostOperationRequest<T>, signal?: AbortSignal): Promise<HostOperationOutput<T>> {
    if (signal?.aborted) throw signal.reason;
    this.calls.push({ operation: request.operation, params: request.params });
    const handler = this.handlers[request.operation];
    if (!handler) throw new Error(`No fake handler for ${request.operation}`);
    return await handler(request.params) as HostOperationOutput<T>;
  }

  async close(): Promise<void> {}
}
