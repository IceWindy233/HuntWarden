import { AsyncLocalStorage } from "node:async_hooks";

const toolTimeout = new AsyncLocalStorage<number>();

export function withHostOperationTimeout<T>(timeoutMs: number, run: () => Promise<T>): Promise<T> {
  return toolTimeout.run(timeoutMs, run);
}

export function effectiveHostOperationTimeout(explicit: number | undefined, fallback: number): number {
  return explicit ?? toolTimeout.getStore() ?? fallback;
}
