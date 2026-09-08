export interface ProviderHttpAttempt {
  attempt: number;
  durationMs: number;
  status?: number;
  retryable?: boolean;
  errorName?: string;
}

function retryableStatus(status: number): boolean {
  return status === 408 || status === 409 || status === 429 || status >= 500;
}

/**
 * 只记录 Provider HTTP 尝试的状态和耗时。请求 URL、Header、正文以及响应正文
 * 都不进入记录，避免模型上下文、API Key 或网关参数被写入审计日志。
 */
export function createObservedProviderFetch(
  onAttempt: (attempt: ProviderHttpAttempt) => void,
  delegate: typeof fetch = globalThis.fetch,
): typeof fetch {
  let sequence = 0;
  return async (input, init) => {
    const attempt = ++sequence;
    const startedAt = Date.now();
    try {
      const response = await delegate(input, init);
      onAttempt({
        attempt,
        durationMs: Date.now() - startedAt,
        status: response.status,
        retryable: retryableStatus(response.status),
      });
      return response;
    } catch (error) {
      onAttempt({
        attempt,
        durationMs: Date.now() - startedAt,
        errorName: error instanceof Error ? error.name : "UnknownError",
      });
      throw error;
    }
  };
}

/** SDK 的 timeoutMs 可能只覆盖取得响应头；独立 AbortSignal 必须覆盖整个 SSE 消费期。 */
export function providerRequestSignal(timeoutMs: number, callerSignal?: AbortSignal): AbortSignal {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  return callerSignal ? AbortSignal.any([callerSignal, timeoutSignal]) : timeoutSignal;
}
