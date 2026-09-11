import { createServer, type IncomingMessage, type RequestListener, type ServerResponse } from "node:http";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import type { Context } from "@earendil-works/pi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { createModelBundle } from "../../src/agent/model.js";
import { smokeModel } from "../../src/agent/model-health.js";
import { createObservedProviderFetch, type ProviderHttpAttempt, providerRequestSignal } from "../../src/agent/provider-observer.js";
import type { AppConfig } from "../../src/config/schema.js";
import { MANIFEST_VERSION } from "../../src/protocol-v2/types.js";
import { testConfig } from "../helpers.js";

const enabled = process.env.HUNTWARDEN_PROVIDER_CONTRACT_TESTS === "1";
const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(async (server) => {
    if (!server.listening) return;
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }));
});

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function sendSse(response: ServerResponse, events: unknown[]): void {
  response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  for (const event of events) response.write(`data: ${JSON.stringify(event)}\n\n`);
  response.end("data: [DONE]\n\n");
}

async function listen(listener: RequestListener): Promise<{ server: ReturnType<typeof createServer>; baseUrl: string }> {
  const server = createServer(listener);
  servers.push(server);
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", () => resolve()).once("error", reject));
  return { server, baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1` };
}

function completionEvents() {
  const base = { id: "chatcmpl_contract", object: "chat.completion.chunk", created: 1, model: "contract-model" };
  return [
    { ...base, choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: "call_contract", type: "function", function: { name: "connection_probe", arguments: "{\"marker\":\"huntwarden-" } }] }, finish_reason: null }] },
    { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: "model-smoke-v1\"}" } }] }, finish_reason: null }] },
    { ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 41, completion_tokens: 9, total_tokens: 50 } },
  ];
}

function responsesEvents() {
  const item = {
    type: "function_call", id: "fc_contract", call_id: "call_contract", name: "connection_probe",
    arguments: "{\"marker\":\"huntwarden-model-smoke-v1\"}", status: "completed",
  };
  const response = {
    id: "resp_contract", object: "response", created_at: 1, model: "contract-model", status: "completed",
    output: [item], error: null, incomplete_details: null,
    usage: { input_tokens: 43, input_tokens_details: { cached_tokens: 0 }, output_tokens: 8, output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 51 },
  };
  return [
    { type: "response.created", response: { ...response, status: "in_progress", output: [], usage: null } },
    { type: "response.output_item.added", output_index: 0, item: { ...item, arguments: "", status: "in_progress" } },
    { type: "response.function_call_arguments.delta", output_index: 0, item_id: item.id, delta: "{\"marker\":\"huntwarden-" },
    { type: "response.function_call_arguments.delta", output_index: 0, item_id: item.id, delta: "model-smoke-v1\"}" },
    { type: "response.function_call_arguments.done", output_index: 0, item_id: item.id, arguments: item.arguments },
    { type: "response.output_item.done", output_index: 0, item },
    { type: "response.completed", response },
  ];
}

function assertContract(request: IncomingMessage, body: Record<string, unknown>, protocol: "openai-completions" | "openai-responses"): void {
  expect(request.method).toBe("POST");
  expect(request.headers.authorization).toBe("Bearer huntwarden-local-no-auth");
  expect(body).toMatchObject({ model: "contract-model", stream: true });
  const tools = body.tools as Array<Record<string, unknown>>;
  expect(tools).toHaveLength(1);
  const tool = protocol === "openai-completions" ? tools[0]?.function as Record<string, unknown> : tools[0];
  expect(tool).toMatchObject({ name: "connection_probe" });
  expect((tool?.parameters as Record<string, unknown>)?.additionalProperties).toBe(false);
  expect(JSON.stringify(body)).toContain("huntwarden-model-smoke-v1");
}

async function runProtocol(protocol: "openai-completions" | "openai-responses") {
  let requestCount = 0;
  const { baseUrl } = await listen(async (request, response) => {
    try {
      requestCount += 1;
      const expectedPath = protocol === "openai-completions" ? "/v1/chat/completions" : "/v1/responses";
      expect(request.url).toBe(expectedPath);
      const body = await readJson(request);
      assertContract(request, body, protocol);
      sendSse(response, protocol === "openai-completions" ? completionEvents() : responsesEvents());
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { message: error instanceof Error ? error.message : String(error) } }));
    }
  });
  const config = testConfig("/tmp/huntwarden-provider-contract") as AppConfig;
  config.model = {
    source: "custom", provider: `contract-${protocol}`, model: "contract-model", thinkingLevel: "off", protocol,
    baseUrl, authentication: { type: "none" }, reasoning: false,
    contextWindow: 32_768, maxTokens: 4_096,
  };
  const { models, model } = createModelBundle(config);
  const result = await smokeModel(config, models, model);
  expect(requestCount).toBe(1);
  expect(result).toMatchObject({ ok: true, toolCallVerified: true, credentialSource: "本机无认证端点" });
  expect(result.usage?.input).toBeGreaterThan(0);
  expect(result.usage?.output).toBeGreaterThan(0);
  return { protocol, requestCount, usage: result.usage, toolCallVerified: result.toolCallVerified };
}

function completionTextEvents(text: string) {
  const base = { id: "chatcmpl_fault", object: "chat.completion.chunk", created: 1, model: "contract-model" };
  return [
    { ...base, choices: [{ index: 0, delta: { role: "assistant", content: text }, finish_reason: null }] },
    { ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 13, completion_tokens: 3, total_tokens: 16 } },
  ];
}

function completionConfig(baseUrl: string): AppConfig {
  const config = testConfig("/tmp/huntwarden-provider-contract") as AppConfig;
  config.model = {
    source: "custom", provider: "contract-faults", model: "contract-model", thinkingLevel: "off",
    protocol: "openai-completions", baseUrl, authentication: { type: "none" }, reasoning: false,
    contextWindow: 32_768, maxTokens: 4_096,
  };
  return config;
}

const basicContext: Context = {
  systemPrompt: "Provider fault contract",
  messages: [{ role: "user", content: "respond", timestamp: 1 }],
};

async function runRetryContract() {
  let requestCount = 0;
  const attempts: ProviderHttpAttempt[] = [];
  const { baseUrl } = await listen((_request, response) => {
    requestCount += 1;
    if (requestCount === 1) {
      response.writeHead(429, { "content-type": "application/json", "retry-after-ms": "1" });
      response.end(JSON.stringify({ error: { message: "injected rate limit", type: "rate_limit_error" } }));
      return;
    }
    sendSse(response, completionTextEvents("recovered"));
  });
  const config = completionConfig(baseUrl);
  const { models, model } = createModelBundle(config);
  const response = await models.completeSimple(model, basicContext, {
    maxRetries: 1, maxRetryDelayMs: 10, timeoutMs: 1_000,
    fetch: createObservedProviderFetch((attempt) => attempts.push(attempt)),
  });
  expect(response.stopReason).toBe("stop");
  expect(requestCount).toBe(2);
  expect(attempts.map((attempt) => attempt.status)).toEqual([429, 200]);
  return { requestCount, attempts };
}

async function runStallContract() {
  const attempts: ProviderHttpAttempt[] = [];
  const { baseUrl } = await listen((_request, response) => {
    response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    response.write(`data: ${JSON.stringify(completionTextEvents("partial")[0])}\n\n`);
    setTimeout(() => response.end(), 300);
  });
  const config = completionConfig(baseUrl);
  const { models, model } = createModelBundle(config);
  const startedAt = Date.now();
  const response = await models.completeSimple(model, basicContext, {
    maxRetries: 0, timeoutMs: 100, signal: providerRequestSignal(100),
    fetch: createObservedProviderFetch((attempt) => attempts.push(attempt)),
  });
  const elapsedMs = Date.now() - startedAt;
  expect(response.stopReason).toBe("aborted");
  expect(elapsedMs).toBeLessThan(250);
  expect(attempts.map((attempt) => attempt.status)).toEqual([200]);
  return { stopReason: response.stopReason, elapsedMs, httpStatus: attempts[0]?.status, runtimeClassification: "PROVIDER_FAILURE" };
}

async function runEmptyContract() {
  const { baseUrl } = await listen((_request, response) => {
    const base = { id: "chatcmpl_empty", object: "chat.completion.chunk", created: 1, model: "contract-model" };
    sendSse(response, [{ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 7, completion_tokens: 0, total_tokens: 7 } }]);
  });
  const config = completionConfig(baseUrl);
  const { models, model } = createModelBundle(config);
  const result = await smokeModel(config, models, model);
  expect(result).toMatchObject({ ok: false, toolCallVerified: false, message: "模型连接成功，但未生成有效 Tool Call" });
  return { rejected: !result.ok, message: result.message };
}

describe.skipIf(!enabled)("OpenAI-compatible Provider HTTP/SSE 契约", () => {
  it("两种协议均完成请求校验、流式分片重组和 Tool Call 验证", async () => {
    const results = [];
    for (const protocol of ["openai-completions", "openai-responses"] as const) results.push(await runProtocol(protocol));
    expect(results).toEqual([
      expect.objectContaining({ protocol: "openai-completions", requestCount: 1, toolCallVerified: true }),
      expect.objectContaining({ protocol: "openai-responses", requestCount: 1, toolCallVerified: true }),
    ]);
    const retry = await runRetryContract();
    const stall = await runStallContract();
    const empty = await runEmptyContract();
    const commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    await writeFile("acceptance/provider-contract/result-local.json", `${JSON.stringify({
      schemaVersion: 1,
      status: "PASS",
      evaluationKind: "PROTOCOL_FIXTURE",
      endpointClass: "LOOPBACK",
      commit,
      manifestVersion: MANIFEST_VERSION,
      protocols: results,
      faults: { retry, stall, empty },
    }, null, 2)}\n`, "utf8");
  });
});
