import { Type, type Context, type Model, type Api, type Models, type Tool } from "@earendil-works/pi-ai";
import type { AppConfig } from "../config/schema.js";

export interface ModelHealthResult {
  ok: boolean;
  provider: string;
  model: string;
  protocol: string;
  endpoint: string;
  credentialSource?: string;
  toolCallVerified: boolean;
  message: string;
  usage?: { input: number; output: number };
}

export async function checkModel(models: Models, model: Model<Api>): Promise<ModelHealthResult> {
  const auth = await models.getAuth(model);
  return {
    ok: Boolean(auth),
    provider: model.provider,
    model: model.id,
    protocol: model.api,
    endpoint: model.baseUrl,
    ...(auth?.source ? { credentialSource: auth.source } : {}),
    toolCallVerified: false,
    message: auth ? "模型配置与凭据解析通过（未发起网络请求）" : "模型配置有效，但未找到可用凭据",
  };
}

export async function smokeModel(config: AppConfig, models: Models, model: Model<Api>): Promise<ModelHealthResult> {
  const checked = await checkModel(models, model);
  if (!checked.ok) return checked;
  const marker = "huntwarden-model-smoke-v1";
  const probe: Tool = {
    name: "connection_probe",
    description: "模型 API 和函数工具调用连接验收；必须按要求调用，工具不会执行外部操作。",
    parameters: Type.Object({ marker: Type.Literal(marker) }, { additionalProperties: false }),
  };
  const context: Context = {
    systemPrompt: "这是只读连接验收。不得解释；必须调用提供的 connection_probe 工具一次。",
    messages: [{ role: "user", content: `调用 connection_probe，marker 必须为 ${marker}。`, timestamp: Date.now() }],
    tools: [probe],
  };
  const response = await models.completeSimple(model, context, {
    ...(config.model.thinkingLevel === "off" ? {} : { reasoning: config.model.thinkingLevel }),
    maxTokens: 1024,
    timeoutMs: 60_000,
    maxRetries: 0,
  });
  if (response.stopReason === "error") throw new Error(response.errorMessage ?? "模型请求失败");
  const toolCall = response.content.find((item) => item.type === "toolCall");
  const verified = Boolean(toolCall && toolCall.name === probe.name && toolCall.arguments.marker === marker);
  return {
    ...checked,
    ok: verified,
    toolCallVerified: verified,
    message: verified ? "模型认证、网络、流式响应与 Tool Call 验证通过" : "模型连接成功，但未生成有效 Tool Call",
    usage: { input: response.usage.input, output: response.usage.output },
  };
}
