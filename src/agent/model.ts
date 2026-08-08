import {
  createModels,
  createProvider,
  envApiKeyAuth,
  getSupportedThinkingLevels,
  type Api,
  type Model,
  type Models,
  type OpenAICompletionsCompat,
  type OpenAIResponsesCompat,
  type AnthropicMessagesCompat,
  type CredentialStore,
} from "@earendil-works/pi-ai";
import { anthropicMessagesApi } from "@earendil-works/pi-ai/api/anthropic-messages.lazy";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { openAIResponsesApi } from "@earendil-works/pi-ai/api/openai-responses.lazy";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import type { AppConfig } from "../config/schema.js";

export interface ModelBundle { models: Models; model: Model<Api> }

type CustomModelConfig = Extract<AppConfig["model"], { source: "custom" }>;

function buildCompatibility(config: CustomModelConfig): Model<Api>["compat"] {
  const compatibility = config.compatibility;
  if (!compatibility) return undefined;
  if (config.protocol === "openai-completions") {
    return {
      ...(compatibility.supportsDeveloperRole === undefined ? {} : { supportsDeveloperRole: compatibility.supportsDeveloperRole }),
      ...(compatibility.supportsReasoningEffort === undefined ? {} : { supportsReasoningEffort: compatibility.supportsReasoningEffort }),
      ...(compatibility.supportsUsageInStreaming === undefined ? {} : { supportsUsageInStreaming: compatibility.supportsUsageInStreaming }),
      ...(compatibility.supportsStrictMode === undefined ? {} : { supportsStrictMode: compatibility.supportsStrictMode }),
      ...(compatibility.maxTokensField === undefined ? {} : { maxTokensField: compatibility.maxTokensField }),
    } satisfies OpenAICompletionsCompat;
  }
  if (config.protocol === "openai-responses") {
    return {
      ...(compatibility.supportsDeveloperRole === undefined ? {} : { supportsDeveloperRole: compatibility.supportsDeveloperRole }),
      ...(compatibility.supportsStrictMode === undefined ? {} : { supportsStrictMode: compatibility.supportsStrictMode }),
    } satisfies OpenAIResponsesCompat;
  }
  return {
    ...(compatibility.supportsStrictTools === undefined ? {} : { supportsStrictTools: compatibility.supportsStrictTools }),
  } satisfies AnthropicMessagesCompat;
}

function createCustomModelBundle(config: CustomModelConfig, credentials?: CredentialStore): ModelBundle {
  const models = createModels(credentials ? { credentials } : undefined);
  const compat = buildCompatibility(config);
  const model: Model<Api> = {
    id: config.model,
    name: `${config.model} (${config.provider})`,
    api: config.protocol,
    provider: config.provider,
    baseUrl: config.baseUrl,
    reasoning: config.reasoning,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: config.contextWindow,
    maxTokens: config.maxTokens,
    ...(compat === undefined ? {} : { compat }),
  };
  const auth = config.authentication.type === "api-key-env"
    ? envApiKeyAuth(`${config.provider} API key`, [config.authentication.apiKeyEnv])
    : {
        name: "本机无认证端点",
        resolve: async ({ signal }: { signal: AbortSignal }) => {
          signal.throwIfAborted();
          return { auth: {}, source: "本机无认证端点" };
        },
      };
  const api = config.protocol === "openai-responses"
    ? openAIResponsesApi()
    : config.protocol === "openai-completions"
      ? openAICompletionsApi()
      : anthropicMessagesApi();
  models.setProvider(createProvider({
    id: config.provider,
    name: config.provider,
    baseUrl: config.baseUrl,
    auth: { apiKey: auth },
    models: [model],
    api,
  }));
  return { models, model };
}

function assertThinkingLevel(config: AppConfig, model: Model<Api>): void {
  const supported = getSupportedThinkingLevels(model);
  if (!supported.includes(config.model.thinkingLevel)) {
    throw new Error(
      `模型 ${model.provider}/${model.id} 不支持推理等级 ${config.model.thinkingLevel}；可用值: ${supported.join(", ")}`,
    );
  }
}

export function createModelBundle(config: AppConfig, credentials?: CredentialStore): ModelBundle {
  const bundle = config.model.source === "custom"
    ? createCustomModelBundle(config.model, credentials)
    : (() => {
        const models = builtinModels(credentials ? { credentials } : undefined);
        const model = models.getModel(config.model.provider, config.model.model);
        if (!model) {
          const providerExists = models.getProvider(config.model.provider) !== undefined;
          throw new Error(providerExists
            ? `Pi 模型目录中不存在 ${config.model.provider}/${config.model.model}`
            : `Pi 不支持内置 Provider: ${config.model.provider}`);
        }
        return { models, model };
      })();
  assertThinkingLevel(config, bundle.model);
  return bundle;
}
