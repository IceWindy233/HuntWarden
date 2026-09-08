import { Type, type Static } from "typebox";

const STRICT_OBJECT = { additionalProperties: false } as const;

const ThinkingLevelSchema = Type.Union([
  Type.Literal("off"), Type.Literal("minimal"), Type.Literal("low"), Type.Literal("medium"),
  Type.Literal("high"), Type.Literal("xhigh"), Type.Literal("max"),
]);

const ProviderIdSchema = Type.String({ minLength: 1, maxLength: 64, pattern: "^[a-z0-9][a-z0-9._-]*$" });
const EnvNameSchema = Type.String({ minLength: 2, maxLength: 128, pattern: "^[A-Z][A-Z0-9_]*$" });

export const BuiltinModelSchema = Type.Object({
  source: Type.Optional(Type.Literal("builtin")),
  provider: ProviderIdSchema,
  model: Type.String({ minLength: 1, maxLength: 256 }),
  thinkingLevel: ThinkingLevelSchema,
}, STRICT_OBJECT);

export const CustomModelSchema = Type.Object({
  source: Type.Literal("custom"),
  provider: ProviderIdSchema,
  model: Type.String({ minLength: 1, maxLength: 256 }),
  thinkingLevel: ThinkingLevelSchema,
  protocol: Type.Union([
    Type.Literal("openai-responses"),
    Type.Literal("openai-completions"),
    Type.Literal("anthropic-messages"),
  ]),
  baseUrl: Type.String({ minLength: 1, maxLength: 2048 }),
  authentication: Type.Union([
    Type.Object({ type: Type.Literal("api-key-env"), apiKeyEnv: EnvNameSchema }, STRICT_OBJECT),
    Type.Object({ type: Type.Literal("none") }, STRICT_OBJECT),
  ]),
  reasoning: Type.Boolean(),
  contextWindow: Type.Integer({ minimum: 4096, maximum: 10_000_000 }),
  maxTokens: Type.Integer({ minimum: 256, maximum: 1_000_000 }),
  compatibility: Type.Optional(Type.Object({
    supportsDeveloperRole: Type.Optional(Type.Boolean()),
    supportsReasoningEffort: Type.Optional(Type.Boolean()),
    supportsUsageInStreaming: Type.Optional(Type.Boolean()),
    supportsStrictMode: Type.Optional(Type.Boolean()),
    supportsStrictTools: Type.Optional(Type.Boolean()),
    maxTokensField: Type.Optional(Type.Union([Type.Literal("max_completion_tokens"), Type.Literal("max_tokens")])),
  }, STRICT_OBJECT)),
}, STRICT_OBJECT);

export const ConfigSchema = Type.Object({
  schemaVersion: Type.Literal(2),
  protocolV2: Type.Object({
    remoteBudget: Type.Object({
      preset: Type.Object({ remoteCalls: Type.Integer({ minimum: 1 }), nodes: Type.Integer({ minimum: 1 }), bytes: Type.Integer({ minimum: 1024 }), wallTimeMs: Type.Integer({ minimum: 1000 }), probeCalls: Type.Integer({ minimum: 0 }) }, STRICT_OBJECT),
      model: Type.Object({ remoteCalls: Type.Integer({ minimum: 1 }), nodes: Type.Integer({ minimum: 1 }), bytes: Type.Integer({ minimum: 1024 }), wallTimeMs: Type.Integer({ minimum: 1000 }), probeCalls: Type.Integer({ minimum: 0 }) }, STRICT_OBJECT),
    }, STRICT_OBJECT),
    localQueryBudget: Type.Object({ calls: Type.Integer({ minimum: 1 }), rows: Type.Integer({ minimum: 1 }), wallTimeMs: Type.Integer({ minimum: 1000 }) }, STRICT_OBJECT),
    externalIntelBudget: Type.Object({ calls: Type.Integer({ minimum: 1 }), iocs: Type.Integer({ minimum: 1 }), wallTimeMs: Type.Integer({ minimum: 1000 }) }, STRICT_OBJECT),
    dataPolicy: Type.Object({ modelContentBytes: Type.Integer({ minimum: 1024 }), evidenceBytes: Type.Integer({ minimum: 1024 }), defaultTextClass: Type.Literal("SENSITIVE_TEXT") }, STRICT_OBJECT),
    grants: Type.Object({ maxRequests: Type.Integer({ minimum: 1, maximum: 100 }), pendingExpiresOnInterruption: Type.Literal(true) }, STRICT_OBJECT),
  }, STRICT_OBJECT),
  agent: Type.Object({
    maxTurns: Type.Integer({ minimum: 1, maximum: 100 }),
    /**
     * 发给 Provider 的上下文保留最近多少个 assistant 回合的完整工具结果。
     *
     * 更旧的成功工具结果换成存根；v2 模型用 `query_facts` 按 sourceRunId 回取。本运行时用的是低层 Agent，
     * 没有 compaction，历史消息全量回放，上下文只增不减；不淘汰则长调查必然撞上下文窗口。
     */
    contextRetainTurns: Type.Integer({ minimum: 1, maximum: 20 }),
    /** 调查循环的 Provider 有界重试次数：一次 429 不应作废整场调查。 */
    providerMaxRetries: Type.Integer({ minimum: 0, maximum: 10 }),
    /** 单次 Provider 流式请求的硬超时；覆盖首 token 与流中停滞，避免任务无限占用。 */
    providerTimeoutSeconds: Type.Integer({ minimum: 30, maximum: 3600 }),
    defaultMode: Type.Union([Type.Literal("SCAN"), Type.Literal("REMEDIATE")]),
    promptVersion: Type.String({ minLength: 1 }),
  }, STRICT_OBJECT),
  model: Type.Union([BuiltinModelSchema, CustomModelSchema]),
  executor: Type.Object({
    type: Type.Literal("ssh"),
    timeoutSeconds: Type.Integer({ minimum: 1, maximum: 600 }),
    helperPath: Type.String({ minLength: 1 }),
    knownHostsPath: Type.String({ minLength: 1 }),
    privateKeyPath: Type.String({ minLength: 1 }),
  }, STRICT_OBJECT),
  storage: Type.Object({ baseDir: Type.String(), databaseFile: Type.String() }, STRICT_OBJECT),
  llmData: Type.Object({ maxTextBytes: Type.Integer({ minimum: 1024, maximum: 262144 }) }, STRICT_OBJECT),
  webshell: Type.Object({
    modifiedWithinHours: Type.Integer({ minimum: 1, maximum: 8_760 }),
  }, STRICT_OBJECT),
  threatIntel: Type.Object({
    enabled: Type.Boolean(),
    provider: Type.Literal("dbapp-ti"),
    baseUrl: Type.Literal("https://ti.dbappsecurity.com.cn/oapi/v1/"),
    apiKeyEnv: Type.Literal("DBAPP_TI_API_KEY"),
    timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }),
    maxBatchSize: Type.Integer({ minimum: 1, maximum: 100 }),
    cacheTtlSeconds: Type.Integer({ minimum: 0, maximum: 86_400 }),
  }, STRICT_OBJECT),
  remediation: Type.Object({
    requireApproval: Type.Literal(true),
    allowedTools: Type.Array(Type.Union([Type.Literal("quarantine_file"), Type.Literal("disable_account")])),
    quarantineRoot: Type.String(),
  }, STRICT_OBJECT),
}, STRICT_OBJECT);

export type AppConfig = Static<typeof ConfigSchema>;
