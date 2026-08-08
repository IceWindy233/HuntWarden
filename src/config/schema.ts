import { Type, type Static } from "typebox";

const ThinkingLevelSchema = Type.Union([
  Type.Literal("off"), Type.Literal("minimal"), Type.Literal("low"), Type.Literal("medium"),
  Type.Literal("high"), Type.Literal("xhigh"), Type.Literal("max"),
]);

const ProviderIdSchema = Type.String({ minLength: 1, maxLength: 64, pattern: "^[a-z0-9][a-z0-9._-]*$" });
const EnvNameSchema = Type.String({ minLength: 2, maxLength: 128, pattern: "^[A-Z][A-Z0-9_]*$" });

const BuiltinModelSchema = Type.Object({
  source: Type.Optional(Type.Literal("builtin")),
  provider: ProviderIdSchema,
  model: Type.String({ minLength: 1, maxLength: 256 }),
  thinkingLevel: ThinkingLevelSchema,
});

const CustomModelSchema = Type.Object({
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
    Type.Object({ type: Type.Literal("api-key-env"), apiKeyEnv: EnvNameSchema }),
    Type.Object({ type: Type.Literal("none") }),
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
  })),
});

export const ConfigSchema = Type.Object({
  agent: Type.Object({
    maxTurns: Type.Integer({ minimum: 1, maximum: 100 }),
    maxToolCalls: Type.Integer({ minimum: 1, maximum: 1000 }),
    defaultMode: Type.Union([Type.Literal("SCAN"), Type.Literal("REMEDIATE")]),
    promptVersion: Type.String({ minLength: 1 }),
  }),
  model: Type.Union([BuiltinModelSchema, CustomModelSchema]),
  executor: Type.Object({
    type: Type.Literal("ssh"),
    timeoutSeconds: Type.Integer({ minimum: 1, maximum: 600 }),
    helperPath: Type.String({ minLength: 1 }),
    knownHostsPath: Type.String({ minLength: 1 }),
    privateKeyPath: Type.String({ minLength: 1 }),
  }),
  storage: Type.Object({ baseDir: Type.String(), databaseFile: Type.String() }),
  llmData: Type.Object({ maxTextBytes: Type.Integer({ minimum: 1024, maximum: 262144 }) }),
  webshell: Type.Object({
    modifiedWithinHours: Type.Integer({ minimum: 1 }),
    maxCandidateFiles: Type.Integer({ minimum: 1, maximum: 5000 }),
    maxFileSizeBytes: Type.Integer({ minimum: 1024 }),
    yaraRuleDir: Type.String(),
  }),
  java: Type.Object({
    supportedContainers: Type.Array(Type.Literal("tomcat")),
    allowClassDump: Type.Boolean(),
    allowRuntimeModification: Type.Literal(false),
    probeJar: Type.String(),
  }),
  account: Type.Object({ checkAuthorizedKeys: Type.Boolean(), checkLoginHistory: Type.Boolean() }),
  remediation: Type.Object({
    requireApproval: Type.Literal(true),
    allowedTools: Type.Array(Type.Union([Type.Literal("quarantine_file"), Type.Literal("disable_account")])),
    quarantineRoot: Type.String(),
  }),
});

export type AppConfig = Static<typeof ConfigSchema>;
