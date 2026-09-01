import { Type, type Static } from "typebox";

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
});

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
  schemaVersion: Type.Literal(2),
  protocolV2: Type.Object({
    remoteBudget: Type.Object({
      preset: Type.Object({ remoteCalls: Type.Integer({ minimum: 1 }), nodes: Type.Integer({ minimum: 1 }), bytes: Type.Integer({ minimum: 1024 }), wallTimeMs: Type.Integer({ minimum: 1000 }), probeCalls: Type.Integer({ minimum: 0 }) }),
      model: Type.Object({ remoteCalls: Type.Integer({ minimum: 1 }), nodes: Type.Integer({ minimum: 1 }), bytes: Type.Integer({ minimum: 1024 }), wallTimeMs: Type.Integer({ minimum: 1000 }), probeCalls: Type.Integer({ minimum: 0 }) }),
    }),
    localQueryBudget: Type.Object({ calls: Type.Integer({ minimum: 1 }), rows: Type.Integer({ minimum: 1 }), wallTimeMs: Type.Integer({ minimum: 1000 }) }),
    externalIntelBudget: Type.Object({ calls: Type.Integer({ minimum: 1 }), iocs: Type.Integer({ minimum: 1 }), wallTimeMs: Type.Integer({ minimum: 1000 }) }),
    dataPolicy: Type.Object({ modelContentBytes: Type.Integer({ minimum: 1024 }), evidenceBytes: Type.Integer({ minimum: 1024 }), defaultTextClass: Type.Literal("SENSITIVE_TEXT") }),
    grants: Type.Object({ maxRequests: Type.Integer({ minimum: 1, maximum: 100 }), pendingExpiresOnInterruption: Type.Literal(true) }),
  }),
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
    /**
     * `inspect_script_file` 交给模型的脚本片段字节预算。
     *
     * 与 `llmData.maxTextBytes` 解耦：后者是每条工具结果的整体预算，schema 上限 262144，而
     * Helper 对本操作硬夹 [1024, 65536] 且越界抛错不夹取。共用一个旋钮时，把 `maxTextBytes`
     * 调大就会让本工具恒定 INVALID_ARGUMENT，WebShell 内容特征分析整条路径静默不可用。
     */
    maxScriptExcerptBytes: Type.Integer({ minimum: 1024, maximum: 65_536 }),
    /** `search_web_access_log` 返回的最大行数；上限对齐 Helper 的 safe_int 区间。 */
    maxAccessLogLines: Type.Integer({ minimum: 1, maximum: 5000 }),
    /** 控制端本地的内置 YARA RuleSet 资产目录；目标端路径是协议常量，不可配置。 */
    yaraRuleDir: Type.String(),
  }),
  java: Type.Object({
    supportedContainers: Type.Array(Type.Literal("tomcat")),
    allowClassDump: Type.Boolean(),
    allowRuntimeModification: Type.Literal(false),
    probeJar: Type.String(),
  }),
  account: Type.Object({
    checkAuthorizedKeys: Type.Boolean(),
    checkLoginHistory: Type.Boolean(),
    /** `get_login_history` 返回的最大条数；上限对齐 Helper 的 safe_int 区间。 */
    maxLoginHistoryEntries: Type.Integer({ minimum: 1, maximum: 500 }),
  }),
  persistence: Type.Object({
    maxItemsPerSource: Type.Integer({ minimum: 1, maximum: 5000 }),
    includeUserScope: Type.Boolean(),
  }),
  /**
   * 采集数量上限。与 helper 侧 1.5 MiB 输出预算（host-helper MAX_OUTPUT_BYTES）和控制端
   * 2 MiB 协议硬顶（src/executor/ssh-executor.ts MAX_OUTPUT_BYTES）同一量级：按每条结构化记录
   * 约 200–400 B 估算，1.5 MiB 约容纳 3900–7800 条，因此上限统一收敛到 5000。
   * helper 超预算会截断 items 并置 partial，所以这里的上限不是"防止传输失败"，
   * 而是让预算在任务创建时就显式化，避免用户长期拿到被静默截断的 partial 结果。
   */
  triage: Type.Object({
    maxProcesses: Type.Integer({ minimum: 1, maximum: 5000 }),
    maxConnections: Type.Integer({ minimum: 1, maximum: 5000 }),
    maxFiles: Type.Integer({ minimum: 1, maximum: 5000 }),
    maxTimelineEvents: Type.Integer({ minimum: 1, maximum: 5000 }),
    maxArtifactBytes: Type.Integer({ minimum: 1024, maximum: 104_857_600 }),
    /** `inspect_process_tree` 的最大深度；上限对齐 Helper 的 safe_int 区间。 */
    maxProcessTreeDepth: Type.Integer({ minimum: 1, maximum: 32 }),
  }),
  threatIntel: Type.Object({
    enabled: Type.Boolean(),
    provider: Type.Literal("dbapp-ti"),
    baseUrl: Type.Literal("https://ti.dbappsecurity.com.cn/oapi/v1/"),
    apiKeyEnv: Type.Literal("DBAPP_TI_API_KEY"),
    timeoutSeconds: Type.Integer({ minimum: 1, maximum: 60 }),
    maxBatchSize: Type.Integer({ minimum: 1, maximum: 100 }),
    cacheTtlSeconds: Type.Integer({ minimum: 0, maximum: 86_400 }),
    autoEnrichConnections: Type.Boolean(),
    includePrivateAddresses: Type.Literal(false),
  }),
  remediation: Type.Object({
    requireApproval: Type.Literal(true),
    allowedTools: Type.Array(Type.Union([Type.Literal("quarantine_file"), Type.Literal("disable_account")])),
    quarantineRoot: Type.String(),
  }),
});

export type AppConfig = Static<typeof ConfigSchema>;
