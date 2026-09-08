import { readFile } from "node:fs/promises";
import { resolve, dirname, isAbsolute } from "node:path";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import YAML from "yaml";
import { BuiltinModelSchema, ConfigSchema, CustomModelSchema, type AppConfig } from "./schema.js";

function resolveConfigPath(configDir: string, value: string): string {
  return isAbsolute(value) ? resolve(value) : resolve(configDir, "..", value);
}

export interface ConfigIssue { path: string; message: string }

const RETIRED_TOP_LEVEL_KEYS = ["java", "account", "persistence", "triage"] as const;
const RETIRED_WEBSHELL_KEYS = [
  "remoteRulePath", "maxCandidateFiles", "maxFileSizeBytes", "maxScriptExcerptBytes", "maxAccessLogLines", "yaraRuleDir",
] as const;
const RETIRED_THREAT_INTEL_KEYS = ["autoEnrichConnections", "includePrivateAddresses"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function withIncrementalDefaults(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const migrated = structuredClone(input) as Record<string, unknown>;
  // 显式 v1→v2 结构迁移：协议预算和数据策略从旧的混合旋钮中拆出，保存时写回 schemaVersion 2。
  if (migrated.schemaVersion === undefined || migrated.schemaVersion === 1) {
    migrated.schemaVersion = 2;
    migrated.protocolV2 = {
      remoteBudget: {
        preset: { remoteCalls: 80, nodes: 20_000, bytes: 64 * 1024 * 1024, wallTimeMs: 15 * 60_000, probeCalls: 10 },
        model: { remoteCalls: 80, nodes: 20_000, bytes: 64 * 1024 * 1024, wallTimeMs: 15 * 60_000, probeCalls: 10 },
      },
      localQueryBudget: { calls: 200, rows: 50_000, wallTimeMs: 5 * 60_000 },
      externalIntelBudget: { calls: 100, iocs: 1_000, wallTimeMs: 5 * 60_000 },
      dataPolicy: { modelContentBytes: 4 * 1024 * 1024, evidenceBytes: 256 * 1024 * 1024, defaultTextClass: "SENSITIVE_TEXT" },
      grants: { maxRequests: 20, pendingExpiresOnInterruption: true },
    };
  }
  if (isRecord(migrated.protocolV2) && migrated.protocolV2.externalIntelBudget === undefined) {
    migrated.protocolV2.externalIntelBudget = { calls: 100, iocs: 1_000, wallTimeMs: 5 * 60_000 };
  }
  if (isRecord(migrated.agent)) {
    delete migrated.agent.maxToolCalls;
    delete migrated.agent.plannerToolCallShare;
    if (migrated.agent.contextRetainTurns === undefined) migrated.agent.contextRetainTurns = 3;
    if (migrated.agent.providerMaxRetries === undefined) migrated.agent.providerMaxRetries = 2;
    if (migrated.agent.providerTimeoutSeconds === undefined) migrated.agent.providerTimeoutSeconds = 600;
    if (migrated.agent.promptVersion === "sechost-agent-v1" || migrated.agent.promptVersion === "huntwarden-agent-v1") migrated.agent.promptVersion = "huntwarden-agent-v2";
  }
  if (isRecord(migrated.webshell)) {
    for (const key of RETIRED_WEBSHELL_KEYS) delete migrated.webshell[key];
  }
  for (const key of RETIRED_TOP_LEVEL_KEYS) delete migrated[key];
  if (migrated.threatIntel === undefined) {
    migrated.threatIntel = {
      enabled: false,
      provider: "dbapp-ti",
      baseUrl: "https://ti.dbappsecurity.com.cn/oapi/v1/",
      apiKeyEnv: "DBAPP_TI_API_KEY",
      timeoutSeconds: 15,
      maxBatchSize: 100,
      cacheTtlSeconds: 3_600,
    };
  }
  if (isRecord(migrated.threatIntel)) for (const key of RETIRED_THREAT_INTEL_KEYS) delete migrated.threatIntel[key];
  return migrated;
}

function schemaIssues(schema: TSchema, value: unknown, prefix: string): ConfigIssue[] {
  const issues: ConfigIssue[] = [];
  const seen = new Set<string>();
  for (const error of Value.Errors(schema, value)) {
    const additional = error.keyword === "additionalProperties" && Array.isArray(error.params.additionalProperties)
      ? error.params.additionalProperties.filter((item): item is string => typeof item === "string")
      : [];
    const current = additional.length > 0
      ? additional.map((name) => ({ path: `${prefix}${error.instancePath}/${name}` || "/", message: "未知配置字段" }))
      : [{ path: `${prefix}${error.instancePath}` || "/", message: error.message }];
    for (const issue of current) {
      const key = `${issue.path}\u0000${issue.message}`;
      if (seen.has(key)) continue;
      seen.add(key);
      issues.push(issue);
    }
  }
  return issues;
}

export function getConfigIssues(input: unknown): ConfigIssue[] {
  const issues = schemaIssues(ConfigSchema, input, "");
  const model = isRecord(input) ? input.model : undefined;
  const branch = !isRecord(model) ? undefined
    : model.source === "custom" ? CustomModelSchema
      : model.source === undefined || model.source === "builtin" ? BuiltinModelSchema
        : undefined;
  if (!branch) return issues;
  /*
   * `model` 是 anyOf 联合：未选中分支的判别式错误会一起冒出来——明确写了
   * `source: custom`，却收到「/model/source: must be equal to constant」，
   * 真正的原因（例如 provider 大小写不合法）反而被埋在同一串里且重复两遍。
   * 因此按 source 选定分支后单独校验该分支，只保留可执行的原因。
   */
  return [
    ...issues.filter((issue) => issue.path !== "/model" && !issue.path.startsWith("/model/")),
    ...schemaIssues(branch, model, "/model"),
  ];
}

function validateCustomModelEndpoint(config: AppConfig): void {
  if (config.model.source !== "custom") return;
  let endpoint: URL;
  try {
    endpoint = new URL(config.model.baseUrl);
  } catch {
    throw new Error("配置校验失败:\n自定义模型 baseUrl 不是有效 URL");
  }
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("配置校验失败:\n自定义模型 baseUrl 禁止包含凭据、查询参数或片段");
  }
  const localHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
  if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && localHosts.has(endpoint.hostname))) {
    throw new Error("配置校验失败:\n远程模型端点必须使用 HTTPS；HTTP 仅允许本机回环地址");
  }
  if (config.model.authentication.type === "none" && !localHosts.has(endpoint.hostname)) {
    throw new Error("配置校验失败:\n无认证自定义模型仅允许本机回环地址");
  }
  config.model.baseUrl = endpoint.href.replace(/\/$/, "");
}

export function normalizeConfig(input: unknown, sourcePath: string): AppConfig {
  const migrated = withIncrementalDefaults(input);
  const issues = getConfigIssues(migrated);
  if (issues.length > 0) throw new Error(`配置校验失败:\n${issues.map((issue) => `${issue.path}: ${issue.message}`).join("\n")}`);
  const config = structuredClone(migrated) as AppConfig;
  validateCustomModelEndpoint(config);
  const configDir = dirname(resolve(sourcePath));
  config.storage.baseDir = resolveConfigPath(configDir, config.storage.baseDir);
  config.executor.knownHostsPath = resolveConfigPath(configDir, config.executor.knownHostsPath);
  config.executor.privateKeyPath = resolveConfigPath(configDir, config.executor.privateKeyPath);
  return config;
}

export function parseConfig(text: string, sourcePath: string): AppConfig {
  let parsed: unknown;
  try {
    parsed = YAML.parse(text);
  } catch (error) {
    throw new Error(`配置 YAML 解析失败: ${error instanceof Error ? error.message : String(error)}`);
  }
  return normalizeConfig(parsed, sourcePath);
}

export function serializeConfig(config: AppConfig): string {
  return YAML.stringify(config, { lineWidth: 120 });
}

export async function loadConfig(path = process.env.HUNTWARDEN_CONFIG ?? process.env.SECHOST_CONFIG ?? "./config/default.yaml"): Promise<AppConfig> {
  const absolutePath = resolve(path);
  return parseConfig(await readFile(absolutePath, "utf8"), absolutePath);
}
