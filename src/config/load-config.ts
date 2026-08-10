import { readFile } from "node:fs/promises";
import { resolve, dirname, isAbsolute } from "node:path";
import { Value } from "typebox/value";
import YAML from "yaml";
import { ConfigSchema, type AppConfig } from "./schema.js";

function resolveConfigPath(configDir: string, value: string): string {
  return isAbsolute(value) ? resolve(value) : resolve(configDir, "..", value);
}

export interface ConfigIssue { path: string; message: string }

function withIncrementalDefaults(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const migrated = structuredClone(input) as Record<string, unknown>;
  if (migrated.persistence === undefined) {
    migrated.persistence = { maxItemsPerSource: 500, includeUserScope: true, maxConnections: 500 };
  }
  if (migrated.triage === undefined) {
    migrated.triage = {
      maxProcesses: 2_000,
      maxConnections: 5_000,
      maxFiles: 10_000,
      maxTimelineEvents: 10_000,
      maxArtifactBytes: 10_485_760,
    };
  }
  if (migrated.threatIntel === undefined) {
    migrated.threatIntel = {
      enabled: false,
      provider: "dbapp-ti",
      baseUrl: "https://ti.dbappsecurity.com.cn/oapi/v1/",
      apiKeyEnv: "DBAPP_TI_API_KEY",
      timeoutSeconds: 15,
      maxBatchSize: 100,
      cacheTtlSeconds: 3_600,
      autoEnrichConnections: true,
      includePrivateAddresses: false,
    };
  }
  return migrated;
}

export function getConfigIssues(input: unknown): ConfigIssue[] {
  return [...Value.Errors(ConfigSchema, input)].map((issue) => ({ path: issue.instancePath || "/", message: issue.message }));
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
  config.webshell.yaraRuleDir = resolveConfigPath(configDir, config.webshell.yaraRuleDir);
  config.java.probeJar = resolveConfigPath(configDir, config.java.probeJar);
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
