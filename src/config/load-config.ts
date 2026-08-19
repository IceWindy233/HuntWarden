import { readFile } from "node:fs/promises";
import { resolve, dirname, isAbsolute } from "node:path";
import { Value } from "typebox/value";
import YAML from "yaml";
import { ConfigSchema, type AppConfig } from "./schema.js";

function resolveConfigPath(configDir: string, value: string): string {
  return isAbsolute(value) ? resolve(value) : resolve(configDir, "..", value);
}

export interface ConfigIssue { path: string; message: string }

/** 目标端 YARA 规则的出厂路径，由 host-helper/install-helper.sh 下发。 */
const DEFAULT_REMOTE_RULE_PATH = "/opt/huntwarden/rules/webshell.yar";
/** 与 ConfigSchema 的 triage 上限一致：旧 Profile 超限时收敛而不是拒绝加载。 */
const TRIAGE_CEILINGS: Record<string, number> = {
  maxProcesses: 5_000, maxConnections: 5_000, maxFiles: 5_000, maxTimelineEvents: 5_000,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function withIncrementalDefaults(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const migrated = structuredClone(input) as Record<string, unknown>;
  if (isRecord(migrated.webshell) && migrated.webshell.remoteRulePath === undefined) {
    migrated.webshell.remoteRulePath = DEFAULT_REMOTE_RULE_PATH;
  }
  if (migrated.persistence === undefined) {
    migrated.persistence = { maxItemsPerSource: 500, includeUserScope: true };
  }
  if (isRecord(migrated.persistence)) {
    // persistence.maxConnections 已退役：进程连接预算统一由 triage.maxConnections 与 Profile 系数提供。
    migrated.persistence = Object.fromEntries(
      Object.entries(migrated.persistence).filter(([key]) => key !== "maxConnections"),
    );
  }
  if (migrated.triage === undefined) {
    migrated.triage = {
      maxProcesses: 2_000,
      maxConnections: 5_000,
      maxFiles: 5_000,
      maxTimelineEvents: 5_000,
      maxArtifactBytes: 10_485_760,
    };
  }
  if (isRecord(migrated.triage)) {
    for (const [key, ceiling] of Object.entries(TRIAGE_CEILINGS)) {
      const value = migrated.triage[key];
      if (typeof value === "number" && value > ceiling) migrated.triage[key] = ceiling;
    }
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

/** remoteRulePath 描述目标主机文件系统，绝不能参与控制端本地路径解析。 */
function validateRemoteRulePath(config: AppConfig): void {
  const value = config.webshell.remoteRulePath;
  if (!value.startsWith("/") || value.includes("..") || value.includes("\0")) {
    throw new Error("配置校验失败:\nwebshell.remoteRulePath 必须是目标端绝对路径，且不得包含 .. 或空字符");
  }
}

export function normalizeConfig(input: unknown, sourcePath: string): AppConfig {
  const migrated = withIncrementalDefaults(input);
  const issues = getConfigIssues(migrated);
  if (issues.length > 0) throw new Error(`配置校验失败:\n${issues.map((issue) => `${issue.path}: ${issue.message}`).join("\n")}`);
  const config = structuredClone(migrated) as AppConfig;
  validateCustomModelEndpoint(config);
  validateRemoteRulePath(config);
  const configDir = dirname(resolve(sourcePath));
  config.storage.baseDir = resolveConfigPath(configDir, config.storage.baseDir);
  config.executor.knownHostsPath = resolveConfigPath(configDir, config.executor.knownHostsPath);
  config.executor.privateKeyPath = resolveConfigPath(configDir, config.executor.privateKeyPath);
  config.webshell.yaraRuleDir = resolveConfigPath(configDir, config.webshell.yaraRuleDir);
  // webshell.remoteRulePath 是目标端路径，此处刻意不做 resolveConfigPath。
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
