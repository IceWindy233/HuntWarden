import type { AppConfig } from "../config/schema.js";
import { getConfigIssues } from "../config/load-config.js";
import type { NewTaskInput } from "../gui/contracts.js";
import { validateTargetConfig } from "../domain/validation.js";

export function exactObject(value: unknown, keys: readonly string[], label = "参数"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}必须是对象`);
  const record = value as Record<string, unknown>;
  const allowed = new Set(keys);
  const unknown = Object.keys(record).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new Error(`${label}包含未知字段: ${unknown.join(", ")}`);
  return record;
}

export function text(value: unknown, label: string, max = 256): string {
  if (typeof value !== "string") throw new Error(`${label}必须是字符串`);
  const normalized = value.trim();
  if (!normalized || normalized.length > max || normalized.includes("\0")) throw new Error(`${label}不能为空且不能超过 ${max} 字符`);
  return normalized;
}

export function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label}必须是布尔值`);
  return value;
}

export function appConfig(value: unknown): AppConfig {
  const issues = getConfigIssues(value);
  if (issues.length > 0) throw new Error(issues.map((item) => `${item.path}: ${item.message}`).join("；"));
  scanForSecrets(value);
  return structuredClone(value) as AppConfig;
}

export function newTaskInput(value: unknown): NewTaskInput {
  const record = exactObject(value, ["request", "mode", "checks", "target"], "任务");
  const request = text(record.request, "调查请求", 20_000);
  if (record.mode !== "SCAN" && record.mode !== "REMEDIATE") throw new Error("任务模式无效");
  if (!Array.isArray(record.checks) || record.checks.length < 1) throw new Error("至少选择一个检测项");
  const allowedChecks = new Set(["webshell", "java_memory_shell", "backdoor_account", "linux_persistence"]);
  if (record.checks.some((item) => typeof item !== "string" || !allowedChecks.has(item))) throw new Error("检测项无效");
  const target = exactObject(record.target, ["host", "port", "username", "hostFingerprint", "privateKeyPath", "knownHostsPath"], "目标");
  const parsed: NewTaskInput = {
    request,
    mode: record.mode,
    checks: [...new Set(record.checks)] as NewTaskInput["checks"],
    target: {
      host: text(target.host, "目标主机", 253),
      port: Number(target.port),
      username: text(target.username, "SSH 用户", 32),
      hostFingerprint: text(target.hostFingerprint, "目标指纹", 256),
      privateKeyPath: text(target.privateKeyPath, "SSH 私钥路径", 4096),
      knownHostsPath: text(target.knownHostsPath, "known_hosts 路径", 4096),
    },
  };
  validateTargetConfig(parsed.target);
  return parsed;
}

function scanForSecrets(value: unknown, path = ""): void {
  if (Array.isArray(value)) { value.forEach((item, index) => scanForSecrets(item, `${path}/${index}`)); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (/^(apiKey|token|password|secret|privateKey)$/i.test(key)) throw new Error(`配置禁止包含秘密字段: ${path}/${key}`);
    scanForSecrets(child, `${path}/${key}`);
  }
}
