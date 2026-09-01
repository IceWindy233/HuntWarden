import { isIP } from "node:net";
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

/**
 * 校验通道的前置守卫：只做「必须是对象」与「不得包含明文凭据」两项安全检查。
 *
 * schema 违规**不在这里抛错**：否则 GUI 的配置校验面板永远收不到结构化 issues，
 * 分析师只会看到一条 `Error invoking remote method 'huntwarden:config:validate'`，
 * 既不知道是哪个字段，也拿不到 anyOf 分支之外的真实原因。
 */
export function candidateConfig(value: unknown): AppConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("配置必须是对象");
  scanForSecrets(value);
  return structuredClone(value) as AppConfig;
}

/** 写入通道的守卫：候选检查之外，schema 违规必须 fail closed。 */
export function appConfig(value: unknown): AppConfig {
  const candidate = candidateConfig(value);
  const issues = getConfigIssues(candidate);
  if (issues.length > 0) throw new Error(issues.map((item) => `${item.path}: ${item.message}`).join("；"));
  return candidate;
}

export function newTaskInput(value: unknown): NewTaskInput {
  const record = exactObject(value, ["request", "mode", "checks", "profile", "timeWindowHours", "iocs", "target"], "任务");
  const request = text(record.request, "调查请求", 20_000);
  if (record.mode !== "SCAN" && record.mode !== "REMEDIATE") throw new Error("任务模式无效");
  if (!Array.isArray(record.checks) || record.checks.length < 1) throw new Error("至少选择一个检测项");
  const allowedChecks = new Set(["webshell", "java_memory_shell", "backdoor_account", "linux_persistence", "linux_intrusion_triage"]);
  if (record.checks.some((item) => typeof item !== "string" || !allowedChecks.has(item))) throw new Error("检测项无效");
  if (record.profile !== undefined && !["QUICK", "STANDARD", "DEEP"].includes(String(record.profile))) throw new Error("扫描预设无效");
  if (record.timeWindowHours !== undefined && (typeof record.timeWindowHours !== "number" || !Number.isInteger(record.timeWindowHours) || record.timeWindowHours < 1 || record.timeWindowHours > 8_760)) {
    throw new Error("调查时间窗必须是 1 到 8760 之间的整数小时");
  }
  const target = exactObject(record.target, ["host", "port", "username", "hostFingerprint", "privateKeyPath", "knownHostsPath"], "目标");
  const parsed: NewTaskInput = {
    request,
    mode: record.mode,
    checks: [...new Set(record.checks)] as NewTaskInput["checks"],
    ...(record.profile !== undefined ? { profile: record.profile as NonNullable<NewTaskInput["profile"]> } : {}),
    ...(record.timeWindowHours !== undefined ? { timeWindowHours: Number(record.timeWindowHours) } : {}),
    ...(record.iocs !== undefined ? { iocs: parseInvestigationIocs(record.iocs) } : {}),
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

const MAX_IOCS_PER_KIND = 100;
const MAX_IOCS_TOTAL = 200;

function iocValues(value: unknown, kind: string, validate: (item: string) => boolean, maxLength: number, normalize: (item: string) => string = (item) => item): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new Error(`IOC ${kind} 必须是字符串数组`);
  if (value.length > MAX_IOCS_PER_KIND) throw new Error(`IOC ${kind} 不能超过 ${MAX_IOCS_PER_KIND} 条`);
  const result: string[] = [];
  for (const raw of value) {
    if (typeof raw !== "string") throw new Error(`IOC ${kind} 必须是字符串数组`);
    const item = raw.trim();
    if (!item || item.length > maxLength || item.includes("\0") || !validate(item)) throw new Error(`IOC ${kind} 格式无效: ${item.slice(0, 80) || "（空）"}`);
    result.push(normalize(item));
  }
  return [...new Set(result)];
}

function validDomain(value: string): boolean {
  if (value.length > 253 || value.endsWith(".") || /\s/.test(value)) return false;
  const labels = value.split(".");
  return labels.length >= 2 && labels.every((label) => label.length >= 1 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
}

function parseInvestigationIocs(value: unknown): NonNullable<NewTaskInput["iocs"]> {
  const record = exactObject(value, ["hash", "domain", "ip", "path", "processName"], "IOC");
  const parsed: NonNullable<NewTaskInput["iocs"]> = {};
  const hash = iocValues(record.hash, "hash", (item) => /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$/.test(item), 128, (item) => item.toLowerCase());
  const domain = iocValues(record.domain, "domain", validDomain, 253, (item) => item.toLowerCase());
  const ip = iocValues(record.ip, "ip", (item) => isIP(item) !== 0, 45, (item) => item.toLowerCase());
  const path = iocValues(record.path, "path", (item) => item.startsWith("/") && !/[\r\n]/.test(item), 4_096);
  const processName = iocValues(record.processName, "processName", (item) => !/[\r\n/]/.test(item), 256);
  if (hash?.length) parsed.hash = hash;
  if (domain?.length) parsed.domain = domain;
  if (ip?.length) parsed.ip = ip;
  if (path?.length) parsed.path = path;
  if (processName?.length) parsed.processName = processName;
  const total = Object.values(parsed).reduce((sum, items) => sum + items.length, 0);
  if (total > MAX_IOCS_TOTAL) throw new Error(`IOC 总数不能超过 ${MAX_IOCS_TOTAL} 条`);
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
