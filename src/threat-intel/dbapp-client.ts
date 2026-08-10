import { isIP } from "node:net";
import type { AppConfig } from "../config/schema.js";
import { InvalidArgumentError, SecurityError, TargetUnavailableError, ToolTimeoutError } from "../common/errors.js";
import {
  DBAPP_THREAT_INTEL_SOURCE,
  type ThreatIntelBatchResult,
  type ThreatIntelClient,
  type ThreatIntelIocType,
  type ThreatIntelRiskLevel,
  type ThreatIntelVerdict,
} from "./types.js";

type Fetch = typeof globalThis.fetch;
type ApiKeyProvider = () => Promise<string | undefined>;

interface CacheEntry { expiresAt: number; verdict: ThreatIntelVerdict }

const MAX_RESPONSE_BYTES = 1024 * 1024;

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => typeof item === "string" ? [item.slice(0, 512)] : []).slice(0, 100);
  return typeof value === "string" && value.trim() ? [value.trim().slice(0, 512)] : [];
}

function first(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function confidence(value: unknown): number | null {
  const number = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : Number.NaN;
  if (!Number.isFinite(number)) return null;
  return Math.max(0, Math.min(1, number > 1 ? number / 100 : number));
}

function riskLevel(value: unknown): ThreatIntelRiskLevel {
  const normalized = typeof value === "string" ? value.toLowerCase().replace(/\s+/g, "_") : "";
  if (["critical", "severe", "极高", "严重"].includes(normalized)) return "critical";
  if (["high", "malicious", "高", "高危"].includes(normalized)) return "high";
  if (["medium", "moderate", "中", "中危"].includes(normalized)) return "medium";
  if (["low", "低", "低危"].includes(normalized)) return "low";
  if (["info", "informational", "safe", "normal", "信息", "正常"].includes(normalized)) return "info";
  return "unknown";
}

function booleanOrNull(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === "1" || value === "true") return true;
  if (value === 0 || value === "0" || value === "false") return false;
  return null;
}

function rowsFrom(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data.flatMap((item) => record(item) ? [record(item)!] : []);
  const root = record(data);
  if (!root) return [];
  for (const key of ["results", "items", "list", "records"]) {
    if (Array.isArray(root[key])) return rowsFrom(root[key]);
  }
  return Object.entries(root).flatMap(([ioc, value]) => {
    const item = record(value);
    return item ? [{ ioc, ...item }] : [];
  });
}

function reportUrl(ioc: string, type: ThreatIntelIocType): string | undefined {
  const encoded = encodeURIComponent(ioc);
  if (type === "ip") return `https://ti.dbappsecurity.com.cn/ip/${encoded}`;
  if (type === "domain") return `https://ti.dbappsecurity.com.cn/domain/${encoded}`;
  if (type === "file") return `https://ti.dbappsecurity.com.cn/file/${encoded}`;
  return undefined;
}

function normalizeVerdict(ioc: string, type: ThreatIntelIocType, row: Record<string, unknown> | undefined): ThreatIntelVerdict {
  const threat = record(first(row?.threat_intel, row?.threatIntel)) ?? row ?? {};
  const malicious = booleanOrNull(first(row?.is_malicious, row?.isMalicious, threat.is_malicious, threat.isMalicious));
  const level = riskLevel(first(row?.risk_level, row?.riskLevel, row?.level, threat.risk_level, threat.riskLevel, threat.level));
  const inferredMalicious = malicious ?? (["critical", "high"].includes(level) ? true : level === "info" ? false : null);
  const description = first(row?.description, threat.description);
  const detailsUrl = reportUrl(ioc, type);
  return {
    ioc,
    iocType: type,
    malicious: inferredMalicious,
    riskLevel: level,
    confidence: confidence(first(row?.confidence, threat.confidence)),
    threatTypes: strings(first(row?.threat_type, row?.threatTypes, threat.threat_type, threat.threat_category, threat.category)),
    apt: booleanOrNull(first(row?.is_apt, row?.isApt, threat.is_apt, threat.isApt)),
    hackerGroups: strings(first(row?.hacker_groups, row?.hackerGroups, threat.hacker_groups, threat.related_hacker_groups)),
    attackEvents: strings(first(row?.attack_events, row?.attackEvents, threat.attack_events, threat.related_attack_events)),
    malwareFamilies: strings(first(row?.malware_families, row?.malwareFamilies, threat.malware_families, threat.related_families)),
    ...(typeof description === "string" ? { description: description.slice(0, 2_048) } : {}),
    cached: false,
    source: DBAPP_THREAT_INTEL_SOURCE,
    ...(detailsUrl ? { reportUrl: detailsUrl } : {}),
  };
}

function rowIoc(row: Record<string, unknown>): string | undefined {
  const value = first(row.ioc, row.indicator, row.ip, row.domain, row.file_hash, row.fileHash, row.sha256, row.md5, row.sha1);
  return typeof value === "string" ? value.toLowerCase() : undefined;
}

function validDomain(value: string): boolean {
  if (value.length > 253 || value.endsWith(".") || /\s/.test(value)) return false;
  const labels = value.split(".");
  return labels.length >= 2 && labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

export class DbappThreatIntelClient implements ThreatIntelClient {
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    private readonly config: AppConfig["threatIntel"],
    private readonly apiKey: ApiKeyProvider,
    private readonly fetcher: Fetch = globalThis.fetch,
  ) {}

  async compromiseDetection(iocs: readonly string[], signal?: AbortSignal): Promise<ThreatIntelBatchResult> {
    const normalized = [...new Set(iocs.map((ioc) => ioc.trim().toLowerCase()))];
    if (normalized.some((ioc) => isIP(ioc) === 0 && !validDomain(ioc))) throw new InvalidArgumentError("威胁情报 IOC 仅允许有效 IP 或域名");
    return await this.query("compromise-detection", normalized, (ioc) => isIP(ioc) ? "ip" : "domain", { iocs: normalized.join(",") }, signal);
  }

  async batchFileInfo(hashes: readonly string[], signal?: AbortSignal): Promise<ThreatIntelBatchResult> {
    const normalized = [...new Set(hashes.map((hash) => hash.trim().toLowerCase()))];
    if (normalized.some((hash) => !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(hash))) throw new InvalidArgumentError("威胁情报文件 IOC 仅允许 MD5、SHA1 或 SHA256");
    return await this.query("batch/file-basic-info", normalized, () => "file", { file_hashes: normalized }, signal);
  }

  private async query(
    path: string,
    iocs: string[],
    typeFor: (ioc: string) => ThreatIntelIocType,
    body: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<ThreatIntelBatchResult> {
    if (iocs.length < 1 || iocs.length > this.config.maxBatchSize) throw new InvalidArgumentError(`单次威胁情报查询必须为 1 到 ${this.config.maxBatchSize} 个 IOC`);
    const now = Date.now();
    const cached: ThreatIntelVerdict[] = [];
    const missing: string[] = [];
    for (const ioc of iocs) {
      const entry = this.cache.get(`${path}:${ioc}`);
      if (entry && entry.expiresAt >= now) cached.push({ ...entry.verdict, cached: true });
      else missing.push(ioc);
    }
    if (missing.length === 0) return {
      provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, queriedAt: new Date().toISOString(), verdicts: cached, warnings: [],
    };

    const key = (await this.apiKey())?.trim();
    if (!key || !/^nti-\S{8,}$/.test(key)) throw new SecurityError("PERMISSION_DENIED", "安恒威胁情报 API Key 未配置或格式无效");
    const endpoint = new URL(path, this.config.baseUrl);
    if (endpoint.protocol !== "https:" || endpoint.hostname !== "ti.dbappsecurity.com.cn") throw new InvalidArgumentError("安恒威胁情报端点必须使用官方 HTTPS 域名");

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new ToolTimeoutError("安恒威胁情报查询超时")), this.config.timeoutSeconds * 1_000);
    const abort = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", abort, { once: true });
    try {
      const requestBody = path === "compromise-detection" ? { iocs: missing.join(",") } : { ...body, file_hashes: missing };
      let response: Response;
      try {
        response = await this.fetcher(endpoint, {
          method: "POST",
          headers: { "X-API-Key": key, "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify(requestBody), signal: controller.signal, redirect: "error",
        });
      } catch (error) {
        if (controller.signal.aborted && controller.signal.reason instanceof ToolTimeoutError) throw controller.signal.reason;
        if (signal?.aborted) throw signal.reason;
        throw new TargetUnavailableError("无法连接安恒威胁情报服务", error instanceof Error ? { cause: error } : undefined);
      }
      if (response.status === 401 || response.status === 403) throw new SecurityError("PERMISSION_DENIED", "安恒威胁情报 API Key 无效或权限不足");
      if (response.status === 429) throw new SecurityError("BUDGET_EXCEEDED", "安恒威胁情报查询额度或速率已达上限");
      if (!response.ok) throw new TargetUnavailableError(`安恒威胁情报服务返回 HTTP ${response.status}`);
      const raw = await response.text();
      if (Buffer.byteLength(raw, "utf8") > MAX_RESPONSE_BYTES) throw new TargetUnavailableError("安恒威胁情报响应超过 1 MiB 安全上限");
      let envelope: Record<string, unknown>;
      try { envelope = record(JSON.parse(raw)) ?? {}; }
      catch { throw new TargetUnavailableError("安恒威胁情报响应不是有效 JSON"); }
      if (envelope.code !== 0 && envelope.code !== 200 && envelope.code !== undefined) {
        throw new TargetUnavailableError(`安恒威胁情报查询失败: ${String(envelope.message ?? envelope.code).slice(0, 256)}`);
      }
      const rows = rowsFrom(envelope.data);
      const byIoc = new Map(rows.flatMap((row) => rowIoc(row) ? [[rowIoc(row)!, row] as const] : []));
      const fresh = missing.map((ioc) => normalizeVerdict(ioc, typeFor(ioc), byIoc.get(ioc)));
      const expiresAt = Date.now() + this.config.cacheTtlSeconds * 1_000;
      for (const verdict of fresh) this.cache.set(`${path}:${verdict.ioc}`, { verdict, expiresAt });
      const requestId = typeof envelope.request_id === "string" ? envelope.request_id.slice(0, 256) : undefined;
      return {
        provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, ...(requestId ? { requestId } : {}), queriedAt: new Date().toISOString(),
        verdicts: iocs.map((ioc) => cached.find((item) => item.ioc === ioc) ?? fresh.find((item) => item.ioc === ioc)!),
        warnings: fresh.filter((verdict) => verdict.malicious === null && verdict.riskLevel === "unknown").map((verdict) => `${verdict.ioc}: 情报库未返回明确判定`),
      };
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }
}
