import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { InvalidArgumentError } from "../../common/errors.js";
import { DBAPP_THREAT_INTEL_SOURCE, type NetworkConnectionReferenceValue, type ThreatIntelVerdict } from "../../threat-intel/types.js";
import { isPublicThreatIntelIp } from "../../threat-intel/network-ioc.js";
import type { ToolDependencies } from "../dependencies.js";
import { requireReference } from "../reference-utils.js";
import { createSecurityTool } from "../tool-factory.js";

const connectionRefSchema = Type.String({ pattern: "^SOCK-[0-9a-f-]{36}$" });

function enrichedVerdict(verdict: ThreatIntelVerdict, refsByIoc: Map<string, string[]>): Record<string, unknown> {
  return { ...verdict, connectionRefs: refsByIoc.get(verdict.ioc) ?? [] };
}

export function createThreatIntelTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  return [
    createSecurityTool(...common, {
      name: "enrich_observed_network_iocs",
      label: "关联安恒网络威胁情报",
      description: "使用安恒威胁情报 (DBAPP Threat Intelligence) 快速检测当前任务已采集 connectionRef 中的公网远端 IP，以及分析师明确提供的 IP/域名 IOC。禁止提交任意原始网络目标；一次最多 100 个 IOC，每次未命中缓存的请求消耗 1 次情报额度。",
      parameters: Type.Object({
        connectionRefs: Type.Optional(Type.Array(connectionRefSchema, { minItems: 1, maxItems: 100, uniqueItems: true })),
      }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: Math.min(65_000, (deps.config.threatIntel.timeoutSeconds + 5) * 1_000),
      auditEvent: "dbapp_network_threat_intel_queried", executionMode: "sequential",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        if (!deps.config.threatIntel.enabled) return {
          status: "success", summary: { enabled: false, provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, queried: 0 },
          items: [], artifactRefs: [], warnings: ["安恒威胁情报未在当前 Profile 启用"],
        };
        if (!deps.threatIntel) throw new InvalidArgumentError("安恒威胁情报客户端不可用");
        const selected = params.connectionRefs?.map((ref) => requireReference<NetworkConnectionReferenceValue>(deps.store, deps.task.taskId, ref, "socket"))
          ?? deps.store.listReferences<NetworkConnectionReferenceValue>(deps.task.taskId, "socket");
        const refsByIoc = new Map<string, string[]>();
        for (const reference of selected) {
          const ip = reference.value.remoteIp.toLowerCase();
          if (!isPublicThreatIntelIp(ip)) continue;
          refsByIoc.set(ip, [...new Set([...(refsByIoc.get(ip) ?? []), reference.ref])]);
        }
        for (const ioc of [...(deps.task.iocs?.ip ?? []), ...(deps.task.iocs?.domain ?? [])]) {
          const normalized = ioc.toLowerCase();
          if (normalized.includes(":") || /^\d+(?:\.\d+){3}$/.test(normalized)) {
            if (!isPublicThreatIntelIp(normalized)) continue;
          }
          if (!refsByIoc.has(normalized)) refsByIoc.set(normalized, []);
        }
        const allIocs = [...refsByIoc.keys()].sort();
        const queriedIocs = allIocs.slice(0, deps.config.threatIntel.maxBatchSize);
        if (queriedIocs.length === 0) return {
          status: "success", summary: { enabled: true, provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, queried: 0 },
          items: [], artifactRefs: [], warnings: ["当前任务没有可发送的公网 IP 或域名 IOC；私网、回环及保留地址已在本地排除"],
        };
        const result = await deps.threatIntel.compromiseDetection(queriedIocs, signal);
        const items = result.verdicts.map((verdict) => enrichedVerdict(verdict, refsByIoc));
        const warnings = [...result.warnings];
        if (allIocs.length > queriedIocs.length) warnings.push(`IOC 数量达到配置上限，仅查询前 ${queriedIocs.length} 项`);
        const evidence = deps.evidence.putStructured({
          taskId: deps.task.taskId, host: deps.task.target.host, type: "dbapp_network_threat_intel",
          source: DBAPP_THREAT_INTEL_SOURCE, tool: "enrich_observed_network_iocs", toolCallId,
          metadata: { provider: result.provider, source: result.source, requestId: result.requestId, queriedAt: result.queriedAt, verdicts: items, warnings },
        });
        return {
          status: allIocs.length > queriedIocs.length ? "partial" : "success",
          summary: {
            provider: result.provider, source: result.source, requestId: result.requestId, queried: queriedIocs.length,
            malicious: result.verdicts.filter((verdict) => verdict.malicious === true).length,
            unknown: result.verdicts.filter((verdict) => verdict.malicious === null).length,
            evidenceId: evidence.evidenceId,
          },
          items, artifactRefs: [...selected.map((reference) => reference.ref), evidence.evidenceId], warnings,
        };
      },
    }),
    createSecurityTool(...common, {
      name: "enrich_task_file_iocs",
      label: "关联安恒文件威胁情报",
      description: "仅查询分析师创建任务时明确提供的 MD5/SHA1/SHA256，不接受模型自由提交哈希。使用安恒威胁情报批量文件接口；每次未命中缓存的请求消耗 1 次情报额度。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: Math.min(65_000, (deps.config.threatIntel.timeoutSeconds + 5) * 1_000),
      auditEvent: "dbapp_file_threat_intel_queried", executionMode: "sequential",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        if (!deps.config.threatIntel.enabled) return {
          status: "success", summary: { enabled: false, provider: "dbapp-ti", source: DBAPP_THREAT_INTEL_SOURCE, queried: 0 },
          items: [], artifactRefs: [], warnings: ["安恒威胁情报未在当前 Profile 启用"],
        };
        if (!deps.threatIntel) throw new InvalidArgumentError("安恒威胁情报客户端不可用");
        const hashes = [...new Set(deps.task.iocs?.hash ?? [])].slice(0, deps.config.threatIntel.maxBatchSize);
        if (hashes.length === 0) return { status: "success", summary: { queried: 0, source: DBAPP_THREAT_INTEL_SOURCE }, items: [], artifactRefs: [], warnings: ["任务未提供文件哈希 IOC"] };
        const result = await deps.threatIntel.batchFileInfo(hashes, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "dbapp_file_threat_intel",
          source: DBAPP_THREAT_INTEL_SOURCE, tool: "enrich_task_file_iocs", toolCallId, metadata: result as unknown as Record<string, unknown> });
        return { status: "success", summary: { provider: result.provider, source: result.source, requestId: result.requestId, queried: hashes.length,
          malicious: result.verdicts.filter((verdict) => verdict.malicious === true).length, evidenceId: evidence.evidenceId },
          items: result.verdicts, artifactRefs: [evidence.evidenceId], warnings: result.warnings };
      },
    }),
  ];
}
