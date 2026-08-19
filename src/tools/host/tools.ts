import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { assertCompatibleHelper, type HostCapabilities } from "../../executor/operations.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference } from "../reference-utils.js";

/** 超过该偏差后，跨源时间线（认证日志 / 文件 mtime / audit）的绝对时刻不再可靠对齐。 */
const TIME_SKEW_WARNING_SECONDS = 300;

interface HostTimeFacts {
  timezone: string | null;
  utcOffsetSeconds: number | null;
  hostTimeUtc: string | null;
  controlPlaneTimeUtc: string;
  skewSeconds: number | null;
}

/** 计算控制端与目标端的时间偏差。偏差是时间线解读的可信度前提，不是能力缺失，因此只产出 warning，不改变 PARTIAL 判定。 */
function assessHostTime(capabilities: HostCapabilities, nowMs: number): { facts: HostTimeFacts; warnings: string[] } {
  const rawTimezone: unknown = capabilities.timezone;
  const rawOffset: unknown = capabilities.utcOffsetSeconds;
  const rawHostTime: unknown = capabilities.hostTimeUtc;
  const timezone = typeof rawTimezone === "string" && rawTimezone !== "" ? rawTimezone : null;
  const utcOffsetSeconds = typeof rawOffset === "number" && Number.isFinite(rawOffset) ? rawOffset : null;
  const hostTimeUtc = typeof rawHostTime === "string" && rawHostTime !== "" ? rawHostTime : null;
  const controlPlaneTimeUtc = new Date(nowMs).toISOString();
  const parsed = hostTimeUtc === null ? Number.NaN : Date.parse(hostTimeUtc);
  if (!Number.isFinite(parsed)) {
    return {
      facts: { timezone, utcOffsetSeconds, hostTimeUtc, controlPlaneTimeUtc, skewSeconds: null },
      warnings: ["目标端未上报可解析的主机时间（hostTimeUtc），无法评估控制端与目标主机的时间偏差；时间线的绝对时刻只能按目标端自述解读。"],
    };
  }
  const skewSeconds = Math.round((nowMs - parsed) / 1000);
  const facts: HostTimeFacts = { timezone, utcOffsetSeconds, hostTimeUtc, controlPlaneTimeUtc, skewSeconds };
  if (Math.abs(skewSeconds) <= TIME_SKEW_WARNING_SECONDS) return { facts, warnings: [] };
  return {
    facts,
    warnings: [`控制端与目标主机时间相差 ${skewSeconds} 秒（阈值 ${TIME_SKEW_WARNING_SECONDS} 秒），时间线关联的可信度下降：请先校准目标主机时间（NTP）再解读跨源时间线。`],
  };
}

function scopedCapabilities(deps: ToolDependencies, capabilities: HostCapabilities) {
  const keys = new Set(["linuxProc", "rootHelper"]);
  const booleanFeatures = new Set<string>();
  if (deps.task.checks.includes("webshell")) { keys.add("yara"); booleanFeatures.add("yara"); }
  if (deps.task.checks.includes("java_memory_shell")) {
    keys.add("javaAttach"); keys.add("tomcatProbe"); keys.add("procVisibility");
    booleanFeatures.add("javaAttach"); booleanFeatures.add("tomcatProbe");
  }
  if (deps.task.checks.includes("backdoor_account")) { keys.add("sudo"); keys.add("journal"); keys.add("auditd"); }
  if (deps.task.checks.includes("linux_intrusion_triage")) { keys.add("procVisibility"); keys.add("journal"); keys.add("auditd"); }
  const featureStatus = Object.fromEntries(Object.entries(capabilities.featureStatus ?? {}).filter(([key]) => keys.has(key)));
  const features = Object.fromEntries(Object.entries(capabilities.features).filter(([key]) => booleanFeatures.has(key)));
  const hasDetailedStatus = Boolean(capabilities.featureStatus && Object.keys(capabilities.featureStatus).length > 0);
  const warnings = hasDetailedStatus
    ? Object.values(featureStatus).filter((value) => value.status !== "SUPPORTED").map((value) => value.reason)
    : capabilities.warnings;
  return {
    protocolVersion: capabilities.protocolVersion,
    helper: capabilities.helper,
    platform: capabilities.platform,
    taskChecks: deps.task.checks,
    artifactTransfer: capabilities.artifactTransfer,
    features,
    featureStatus,
    ...(capabilities.runtime ? { runtime: capabilities.runtime } : {}),
    ...(capabilities.securityContext ? { securityContext: capabilities.securityContext } : {}),
    partial: hasDetailedStatus ? warnings.length > 0 : capabilities.partial,
    warnings,
  };
}

export function createHostTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  return [
    createSecurityTool(...common, {
      name: "get_capabilities",
      label: "协商目标能力",
      description: "读取当前任务绑定 Helper 的协议版本、固定操作和运行时依赖能力。缺失能力必须按 PARTIAL 处理，不得表述为已安全检查。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 15_000, auditEvent: "host_capabilities_collected",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const capabilities = await deps.executor.invoke({ operation: "get_capabilities", params: {} }, signal);
        assertCompatibleHelper(capabilities);
        deps.store.appendAudit({ taskId: deps.task.taskId, event: "host_capabilities_scoped_for_task", level: "debug", data: {
          selectedChecks: deps.task.checks, availableOperationCount: capabilities.operations.length,
        } });
        const scoped = scopedCapabilities(deps, capabilities);
        const hostTime = assessHostTime(capabilities, Date.now());
        const item = { ...scoped, hostTime: hostTime.facts };
        const evidence = deps.evidence.putStructured({
          taskId: deps.task.taskId, host: deps.task.target.host, type: "host_capabilities",
          source: "helper capability negotiation", tool: "get_capabilities", toolCallId,
          metadata: { ...item, warnings: [...scoped.warnings, ...hostTime.warnings] },
        });
        return {
          status: scoped.partial ? "partial" : "success",
          summary: {
            protocolVersion: scoped.protocolVersion, helper: scoped.helper, taskChecks: deps.task.checks,
            features: scoped.features, hostTime: hostTime.facts, evidenceId: evidence.evidenceId,
          },
          items: [item], artifactRefs: [evidence.evidenceId], warnings: [...scoped.warnings, ...hostTime.warnings],
        };
      },
    }),
    createSecurityTool(...common, {
      name: "get_host_info",
      label: "获取主机信息",
      description: "获取当前任务绑定主机的操作系统、内核、架构、Java 与 YARA 可用性。应在调查开始时调用。本工具只读且不接受目标参数。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "host_info_collected",
      run: async (_id, _params, signal): Promise<SecurityToolResult> => {
        const info = await deps.executor.invoke({ operation: "get_host_info", params: {} }, signal);
        return { status: "success", summary: info, items: [info], artifactRefs: [], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "list_processes",
      label: "列出进程",
      description: "按可选名称片段查询进程并返回不透明 processRef。用于通用进程关联，不执行任何进程操作。",
      parameters: Type.Object({ pattern: Type.Optional(Type.String({ maxLength: 128 })) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "processes_listed",
      run: async (_id, params, signal): Promise<SecurityToolResult> => {
        const items = await deps.executor.invoke({ operation: "list_processes", params }, signal);
        const refs = items.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value));
        return { status: "success", summary: { count: refs.length }, items: refs.map(({ ref, value }) => ({ processRef: ref, ...value })), artifactRefs: refs.map((item) => item.ref), warnings: [] };
      },
    }),
  ];
}
