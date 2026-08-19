import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import type { PartialItemsOutput, StableProcessIdentity } from "../../executor/operations.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference, requireReference } from "../reference-utils.js";
import { createSecurityTool } from "../tool-factory.js";
import { attachConnectionReferences } from "../../threat-intel/network-ioc.js";
import { scaleForProfile } from "../shared/process-connections.js";

/**
 * 超时预算约定。
 *
 * 每个工具的 `timeoutMs` 是控制端预算；`SshExecutor` 由它派生目标端墙钟 deadline
 * （`deadlineMs = timeoutMs - 5000`），Helper 到期返回**已采集部分** + `partial` + 原因，
 * 而不是抛错丢弃数据。因此预算不必覆盖病态主机的最坏耗时，但必须让典型主机跑完，
 * 否则分诊会稳定退化成一份内容极少的 `PARTIAL`，看起来正常实则漏检。
 *
 * 调这些数值时同时看 Helper 侧对应操作的成本：跨多个固定根聚合、或串联多个子采集器的操作
 * 成本是单次读取的一个数量级以上，不能沿用默认 45s/60s。
 */

interface ProcessValue extends StableProcessIdentity {
  exePath?: string;
  launcherPath?: string | null;
  [key: string]: unknown;
}

interface ExecutableValue {
  path: string;
  inode: string;
  sha256: string;
  [key: string]: unknown;
}

const processRefSchema = Type.String({ pattern: "^PROC-" });
const executableRefSchema = Type.String({ pattern: "^CAND-" });

function stableRequest(value: ProcessValue): StableProcessIdentity {
  return {
    bootId: value.bootId,
    pid: value.pid,
    startTicks: value.startTicks,
    exeInode: value.exeInode,
    exeSha256: value.exeSha256,
  };
}

function partialResult(
  output: PartialItemsOutput,
  summary: Record<string, unknown>,
  items: unknown[],
  artifactRefs: string[],
): SecurityToolResult {
  return {
    status: output.partial ? "partial" : "success",
    summary: { ...summary, count: items.length, partial: output.partial },
    items,
    artifactRefs,
    warnings: output.warnings,
  };
}

export function createTriageTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  const profile = deps.task.profile ?? "STANDARD";
  const scaled = (value: number, maximum: number) => scaleForProfile(profile, value, maximum);
  const timeWindowHours = Math.max(1, Math.min(8760, deps.task.timeWindowHours ?? 168));
  const maxProcesses = scaled(deps.config.triage.maxProcesses, 10_000);
  const maxConnections = scaled(deps.config.triage.maxConnections, 20_000);
  const maxFiles = scaled(deps.config.triage.maxFiles, 50_000);
  const maxTimelineEvents = scaled(deps.config.triage.maxTimelineEvents, 50_000);
  const structuredEvidence = (
    toolCallId: string,
    tool: string,
    type: string,
    source: string,
    metadata: Record<string, unknown>,
  ) => deps.evidence.putStructured({
    taskId: deps.task.taskId,
    host: deps.task.target.host,
    type,
    source,
    tool,
    toolCallId,
    metadata,
  });

  const tools: SecurityToolDefinition[] = [
    createSecurityTool(...common, {
      name: "capture_volatile_snapshot",
      label: "采集易失性快照",
      description: "采集有界的进程、网络、内存与负载事实。进程以 bootId + PID + startTicks + 可执行文件 inode/SHA-256 固定身份，并返回当前任务专属 processRef。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "volatile_snapshot_captured", executionMode: "sequential",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "capture_volatile_snapshot", params: { maxProcesses, maxConnections } }, signal);
        const refs = output.processes.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value as ProcessValue));
        const processes = refs.map(({ ref, value }) => ({ processRef: ref, ...value }));
        const refsByPid = new Map(refs.map(({ ref, value }) => [value.pid, ref]));
        const rawConnections = Array.isArray(output.connections)
          ? (output.connections as Record<string, unknown>[]).map(({ processPid, ...connection }) => ({
              ...connection,
              ...(typeof processPid === "number" && refsByPid.has(processPid) ? { processRef: refsByPid.get(processPid) } : {}),
            }))
          : [];
        const connections = attachConnectionReferences(deps.store, deps.task.taskId, rawConnections);
        const evidence = structuredEvidence(toolCallId, "capture_volatile_snapshot", "volatile_snapshot", "Linux /proc fixed snapshot", {
          ...output, processes, connections: connections.items,
        });
        return {
          status: output.partial ? "partial" : "success",
          summary: { processCount: refs.length, connectionCount: connections.items.length, threatIntelEligible: connections.refs.length, evidenceId: evidence.evidenceId, partial: output.partial },
          items: [{ evidenceId: evidence.evidenceId, bootId: output.bootId, capturedAt: output.capturedAt, processes, connections: connections.items }],
          artifactRefs: [...refs.map(({ ref }) => ref), ...connections.refs, evidence.evidenceId], warnings: output.warnings,
        };
      },
    }),
    createSecurityTool(...common, {
      name: "list_suspicious_processes",
      label: "枚举可疑进程",
      description: "基于删除后运行、临时目录、隐藏名称、可写可执行映射等固定特征枚举进程；环境只返回变量名与风险标签，不返回变量值或完整命令参数。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "suspicious_processes_listed",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "list_suspicious_processes", params: { maxProcesses } }, signal);
        const refs = output.items.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value as ProcessValue));
        const items = refs.map(({ ref, value }) => ({ processRef: ref, ...value }));
        const evidence = structuredEvidence(toolCallId, "list_suspicious_processes", "suspicious_processes", "Linux /proc fixed scope", { ...output, items });
        return partialResult(output, { evidenceId: evidence.evidenceId }, items, [...refs.map(({ ref }) => ref), evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_process_tree",
      label: "检查进程树",
      description: "只接受当前任务 processRef；Helper 重新验证稳定身份后采集最多 12 层、1000 个祖先/后代节点。",
      parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "process_tree_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const target = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
        const output = await deps.executor.invoke({ operation: "inspect_process_tree", params: { ...stableRequest(target.value), maxDepth: 12, maxNodes: maxProcesses } }, signal);
        const refs = output.items.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value as ProcessValue));
        const items = refs.map(({ ref, value }) => ({ processRef: ref, ...value }));
        const evidence = structuredEvidence(toolCallId, "inspect_process_tree", "process_tree", params.processRef, { targetRef: params.processRef, ...output, items });
        return partialResult(output, { targetRef: params.processRef, evidenceId: evidence.evidenceId }, items,
          [params.processRef, ...refs.map(({ ref }) => ref), evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_process_fds",
      label: "检查进程文件描述符",
      description: "只接受当前任务 processRef；稳定身份复核后采集有界 FD 类型与目标，不读取 FD 内容。",
      parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "process_fds_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const target = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
        const output = await deps.executor.invoke({ operation: "inspect_process_fds", params: { ...stableRequest(target.value), maxItems: Math.min(maxFiles, 5000) } }, signal);
        const evidence = structuredEvidence(toolCallId, "inspect_process_fds", "process_fds", params.processRef, { processRef: params.processRef, ...output });
        return partialResult(output, { processRef: params.processRef, evidenceId: evidence.evidenceId }, output.items, [params.processRef, evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_process_memory_maps",
      label: "检查进程内存映射",
      description: "只接受当前任务 processRef；稳定身份复核后采集有界 /proc maps 元数据，不读取进程内存。",
      parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "process_memory_maps_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const target = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
        const output = await deps.executor.invoke({ operation: "inspect_process_memory_maps", params: { ...stableRequest(target.value), maxItems: Math.min(maxFiles, 5000) } }, signal);
        const evidence = structuredEvidence(toolCallId, "inspect_process_memory_maps", "process_memory_maps", params.processRef, { processRef: params.processRef, ...output });
        return partialResult(output, { processRef: params.processRef, evidenceId: evidence.evidenceId }, output.items, [params.processRef, evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "collect_process_executable",
      label: "采集进程可执行文件",
      description: "只接受当前任务 processRef；Helper 复核 boot/PID/startTicks/inode/SHA-256 后，将可执行文件放入短期 Artifact spool，并由 SFTP 分块写入本地 Evidence。",
      parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 120_000, auditEvent: "process_executable_collected", executionMode: "sequential",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const target = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
        const output = await deps.executor.invoke({ operation: "collect_process_executable", params: { ...stableRequest(target.value), maxBytes: deps.config.triage.maxArtifactBytes } }, signal);
        if (output.sha256 !== target.value.exeSha256) throw new Error("进程可执行文件哈希在采集时发生变化");
        const source = target.value.exePath ?? params.processRef;
        const commonInput = { taskId: deps.task.taskId, host: deps.task.target.host, type: "process_executable", source,
          tool: "collect_process_executable", toolCallId, metadata: { processRef: params.processRef, stableIdentity: stableRequest(target.value) } };
        const evidence = output.artifact
          ? await deps.evidence.putStream({ ...commonInput, transfer: async (onChunk) => deps.executor.downloadArtifact(output.artifact!, onChunk, signal, 120_000) })
          : typeof output.dataBase64 === "string"
            ? await deps.evidence.putBuffer({ ...commonInput, data: Buffer.from(output.dataBase64, "base64") })
            : (() => { throw new Error("采集结果没有 Artifact Token 或兼容字节数据"); })();
        return { status: "success", summary: { processRef: params.processRef, evidenceId: evidence.evidenceId, sha256: evidence.sha256, size: output.size },
          items: [{ processRef: params.processRef, evidenceId: evidence.evidenceId, sha256: evidence.sha256, size: output.size }],
          artifactRefs: [params.processRef, evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "list_recent_executables",
      label: "枚举近期可执行文件",
      description: "仅扫描 Helper 固定 Linux 目录，限定 168 小时、500 结果、单文件 100 MiB，并返回当前任务 executableRef。",
      parameters: Type.Object({}, { additionalProperties: false }),
      // 遍历 11 个固定根并逐文件 SHA-256；见文件头的预算约定。
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 180_000, auditEvent: "recent_executables_listed",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "list_recent_executables", params: { modifiedWithinHours: timeWindowHours, maxItems: maxFiles, maxFileSizeBytes: deps.config.triage.maxArtifactBytes } }, signal);
        const refs = output.items.map((value) => createReference(deps.store, deps.task.taskId, "file", "candidate", value as ExecutableValue));
        const items = refs.map(({ ref, value }) => ({ executableRef: ref, ...value }));
        const evidence = structuredEvidence(toolCallId, "list_recent_executables", "recent_executables", "fixed Linux executable roots", { ...output, items });
        return partialResult(output, { evidenceId: evidence.evidenceId }, items, [...refs.map(({ ref }) => ref), evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "list_privileged_files",
      label: "枚举特权文件",
      description: "仅扫描 Helper 固定目录中的 setuid/setgid/capability 文件，结果有界且返回当前任务 executableRef。",
      parameters: Type.Object({}, { additionalProperties: false }),
      // 11 个 TRIAGE_ROOTS 各跑一次 getcap，是分诊里最贵的单次操作；见文件头的预算约定。
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 180_000, auditEvent: "privileged_files_listed",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "list_privileged_files", params: { maxItems: maxFiles } }, signal);
        const refs = output.items.map((value) => createReference(deps.store, deps.task.taskId, "file", "candidate", value as ExecutableValue));
        const items = refs.map(({ ref, value }) => ({ executableRef: ref, ...value }));
        const evidence = structuredEvidence(toolCallId, "list_privileged_files", "privileged_files", "fixed Linux privileged-file roots", { ...output, items });
        return partialResult(output, { evidenceId: evidence.evidenceId }, items, [...refs.map(({ ref }) => ref), evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "verify_package_integrity",
      label: "核验软件包完整性",
      description: "只接受由近期/特权文件枚举产生的 executableRef；Helper 复核路径、inode、SHA-256 后调用固定 dpkg/rpm argv。",
      parameters: Type.Object({ executableRef: executableRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "package_integrity_verified",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<ExecutableValue>(deps.store, deps.task.taskId, params.executableRef, "file");
        const output = await deps.executor.invoke({ operation: "verify_package_integrity", params: {
          path: candidate.value.path, expectedInode: candidate.value.inode, expectedSha256: candidate.value.sha256,
        } }, signal);
        const evidence = structuredEvidence(toolCallId, "verify_package_integrity", "package_integrity", params.executableRef,
          { executableRef: params.executableRef, ...output });
        return { status: output.partial ? "partial" : "success", summary: { executableRef: params.executableRef, changed: output.changed, package: output.package, evidenceId: evidence.evidenceId },
          items: [{ executableRef: params.executableRef, ...output }], artifactRefs: [params.executableRef, evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_dynamic_loader",
      label: "检查动态加载器",
      description: "检查固定的 ld.so.preload/ld.so.conf 配置及其绝对路径库引用，不读取进程环境变量。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "dynamic_loader_inspected",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "inspect_dynamic_loader", params: { maxItems: maxFiles } }, signal);
        const refs = output.items.filter((value) => typeof value.path === "string" && typeof value.inode === "string" && typeof value.sha256 === "string")
          .map((value) => createReference(deps.store, deps.task.taskId, "file", "candidate", value as unknown as ExecutableValue));
        const byPath = new Map(refs.map(({ ref, value }) => [value.path, ref]));
        const items = output.items.map((value) => ({ ...(byPath.has(String(value.path)) ? { executableRef: byPath.get(String(value.path)) } : {}), ...value }));
        const evidence = structuredEvidence(toolCallId, "inspect_dynamic_loader", "dynamic_loader", "fixed ld.so configuration", { ...output, items });
        return partialResult(output, { evidenceId: evidence.evidenceId }, items, [...refs.map(({ ref }) => ref), evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "query_auth_events",
      label: "查询认证事件",
      description: "读取固定认证日志源的最近 168 小时规范化事件；凭据形态字段始终脱敏，日志不可用时返回 PARTIAL。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "auth_events_queried",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "query_auth_events", params: { sinceHours: timeWindowHours, maxEvents: maxTimelineEvents } }, signal);
        const evidence = structuredEvidence(toolCallId, "query_auth_events", "auth_events", "fixed authentication logs", output as unknown as Record<string, unknown>);
        return partialResult(output, { evidenceId: evidence.evidenceId }, output.items, [evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "query_exec_events",
      label: "查询进程执行事件",
      description: "读取固定 audit 日志源的最近 168 小时规范化 SYSCALL；不返回 EXECVE 参数，数据源缺失时返回 PARTIAL。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "exec_events_queried",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "query_exec_events", params: { sinceHours: timeWindowHours, maxEvents: maxTimelineEvents } }, signal);
        const evidence = structuredEvidence(toolCallId, "query_exec_events", "exec_events", "fixed Linux audit log", output as unknown as Record<string, unknown>);
        return partialResult(output, { evidenceId: evidence.evidenceId }, output.items, [evidence.evidenceId]);
      },
    }),
    createSecurityTool(...common, {
      name: "build_incident_timeline",
      label: "构建入侵时间线",
      description: "在目标端合并固定认证、执行与近期可执行文件事实并按时间排序；任一来源缺失会保留 PARTIAL 和原因。",
      parameters: Type.Object({}, { additionalProperties: false }),
      // 串联认证、执行与近期可执行文件三个子采集器；见文件头的预算约定。
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 240_000, auditEvent: "incident_timeline_built", executionMode: "sequential",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "build_incident_timeline", params: { sinceHours: timeWindowHours, maxEvents: maxTimelineEvents } }, signal);
        const evidence = structuredEvidence(toolCallId, "build_incident_timeline", "incident_timeline", "fixed Linux triage sources", output as unknown as Record<string, unknown>);
        return partialResult(output, { evidenceId: evidence.evidenceId }, output.items, [evidence.evidenceId]);
      },
    }),
  ];
  return profile === "DEEP"
    ? tools
    : tools.filter((tool) => !["verify_package_integrity", "build_incident_timeline"].includes(tool.name));
}
