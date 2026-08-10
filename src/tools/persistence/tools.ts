import { Type } from "typebox";
import type { HostOperation } from "../../executor/operations.js";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference, requireReference } from "../reference-utils.js";
import { createSecurityTool } from "../tool-factory.js";
import { attachConnectionReferences } from "../../threat-intel/network-ioc.js";

interface PersistenceValue {
  kind: "cron" | "systemd" | "ssh" | "shell" | "extended";
  path: string;
  sha256: string;
  username?: string;
  commandSummary?: string;
  commandSummaries?: string[];
  execStart?: string[];
  [key: string]: unknown;
}

interface ProcessValue { bootId?: string; pid: number; startTicks?: string; exeInode?: string; exeSha256?: string; command?: string; executable?: string; [key: string]: unknown }

const persistenceRefSchema = Type.String({ pattern: "^PERSIST-" });
const processRefSchema = Type.String({ pattern: "^PROC-" });

export function createPersistenceTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  const listTool = (
    name: "list_cron_entries" | "list_systemd_units" | "list_extended_persistence" | "list_ssh_persistence" | "list_shell_startup_files",
    label: string,
    description: string,
    operation: HostOperation,
  ) => createSecurityTool(...common, {
    name, label, description,
    parameters: Type.Object({}, { additionalProperties: false }),
    risk: "READ" as const, replayPolicy: "SAFE" as const, timeoutMs: 30_000, auditEvent: `${name}_completed`,
    run: async (toolCallId: string, _params: object, signal?: AbortSignal): Promise<SecurityToolResult> => {
      const output = await deps.executor.invoke({
        operation: operation as "list_cron_entries",
        params: { maxItems: deps.config.persistence.maxItemsPerSource, includeUserScope: deps.config.persistence.includeUserScope },
      }, signal);
      const rawItems = Array.isArray(output.items) ? output.items as PersistenceValue[] : [];
      const refs = rawItems.filter((item) => typeof item.path === "string" && typeof item.sha256 === "string")
        .map((value) => createReference(deps.store, deps.task.taskId, "persistence", "persistence", value));
      const warnings = Array.isArray(output.warnings) ? output.warnings : [];
      const evidence = deps.evidence.putStructured({
        taskId: deps.task.taskId, host: deps.task.target.host, type: name, source: "Linux persistence fixed scope",
        tool: name, toolCallId, metadata: { items: refs.map(({ ref, value }) => ({ persistenceRef: ref, ...value })), partial: Boolean(output.partial), warnings,
          ...(name === "list_ssh_persistence" ? { sshdConfig: (output as Record<string, unknown>).sshdConfig } : {}) },
      });
      return {
        status: output.partial ? "partial" : "success",
        summary: { count: refs.length, evidenceId: evidence.evidenceId, partial: Boolean(output.partial) },
        items: refs.map(({ ref, value }) => ({ persistenceRef: ref, ...value })),
        artifactRefs: [...refs.map((item) => item.ref), evidence.evidenceId], warnings,
      };
    },
  });

  return [
    listTool("list_cron_entries", "枚举 Cron 持久化", "枚举系统和用户 Cron（MITRE T1053.003），返回只属于当前任务的 persistenceRef。", "list_cron_entries"),
    listTool("list_systemd_units", "枚举 systemd 持久化", "枚举 system/user service 与 timer（MITRE T1543.002）、启用链接和 ExecStart；管理器缺失时返回 PARTIAL。", "list_systemd_units"),
    listTool("list_extended_persistence", "枚举扩展持久化", "枚举 at/anacron、SysV/rc.local、XDG、PAM、udev、modprobe、cloud-init、包管理 Hook 与 user linger。", "list_extended_persistence"),
    listTool("list_ssh_persistence", "枚举 SSH Key 持久化", "检查有效 sshd 配置与交互账户 Key 指纹（MITRE T1098.004）；不返回完整公钥。", "list_ssh_persistence"),
    listTool("list_shell_startup_files", "枚举 Shell 启动项", "检查系统及用户 Shell 启动文件（MITRE T1546.004）的权限、哈希和危险执行特征。", "list_shell_startup_files"),
    createSecurityTool(...common, {
      name: "inspect_persistence_item", label: "检查持久化项",
      description: "只接受 persistenceRef；目标 Helper 重新校验固定目录与当前哈希，然后返回详情。",
      parameters: Type.Object({ persistenceRef: persistenceRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "persistence_item_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const item = requireReference<PersistenceValue>(deps.store, deps.task.taskId, params.persistenceRef, "persistence");
        const result = await deps.executor.invoke({ operation: "inspect_persistence_item", params: {
          kind: item.value.kind, path: item.value.path, expectedSha256: item.value.sha256,
          ...(item.value.username ? { username: item.value.username } : {}),
        } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "persistence_item_detail",
          source: item.value.path, tool: "inspect_persistence_item", toolCallId, metadata: { persistenceRef: params.persistenceRef, ...result } });
        return { status: "success", summary: { kind: item.value.kind, path: item.value.path, evidenceId: evidence.evidenceId },
          items: [{ persistenceRef: params.persistenceRef, evidenceId: evidence.evidenceId, ...result }],
          artifactRefs: [params.persistenceRef, evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "find_related_processes", label: "关联运行进程",
      description: "只接受 persistenceRef，按该持久化项中已固定的命令特征关联进程并返回 processRef。",
      parameters: Type.Object({ persistenceRef: persistenceRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "persistence_processes_correlated",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const item = requireReference<PersistenceValue>(deps.store, deps.task.taskId, params.persistenceRef, "persistence");
        const commandHint = item.value.commandSummary ?? item.value.execStart?.join(" ") ?? item.value.commandSummaries?.join(" ") ?? "";
        const result = await deps.executor.invoke({ operation: "find_related_processes", params: {
          kind: item.value.kind, path: item.value.path, expectedSha256: item.value.sha256, commandHint, maxProcesses: 500,
        } }, signal) as ProcessValue[];
        const refs = result.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value));
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "persistence_related_processes",
          source: item.value.path, tool: "find_related_processes", toolCallId,
          metadata: { persistenceRef: params.persistenceRef, processes: refs.map(({ ref, value }) => ({ processRef: ref, ...value })) } });
        return { status: "success", summary: { count: refs.length, evidenceId: evidence.evidenceId },
          items: refs.map(({ ref, value }) => ({ processRef: ref, ...value })),
          artifactRefs: [...refs.map((value) => value.ref), evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "list_process_connections", label: "关联进程网络连接",
      description: "只接受当前任务的 processRef，返回该进程的监听与连接事实，最多采用配置上限。",
      parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "process_connections_listed",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const process = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
        const stable = process.value.bootId && process.value.startTicks && process.value.exeInode && process.value.exeSha256
          ? { bootId: process.value.bootId, startTicks: process.value.startTicks, exeInode: process.value.exeInode, exeSha256: process.value.exeSha256 }
          : {};
        const output = await deps.executor.invoke({ operation: "list_process_connections", params: {
          pid: process.value.pid, ...stable, maxConnections: deps.config.persistence.maxConnections,
        } }, signal);
        const warnings = Array.isArray(output.warnings) ? output.warnings : [];
        const connections = attachConnectionReferences(deps.store, deps.task.taskId, output.items as Record<string, unknown>[], params.processRef);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "process_connections",
          source: `PID:${process.value.pid}`, tool: "list_process_connections", toolCallId,
          metadata: { processRef: params.processRef, connections: connections.items, partial: output.partial, warnings } });
        return { status: output.partial ? "partial" : "success", summary: { count: connections.items.length, threatIntelEligible: connections.refs.length, evidenceId: evidence.evidenceId },
          items: connections.items, artifactRefs: [params.processRef, ...connections.refs, evidence.evidenceId], warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "collect_persistence_artifact", label: "采集持久化文件",
      description: "只接受 persistenceRef；Helper 校验固定目录和列表时哈希后，采集不超过 10 MiB 的原始文件到本地 Evidence。",
      parameters: Type.Object({ persistenceRef: persistenceRefSchema }, { additionalProperties: false }),
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "persistence_artifact_collected", executionMode: "sequential",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const item = requireReference<PersistenceValue>(deps.store, deps.task.taskId, params.persistenceRef, "persistence");
        const result = await deps.executor.invoke({ operation: "collect_persistence_artifact", params: {
          kind: item.value.kind, path: item.value.path, expectedSha256: item.value.sha256, maxBytes: 10 * 1024 * 1024,
        } }, signal);
        const commonInput = { taskId: deps.task.taskId, host: deps.task.target.host, type: "persistence_artifact",
          source: item.value.path, tool: "collect_persistence_artifact", toolCallId,
          metadata: { persistenceRef: params.persistenceRef, kind: item.value.kind } };
        const evidence = result.artifact
          ? await deps.evidence.putStream({ ...commonInput, transfer: async (onChunk) => deps.executor.downloadArtifact(result.artifact!, onChunk, signal, 120_000) })
          : typeof result.dataBase64 === "string"
            ? await deps.evidence.putBuffer({ ...commonInput, data: Buffer.from(result.dataBase64, "base64") })
            : (() => { throw new Error("持久化 Evidence 未返回可采集内容"); })();
        return { status: "success", summary: { evidenceId: evidence.evidenceId, sha256: evidence.sha256, size: result.size },
          items: [{ persistenceRef: params.persistenceRef, evidenceId: evidence.evidenceId }], artifactRefs: [params.persistenceRef, evidence.evidenceId], warnings: [] };
      },
    }),
  ];
}
