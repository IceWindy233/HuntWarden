import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference } from "../reference-utils.js";

export function createHostTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  return [
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
