import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference, requireReference } from "../reference-utils.js";

interface JavaProcess { pid: number; command?: string; user?: string }
interface JavaComponent { pid: number; type: string; name: string; className: string; [key: string]: unknown }
interface JavaClass { pid: number; className: string; [key: string]: unknown }

export function createJavaTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  const processRef = Type.String({ pattern: "^PROC-" });
  const componentRef = Type.String({ pattern: "^COMP-" });
  const classRef = Type.String({ pattern: "^CLASS-" });

  const listComponents = (toolName: string, label: string, componentType: "filter" | "servlet" | "listener") =>
    createSecurityTool(...common, {
      name: toolName, label,
      description: `枚举已确认 Tomcat 进程中的 ${componentType} 运行时组件，返回 componentRef；仅收集事实，不做卸载或修改。`,
      parameters: Type.Object({ processRef }, { additionalProperties: false }),
      risk: "READ" as const, replayPolicy: "SAFE" as const, timeoutMs: 45_000, auditEvent: "tomcat_components_listed",
      run: async (toolCallId, params: { processRef: string }, signal?: AbortSignal): Promise<SecurityToolResult> => {
        const process = requireReference<JavaProcess>(deps.store, deps.task.taskId, params.processRef, "process");
        const output = await deps.executor.invoke({ operation: "run_tomcat_probe", params: { pid: process.value.pid, command: "list_components" } }, signal);
        const components = Array.isArray(output.components) ? output.components as JavaComponent[] : [];
        const selected = components.filter((item) => String(item.type).toLowerCase() === componentType);
        const refs = selected.map((value) => createReference(deps.store, deps.task.taskId, "component", "component", { ...value, pid: process.value.pid }));
        const warnings = Array.isArray(output.warnings) ? output.warnings as string[] : [];
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: `tomcat_${componentType}s`, source: `PID:${process.value.pid}`, tool: toolName, toolCallId, metadata: { processRef: params.processRef, components: refs.map(({ ref, value }) => ({ componentRef: ref, ...value })), warnings, partial: Boolean(output.partial) } });
        return { status: output.partial ? "partial" : "success", summary: { type: componentType, count: refs.length, evidenceId: evidence.evidenceId }, items: refs.map(({ ref, value }) => ({ componentRef: ref, ...value })), artifactRefs: [...refs.map((v) => v.ref), evidence.evidenceId], warnings };
      },
    });

  return [
    createSecurityTool(...common, {
      name: "list_java_processes", label: "发现 Java 进程",
      description: "列出目标主机 Java 进程并返回 processRef。Java 内存马调查应先调用本工具。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "java_processes_listed",
      run: async (_id, _params, signal): Promise<SecurityToolResult> => {
        const processes = await deps.executor.invoke({ operation: "list_java_processes", params: {} }, signal) as unknown as JavaProcess[];
        const refs = processes.map((value) => createReference(deps.store, deps.task.taskId, "process", "process", value));
        return { status: "success", summary: { count: refs.length }, items: refs.map(({ ref, value }) => ({ processRef: ref, ...value })), artifactRefs: refs.map((v) => v.ref), warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "detect_java_container", label: "识别 Java 容器",
      description: "识别 processRef 是否为受支持的 Tomcat；非 Tomcat 只报告不适用，不继续 Attach。",
      parameters: Type.Object({ processRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "java_container_detected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const process = requireReference<JavaProcess>(deps.store, deps.task.taskId, params.processRef, "process");
        const result = await deps.executor.invoke({ operation: "detect_java_container", params: { pid: process.value.pid } }, signal);
        return { status: "success", summary: result, items: [{ processRef: params.processRef, ...result }], artifactRefs: [params.processRef], warnings: result.supported ? [] : ["该 Java 进程不是受支持的 Tomcat"] };
      },
    }),
    listComponents("list_tomcat_filters", "枚举 Tomcat Filter", "filter"),
    listComponents("list_tomcat_servlets", "枚举 Tomcat Servlet", "servlet"),
    listComponents("list_tomcat_listeners", "枚举 Tomcat Listener", "listener"),
    createSecurityTool(...common, {
      name: "inspect_java_class", label: "检查运行时 Class",
      description: "检查 componentRef 对应运行时类的 ClassLoader、CodeSource、ProtectionDomain 和可修改性，返回 classRef。",
      parameters: Type.Object({ componentRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "java_class_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const component = requireReference<JavaComponent>(deps.store, deps.task.taskId, params.componentRef, "component");
        const result = await deps.executor.invoke({ operation: "run_tomcat_probe", params: { pid: component.value.pid, command: "inspect_class", className: component.value.className } }, signal);
        const ref = createReference(deps.store, deps.task.taskId, "class", "class", { pid: component.value.pid, className: component.value.className, ...result } satisfies JavaClass);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "java_class_facts", source: `PID:${component.value.pid}/${component.value.className}`, tool: "inspect_java_class", toolCallId, metadata: { componentRef: params.componentRef, classRef: ref.ref, ...result } });
        return { status: result.partial ? "partial" : "success", summary: { ...result, evidenceId: evidence.evidenceId }, items: [{ classRef: ref.ref, evidenceId: evidence.evidenceId, ...ref.value }], artifactRefs: [ref.ref, evidence.evidenceId], warnings: Array.isArray(result.warnings) ? result.warnings as string[] : [] };
      },
    }),
    createSecurityTool(...common, {
      name: "search_class_on_disk", label: "查找磁盘 Class 来源",
      description: "检查 classRef 对应类是否能在 Tomcat 应用目录或工作目录定位磁盘来源。",
      parameters: Type.Object({ classRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "java_class_disk_searched",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const target = requireReference<JavaClass>(deps.store, deps.task.taskId, params.classRef, "class");
        const result = await deps.executor.invoke({ operation: "search_class_on_disk", params: { pid: target.value.pid, className: target.value.className } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "java_class_disk_search", source: `PID:${target.value.pid}/${target.value.className}`, tool: "search_class_on_disk", toolCallId, metadata: { classRef: params.classRef, ...result } });
        return { status: "success", summary: { ...result, evidenceId: evidence.evidenceId }, items: [{ evidenceId: evidence.evidenceId, ...result }], artifactRefs: [params.classRef, evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "dump_java_class", label: "导出 Java Class",
      description: "通过只读探针捕获 classRef 对应类的字节码并保存为本地 Evidence。不会加载、执行或重新定义未知 Class。",
      parameters: Type.Object({ classRef }, { additionalProperties: false }),
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "java_class_dumped", executionMode: "sequential",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        if (!deps.config.java.allowClassDump) throw new Error("配置禁止 Class Dump");
        const target = requireReference<JavaClass>(deps.store, deps.task.taskId, params.classRef, "class");
        const result = await deps.executor.invoke({ operation: "run_tomcat_probe", params: { pid: target.value.pid, command: "dump_class", className: target.value.className } }, signal);
        const commonInput = { taskId: deps.task.taskId, host: deps.task.target.host, type: "java_class", source: `PID:${target.value.pid}/${target.value.className}`, tool: "dump_java_class", toolCallId, metadata: { classRef: params.classRef } };
        const evidence = result.artifact
          ? await deps.evidence.putStream({ ...commonInput, transfer: async (onChunk) => deps.executor.downloadArtifact(result.artifact!, onChunk, signal, 120_000) })
          : typeof result.dataBase64 === "string"
            ? await deps.evidence.putBuffer({ ...commonInput, data: Buffer.from(result.dataBase64, "base64") })
            : (() => { throw new Error("Class Dump 未返回可采集内容"); })();
        return { status: result.partial ? "partial" : "success", summary: { evidenceId: evidence.evidenceId, sha256: evidence.sha256 }, items: [{ evidenceId: evidence.evidenceId, className: target.value.className }], artifactRefs: [evidence.evidenceId], warnings: [] };
      },
    }),
  ];
}
