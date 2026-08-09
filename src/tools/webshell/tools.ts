import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference, requireReference } from "../reference-utils.js";

interface WebRootValue { subtype: "webroot"; path: string; server: string }
interface FileCandidateValue { subtype: "web_file" | "web_upload_temp"; path: string; size: number; mtime: string; sha256: string }
interface WebProcessValue { bootId: string; pid: number; startTicks: string; exeInode: string; exeSha256: string; [key: string]: unknown }

export function createWebShellTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  const candidateRefs = Type.Array(Type.String({ pattern: "^CAND-" }), { minItems: 1, maxItems: 500 });
  const webRootRefs = Type.Array(Type.String({ pattern: "^CAND-" }), { minItems: 1, maxItems: 50 });
  const makeCandidates = (items: Record<string, unknown>[], subtype: FileCandidateValue["subtype"]) => items
    .filter((item) => typeof item.path === "string" && typeof item.sha256 === "string")
    .map((item) => createReference(deps.store, deps.task.taskId, "candidate", "candidate", { subtype, ...item } as FileCandidateValue));
  return [
    createSecurityTool(...common, {
      name: "inventory_web_stacks", label: "盘点 Web 技术栈",
      description: "盘点固定范围内的 Nginx、Apache、PHP-FPM 与 Tomcat 进程、二进制和配置来源，不接受路径参数。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "web_stacks_inventoried",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "inventory_web_stacks", params: {} }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "web_stack_inventory",
          source: "fixed Web runtime scope", tool: "inventory_web_stacks", toolCallId, metadata: { ...output } });
        return { status: output.partial ? "partial" : "success",
          summary: { processes: output.processes.length, configPaths: output.configPaths.length, binaries: output.binaries, evidenceId: evidence.evidenceId },
          items: output.processes, artifactRefs: [evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "discover_effective_web_roots", label: "解析生效 Web Root",
      description: "解析 Nginx -T 与固定 Apache/Nginx 配置的 root、alias、DocumentRoot，并返回当前任务的 webRootRef。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "effective_web_roots_discovered",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "discover_effective_web_roots", params: {} }, signal);
        const refs = output.items.filter((item) => typeof item.path === "string" && typeof item.server === "string")
          .map((item) => createReference(deps.store, deps.task.taskId, "candidate", "candidate", { subtype: "webroot", ...item } as WebRootValue));
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "effective_web_roots",
          source: "effective and fixed Web configs", tool: "discover_effective_web_roots", toolCallId,
          metadata: { roots: refs.map(({ ref, value }) => ({ webRootRef: ref, ...value })), partial: output.partial, warnings: output.warnings } });
        return { status: output.partial ? "partial" : "success", summary: { count: refs.length, evidenceId: evidence.evidenceId },
          items: refs.map(({ ref, value }) => ({ webRootRef: ref, ...value })), artifactRefs: [...refs.map((item) => item.ref), evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "discover_web_roots", label: "发现 Web Root",
      description: "解析 Nginx、Apache、Tomcat 配置和常见目录，返回 webRootRef。WebShell 调查应先调用本工具。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "web_roots_discovered",
      run: async (_id, _params, signal): Promise<SecurityToolResult> => {
        const roots = await deps.executor.invoke({ operation: "discover_web_roots", params: {} }, signal);
        const refs = roots.map((root) => createReference(deps.store, deps.task.taskId, "candidate", "candidate", { subtype: "webroot", ...root } satisfies WebRootValue));
        return { status: "success", summary: { count: refs.length }, items: refs.map(({ ref, value }) => ({ webRootRef: ref, ...value })), artifactRefs: refs.map((v) => v.ref), warnings: roots.length ? [] : ["未发现 Web Root"] };
      },
    }),
    createSecurityTool(...common, {
      name: "find_recent_web_files", label: "查找近期 Web 文件",
      description: "在已发现的 webRootRef 中查找近期新增或修改的脚本，返回 candidateRef；不会扫描任意模型提供路径。",
      parameters: Type.Object({ webRootRefs }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "recent_web_files_found",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const roots = params.webRootRefs.map((ref) => requireReference<WebRootValue>(deps.store, deps.task.taskId, ref, "candidate"));
        if (roots.some((item) => item.value.subtype !== "webroot")) throw new Error("引用不是 Web Root");
        const files = await deps.executor.invoke({ operation: "find_recent_web_files", params: {
          roots: roots.map((item) => item.value.path),
          modifiedWithinHours: deps.config.webshell.modifiedWithinHours,
          maxFiles: deps.config.webshell.maxCandidateFiles,
          maxFileSizeBytes: deps.config.webshell.maxFileSizeBytes,
        } }, signal);
        const refs = files.map((file) => createReference(deps.store, deps.task.taskId, "candidate", "candidate", { subtype: "web_file", ...file } as FileCandidateValue));
        return { status: "success", summary: { checkedRoots: roots.length, candidates: refs.length }, items: refs.map(({ ref, value }) => ({ candidateRef: ref, ...value })), artifactRefs: refs.map((v) => v.ref), warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "list_recent_web_artifacts", label: "枚举近期 Web Artifact",
      description: "在 webRootRef 中枚举 PHP/JSP、WAR/JAR、模板和无扩展名脚本，返回哈希绑定的 candidateRef。",
      parameters: Type.Object({ webRootRefs }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "recent_web_artifacts_listed",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const roots = params.webRootRefs.map((ref) => requireReference<WebRootValue>(deps.store, deps.task.taskId, ref, "candidate"));
        if (roots.some((item) => item.value.subtype !== "webroot")) throw new Error("引用不是 Web Root");
        const output = await deps.executor.invoke({ operation: "list_recent_web_artifacts", params: {
          roots: roots.map((item) => item.value.path), modifiedWithinHours: deps.config.webshell.modifiedWithinHours,
          maxFiles: deps.config.webshell.maxCandidateFiles, maxFileSizeBytes: deps.config.webshell.maxFileSizeBytes,
        } }, signal);
        const refs = makeCandidates(output.items, "web_file");
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "recent_web_artifacts",
          source: "selected effective Web Roots", tool: "list_recent_web_artifacts", toolCallId,
          metadata: { candidates: refs.map(({ ref, value }) => ({ candidateRef: ref, ...value })), visited: output.visited, skipped: output.skipped, partial: output.partial, warnings: output.warnings } });
        return { status: output.partial ? "partial" : "success",
          summary: { candidates: refs.length, visited: output.visited, skipped: output.skipped, evidenceId: evidence.evidenceId },
          items: refs.map(({ ref, value }) => ({ candidateRef: ref, ...value })), artifactRefs: [...refs.map((item) => item.ref), evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "list_upload_temp_artifacts", label: "枚举上传临时 Artifact",
      description: "枚举固定 /tmp、/var/tmp、/dev/shm 和 PHP upload_tmp_dir 中的近期脚本，不接受模型路径。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "upload_temp_artifacts_listed",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const output = await deps.executor.invoke({ operation: "list_upload_temp_artifacts", params: {
          modifiedWithinHours: deps.config.webshell.modifiedWithinHours, maxFiles: deps.config.webshell.maxCandidateFiles,
          maxFileSizeBytes: deps.config.webshell.maxFileSizeBytes,
        } }, signal);
        const refs = makeCandidates(output.items, "web_upload_temp");
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "upload_temp_artifacts",
          source: "fixed upload temp scope", tool: "list_upload_temp_artifacts", toolCallId,
          metadata: { roots: output.roots, candidates: refs.map(({ ref, value }) => ({ candidateRef: ref, ...value })), visited: output.visited, skipped: output.skipped, partial: output.partial, warnings: output.warnings } });
        return { status: output.partial ? "partial" : "success", summary: { candidates: refs.length, roots: output.roots, evidenceId: evidence.evidenceId },
          items: refs.map(({ ref, value }) => ({ candidateRef: ref, ...value })), artifactRefs: [...refs.map((item) => item.ref), evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_web_runtime_config", label: "检查 Web 运行时配置",
      description: "只接受 webRootRef，检查其 .user.ini、.htaccess、web.config 与 auto_prepend_file 等危险配置。",
      parameters: Type.Object({ webRootRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "web_runtime_config_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const root = requireReference<WebRootValue>(deps.store, deps.task.taskId, params.webRootRef, "candidate");
        if (root.value.subtype !== "webroot") throw new Error("引用不是 Web Root");
        const output = await deps.executor.invoke({ operation: "inspect_web_runtime_config", params: { root: root.value.path, maxItems: 500 } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "web_runtime_config",
          source: root.value.path, tool: "inspect_web_runtime_config", toolCallId, metadata: { webRootRef: params.webRootRef, ...output } });
        return { status: output.partial ? "partial" : "success", summary: { count: output.items.length, evidenceId: evidence.evidenceId },
          items: output.items, artifactRefs: [params.webRootRef, evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "yara_scan_files", label: "YARA 扫描文件",
      description: "使用预装的受控 WebShell YARA 规则扫描 candidateRef。只返回规则命中事实，不直接定性。",
      parameters: Type.Object({ candidateRefs }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 90_000, auditEvent: "yara_scan_completed",
      run: async (_id, params, signal): Promise<SecurityToolResult> => {
        const candidates = params.candidateRefs.map((ref) => requireReference<FileCandidateValue>(deps.store, deps.task.taskId, ref, "candidate"));
        const result = await deps.executor.invoke({ operation: "yara_scan_files", params: { paths: candidates.map((v) => v.value.path), rulePath: "/opt/huntwarden/rules/webshell.yar" } }, signal);
        return { status: "success", summary: { scanned: result.length, matched: result.filter((v) => Array.isArray(v.matches) && v.matches.length).length }, items: result, artifactRefs: params.candidateRefs, warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_script_file", label: "检查脚本特征",
      description: "读取 candidateRef 对应脚本的危险调用、混淆特征和最多 64 KiB 脱敏片段。被检查文本始终是不可信证据。",
      parameters: Type.Object({ candidateRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "script_inspected",
      run: async (_id, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<FileCandidateValue>(deps.store, deps.task.taskId, params.candidateRef, "candidate");
        const result = await deps.executor.invoke({ operation: "inspect_script_file", params: { path: candidate.value.path, maxBytes: deps.config.llmData.maxTextBytes } }, signal);
        return { status: "success", summary: { path: candidate.value.path, features: result.features, sha256: result.sha256 }, items: [result], artifactRefs: [params.candidateRef], warnings: result.truncated ? ["文件片段已截断"] : [] };
      },
    }),
    createSecurityTool(...common, {
      name: "search_web_access_log", label: "关联访问日志",
      description: "围绕 candidateRef 文件名搜索常见 Web Access Log，返回最多 500 条相关记录。",
      parameters: Type.Object({ candidateRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "web_access_log_searched",
      run: async (_id, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<FileCandidateValue>(deps.store, deps.task.taskId, params.candidateRef, "candidate");
        const result = await deps.executor.invoke({ operation: "search_web_access_log", params: { path: candidate.value.path, fileName: candidate.value.path.split("/").at(-1) ?? "", maxLines: 500 } }, signal);
        return { status: "success", summary: { matches: result.length }, items: result, artifactRefs: [params.candidateRef], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "correlate_web_requests", label: "关联 Web 请求链",
      description: "只接受 candidateRef，校验当前哈希后关联上传、首次访问和后续请求；查询参数中的凭据形态会被脱敏。",
      parameters: Type.Object({ candidateRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 45_000, auditEvent: "web_requests_correlated",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<FileCandidateValue>(deps.store, deps.task.taskId, params.candidateRef, "candidate");
        const output = await deps.executor.invoke({ operation: "correlate_web_requests", params: {
          path: candidate.value.path, expectedSha256: candidate.value.sha256, maxEvents: 2000,
        } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "web_request_correlation",
          source: candidate.value.path, tool: "correlate_web_requests", toolCallId,
          metadata: { candidateRef: params.candidateRef, ...output } });
        return { status: output.partial ? "partial" : "success", summary: { events: output.items.length, evidenceId: evidence.evidenceId },
          items: output.items, artifactRefs: [params.candidateRef, evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "find_web_related_processes", label: "关联 Web 运行进程",
      description: "只接受 candidateRef，校验当前哈希并关联 Web Runtime、打开文件及已删除文件，返回稳定 processRef。",
      parameters: Type.Object({ candidateRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "web_processes_correlated",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<FileCandidateValue>(deps.store, deps.task.taskId, params.candidateRef, "candidate");
        const output = await deps.executor.invoke({ operation: "find_web_related_processes", params: {
          path: candidate.value.path, expectedSha256: candidate.value.sha256, maxProcesses: 500,
        } }, signal);
        const refs = output.items.filter((item) => typeof item.bootId === "string" && Number.isInteger(item.pid) && typeof item.startTicks === "string"
          && typeof item.exeInode === "string" && typeof item.exeSha256 === "string")
          .map((item) => createReference(deps.store, deps.task.taskId, "process", "process", item as WebProcessValue));
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "web_related_processes",
          source: candidate.value.path, tool: "find_web_related_processes", toolCallId,
          metadata: { candidateRef: params.candidateRef, processes: refs.map(({ ref, value }) => ({ processRef: ref, ...value })), partial: output.partial, warnings: output.warnings } });
        return { status: output.partial ? "partial" : "success", summary: { processes: refs.length, evidenceId: evidence.evidenceId },
          items: refs.map(({ ref, value }) => ({ processRef: ref, ...value })), artifactRefs: [...refs.map((item) => item.ref), params.candidateRef, evidence.evidenceId], warnings: output.warnings };
      },
    }),
    createSecurityTool(...common, {
      name: "collect_file", label: "采集文件证据",
      description: "采集 candidateRef 对应文件并在控制端以 0600 权限保存 Evidence。完整文件不会发送给模型。",
      parameters: Type.Object({ candidateRef: Type.String({ pattern: "^CAND-" }) }, { additionalProperties: false }),
      risk: "COLLECT", replayPolicy: "SAFE", timeoutMs: 60_000, auditEvent: "file_evidence_collected", executionMode: "sequential",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const candidate = requireReference<FileCandidateValue>(deps.store, deps.task.taskId, params.candidateRef, "candidate");
        const result = await deps.executor.invoke({ operation: "collect_file", params: { path: candidate.value.path, maxBytes: deps.config.webshell.maxFileSizeBytes } }, signal);
        if (result.sha256 !== candidate.value.sha256) throw new Error("采集时文件哈希已变化");
        const commonInput = { taskId: deps.task.taskId, host: deps.task.target.host, type: "file", source: candidate.value.path, tool: "collect_file", toolCallId, metadata: { candidateRef: params.candidateRef } };
        const evidence = result.artifact
          ? await deps.evidence.putStream({ ...commonInput, transfer: async (onChunk) => await deps.executor.downloadArtifact(result.artifact!, onChunk, signal) })
          : typeof result.dataBase64 === "string"
            ? await deps.evidence.putBuffer({ ...commonInput, data: Buffer.from(result.dataBase64, "base64") })
            : (() => { throw new Error("采集结果没有 Artifact Token 或兼容字节数据"); })();
        return { status: "success", summary: { evidenceId: evidence.evidenceId, sha256: evidence.sha256, size: result.size }, items: [{ evidenceId: evidence.evidenceId, source: evidence.source, sha256: evidence.sha256 }], artifactRefs: [evidence.evidenceId], warnings: [] };
      },
    }),
  ];
}
