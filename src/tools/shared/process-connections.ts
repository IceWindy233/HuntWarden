import { Type } from "typebox";
import type { ScanProfile, SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import type { StableProcessIdentity } from "../../executor/operations.js";
import type { ToolDependencies } from "../dependencies.js";
import { requireReference } from "../reference-utils.js";
import { createSecurityTool } from "../tool-factory.js";
import { attachConnectionReferences } from "../../threat-intel/network-ioc.js";

interface ProcessValue extends StableProcessIdentity {
  exePath?: string;
  [key: string]: unknown;
}

const processRefSchema = Type.String({ pattern: "^PROC-" });

/**
 * 按扫描预设缩放资源预算：QUICK 只花 25% 预算，STANDARD 50%，DEEP 全额，结果夹在 [1, maximum] 内。
 * triage 工具包与共享工具都用它，避免两处各自实现导致预算漂移。
 */
export function scaleForProfile(profile: ScanProfile | undefined, value: number, maximum: number): number {
  const factor = profile === "QUICK" ? 0.25 : profile === "DEEP" ? 1 : 0.5;
  return Math.max(1, Math.min(maximum, Math.ceil(value * factor)));
}

/**
 * `list_process_connections` 的唯一权威实现。
 *
 * 该工具此前在 persistence 与 triage 两个包里各声明一次（语义、超时、校验强度均不同），
 * 默认全选五类检测时会装配出重名工具：`tools.find(name === )` 只命中先注册的弱校验版本，
 * 确定性执行图因此拿到弱实现，且供应商侧对重复 function name 会直接拒绝请求。
 *
 * 现统一为强校验语义：Helper 必须复核 bootId、PID、startTicks、可执行文件 inode/SHA-256
 * 之后才读取该进程 socket，杜绝按裸 PID 查询带来的 PID 复用风险。
 * 预算统一取 `triage.maxConnections` 并按扫描预设缩放，不随所选检测类别变化。
 */
export function createProcessConnectionTool(deps: ToolDependencies): SecurityToolDefinition {
  const maxConnections = scaleForProfile(deps.task.profile, deps.config.triage.maxConnections, 20_000);
  return createSecurityTool(deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes, {
    name: "list_process_connections",
    label: "检查进程网络连接",
    description: "只接受当前任务 processRef；Helper 必须复核 bootId、PID、startTicks、可执行文件 inode/SHA-256 后才读取该进程 socket。",
    parameters: Type.Object({ processRef: processRefSchema }, { additionalProperties: false }),
    risk: "READ",
    replayPolicy: "SAFE",
    timeoutMs: 45_000,
    auditEvent: "process_connections_listed",
    run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
      const target = requireReference<ProcessValue>(deps.store, deps.task.taskId, params.processRef, "process");
      const output = await deps.executor.invoke({
        operation: "list_process_connections",
        params: {
          bootId: target.value.bootId,
          pid: target.value.pid,
          startTicks: target.value.startTicks,
          exeInode: target.value.exeInode,
          exeSha256: target.value.exeSha256,
          maxConnections,
        },
      }, signal);
      const connections = attachConnectionReferences(deps.store, deps.task.taskId, output.items as Record<string, unknown>[], params.processRef);
      const evidence = deps.evidence.putStructured({
        taskId: deps.task.taskId,
        host: deps.task.target.host,
        type: "process_connections",
        source: target.value.exePath ?? params.processRef,
        tool: "list_process_connections",
        toolCallId,
        metadata: { processRef: params.processRef, ...output, items: connections.items },
      });
      return {
        status: output.partial ? "partial" : "success",
        summary: {
          processRef: params.processRef,
          evidenceId: evidence.evidenceId,
          threatIntelEligible: connections.refs.length,
          count: connections.items.length,
          partial: output.partial,
        },
        items: connections.items,
        artifactRefs: [params.processRef, ...connections.refs, evidence.evidenceId],
        warnings: output.warnings,
      };
    },
  });
}
