import type { SecurityToolDefinition } from "../domain/types.js";
import type { ToolDependencies } from "./dependencies.js";
import { createHostTools } from "./host/tools.js";
import { createWebShellTools } from "./webshell/tools.js";
import { createJavaTools } from "./java/tools.js";
import { createAccountTools } from "./account/tools.js";
import { createRecordFindingTool } from "./local/record-finding.js";
import { createRemediationTools } from "./remediation/tools.js";
import { createPersistenceTools } from "./persistence/tools.js";
import { createTriageTools } from "./triage/tools.js";
import { createThreatIntelTools } from "./threat-intel/tools.js";
import { createProcessConnectionTool } from "./shared/process-connections.js";
import { SecurityError } from "../common/errors.js";

export function createSecurityTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const tools: SecurityToolDefinition[] = [...createHostTools(deps)];
  const selected = new Set(deps.task.checks);

  if (selected.has("webshell")) tools.push(...createWebShellTools(deps));
  if (selected.has("java_memory_shell")) tools.push(...createJavaTools(deps));
  if (selected.has("backdoor_account")) tools.push(...createAccountTools(deps));
  if (selected.has("linux_persistence")) tools.push(...createPersistenceTools(deps));
  if (selected.has("linux_intrusion_triage")) tools.push(...createTriageTools(deps));
  if (selected.has("linux_intrusion_triage") || selected.has("linux_persistence")) {
    tools.push(createProcessConnectionTool(deps));
    tools.push(...createThreatIntelTools(deps));
  }

  tools.push(createRecordFindingTool(deps));

  if (deps.task.mode === "REMEDIATE") {
    const allowedWriteTools = new Set<string>();
    if (selected.has("webshell")) allowedWriteTools.add("quarantine_file");
    if (selected.has("backdoor_account")) allowedWriteTools.add("disable_account");
    tools.push(...createRemediationTools(deps).filter((tool) => allowedWriteTools.has(tool.name)));
  }

  assertUniqueToolNames(tools);
  return tools;
}

/**
 * 工具名唯一性不变量。
 *
 * 模型侧的函数名是工具的唯一标识：重名会让 `tools.find(name === )`（确定性执行图与写门控都依赖它）
 * 静默命中先注册的那个实现，同时供应商侧对重复 function name 直接拒绝请求。
 * 因此重名必须在装配期失败，而不是等到第一次模型调用。
 */
function assertUniqueToolNames(tools: readonly SecurityToolDefinition[]): void {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const tool of tools) {
    if (seen.has(tool.name)) duplicates.add(tool.name);
    seen.add(tool.name);
  }
  if (duplicates.size > 0) {
    throw new SecurityError("INVALID_ARGUMENT", `工具装配产生重名工具：${[...duplicates].join("、")}`, {
      duplicates: [...duplicates],
      total: tools.length,
      unique: seen.size,
    });
  }
}
