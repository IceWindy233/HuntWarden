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

export function createSecurityTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const tools: SecurityToolDefinition[] = [...createHostTools(deps)];
  const selected = new Set(deps.task.checks);

  if (selected.has("webshell")) tools.push(...createWebShellTools(deps));
  if (selected.has("java_memory_shell")) tools.push(...createJavaTools(deps));
  if (selected.has("backdoor_account")) tools.push(...createAccountTools(deps));
  if (selected.has("linux_persistence")) tools.push(...createPersistenceTools(deps));
  if (selected.has("linux_intrusion_triage")) tools.push(...createTriageTools(deps));

  tools.push(createRecordFindingTool(deps));

  if (deps.task.mode === "REMEDIATE") {
    const allowedWriteTools = new Set<string>();
    if (selected.has("webshell")) allowedWriteTools.add("quarantine_file");
    if (selected.has("backdoor_account")) allowedWriteTools.add("disable_account");
    tools.push(...createRemediationTools(deps).filter((tool) => allowedWriteTools.has(tool.name)));
  }

  return tools;
}
