import type { SecurityToolDefinition } from "../domain/types.js";
import type { ToolDependencies } from "./dependencies.js";
import { createHostTools } from "./host/tools.js";
import { createWebShellTools } from "./webshell/tools.js";
import { createJavaTools } from "./java/tools.js";
import { createAccountTools } from "./account/tools.js";
import { createRecordFindingTool } from "./local/record-finding.js";
import { createRemediationTools } from "./remediation/tools.js";
import { createPersistenceTools } from "./persistence/tools.js";

export function createSecurityTools(deps: ToolDependencies): SecurityToolDefinition[] {
  return [
    ...createHostTools(deps),
    ...createWebShellTools(deps),
    ...createJavaTools(deps),
    ...createAccountTools(deps),
    ...createPersistenceTools(deps),
    createRecordFindingTool(deps),
    ...createRemediationTools(deps),
  ];
}
