import type { CheckCategory } from "../domain/types.js";

export interface ScanStepContext {
  results(stepId: string): readonly unknown[];
}

export interface MinimumScanStep {
  stepId: string;
  toolName: string;
  dependsOn?: readonly string[];
  buildArguments(context: ScanStepContext): readonly Record<string, unknown>[];
}

export interface CheckDefinition {
  category: CheckCategory;
  label: string;
  minimumExecutionGraph: readonly MinimumScanStep[];
}

const noArguments = (): readonly Record<string, unknown>[] => [{}];

function chunks<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let offset = 0; offset < items.length; offset += size) result.push(items.slice(offset, offset + size));
  return result;
}

function referenceArguments(stepId: string, field: string, prefix: string) {
  return (context: ScanStepContext): readonly Record<string, unknown>[] => context.results(stepId)
    .flatMap((result) => {
      if (!result || typeof result !== "object" || !("items" in result) || !Array.isArray(result.items)) return [];
      return result.items;
    })
    .map((item) => item && typeof item === "object" && field in item ? item[field as keyof typeof item] : undefined)
    .filter((ref): ref is string => typeof ref === "string" && ref.startsWith(prefix))
    .map((ref) => ({ [field]: ref }));
}

export const PREFLIGHT_EXECUTION_GRAPH: readonly MinimumScanStep[] = [
  { stepId: "capabilities", toolName: "get_capabilities", buildArguments: noArguments },
  { stepId: "host-info", toolName: "get_host_info", buildArguments: noArguments },
];

export const CHECK_DEFINITIONS: Record<string, CheckDefinition> = {
  webshell: {
    category: "webshell",
    label: "WebShell",
    minimumExecutionGraph: [
      { stepId: "web-roots", toolName: "discover_web_roots", buildArguments: noArguments },
      {
        stepId: "web-candidates",
        toolName: "find_recent_web_files",
        dependsOn: ["web-roots"],
        buildArguments: (context) => {
          const refs = context.results("web-roots")
            .flatMap((result) => {
              if (!result || typeof result !== "object" || !("items" in result) || !Array.isArray(result.items)) return [];
              return result.items;
            })
            .map((item) => item && typeof item === "object" && "webRootRef" in item ? item.webRootRef : undefined)
            .filter((ref): ref is string => typeof ref === "string");
          return chunks(refs, 50).map((webRootRefs) => ({ webRootRefs }));
        },
      },
    ],
  },
  java_memory_shell: {
    category: "java_memory_shell",
    label: "Java 内存马",
    minimumExecutionGraph: [
      { stepId: "java-processes", toolName: "list_java_processes", buildArguments: noArguments },
    ],
  },
  backdoor_account: {
    category: "backdoor_account",
    label: "后门账户",
    minimumExecutionGraph: [
      { stepId: "privileged-accounts", toolName: "list_privileged_accounts", buildArguments: noArguments },
      { stepId: "privilege-delegation", toolName: "inspect_privilege_delegation", buildArguments: noArguments },
      { stepId: "ssh-trust", toolName: "inspect_ssh_trust_configuration", buildArguments: noArguments },
      { stepId: "account-details", toolName: "inspect_account", dependsOn: ["privileged-accounts"],
        buildArguments: referenceArguments("privileged-accounts", "accountRef", "ACCT-") },
      { stepId: "authorized-keys", toolName: "inspect_authorized_keys", dependsOn: ["privileged-accounts"],
        buildArguments: referenceArguments("privileged-accounts", "accountRef", "ACCT-") },
      { stepId: "login-history", toolName: "get_login_history", dependsOn: ["privileged-accounts"],
        buildArguments: referenceArguments("privileged-accounts", "accountRef", "ACCT-") },
    ],
  },
  linux_persistence: {
    category: "linux_persistence",
    label: "Linux 持久化",
    minimumExecutionGraph: [
      { stepId: "cron", toolName: "list_cron_entries", buildArguments: noArguments },
      { stepId: "systemd", toolName: "list_systemd_units", buildArguments: noArguments },
      { stepId: "extended-persistence", toolName: "list_extended_persistence", buildArguments: noArguments },
      { stepId: "ssh-persistence", toolName: "list_ssh_persistence", buildArguments: noArguments },
      { stepId: "shell-startup", toolName: "list_shell_startup_files", buildArguments: noArguments },
    ],
  },
  linux_intrusion_triage: {
    category: "linux_intrusion_triage" as CheckCategory,
    label: "Linux 入侵分诊",
    minimumExecutionGraph: [
      { stepId: "suspicious-processes", toolName: "list_suspicious_processes", buildArguments: noArguments },
    ],
  },
};

export function selectedCheckDefinitions(checks: readonly CheckCategory[]): CheckDefinition[] {
  return [...new Set(checks)].map((category) => CHECK_DEFINITIONS[category] ?? {
    category,
    label: category,
    minimumExecutionGraph: [],
  });
}
