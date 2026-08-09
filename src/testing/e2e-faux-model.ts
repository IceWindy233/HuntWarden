import { createModels, type Context } from "@earendil-works/pi-ai";
import {
  fauxAssistantMessage,
  fauxProvider,
  fauxToolCall,
  type FauxResponseStep,
} from "@earendil-works/pi-ai/providers/faux";
import type { ModelBundle } from "../agent/model.js";
import type { SecurityToolResult } from "../domain/types.js";

export type E2eFauxScenario =
  | "web-quarantine"
  | "account-disable"
  | "web-scan"
  | "java-scan"
  | "account-scan"
  | "persistence-scan";

function userMessageText(message: Context["messages"][number]): string {
  if (message.role !== "user") return "";
  if (typeof message.content === "string") return message.content;
  return message.content
    .filter((item): item is Extract<(typeof message.content)[number], { type: "text" }> => item.type === "text")
    .map((item) => item.text)
    .join("\n");
}

function minimumToolResult(context: Context, toolName: string): SecurityToolResult<Record<string, unknown>, Record<string, unknown>> | undefined {
  for (const message of [...context.messages].reverse()) {
    const text = userMessageText(message);
    const encoded = text.match(/<deterministic-minimum-scan>\s*([\s\S]*?)\s*<\/deterministic-minimum-scan>/)?.[1];
    if (!encoded) continue;
    try {
      const payload = JSON.parse(encoded) as { outcomes?: { toolName?: string; details?: unknown }[] };
      const details = payload.outcomes?.find((outcome) => outcome.toolName === toolName)?.details;
      if (details && typeof details === "object") {
        return details as SecurityToolResult<Record<string, unknown>, Record<string, unknown>>;
      }
    } catch {
      // 测试 Provider 只消费应用生成的结构化摘要；格式不匹配时按缺失处理。
    }
  }
  return undefined;
}

function toolResult(context: Context, toolName: string): SecurityToolResult<Record<string, unknown>, Record<string, unknown>> {
  const message = [...context.messages].reverse().find((item) => item.role === "toolResult" && item.toolName === toolName);
  if (message?.role === "toolResult") return message.details as SecurityToolResult<Record<string, unknown>, Record<string, unknown>>;
  const minimum = minimumToolResult(context, toolName);
  if (minimum) return minimum;
  throw new Error(`E2E Faux 缺少工具结果: ${toolName}`);
}

function stringField(value: unknown, field: string): string {
  if (!value || typeof value !== "object" || typeof (value as Record<string, unknown>)[field] !== "string") {
    throw new Error(`E2E Faux 缺少字段: ${field}`);
  }
  return String((value as Record<string, unknown>)[field]);
}

function call(name: string, args: Record<string, unknown>, id: string) {
  return fauxAssistantMessage(fauxToolCall(name, args, { id }), { stopReason: "toolUse" });
}

function hasToolResult(context: Context, toolName: string): boolean {
  return context.messages.some((item) => item.role === "toolResult" && item.toolName === toolName)
    || Boolean(minimumToolResult(context, toolName));
}

function nextWebQuarantineResponse(context: Context) {
  if (!hasToolResult(context, "discover_web_roots")) return call("discover_web_roots", {}, "e2e-web-discover");
  if (!hasToolResult(context, "find_recent_web_files")) {
      const root = toolResult(context, "discover_web_roots").items.find((item) => item.path === "/var/www/html");
      return call("find_recent_web_files", { webRootRefs: [stringField(root, "webRootRef")] }, "e2e-web-find");
  }
  if (!hasToolResult(context, "yara_scan_files")) {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("yara_scan_files", { candidateRefs: [stringField(candidate, "candidateRef")] }, "e2e-web-yara");
  }
  if (!hasToolResult(context, "inspect_script_file")) {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("inspect_script_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-inspect");
  }
  if (!hasToolResult(context, "collect_file")) {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("collect_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-collect");
  }
  if (!hasToolResult(context, "quarantine_file")) return call("quarantine_file", { evidenceRef: stringField(toolResult(context, "collect_file").summary, "evidenceId") }, "e2e-web-quarantine");
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
      category: "webshell", severity: "HIGH", confidence: 0.99, status: "CONFIRMED",
      title: "Lab WebShell 模拟样本", summary: "YARA、脚本特征与文件证据确认该无害模拟样本；处置结果以审批和 ActionReceipt 为准。",
      evidenceRefs: [stringField(toolResult(context, "collect_file").summary, "evidenceId")],
      recommendation: "复核隔离回执并保留 Evidence。",
    }, "e2e-web-finding");
  return fauxAssistantMessage("WebShell 处置闭环 E2E 已完成。");
}

function webQuarantineResponses(): FauxResponseStep[] {
  return Array.from({ length: 40 }, () => (context: Context) => nextWebQuarantineResponse(context));
}

function nextWebScanResponse(context: Context) {
  if (!hasToolResult(context, "discover_web_roots")) return call("discover_web_roots", {}, "e2e-web-scan-discover");
  if (!hasToolResult(context, "find_recent_web_files")) {
    const root = toolResult(context, "discover_web_roots").items.find((item) => item.path === "/var/www/html");
    return call("find_recent_web_files", { webRootRefs: [stringField(root, "webRootRef")] }, "e2e-web-scan-find");
  }
  const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
  if (!hasToolResult(context, "yara_scan_files")) return call("yara_scan_files", { candidateRefs: [stringField(candidate, "candidateRef")] }, "e2e-web-scan-yara");
  if (!hasToolResult(context, "inspect_script_file")) return call("inspect_script_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-scan-inspect");
  if (!hasToolResult(context, "collect_file")) return call("collect_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-scan-collect");
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
    category: "webshell", severity: "HIGH", confidence: 0.98, status: "CONFIRMED",
    title: "Lab WebShell 模拟样本", summary: "YARA、脚本特征与已采集文件证据共同确认无害模拟样本。",
    evidenceRefs: [stringField(toolResult(context, "collect_file").summary, "evidenceId")],
    recommendation: "保留 Evidence，并在处置模式中审批隔离。",
  }, "e2e-web-scan-finding");
  return fauxAssistantMessage("WebShell 只读调查 E2E 已完成。");
}

function nextJavaScanResponse(context: Context) {
  if (!hasToolResult(context, "list_java_processes")) return call("list_java_processes", {}, "e2e-java-list");
  const process = toolResult(context, "list_java_processes").items.find((item) => String(item.command ?? "").toLowerCase().includes("catalina"))
    ?? toolResult(context, "list_java_processes").items[0];
  if (!hasToolResult(context, "detect_java_container")) return call("detect_java_container", { processRef: stringField(process, "processRef") }, "e2e-java-detect");
  if (!hasToolResult(context, "list_tomcat_filters")) return call("list_tomcat_filters", { processRef: stringField(process, "processRef") }, "e2e-java-filters");
  const component = toolResult(context, "list_tomcat_filters").items.find((item) => item.className === "lab.DynamicMarkerFilter")
    ?? toolResult(context, "list_tomcat_filters").items[0];
  if (!hasToolResult(context, "inspect_java_class")) return call("inspect_java_class", { componentRef: stringField(component, "componentRef") }, "e2e-java-inspect");
  const classItem = toolResult(context, "inspect_java_class").items[0];
  if (!hasToolResult(context, "search_class_on_disk")) return call("search_class_on_disk", { classRef: stringField(classItem, "classRef") }, "e2e-java-search");
  if (!hasToolResult(context, "dump_java_class")) return call("dump_java_class", { classRef: stringField(classItem, "classRef") }, "e2e-java-dump");
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
    category: "java_memory_shell", severity: "HIGH", confidence: 0.96, status: "CONFIRMED",
    title: "Lab 动态 Tomcat Filter", summary: "运行时 Filter 缺少磁盘来源，并已成功完成只读 Class Dump。",
    evidenceRefs: [
      stringField(toolResult(context, "list_tomcat_filters").summary, "evidenceId"),
      stringField(toolResult(context, "inspect_java_class").summary, "evidenceId"),
      stringField(toolResult(context, "search_class_on_disk").summary, "evidenceId"),
      stringField(toolResult(context, "dump_java_class").summary, "evidenceId"),
    ],
    recommendation: "结合应用发布基线复核类来源；首期不自动卸载组件。",
  }, "e2e-java-finding");
  return fauxAssistantMessage("Tomcat 内存马只读调查 E2E 已完成。");
}

function nextAccountScanResponse(context: Context) {
  if (!hasToolResult(context, "list_privileged_accounts")) return call("list_privileged_accounts", {}, "e2e-account-scan-list");
  const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
  if (!hasToolResult(context, "inspect_account")) return call("inspect_account", { accountRef: stringField(account, "accountRef") }, "e2e-account-scan-inspect");
  if (!hasToolResult(context, "inspect_authorized_keys")) return call("inspect_authorized_keys", { accountRef: stringField(account, "accountRef") }, "e2e-account-scan-keys");
  if (!hasToolResult(context, "get_login_history")) return call("get_login_history", { accountRef: stringField(account, "accountRef") }, "e2e-account-scan-logins");
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
    category: "backdoor_account", severity: "CRITICAL", confidence: 1, status: "CONFIRMED",
    title: "Lab UID 0 后门账户", summary: "labroot 具有 UID 0，且 SSH Key 指纹与登录历史已完成取证。",
    evidenceRefs: [
      stringField(toolResult(context, "list_privileged_accounts").summary, "evidenceId"),
      stringField(toolResult(context, "inspect_account").summary, "evidenceId"),
      stringField(toolResult(context, "inspect_authorized_keys").summary, "evidenceId"),
      stringField(toolResult(context, "get_login_history").summary, "evidenceId"),
    ],
    recommendation: "确认业务归属后，在处置模式中审批禁用。",
  }, "e2e-account-scan-finding");
  return fauxAssistantMessage("后门账户只读调查 E2E 已完成。");
}

function nextPersistenceScanResponse(context: Context) {
  if (!hasToolResult(context, "list_cron_entries")) return call("list_cron_entries", {}, "e2e-persist-cron");
  if (!hasToolResult(context, "list_systemd_units")) return call("list_systemd_units", {}, "e2e-persist-systemd");
  if (!hasToolResult(context, "list_ssh_persistence")) return call("list_ssh_persistence", {}, "e2e-persist-ssh");
  if (!hasToolResult(context, "list_shell_startup_files")) return call("list_shell_startup_files", {}, "e2e-persist-shell");
  const unit = toolResult(context, "list_systemd_units").items.find((item) => item.unit === "huntwarden-lab.service");
  if (!hasToolResult(context, "inspect_persistence_item")) return call("inspect_persistence_item", { persistenceRef: stringField(unit, "persistenceRef") }, "e2e-persist-inspect");
  if (!hasToolResult(context, "find_related_processes")) return call("find_related_processes", { persistenceRef: stringField(unit, "persistenceRef") }, "e2e-persist-processes");
  const process = toolResult(context, "find_related_processes").items.find((item) => String(item.executable ?? "").includes("python"))
    ?? toolResult(context, "find_related_processes").items[0];
  if (!hasToolResult(context, "list_process_connections")) return call("list_process_connections", { processRef: stringField(process, "processRef") }, "e2e-persist-connections");
  if (!hasToolResult(context, "collect_persistence_artifact")) return call("collect_persistence_artifact", { persistenceRef: stringField(unit, "persistenceRef") }, "e2e-persist-collect");
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
    category: "linux_persistence", severity: "HIGH", confidence: 0.95, status: "HIGHLY_SUSPICIOUS",
    title: "Lab 多机制持久化模拟", summary: "Cron、启用 Unit、未知 Key、Shell 启动项与本地监听进程形成关联；均为无害 Lab 模拟样本。",
    evidenceRefs: [
      stringField(toolResult(context, "list_cron_entries").summary, "evidenceId"),
      stringField(toolResult(context, "list_systemd_units").summary, "evidenceId"),
      stringField(toolResult(context, "list_ssh_persistence").summary, "evidenceId"),
      stringField(toolResult(context, "list_shell_startup_files").summary, "evidenceId"),
      stringField(toolResult(context, "inspect_persistence_item").summary, "evidenceId"),
      stringField(toolResult(context, "find_related_processes").summary, "evidenceId"),
      stringField(toolResult(context, "list_process_connections").summary, "evidenceId"),
      stringField(toolResult(context, "collect_persistence_artifact").summary, "evidenceId"),
    ],
    recommendation: "核对配置来源、变更记录与 Key 所有者；本阶段不提供清除动作。",
  }, "e2e-persist-finding");
  return fauxAssistantMessage("Linux 持久化只读调查 E2E 已完成。");
}

function scanResponses(next: (context: Context) => ReturnType<typeof nextWebScanResponse>): FauxResponseStep[] {
  return Array.from({ length: 40 }, () => (context: Context) => next(context));
}

function nextAccountDisableResponse(context: Context) {
  if (!hasToolResult(context, "list_privileged_accounts")) return call("list_privileged_accounts", {}, "e2e-account-list");
  if (!hasToolResult(context, "inspect_account")) {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("inspect_account", { accountRef: stringField(account, "accountRef") }, "e2e-account-inspect");
  }
  if (!hasToolResult(context, "inspect_authorized_keys")) {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("inspect_authorized_keys", { accountRef: stringField(account, "accountRef") }, "e2e-account-keys");
  }
  if (!hasToolResult(context, "disable_account")) {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("disable_account", { accountRef: stringField(account, "accountRef") }, "e2e-account-disable");
  }
  if (!hasToolResult(context, "record_finding")) return call("record_finding", {
      category: "backdoor_account", severity: "CRITICAL", confidence: 1, status: "CONFIRMED",
      title: "Lab UID 0 后门账户", summary: "labroot 具有 UID 0 且存在未知 SSH Key；处置结果以审批和 ActionReceipt 为准。",
      evidenceRefs: [
        stringField(toolResult(context, "list_privileged_accounts").summary, "evidenceId"),
        stringField(toolResult(context, "inspect_account").summary, "evidenceId"),
        stringField(toolResult(context, "inspect_authorized_keys").summary, "evidenceId"),
      ],
      recommendation: "复核账户禁用回执并调查 SSH Key 来源。",
    }, "e2e-account-finding");
  return fauxAssistantMessage("后门账户处置闭环 E2E 已完成。");
}

function accountDisableResponses(): FauxResponseStep[] {
  return Array.from({ length: 40 }, () => (context: Context) => nextAccountDisableResponse(context));
}

export function createE2eFauxModelBundle(scenario: string): ModelBundle {
  const supported: E2eFauxScenario[] = ["web-quarantine", "account-disable", "web-scan", "java-scan", "account-scan", "persistence-scan"];
  if (!supported.includes(scenario as E2eFauxScenario)) throw new Error(`未知 E2E Faux 场景: ${scenario}`);
  const faux = fauxProvider({ provider: "huntwarden-e2e", tokensPerSecond: 0 });
  const responses = scenario === "web-quarantine" ? webQuarantineResponses()
    : scenario === "account-disable" ? accountDisableResponses()
      : scenario === "web-scan" ? scanResponses(nextWebScanResponse)
        : scenario === "java-scan" ? scanResponses(nextJavaScanResponse)
          : scenario === "account-scan" ? scanResponses(nextAccountScanResponse)
            : scanResponses(nextPersistenceScanResponse);
  faux.setResponses(responses);
  const models = createModels();
  models.setProvider(faux.provider);
  return { models, model: faux.getModel() } as ModelBundle;
}
