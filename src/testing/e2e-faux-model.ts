import { createModels, type Context } from "@earendil-works/pi-ai";
import {
  fauxAssistantMessage,
  fauxProvider,
  fauxToolCall,
  type FauxResponseStep,
} from "@earendil-works/pi-ai/providers/faux";
import type { ModelBundle } from "../agent/model.js";
import type { SecurityToolResult } from "../domain/types.js";

export type E2eFauxScenario = "web-quarantine" | "account-disable";

function toolResult(context: Context, toolName: string): SecurityToolResult<Record<string, unknown>, Record<string, unknown>> {
  const message = [...context.messages].reverse().find((item) => item.role === "toolResult" && item.toolName === toolName);
  if (!message || message.role !== "toolResult") throw new Error(`E2E Faux 缺少工具结果: ${toolName}`);
  return message.details as SecurityToolResult<Record<string, unknown>, Record<string, unknown>>;
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

function webQuarantineResponses(): FauxResponseStep[] {
  return [
    call("discover_web_roots", {}, "e2e-web-discover"),
    (context) => {
      const root = toolResult(context, "discover_web_roots").items.find((item) => item.path === "/var/www/html");
      return call("find_recent_web_files", { webRootRefs: [stringField(root, "webRootRef")] }, "e2e-web-find");
    },
    (context) => {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("yara_scan_files", { candidateRefs: [stringField(candidate, "candidateRef")] }, "e2e-web-yara");
    },
    (context) => {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("inspect_script_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-inspect");
    },
    (context) => {
      const candidate = toolResult(context, "find_recent_web_files").items.find((item) => item.path === "/var/www/html/lab-webshell.php");
      return call("collect_file", { candidateRef: stringField(candidate, "candidateRef") }, "e2e-web-collect");
    },
    (context) => call("quarantine_file", { evidenceRef: stringField(toolResult(context, "collect_file").summary, "evidenceId") }, "e2e-web-quarantine"),
    (context) => call("record_finding", {
      category: "webshell", severity: "HIGH", confidence: 0.99, status: "CONFIRMED",
      title: "Lab WebShell 模拟样本", summary: "YARA、脚本特征与文件证据确认该无害模拟样本；处置结果以审批和 ActionReceipt 为准。",
      evidenceRefs: [stringField(toolResult(context, "collect_file").summary, "evidenceId")],
      recommendation: "复核隔离回执并保留 Evidence。",
    }, "e2e-web-finding"),
    fauxAssistantMessage("WebShell 处置闭环 E2E 已完成。"),
  ];
}

function accountDisableResponses(): FauxResponseStep[] {
  return [
    call("list_privileged_accounts", {}, "e2e-account-list"),
    (context) => {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("inspect_account", { accountRef: stringField(account, "accountRef") }, "e2e-account-inspect");
    },
    (context) => {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("inspect_authorized_keys", { accountRef: stringField(account, "accountRef") }, "e2e-account-keys");
    },
    (context) => {
      const account = toolResult(context, "list_privileged_accounts").items.find((item) => item.username === "labroot");
      return call("disable_account", { accountRef: stringField(account, "accountRef") }, "e2e-account-disable");
    },
    (context) => call("record_finding", {
      category: "backdoor_account", severity: "CRITICAL", confidence: 1, status: "CONFIRMED",
      title: "Lab UID 0 后门账户", summary: "labroot 具有 UID 0 且存在未知 SSH Key；处置结果以审批和 ActionReceipt 为准。",
      evidenceRefs: [
        stringField(toolResult(context, "list_privileged_accounts").summary, "evidenceId"),
        stringField(toolResult(context, "inspect_account").summary, "evidenceId"),
        stringField(toolResult(context, "inspect_authorized_keys").summary, "evidenceId"),
      ],
      recommendation: "复核账户禁用回执并调查 SSH Key 来源。",
    }, "e2e-account-finding"),
    fauxAssistantMessage("后门账户处置闭环 E2E 已完成。"),
  ];
}

export function createE2eFauxModelBundle(scenario: string): ModelBundle {
  if (scenario !== "web-quarantine" && scenario !== "account-disable") throw new Error(`未知 E2E Faux 场景: ${scenario}`);
  const faux = fauxProvider({ provider: "huntwarden-e2e", tokensPerSecond: 0 });
  faux.setResponses(scenario === "web-quarantine" ? webQuarantineResponses() : accountDisableResponses());
  const models = createModels();
  models.setProvider(faux.provider);
  return { models, model: faux.getModel() } as ModelBundle;
}
