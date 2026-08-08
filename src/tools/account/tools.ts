import { Type } from "typebox";
import type { SecurityToolDefinition, SecurityToolResult } from "../../domain/types.js";
import { createSecurityTool } from "../tool-factory.js";
import type { ToolDependencies } from "../dependencies.js";
import { createReference, requireReference } from "../reference-utils.js";

interface AccountValue { username: string; uid: number; [key: string]: unknown }

export function createAccountTools(deps: ToolDependencies): SecurityToolDefinition[] {
  const common = [deps.store, deps.task.taskId, deps.config.llmData.maxTextBytes] as const;
  const accountRef = Type.String({ pattern: "^ACCT-" });
  return [
    createSecurityTool(...common, {
      name: "list_privileged_accounts", label: "列出特权账户",
      description: "列出 UID 0、sudo/wheel 及异常低 UID 交互账户并返回 accountRef。Linux 后门账户调查应先调用。",
      parameters: Type.Object({}, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "privileged_accounts_listed",
      run: async (toolCallId, _params, signal): Promise<SecurityToolResult> => {
        const accounts = await deps.executor.invoke({ operation: "list_privileged_accounts", params: {} }, signal) as AccountValue[];
        const refs = accounts.map((value) => createReference(deps.store, deps.task.taskId, "account", "account", value));
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "privileged_accounts", source: "/etc/passwd + group database", tool: "list_privileged_accounts", toolCallId, metadata: { accounts: refs.map(({ ref, value }) => ({ accountRef: ref, ...value })) } });
        return { status: "success", summary: { count: refs.length, evidenceId: evidence.evidenceId }, items: refs.map(({ ref, value }) => ({ accountRef: ref, ...value })), artifactRefs: [...refs.map((v) => v.ref), evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_account", label: "检查账户详情",
      description: "检查 accountRef 的 UID/GID、组、Shell、Home、密码锁定与过期状态，不修改账户。",
      parameters: Type.Object({ accountRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "account_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const account = requireReference<AccountValue>(deps.store, deps.task.taskId, params.accountRef, "account");
        const result = await deps.executor.invoke({ operation: "inspect_account", params: { username: account.value.username } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "account_detail", source: `account:${account.value.username}`, tool: "inspect_account", toolCallId, metadata: { accountRef: params.accountRef, ...result } });
        return { status: "success", summary: { ...result, evidenceId: evidence.evidenceId }, items: [{ accountRef: params.accountRef, evidenceId: evidence.evidenceId, ...result }], artifactRefs: [params.accountRef, evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "inspect_authorized_keys", label: "检查 SSH Key",
      description: "返回 accountRef 的 authorized_keys 类型、SHA-256 指纹、注释和选项；绝不返回完整 Key。",
      parameters: Type.Object({ accountRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "authorized_keys_inspected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const account = requireReference<AccountValue>(deps.store, deps.task.taskId, params.accountRef, "account");
        const result = await deps.executor.invoke({ operation: "inspect_authorized_keys", params: { username: account.value.username } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "ssh_key_fingerprints", source: `${account.value.username}:authorized_keys`, tool: "inspect_authorized_keys", toolCallId, metadata: { accountRef: params.accountRef, keys: result } });
        return { status: "success", summary: { username: account.value.username, keyCount: result.length, evidenceId: evidence.evidenceId }, items: result, artifactRefs: [params.accountRef, evidence.evidenceId], warnings: [] };
      },
    }),
    createSecurityTool(...common, {
      name: "get_login_history", label: "查询登录历史",
      description: "返回 accountRef 最近最多 100 条登录历史，用于关联来源地址和时间。",
      parameters: Type.Object({ accountRef }, { additionalProperties: false }),
      risk: "READ", replayPolicy: "SAFE", timeoutMs: 30_000, auditEvent: "login_history_collected",
      run: async (toolCallId, params, signal): Promise<SecurityToolResult> => {
        const account = requireReference<AccountValue>(deps.store, deps.task.taskId, params.accountRef, "account");
        const result = await deps.executor.invoke({ operation: "get_login_history", params: { username: account.value.username, maxEntries: 100 } }, signal);
        const evidence = deps.evidence.putStructured({ taskId: deps.task.taskId, host: deps.task.target.host, type: "login_history", source: `last:${account.value.username}`, tool: "get_login_history", toolCallId, metadata: { accountRef: params.accountRef, entries: result } });
        return { status: "success", summary: { username: account.value.username, entries: result.length, evidenceId: evidence.evidenceId }, items: result, artifactRefs: [params.accountRef, evidence.evidenceId], warnings: [] };
      },
    }),
  ];
}
