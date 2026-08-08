import { EventEmitter } from "node:events";
import { createId } from "../common/ids.js";
import { digestObject } from "../common/json.js";
import type { ApprovalTicket, TaskContext } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

export class ApprovalService extends EventEmitter {
  constructor(private readonly store: RuntimeStore) { super(); }

  getArgsDigest(args: unknown): string { return digestObject(args); }

  request(task: TaskContext, tool: string, args: unknown, context?: string): ApprovalTicket {
    const digest = this.getArgsDigest(args);
    const pending = this.store.listPendingApprovals(task.taskId)
      .find((item) => item.tool === tool && item.argsDigest === digest && item.targetFingerprint === task.target.hostFingerprint);
    if (pending) return pending;
    const ticket: ApprovalTicket = {
      approvalId: createId("approval"),
      taskId: task.taskId,
      targetFingerprint: task.target.hostFingerprint,
      tool,
      argsDigest: digest,
      actionId: createId("action"),
      actionSummary: [context, this.actionSummary(task, tool, args)].filter(Boolean).join("；"),
      status: "PENDING",
      createdAt: new Date().toISOString(),
    };
    this.store.putApproval(ticket);
    task.status = "WAITING_APPROVAL";
    this.store.saveTask(task);
    this.store.appendAudit({ taskId: task.taskId, event: "write_tool_requested", level: "warn", data: { ...ticket } });
    this.emit("requested", ticket);
    return ticket;
  }

  async waitForDecision(ticket: ApprovalTicket, signal?: AbortSignal): Promise<ApprovalTicket> {
    if (ticket.status !== "PENDING") return ticket;
    return await new Promise<ApprovalTicket>((resolve, reject) => {
      const onDecision = (decided: ApprovalTicket) => {
        if (decided.approvalId !== ticket.approvalId) return;
        cleanup();
        resolve(decided);
      };
      const onAbort = () => {
        cleanup();
        reject(signal?.reason ?? new Error("approval wait aborted"));
      };
      const cleanup = () => {
        this.off("decided", onDecision);
        signal?.removeEventListener("abort", onAbort);
      };
      this.on("decided", onDecision);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  decide(approvalId: string, approved: boolean): ApprovalTicket {
    const ticket = this.store.updateApproval(approvalId, approved ? "APPROVED" : "DENIED");
    this.store.appendAudit({
      taskId: ticket.taskId,
      event: approved ? "write_tool_approved" : "write_tool_denied",
      level: approved ? "warn" : "info",
      data: { approvalId, actionId: ticket.actionId, tool: ticket.tool },
    });
    const task = this.store.getTask(ticket.taskId);
    if (task?.status === "WAITING_APPROVAL" && this.store.listPendingApprovals(ticket.taskId).length === 0) {
      task.status = "RUNNING";
      this.store.saveTask(task);
    }
    this.emit("decided", ticket);
    return ticket;
  }

  consume(task: TaskContext, tool: string, args: unknown): ApprovalTicket | undefined {
    const ticket = this.store.findApproval(task.taskId, tool, this.getArgsDigest(args));
    if (!ticket || ticket.targetFingerprint !== task.target.hostFingerprint) return undefined;
    const consumed = this.store.updateApproval(ticket.approvalId, "CONSUMED");
    return consumed;
  }

  private actionSummary(task: TaskContext, tool: string, args: unknown): string {
    const value = args && typeof args === "object" ? args as Record<string, unknown> : {};
    if (tool === "quarantine_file" && typeof value.evidenceRef === "string") {
      const evidence = this.store.getEvidence(task.taskId, value.evidenceRef);
      return evidence
        ? `隔离文件 ${evidence.source}（SHA-256 ${evidence.sha256 ?? "缺失"}）`
        : `隔离文件证据 ${value.evidenceRef}`;
    }
    if (tool === "disable_account" && typeof value.accountRef === "string") {
      const account = this.store.getReference<{ username?: string }>(task.taskId, value.accountRef, "account");
      return `禁用账户 ${account?.value.username ?? value.accountRef}`;
    }
    return `执行 ${tool}，参数摘要 ${this.getArgsDigest(args)}`;
  }
}
