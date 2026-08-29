// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApprovalDialog } from "../../src/renderer/components/ApprovalDialog.js";
import type { ApprovalTicket } from "../../src/domain/types.js";

afterEach(cleanup);

const ticket: ApprovalTicket = {
  approvalId: "APPROVAL-1", taskId: "TASK-1", targetFingerprint: "SHA256:known-host",
  tool: "quarantine_file", argsDigest: "abc123", actionId: "ACTION-12345678901234567890",
  actionSummary: "隔离 /var/www/html/suspicious.php", status: "PENDING", createdAt: new Date().toISOString(),
};

describe("ApprovalDialog", () => {
  it("批准必须二次点击，拒绝只提交明确的 false", async () => {
    const decideApproval = vi.fn(async () => undefined);
    Object.defineProperty(window, "huntwarden", { configurable: true, value: { decideApproval } });
    const onDone = vi.fn();
    const notify = vi.fn();
    const view = render(<ApprovalDialog ticket={ticket} onDone={onDone} notify={notify} />);

    fireEvent.click(screen.getByRole("button", { name: "批准一次" }));
    expect(decideApproval).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "确认执行" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "确认执行" }));
    await waitFor(() => expect(decideApproval).toHaveBeenCalledWith({ approvalId: "APPROVAL-1", approved: true }));
    expect(onDone).toHaveBeenCalledOnce();

    view.unmount();
    decideApproval.mockClear();
    render(<ApprovalDialog ticket={ticket} onDone={onDone} notify={notify} />);
    fireEvent.click(screen.getByRole("button", { name: "拒绝" }));
    await waitFor(() => expect(decideApproval).toHaveBeenCalledWith({ approvalId: "APPROVAL-1", approved: false }));
  });
});
