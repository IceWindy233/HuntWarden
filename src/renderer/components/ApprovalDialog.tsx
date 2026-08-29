import { useState } from "react";
import type { ApprovalTicket } from "../../domain/types.js";
import { Button, Modal, shortId } from "./ui.js";

export function ApprovalDialog({ ticket, onDone, notify }: { ticket: ApprovalTicket; onDone: () => void; notify: (message: string, tone?: "success" | "error" | "info") => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  async function decide(approved: boolean): Promise<void> {
    if (approved && !confirming) { setConfirming(true); return; }
    setBusy(true);
    try { await window.huntwarden.decideApproval({ approvalId: ticket.approvalId, approved }); notify(approved ? "一次性处置授权已提交" : "处置已拒绝", approved ? "info" : "success"); onDone(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(false); }
  }

  return <Modal title="高风险写操作审批">
    <div className="approval-alert"><span>!</span><div><strong>该动作将修改远程主机</strong><p>授权票据只绑定当前任务、目标指纹、工具、参数摘要和 Action ID，且只能消费一次。</p></div></div>
    <dl className="approval-details"><div><dt>工具</dt><dd>{ticket.tool}</dd></div><div><dt>动作</dt><dd>{ticket.actionSummary}</dd></div><div><dt>目标指纹</dt><dd className="mono">{ticket.targetFingerprint}</dd></div><div><dt>参数摘要</dt><dd className="mono">{ticket.argsDigest}</dd></div><div><dt>Action ID</dt><dd className="mono" title={ticket.actionId}>{shortId(ticket.actionId)}</dd></div></dl>
    {confirming ? <div className="confirm-strip">请再次点击“确认执行”完成授权。执行结果将写入远端原子回执和本地审计日志。</div> : null}
    <footer className="modal-footer"><Button variant="ghost" onClick={() => decide(false)} busy={busy}>拒绝</Button><div className="spacer" /><Button variant="danger" onClick={() => decide(true)} busy={busy}>{confirming ? "确认执行" : "批准一次"}</Button></footer>
  </Modal>;
}
