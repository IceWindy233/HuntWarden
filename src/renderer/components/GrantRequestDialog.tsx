import { useState } from "react";
import type { GrantRequest } from "../../protocol-v2/types.js";
import { Button, Modal, shortId } from "./ui.js";

export function GrantRequestDialog({ request, onDone, notify }: {
  request: GrantRequest;
  onDone: () => void;
  notify: (message: string, tone?: "success" | "error" | "info") => void;
}) {
  const [busy, setBusy] = useState(false);
  async function decide(approved: boolean): Promise<void> {
    setBusy(true);
    try {
      await window.huntwarden.decideGrantRequest({ requestId: request.requestId, approved });
      notify(approved ? "调查授权已激活" : "调查授权已拒绝", approved ? "info" : "success");
      onDone();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setBusy(false);
    }
  }
  const target = request.kind === "SCOPE"
    ? String(request.binding.requestedRoot ?? "未提供")
    : String(request.binding.subjectRef ?? "未提供");
  return <Modal title="调查范围授权">
    <div className="approval-alert"><span>i</span><div><strong>该授权只扩大只读调查范围</strong><p>Grant 与当前任务和目标指纹绑定，不包含写能力；拒绝会形成 Investigation Gap。</p></div></div>
    <dl className="approval-details"><div><dt>类型</dt><dd>{request.kind}</dd></div><div><dt>对象 / 范围</dt><dd className="mono">{target}</dd></div><div><dt>目标指纹</dt><dd className="mono">{request.targetFingerprint}</dd></div><div><dt>Request ID</dt><dd className="mono">{shortId(request.requestId)}</dd></div></dl>
    <footer className="modal-footer"><Button variant="ghost" onClick={() => void decide(false)} busy={busy}>拒绝</Button><div className="spacer" /><Button variant="primary" onClick={() => void decide(true)} busy={busy}>批准只读授权</Button></footer>
  </Modal>;
}
