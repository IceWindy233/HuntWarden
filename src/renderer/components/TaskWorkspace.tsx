import React, { useEffect, useMemo, useState } from "react";
import type { TaskSnapshot } from "../../gui/contracts.js";
import { Button, EmptyState, formatTime, shortId, StatusPill, Textarea } from "./ui.js";

type TaskTab = "调查" | "工具" | "发现" | "证据" | "审计" | "报告";
const TABS: TaskTab[] = ["调查", "工具", "发现", "证据", "审计", "报告"];

export function TaskWorkspace({ snapshot, refresh, notify }: { snapshot: TaskSnapshot; refresh: () => Promise<void>; notify: (message: string, tone?: "success" | "error" | "info") => void }) {
  const [tab, setTab] = useState<TaskTab>("调查");
  const [steering, setSteering] = useState("");
  const [busy, setBusy] = useState<string>();
  const [report, setReport] = useState<string>();
  const { task } = snapshot;
  const active = ["RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"].includes(task.status);

  useEffect(() => { setTab("调查"); setReport(undefined); }, [task.taskId]);
  useEffect(() => { if (tab === "报告") void window.huntwarden.readReport(task.taskId).then((value) => setReport(value)); }, [tab, task.taskId, task.updatedAt]);

  async function action(name: string, operation: () => Promise<unknown>, success: string): Promise<void> {
    setBusy(name);
    try { await operation(); notify(success, "success"); await refresh(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function steer(): Promise<void> {
    if (!steering.trim()) return;
    await action("steer", () => window.huntwarden.steerTask({ taskId: task.taskId, text: steering }), "Steering 已加入队列");
    setSteering("");
  }

  async function generateReport(): Promise<void> {
    await action("report", () => window.huntwarden.generateReport(task.taskId), "报告已生成");
    setReport(await window.huntwarden.readReport(task.taskId)); setTab("报告");
  }

  const counts = useMemo(() => ({ critical: snapshot.findings.filter((item) => item.severity === "CRITICAL").length, suspicious: snapshot.findings.filter((item) => ["CONFIRMED", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"].includes(item.status)).length }), [snapshot.findings]);

  return <div className="workspace">
    <header className="workspace-header">
      <div><div className="target-line"><span className="target-host">{task.target.host}</span><span className="target-user">{task.target.username}@{task.target.port}</span><StatusPill value={task.status} /><StatusPill value={task.mode} /></div><h1>{task.request}</h1><span className="mono muted">{task.taskId}</span></div>
      <div className="task-actions">{task.status === "CREATED" ? <Button variant="primary" onClick={() => action("start", () => window.huntwarden.startTask(task.taskId), "任务已启动")} busy={busy === "start"}>开始调查</Button> : null}{active ? <Button variant="danger" onClick={() => action("abort", () => window.huntwarden.abortTask(task.taskId), "终止请求已提交")} busy={busy === "abort"}>终止</Button> : null}{["FAILED", "ABORTED"].includes(task.status) ? <Button variant="primary" onClick={() => action("recover", () => window.huntwarden.recoverTask(task.taskId), "恢复流程已启动")} busy={busy === "recover"}>恢复</Button> : null}{!active && task.status !== "CREATED" ? <Button onClick={generateReport} busy={busy === "report"}>生成报告</Button> : null}</div>
    </header>

    <div className="metrics-row">
      <Metric label="轮次" value={`${task.turnCount} / 30`} tone="blue" />
      <Metric label="工具调用" value={`${task.toolCallCount}`} tone="blue" />
      <Metric label="高风险发现" value={`${counts.suspicious}`} tone={counts.suspicious ? "amber" : "green"} />
      <Metric label="Evidence" value={`${snapshot.evidence.length}`} tone="violet" />
      <div className="coverage-metric"><span>检测覆盖</span><div className="coverage-tags">{task.checks.map((check) => <span key={check} className={`coverage-tag ${task.coverage[check] ? "done" : "pending"}`} title={task.coverage[check]}>{check === "webshell" ? "WEB" : check === "java_memory_shell" ? "JAVA" : "ACCOUNT"}</span>)}</div></div>
    </div>

    <nav className="task-tabs">{TABS.map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{item}{item === "发现" && snapshot.findings.length ? <span>{snapshot.findings.length}</span> : item === "证据" && snapshot.evidence.length ? <span>{snapshot.evidence.length}</span> : null}</button>)}</nav>

    <main className="task-content">
      {tab === "调查" ? <Investigation snapshot={snapshot} /> : null}
      {tab === "工具" ? <ToolTimeline snapshot={snapshot} /> : null}
      {tab === "发现" ? <Findings snapshot={snapshot} /> : null}
      {tab === "证据" ? <EvidenceList snapshot={snapshot} notify={notify} /> : null}
      {tab === "审计" ? <AuditLog snapshot={snapshot} /> : null}
      {tab === "报告" ? <ReportView taskId={task.taskId} report={report} onGenerate={generateReport} busy={busy === "report"} notify={notify} /> : null}
    </main>

    <div className="steering-composer"><div className="composer-orb">↗</div><Textarea value={steering} onChange={(event) => setSteering(event.target.value)} placeholder={active ? "向正在运行的 Agent 提交 Steering，例如：优先核实 JAVA Filter 的来源…" : "任务运行时可提交 Steering"} disabled={!active || task.status === "WAITING_APPROVAL"} rows={2} onKeyDown={(event) => { if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) { event.preventDefault(); void steer(); } }} /><Button variant="primary" onClick={steer} busy={busy === "steer"} disabled={!active || !steering.trim()}>提交</Button><span className="composer-hint">⌘↵</span></div>
  </div>;
}

function Metric({ label, value, tone }: { label: string; value: string; tone: string }) { return <div className={`metric metric-${tone}`}><span>{label}</span><strong>{value}</strong></div>; }

function Investigation({ snapshot }: { snapshot: TaskSnapshot }) {
  if (snapshot.conversation.length === 0) return <EmptyState icon="⌁" title="调查尚未开始" description="启动任务后，模型消息、工具请求和脱敏结果会显示在这里。" />;
  return <div className="conversation">{snapshot.conversation.map((message, index) => <article key={`${message.timestamp}-${index}`} className={`message message-${message.role} ${message.isError ? "message-error" : ""}`}><div className="message-meta"><span>{message.role === "assistant" ? "SEC AGENT" : message.role === "tool" ? `TOOL · ${message.toolName}` : "ANALYST"}</span><time>{formatTime(message.timestamp)}</time></div><div className="message-body">{message.text || <span className="muted">（无文本输出）</span>}</div></article>)}</div>;
}

function ToolTimeline({ snapshot }: { snapshot: TaskSnapshot }) {
  if (snapshot.toolRuns.length === 0) return <EmptyState icon="⌘" title="暂无工具调用" description="工具生命周期、风险级别和恢复状态会集中展示。" />;
  return <div className="tool-table"><div className="table-head"><span>工具</span><span>风险</span><span>状态</span><span>开始时间</span><span>耗时</span></div>{[...snapshot.toolRuns].reverse().map((run) => { const duration = run.finishedAt ? `${Math.max(0, new Date(run.finishedAt).valueOf() - new Date(run.startedAt).valueOf())} ms` : "运行中"; return <div className="table-row" key={run.toolCallId}><div><strong>{run.toolName}</strong><small className="mono">{shortId(run.toolCallId)}</small>{run.error ? <small className="error-text">{run.error}</small> : null}</div><span><StatusPill value={run.risk} /></span><span><StatusPill value={run.status} /></span><span>{formatTime(run.startedAt)}</span><span>{duration}</span></div>; })}</div>;
}

function Findings({ snapshot }: { snapshot: TaskSnapshot }) {
  if (snapshot.findings.length === 0) return <EmptyState icon="△" title="暂无 Finding" description="Agent 固化的结构化结论会在这里展示；没有 Finding 不代表目标安全。" />;
  return <div className="card-list">{snapshot.findings.map((finding) => <article className="finding-card" key={finding.findingId}><header><div><span className="mono muted">{finding.findingId}</span><h3>{finding.title}</h3></div><div><StatusPill value={finding.severity} /><StatusPill value={finding.status} /></div></header><p>{finding.summary}</p><footer><span>置信度 <strong>{Math.round(finding.confidence * 100)}%</strong></span><span>类别 <strong>{finding.category}</strong></span><span>证据 <strong>{finding.evidenceRefs.length}</strong></span></footer>{finding.recommendation ? <div className="recommendation"><strong>建议</strong>{finding.recommendation}</div> : null}</article>)}</div>;
}

function EvidenceList({ snapshot, notify }: { snapshot: TaskSnapshot; notify: (message: string, tone?: "success" | "error" | "info") => void }) {
  if (snapshot.evidence.length === 0) return <EmptyState icon="▣" title="暂无 Evidence" description="采集结果、哈希和本地受管文件会在这里展示。" />;
  return <div className="evidence-grid">{snapshot.evidence.map((item) => <article className="evidence-card" key={item.evidenceId}><div className="evidence-icon">{item.storagePath ? "FILE" : "JSON"}</div><div className="evidence-main"><span className="mono">{item.evidenceId}</span><h3>{item.type}</h3><p title={item.source}>{item.source}</p><div className="evidence-meta"><span>采集 {formatTime(item.collectedAt)}</span><span>工具 {item.tool}</span>{item.sha256 ? <span className="mono">SHA {shortId(item.sha256)}</span> : null}</div></div>{item.storagePath ? <Button variant="ghost" onClick={async () => { try { await window.huntwarden.revealEvidence(item.evidenceId); } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); } }}>在 Finder 显示</Button> : null}</article>)}</div>;
}

function AuditLog({ snapshot }: { snapshot: TaskSnapshot }) {
  if (snapshot.audit.length === 0 && snapshot.actionReceipts.length === 0) return <EmptyState icon="≡" title="暂无审计事件" description="任务、模型、工具、审批和恢复事件会写入不可省略的审计流。" />;
  return <div className="audit-sections">
    {snapshot.actionReceipts.length ? <section className="receipt-section"><div className="receipt-heading"><strong>远程动作回执</strong><span>{snapshot.actionReceipts.length}</span></div><div className="receipt-grid">{[...snapshot.actionReceipts].reverse().map((receipt) => <article className="receipt-card" key={receipt.actionId}><header><div><strong>{receipt.tool}</strong><span className="mono">{receipt.actionId}</span></div><StatusPill value={receipt.status} /></header><dl><div><dt>目标指纹</dt><dd className="mono">{receipt.targetFingerprint}</dd></div><div><dt>开始</dt><dd>{formatTime(receipt.startedAt)}</dd></div>{receipt.finishedAt ? <div><dt>完成</dt><dd>{formatTime(receipt.finishedAt)}</dd></div> : null}</dl>{receipt.result ? <code>{JSON.stringify(receipt.result)}</code> : null}</article>)}</div></section> : null}
    <div className="audit-log">{[...snapshot.audit].reverse().map((event) => <div className={`audit-line audit-${event.level}`} key={event.eventId}><time>{formatTime(event.createdAt)}</time><span className="audit-level">{event.level}</span><strong>{event.event}</strong><code>{Object.keys(event.data).length ? JSON.stringify(event.data) : ""}</code></div>)}</div>
  </div>;
}

function ReportView({ taskId, report, onGenerate, busy, notify }: { taskId: string; report: string | undefined; onGenerate: () => Promise<void>; busy: boolean; notify: (message: string, tone?: "success" | "error" | "info") => void }) {
  if (!report) return <EmptyState icon="▤" title="尚未生成报告" description="报告将校验所有 Finding/Evidence 引用，失败时自动修复一次并回退确定性模板。" action={<Button variant="primary" onClick={onGenerate} busy={busy}>生成 Markdown 报告</Button>} />;
  return <div className="report-view"><div className="report-toolbar"><span>Markdown · {taskId}</span><Button variant="ghost" onClick={async () => { try { await window.huntwarden.revealReport(taskId); } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); } }}>在 Finder 显示</Button></div><pre>{report}</pre></div>;
}
