import React, { useEffect, useMemo, useState } from "react";
import { CHECK_CATEGORY_SHORT_LABELS, type ReportRecord } from "../../domain/types.js";
import type { TaskSnapshot } from "../../gui/contracts.js";
import { Button, EmptyState, formatTime, shortId, StatusPill, Textarea } from "./ui.js";

type TaskTab = "调查" | "工具" | "发现" | "证据" | "情报" | "审计" | "报告";
const TABS: TaskTab[] = ["调查", "工具", "发现", "证据", "情报", "审计", "报告"];

export interface LiveAgentStream {
  taskId: string;
  streamId: string;
  text: string;
  timestamp: number;
  phase: "streaming" | "complete" | "error";
  truncated: boolean;
}

export function TaskWorkspace({ snapshot, refresh, notify, liveStream }: { snapshot: TaskSnapshot; refresh: () => Promise<void>; notify: (message: string, tone?: "success" | "error" | "info") => void; liveStream?: LiveAgentStream }) {
  const [tab, setTab] = useState<TaskTab>("调查");
  const [steering, setSteering] = useState("");
  const [busy, setBusy] = useState<string>();
  const [reports, setReports] = useState<ReportRecord[]>(snapshot.reports);
  const [selectedReportId, setSelectedReportId] = useState<string>();
  const [report, setReport] = useState<string>();
  const { task } = snapshot;
  const archived = Boolean(task.archivedAt);
  const active = !archived && ["RUNNING", "WAITING_APPROVAL", "RECOVERING", "REPORTING"].includes(task.status);
  const hasReports = snapshot.reports.length > 0;
  const firstReportLabel = task.status === "COMPLETED" ? "确认并生成报告" : "生成阶段性报告";

  useEffect(() => { setTab("调查"); setReports(snapshot.reports); setSelectedReportId(undefined); setReport(undefined); }, [task.taskId]);
  useEffect(() => {
    if (tab !== "报告") return;
    void window.huntwarden.listReports(task.taskId).then(async (items) => {
      setReports(items);
      const reportId = selectedReportId && items.some((item) => item.reportId === selectedReportId)
        ? selectedReportId
        : items.at(-1)?.reportId;
      setSelectedReportId(reportId);
      const value = await window.huntwarden.readReport({ taskId: task.taskId, ...(reportId ? { reportId } : {}) });
      setReport(value?.markdown);
    });
  }, [tab, task.taskId, task.updatedAt, selectedReportId]);

  async function action(name: string, operation: () => Promise<unknown>, success: string): Promise<boolean> {
    setBusy(name);
    try { await operation(); notify(success, "success"); await refresh(); return true; }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); return false; }
    finally { setBusy(undefined); }
  }

  async function steer(): Promise<void> {
    if (!steering.trim()) return;
    await action("steer", () => window.huntwarden.steerTask({ taskId: task.taskId, text: steering }), "Steering 已加入队列");
    setSteering("");
  }

  async function generateReport(): Promise<void> {
    if (!hasReports) {
      const description = task.status === "COMPLETED"
        ? "确认基于当前 Finding、Evidence、处置与检测覆盖生成正式报告？生成后仍可创建新版本。"
        : "当前任务未正常完成。确认生成阶段性报告？报告会保留 ERROR、NOT_CHECKED 和未完成原因。";
      if (!window.confirm(description)) return;
    }
    let generated: ReportRecord | undefined;
    const completed = await action("report", async () => { generated = await window.huntwarden.generateReport(task.taskId); }, hasReports ? "新报告版本已生成" : "报告已生成");
    if (!completed || !generated) return;
    const items = await window.huntwarden.listReports(task.taskId);
    setReports(items);
    if (generated) setSelectedReportId(generated.reportId);
    const value = await window.huntwarden.readReport({ taskId: task.taskId, ...(generated ? { reportId: generated.reportId } : {}) });
    setReport(value?.markdown); setTab("报告");
  }

  async function archiveTask(): Promise<void> {
    if (!window.confirm("归档后任务会从当前列表隐藏，但 Finding、Evidence、报告与审计记录都会保留。确认归档？")) return;
    await action("archive", () => window.huntwarden.archiveTask(task.taskId), "任务已归档");
  }

  async function restoreTask(): Promise<void> {
    await action("restore", () => window.huntwarden.restoreTask(task.taskId), "任务已恢复到当前列表");
  }

  async function selectReport(reportId: string): Promise<void> {
    setSelectedReportId(reportId);
    const value = await window.huntwarden.readReport({ taskId: task.taskId, reportId });
    setReport(value?.markdown);
  }

  const counts = useMemo(() => ({ critical: snapshot.findings.filter((item) => item.severity === "CRITICAL").length, suspicious: snapshot.findings.filter((item) => ["CONFIRMED", "HIGHLY_SUSPICIOUS", "SUSPICIOUS"].includes(item.status)).length }), [snapshot.findings]);

  return <div className="workspace">
    <header className="workspace-header">
      <div><div className="target-line"><span className="target-host">{task.target.host}</span><span className="target-user">{task.target.username}@{task.target.port}</span><StatusPill value={task.status} /><StatusPill value={task.mode} /></div><h1>{task.request}</h1><span className="mono muted">{task.taskId}</span></div>
      <div className="task-actions">
        {archived
          ? <Button variant="primary" onClick={restoreTask} busy={busy === "restore"}>恢复归档</Button>
          : <>
            {task.status === "CREATED" ? <Button variant="primary" onClick={() => action("start", () => window.huntwarden.startTask(task.taskId), "任务已启动")} busy={busy === "start"}>开始调查</Button> : null}
            {active ? <Button variant="danger" onClick={() => action("abort", () => window.huntwarden.abortTask(task.taskId), "终止请求已提交")} busy={busy === "abort"}>终止</Button> : null}
            {task.interruption?.recoveryRequired ? <Button variant="primary" onClick={() => action("recover", () => window.huntwarden.recoverTask(task.taskId), "恢复流程已启动")} busy={busy === "recover"}>恢复任务</Button> : null}
            {!active && task.status !== "CREATED" && !task.interruption?.recoveryRequired ? <Button variant={hasReports ? "secondary" : "primary"} onClick={generateReport} busy={busy === "report"}>{hasReports ? "重新生成报告" : firstReportLabel}</Button> : null}
            {!active && !task.interruption?.recoveryRequired ? <Button variant="ghost" onClick={archiveTask} busy={busy === "archive"}>归档</Button> : null}
          </>}
      </div>
    </header>

    <div className="workspace-notices">
      {task.archivedAt ? <div className="archive-banner"><strong>任务已归档</strong><span>{formatTime(task.archivedAt)} · 当前为只读查看，所有取证与审计数据均保留。</span></div> : null}
      {task.interruption?.recoveryRequired ? <div className="interruption-banner"><strong>检测到任务中断</strong><span>原状态 {task.interruption.previousStatus} · {formatTime(task.interruption.detectedAt)}。旧审批已失效，恢复后会先核对远程回执。</span></div> : null}
      {!archived && !active && task.status !== "CREATED" && !task.interruption?.recoveryRequired && !hasReports ? <div className="report-pending-banner"><strong>{task.status === "COMPLETED" ? "调查已完成，报告待确认" : "任务未正常完成，可生成阶段性报告"}</strong><span>{task.status === "COMPLETED" ? "请先复核 Finding、Evidence 与检测覆盖，再手动确认生成报告。" : "报告将明确保留未检查项、错误状态和未完成原因。"}</span></div> : null}
    </div>

    <div className="metrics-row">
      <Metric label="轮次" value={`${task.turnCount} / 30`} tone="blue" />
      <Metric label="工具调用" value={`${task.toolCallCount}`} tone="blue" />
      <Metric label="高风险发现" value={`${counts.suspicious}`} tone={counts.suspicious ? "amber" : "green"} />
      <Metric label="Evidence" value={`${snapshot.evidence.length}`} tone="violet" />
      <div className="coverage-metric"><span>检测覆盖</span><div className="coverage-tags">{task.checks.map((check) => <span key={check} className={`coverage-tag ${task.coverage[check] ? "done" : "pending"}`} title={task.coverage[check]}>{CHECK_CATEGORY_SHORT_LABELS[check]}</span>)}</div></div>
    </div>

    <nav className="task-tabs">{TABS.map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{item}{item === "发现" && snapshot.findings.length ? <span>{snapshot.findings.length}</span> : item === "证据" && snapshot.evidence.length ? <span>{snapshot.evidence.length}</span> : null}</button>)}</nav>

    <main className="task-content">
      {tab === "调查" ? <Investigation snapshot={snapshot} {...(liveStream ? { liveStream } : {})} /> : null}
      {tab === "工具" ? <ToolTimeline snapshot={snapshot} /> : null}
      {tab === "发现" ? <Findings snapshot={snapshot} /> : null}
      {tab === "证据" ? <EvidenceList snapshot={snapshot} notify={notify} /> : null}
      {tab === "情报" ? <ThreatIntelView snapshot={snapshot} /> : null}
      {tab === "审计" ? <AuditLog snapshot={snapshot} /> : null}
      {tab === "报告" ? <ReportView taskId={task.taskId} reports={reports} selectedReportId={selectedReportId} report={report} onSelect={selectReport} onGenerate={generateReport} busy={busy === "report"} notify={notify} readOnly={archived} firstReportLabel={firstReportLabel} /> : null}
    </main>

    <div className="steering-composer"><div className="composer-orb">↗</div><Textarea value={steering} onChange={(event) => setSteering(event.target.value)} placeholder={active ? "向正在运行的 Agent 提交 Steering，例如：优先核实 JAVA Filter 的来源…" : "任务运行时可提交 Steering"} disabled={!active || task.status === "WAITING_APPROVAL"} rows={2} onKeyDown={(event) => { if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) { event.preventDefault(); void steer(); } }} /><Button variant="primary" onClick={steer} busy={busy === "steer"} disabled={!active || !steering.trim()}>提交</Button><span className="composer-hint">⌘↵</span></div>
  </div>;
}

function Metric({ label, value, tone }: { label: string; value: string; tone: string }) { return <div className={`metric metric-${tone}`}><span>{label}</span><strong>{value}</strong></div>; }

function Investigation({ snapshot, liveStream }: { snapshot: TaskSnapshot; liveStream?: LiveAgentStream }) {
  if (snapshot.conversation.length === 0 && !liveStream) return <EmptyState icon="⌁" title="调查尚未开始" description="启动任务后，模型消息、工具请求和脱敏结果会显示在这里。" />;
  return <div className="conversation">{snapshot.conversation.map((message, index) => <article key={`${message.timestamp}-${index}`} className={`message message-${message.role} ${message.isError ? "message-error" : ""}`}><div className="message-meta"><span>{message.role === "assistant" ? "SEC AGENT" : message.role === "tool" ? `TOOL · ${message.toolName}` : "ANALYST"}</span><time>{formatTime(message.timestamp)}</time></div><div className="message-body">{message.text || <span className="muted">（无文本输出）</span>}</div></article>)}{liveStream ? <article key={liveStream.streamId} className={`message message-assistant message-streaming ${liveStream.phase === "error" ? "message-error" : ""}`} aria-live="polite"><div className="message-meta"><span>SEC AGENT · LIVE</span><time>{formatTime(liveStream.timestamp)}</time></div><div className="message-body">{liveStream.text || <span className="muted">正在生成响应…</span>}{liveStream.truncated ? <span className="stream-truncated">实时预览已达 512K 字符，完整消息将在生成结束后显示。</span> : null}<span className="stream-cursor" aria-hidden="true" /></div></article> : null}</div>;
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

function ThreatIntelView({ snapshot }: { snapshot: TaskSnapshot }) {
  const evidence = snapshot.evidence.filter((item) => item.type.startsWith("dbapp_"));
  const verdicts = evidence.flatMap((item) => {
    const rows = item.metadata?.verdicts;
    return Array.isArray(rows) ? rows.flatMap((row) => row && typeof row === "object" ? [{ evidenceId: item.evidenceId, ...row as Record<string, unknown> }] : []) : [];
  });
  if (evidence.length === 0) return <EmptyState icon="◎" title="暂无威胁情报" description="启用安恒威胁情报后，当前任务已观测的公网外联 IP 和分析师提供的 IOC 会在这里显示。私网、回环和保留地址不会上送。" />;
  return <div className="ti-view">
    <div className="ti-source-banner"><strong>情报来源：安恒威胁情报 (DBAPP Threat Intelligence)</strong><span>外部情报是关联证据，必须结合进程、文件和时间线事实，不会单独形成 CONFIRMED 结论。</span></div>
    <div className="card-list">{verdicts.map((verdict, index) => {
      const malicious = verdict.malicious === true;
      const unknown = verdict.malicious === null;
      const types = Array.isArray(verdict.threatTypes) ? verdict.threatTypes.map(String).join("、") : "";
      const refs = Array.isArray(verdict.connectionRefs) ? verdict.connectionRefs.map(String) : [];
      return <article className={`finding-card ti-card ${malicious ? "ti-malicious" : ""}`} key={`${String(verdict.evidenceId)}-${String(verdict.ioc)}-${index}`}><header><div><span className="mono muted">{String(verdict.evidenceId)}</span><h3>{String(verdict.ioc ?? "未知 IOC")}</h3></div><div><StatusPill value={malicious ? "SUSPICIOUS" : unknown ? "UNKNOWN" : "NO_FINDING"} /><StatusPill value={String(verdict.riskLevel ?? "unknown").toUpperCase()} /></div></header><p>{typeof verdict.description === "string" ? verdict.description : malicious ? "情报库返回恶意或高风险判定。" : unknown ? "情报库未返回明确判定。" : "情报库未标记为恶意。"}</p><footer><span>类型 <strong>{String(verdict.iocType ?? "unknown")}</strong></span><span>威胁标签 <strong>{types || "--"}</strong></span><span>关联连接 <strong>{refs.length}</strong></span><span>缓存 <strong>{verdict.cached === true ? "是" : "否"}</strong></span></footer></article>;
    })}</div>
  </div>;
}

function AuditLog({ snapshot }: { snapshot: TaskSnapshot }) {
  if (snapshot.audit.length === 0 && snapshot.actionReceipts.length === 0) return <EmptyState icon="≡" title="暂无审计事件" description="任务、模型、工具、审批和恢复事件会写入不可省略的审计流。" />;
  return <div className="audit-sections">
    {snapshot.actionReceipts.length ? <section className="receipt-section"><div className="receipt-heading"><strong>远程动作回执</strong><span>{snapshot.actionReceipts.length}</span></div><div className="receipt-grid">{[...snapshot.actionReceipts].reverse().map((receipt) => <article className="receipt-card" key={receipt.actionId}><header><div><strong>{receipt.tool}</strong><span className="mono">{receipt.actionId}</span></div><StatusPill value={receipt.status} /></header><dl><div><dt>目标指纹</dt><dd className="mono">{receipt.targetFingerprint}</dd></div><div><dt>开始</dt><dd>{formatTime(receipt.startedAt)}</dd></div>{receipt.finishedAt ? <div><dt>完成</dt><dd>{formatTime(receipt.finishedAt)}</dd></div> : null}</dl>{receipt.result ? <code>{JSON.stringify(receipt.result)}</code> : null}</article>)}</div></section> : null}
    <div className="audit-log">{[...snapshot.audit].reverse().map((event) => <div className={`audit-line audit-${event.level}`} key={event.eventId}><time>{formatTime(event.createdAt)}</time><span className="audit-level">{event.level}</span><strong>{event.event}</strong><code>{Object.keys(event.data).length ? JSON.stringify(event.data) : ""}</code></div>)}</div>
  </div>;
}

function ReportView({ taskId, reports, selectedReportId, report, onSelect, onGenerate, busy, notify, readOnly, firstReportLabel }: { taskId: string; reports: ReportRecord[]; selectedReportId: string | undefined; report: string | undefined; onSelect: (reportId: string) => Promise<void>; onGenerate: () => Promise<void>; busy: boolean; notify: (message: string, tone?: "success" | "error" | "info") => void; readOnly: boolean; firstReportLabel: string }) {
  if (!report) return <EmptyState icon="▤" title="尚未生成报告" description="请先复核调查结果。确认后，报告会校验所有 Finding/Evidence 引用，失败时自动修复一次并回退确定性模板。" action={readOnly ? undefined : <Button variant="primary" onClick={onGenerate} busy={busy}>{firstReportLabel}</Button>} />;
  const selected = reports.find((item) => item.reportId === selectedReportId) ?? reports.at(-1);
  return <div className="report-view"><div className="report-toolbar"><span>Markdown · {taskId}</span><div className="report-version-controls"><select aria-label="报告版本" value={selected?.reportId ?? ""} onChange={(event) => void onSelect(event.target.value)}>{reports.map((item) => <option value={item.reportId} key={item.reportId}>v{item.version} · {item.generationMode}</option>)}</select>{readOnly ? null : <Button variant="ghost" onClick={onGenerate} busy={busy}>重新生成</Button>}<Button variant="ghost" onClick={async () => { try { await window.huntwarden.revealReport({ taskId, ...(selected ? { reportId: selected.reportId } : {}) }); } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); } }}>在 Finder 显示</Button></div></div>{selected ? <div className="report-meta"><span>SHA-256 {shortId(selected.sha256)}</span><span>{formatTime(selected.createdAt)}</span>{selected.validationErrors.length ? <span>自动修复记录 {selected.validationErrors.length}</span> : null}</div> : null}<pre>{report}</pre></div>;
}
