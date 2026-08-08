import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { TaskContext } from "../domain/types.js";
import type { ConfigProfileSummary, DesktopEvent, TaskSnapshot } from "../gui/contracts.js";
import { ApprovalDialog } from "./components/ApprovalDialog.js";
import { NewTaskDialog } from "./components/NewTaskDialog.js";
import { SettingsView } from "./components/SettingsView.js";
import { TaskWorkspace } from "./components/TaskWorkspace.js";
import { Button, EmptyState, formatTime, StatusPill } from "./components/ui.js";

type View = "tasks" | "settings";
type ToastTone = "success" | "error" | "info";
interface Toast { id: number; message: string; tone: ToastTone }

export function App() {
  const [view, setView] = useState<View>("tasks");
  const [profiles, setProfiles] = useState<ConfigProfileSummary[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string>();
  const [tasks, setTasks] = useState<TaskContext[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState<string>();
  const [snapshot, setSnapshot] = useState<TaskSnapshot>();
  const [newTaskOpen, setNewTaskOpen] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [loading, setLoading] = useState(true);
  const [fatalError, setFatalError] = useState<string>();
  const toastSequence = useRef(0);
  const refreshSequence = useRef(0);

  const notify = useCallback((message: string, tone: ToastTone = "info") => {
    const id = ++toastSequence.current;
    setToasts((current) => [...current.slice(-3), { id, message, tone }]);
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 5_000);
  }, []);

  const loadBootstrap = useCallback(async () => {
    const state = await window.huntwarden.getBootstrap();
    setProfiles(state.profiles);
    setActiveProfileId(state.activeProfileId);
    setTasks(state.tasks);
    setSelectedTaskId((current) => current && state.tasks.some((item) => item.taskId === current)
      ? current
      : state.tasks[0]?.taskId);
    return state;
  }, []);

  const refreshSnapshot = useCallback(async () => {
    if (!selectedTaskId) { setSnapshot(undefined); return; }
    const sequence = ++refreshSequence.current;
    try {
      const next = await window.huntwarden.getTaskSnapshot(selectedTaskId);
      if (sequence === refreshSequence.current) setSnapshot(next);
    } catch (error) {
      if (sequence === refreshSequence.current) notify(error instanceof Error ? error.message : String(error), "error");
    }
  }, [notify, selectedTaskId]);

  const reloadProfiles = useCallback(async () => {
    await loadBootstrap();
  }, [loadBootstrap]);

  useEffect(() => {
    let mounted = true;
    void loadBootstrap().then((state) => {
      if (!mounted) return;
      if (!state.activeProfileId) setView("settings");
    }).catch((error) => {
      if (mounted) setFatalError(error instanceof Error ? error.message : String(error));
    }).finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [loadBootstrap]);

  useEffect(() => { void refreshSnapshot(); }, [refreshSnapshot]);

  useEffect(() => {
    const unsubscribe = window.huntwarden.subscribe((event: DesktopEvent) => {
      if (event.type === "runtime_error") notify(event.message, "error");
      if (event.type === "approval_requested") notify("Agent 正在等待高风险写操作审批", "info");
      if (event.type === "finding_recorded") notify(`新增 Finding：${event.finding.title}`, event.finding.severity === "CRITICAL" ? "error" : "info");
      if (event.type === "task_updated") {
        setTasks((current) => {
          const next = current.some((item) => item.taskId === event.task.taskId)
            ? current.map((item) => item.taskId === event.task.taskId ? event.task : item)
            : [event.task, ...current];
          return next.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        });
      }
      if ("taskId" in event && event.taskId === selectedTaskId) void refreshSnapshot();
      else if (event.type === "task_updated" && event.task.taskId === selectedTaskId) void refreshSnapshot();
      else if (event.type === "approval_requested" && event.ticket.taskId === selectedTaskId) void refreshSnapshot();
      else if (event.type === "finding_recorded" && event.finding.taskId === selectedTaskId) void refreshSnapshot();
      else if (event.type === "evidence_recorded" && event.evidence.taskId === selectedTaskId) void refreshSnapshot();
      else if (event.type === "audit_recorded" && event.event.taskId === selectedTaskId) void refreshSnapshot();
    });
    return unsubscribe;
  }, [notify, refreshSnapshot, selectedTaskId]);

  useEffect(() => {
    if (!selectedTaskId || view !== "tasks") return;
    const timer = window.setInterval(() => void refreshSnapshot(), 1_500);
    return () => window.clearInterval(timer);
  }, [refreshSnapshot, selectedTaskId, view]);

  const activeProfile = profiles.find((profile) => profile.profileId === activeProfileId);
  const pendingApproval = snapshot?.approvals.find((ticket) => ticket.status === "PENDING");

  async function openNewTask(): Promise<void> {
    if (!activeProfileId) { setView("settings"); notify("请先激活一个配置 Profile", "info"); return; }
    setNewTaskOpen(true);
  }

  function onTaskCreated(task: TaskContext): void {
    setTasks((current) => [task, ...current.filter((item) => item.taskId !== task.taskId)]);
    setSelectedTaskId(task.taskId);
    setNewTaskOpen(false);
    setView("tasks");
  }

  if (loading) return <div className="boot-screen"><div className="brand-mark large">H</div><div><strong>HuntWarden</strong><span>正在初始化安全桌面环境…</span></div></div>;
  if (fatalError) return <div className="fatal-screen"><div className="fatal-symbol">!</div><h1>GUI 初始化失败</h1><p>{fatalError}</p><Button variant="primary" onClick={() => window.location.reload()}>重新加载</Button></div>;

  return <div className="app-shell">
    <aside className="app-sidebar">
      <div className="app-brand"><div className="brand-mark">H</div><div><strong>HuntWarden</strong><span>THREAT HUNT &amp; RESPONSE</span></div></div>
      <nav className="main-nav">
        <button className={view === "tasks" ? "active" : ""} onClick={() => setView("tasks")}><span className="nav-glyph">⌁</span><span>安全调查</span><small>{tasks.filter((task) => ["RUNNING", "RECOVERING", "WAITING_APPROVAL"].includes(task.status)).length || ""}</small></button>
        <button className={view === "settings" ? "active" : ""} onClick={() => setView("settings")}><span className="nav-glyph">⚙</span><span>配置中心</span></button>
      </nav>
      <div className="sidebar-divider" />
      <div className="sidebar-label"><span>调查任务</span><button aria-label="新建任务" onClick={() => void openNewTask()}>＋</button></div>
      <div className="sidebar-tasks">
        {tasks.map((task) => <button key={task.taskId} className={view === "tasks" && selectedTaskId === task.taskId ? "selected" : ""} onClick={() => { setSelectedTaskId(task.taskId); setView("tasks"); }}>
          <span className={`task-dot status-${task.status.toLowerCase()}`} />
          <span className="sidebar-task-main"><strong>{task.target.host}</strong><small>{task.request}</small></span>
          <time>{formatTime(task.updatedAt).slice(6, 11)}</time>
        </button>)}
        {tasks.length === 0 ? <span className="sidebar-empty">还没有调查任务</span> : null}
      </div>
      <div className="sidebar-footer">
        <div className="connection-indicator"><span /><div><strong>LOCAL SECURE</strong><small>IPC 隔离已启用</small></div></div>
        <button className="active-profile-button" onClick={() => setView("settings")}><div><span>活动模型</span><strong>{activeProfile?.model ?? "未配置"}</strong></div><small>{activeProfile?.provider ?? "--"}</small></button>
      </div>
    </aside>

    <section className="app-main">
      <div className="titlebar-drag"><span>{view === "settings" ? "配置与凭据" : snapshot ? `${snapshot.task.target.host} · ${snapshot.task.status}` : "安全调查"}</span><div className="titlebar-meta"><i />本地数据受保护</div></div>
      {view === "settings"
        ? <SettingsView profiles={profiles} {...(activeProfileId ? { activeProfileId } : {})} onProfilesChanged={reloadProfiles} notify={notify} />
        : snapshot
          ? <TaskWorkspace snapshot={snapshot} refresh={refreshSnapshot} notify={notify} />
          : <Dashboard tasks={tasks} activeProfile={activeProfile} onNewTask={() => void openNewTask()} onOpenSettings={() => setView("settings")} onSelectTask={(taskId) => setSelectedTaskId(taskId)} />}
    </section>

    {newTaskOpen && activeProfileId ? <NewTaskLoader profileId={activeProfileId} onClose={() => setNewTaskOpen(false)} onCreated={onTaskCreated} notify={notify} /> : null}
    {pendingApproval ? <ApprovalDialog ticket={pendingApproval} onDone={() => void refreshSnapshot()} notify={notify} /> : null}
    <div className="toast-stack" aria-live="polite">{toasts.map((toast) => <div key={toast.id} className={`toast toast-${toast.tone}`}><span>{toast.tone === "success" ? "✓" : toast.tone === "error" ? "!" : "i"}</span><p>{toast.message}</p><button onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))}>×</button></div>)}</div>
  </div>;
}

function NewTaskLoader({ profileId, onClose, onCreated, notify }: { profileId: string; onClose: () => void; onCreated: (task: TaskContext) => void; notify: (message: string, tone?: ToastTone) => void }) {
  const [profile, setProfile] = useState<Awaited<ReturnType<typeof window.huntwarden.getConfigProfile>>>();
  const [error, setError] = useState<string>();
  useEffect(() => { void window.huntwarden.getConfigProfile(profileId).then(setProfile).catch((value) => setError(value instanceof Error ? value.message : String(value))); }, [profileId]);
  if (error) return <div className="modal-backdrop"><div className="modal"><EmptyState icon="!" title="无法加载活动 Profile" description={error} action={<Button onClick={onClose}>关闭</Button>} /></div></div>;
  if (!profile) return <div className="modal-backdrop"><div className="modal modal-loading"><span className="spinner" />正在读取活动配置…</div></div>;
  return <NewTaskDialog profile={profile} onClose={onClose} onCreated={onCreated} notify={notify} />;
}

function Dashboard({ tasks, activeProfile, onNewTask, onOpenSettings, onSelectTask }: { tasks: TaskContext[]; activeProfile: ConfigProfileSummary | undefined; onNewTask: () => void; onOpenSettings: () => void; onSelectTask: (taskId: string) => void }) {
  const summary = useMemo(() => ({
    active: tasks.filter((task) => ["RUNNING", "RECOVERING", "WAITING_APPROVAL"].includes(task.status)).length,
    completed: tasks.filter((task) => task.status === "COMPLETED").length,
    failed: tasks.filter((task) => ["FAILED", "ABORTED"].includes(task.status)).length,
  }), [tasks]);
  return <div className="dashboard">
    <header className="dashboard-hero"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>主机安全调查台</h1><p>在一个受控工作区中完成检测、取证、逐动作审批和可恢复处置。</p></div><Button variant="primary" onClick={onNewTask}>＋ 新建调查</Button></header>
    <div className="overview-grid"><div className="overview-card accent-blue"><span>活动任务</span><strong>{summary.active}</strong><small>同一时间最多运行 1 个任务</small></div><div className="overview-card accent-green"><span>已完成</span><strong>{summary.completed}</strong><small>报告与 Evidence 可追溯</small></div><div className="overview-card accent-amber"><span>需关注</span><strong>{summary.failed}</strong><small>失败或人工终止</small></div><button className="overview-card model-card" onClick={onOpenSettings}><span>活动模型</span><strong>{activeProfile?.model ?? "配置模型"}</strong><small>{activeProfile ? `${activeProfile.provider} · ${activeProfile.name}` : "需要先完成模型配置"}</small></button></div>
    <section className="dashboard-section"><div className="dashboard-section-title"><div><h2>最近调查</h2><p>任务状态、目标和检测范围均保存在本地 SQLite 事件流中。</p></div>{tasks.length ? <Button variant="ghost" onClick={onNewTask}>新建任务</Button> : null}</div>
      {tasks.length ? <div className="recent-table"><div className="recent-head"><span>目标</span><span>状态</span><span>模式</span><span>检测范围</span><span>更新时间</span></div>{tasks.slice(0, 10).map((task) => <button className="recent-row" key={task.taskId} onClick={() => onSelectTask(task.taskId)}><div><strong>{task.target.host}</strong><small>{task.target.username}@{task.target.port}</small></div><span><StatusPill value={task.status} /></span><span><StatusPill value={task.mode} /></span><span className="check-mini">{task.checks.map((check) => <i key={check}>{check === "webshell" ? "WEB" : check === "java_memory_shell" ? "JAVA" : check === "backdoor_account" ? "ACCOUNT" : "PERSIST"}</i>)}</span><time>{formatTime(task.updatedAt)}</time></button>)}</div>
        : <EmptyState icon="⌁" title="从第一场主机调查开始" description="配置 SSH 目标、选择四个专项检测，并由 Agent 在安全工具边界内完成调查。" action={<Button variant="primary" onClick={onNewTask}>创建调查任务</Button>} />}
    </section>
    <section className="safety-strip"><div><span className="safety-icon">⌾</span><div><strong>处置安全边界</strong><p>模型没有 Shell 权限；文件隔离和账户禁用必须绑定 Evidence、目标指纹与一次性审批。</p></div></div><button onClick={onOpenSettings}>检查配置 →</button></section>
  </div>;
}
