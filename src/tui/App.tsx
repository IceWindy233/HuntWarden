import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, useApp, useInput } from "ink";
import type { AgentStreamUpdate, ApprovalTicket, TaskContext } from "../domain/types.js";
import type { Application } from "../runtime/application.js";

type Tab = "任务" | "事件" | "发现" | "证据";
const TABS: Tab[] = ["任务", "事件", "发现", "证据"];
type NewTaskField = "host" | "port" | "username" | "fingerprint" | "mode" | "request";
const NEW_TASK_FIELDS: { key: NewTaskField; label: string; defaultValue: (application: Application) => string }[] = [
  { key: "host", label: "目标主机", defaultValue: () => "127.0.0.1" },
  { key: "port", label: "SSH 端口", defaultValue: () => "22" },
  { key: "username", label: "SSH 用户", defaultValue: () => "secagent" },
  { key: "fingerprint", label: "SHA-256 主机指纹（留空从 known_hosts 读取）", defaultValue: () => "" },
  { key: "mode", label: "模式 SCAN/REMEDIATE", defaultValue: (application) => application.config.agent.defaultMode },
  { key: "request", label: "调查请求", defaultValue: () => "排查 WebShell、Tomcat Java 内存马、Linux 后门账户和持久化，并形成结构化报告。" },
];

export interface AppProps { application: Application; initialTask?: TaskContext; autoStart?: boolean }

function currentTasks(application: Application): TaskContext[] {
  return application.store.listTasks().filter((task) => !task.archivedAt);
}

export function App({ application, initialTask, autoStart = false }: AppProps) {
  const { exit } = useApp();
  const [tasks, setTasks] = useState(() => currentTasks(application));
  const [selected, setSelected] = useState(0);
  const [selectedTaskId, setSelectedTaskId] = useState(initialTask?.taskId);
  const [tabIndex, setTabIndex] = useState(0);
  const [status, setStatus] = useState("就绪");
  const [approval, setApproval] = useState<ApprovalTicket | undefined>();
  const [inputMode, setInputMode] = useState(false);
  const [input, setInput] = useState("");
  const [newTaskStep, setNewTaskStep] = useState<number | undefined>();
  const [newTaskDraft, setNewTaskDraft] = useState<Partial<Record<NewTaskField, string>>>({});
  const [liveOutput, setLiveOutput] = useState<{ streamId: string; text: string; active: boolean; error: boolean }>();
  const current = selectedTaskId
    ? tasks.find((task) => task.taskId === selectedTaskId) ?? (initialTask?.taskId === selectedTaskId ? initialTask : undefined)
    : tasks[selected];

  const refresh = () => {
    const next = currentTasks(application);
    setTasks(next);
    if (current) setApproval(application.store.listPendingApprovals(current.taskId)[0]);
  };

  useEffect(() => {
    const timer = setInterval(refresh, 500);
    const onApproval = (ticket: ApprovalTicket) => setApproval(ticket);
    const onStream = (update: AgentStreamUpdate) => {
      if (update.phase === "start") setLiveOutput({ streamId: update.streamId, text: "", active: true, error: false });
      else if (update.phase === "delta") setLiveOutput((current) => ({
        streamId: update.streamId,
        text: `${current?.streamId === update.streamId ? current.text : ""}${update.delta ?? ""}`.slice(-65_536),
        active: true,
        error: false,
      }));
      else setLiveOutput((current) => current?.streamId === update.streamId ? { ...current, active: false, error: update.phase === "error" } : current);
    };
    application.approvals.on("requested", onApproval);
    application.on("stream", onStream);
    if (initialTask && autoStart) {
      const runtime = application.runtimeFor(initialTask);
      void runtime.prompt(initialTask.request).then(() => setStatus("调查阶段完成，可按 g 生成报告")).catch((error) => setStatus(`失败: ${error instanceof Error ? error.message : String(error)}`));
    }
    return () => { clearInterval(timer); application.approvals.off("requested", onApproval); application.off("stream", onStream); };
  }, []);

  useInput((value, key) => {
    if (approval) {
      if (value.toLowerCase() === "y") { application.approvals.decide(approval.approvalId, true); setApproval(undefined); setStatus("已批准一次性写操作"); }
      if (value.toLowerCase() === "n") { application.approvals.decide(approval.approvalId, false); setApproval(undefined); setStatus("已拒绝写操作"); }
      return;
    }
    if (newTaskStep !== undefined) {
      if (key.escape) { setNewTaskStep(undefined); setNewTaskDraft({}); setInput(""); setStatus("已取消新建任务"); return; }
      if (key.return) {
        const field = NEW_TASK_FIELDS[newTaskStep];
        if (!field) return;
        const entered = input.trim() || field.defaultValue(application);
        const nextDraft = { ...newTaskDraft, [field.key]: entered };
        setNewTaskDraft(nextDraft);
        setInput("");
        if (newTaskStep < NEW_TASK_FIELDS.length - 1) { setNewTaskStep(newTaskStep + 1); return; }
        setNewTaskStep(undefined);
        const port = Number(nextDraft.port);
        const mode = nextDraft.mode?.toUpperCase();
        if (!Number.isInteger(port) || port < 1 || port > 65_535 || !["SCAN", "REMEDIATE"].includes(mode ?? "")) {
          setStatus("新建失败：端口或模式无效");
          return;
        }
        void (async () => {
          const fingerprint = nextDraft.fingerprint || await application.inferLabFingerprint(application.config.executor.knownHostsPath, port);
          const created = application.createTask({
            request: nextDraft.request!, mode: mode as "SCAN" | "REMEDIATE",
            target: {
              host: nextDraft.host!, port, username: nextDraft.username!, hostFingerprint: fingerprint,
              privateKeyPath: application.config.executor.privateKeyPath,
              knownHostsPath: application.config.executor.knownHostsPath,
            },
          });
          setSelectedTaskId(created.taskId);
          setSelected(0);
          setTasks(currentTasks(application));
          setNewTaskDraft({});
          setStatus(`已创建任务 ${created.taskId}`);
        })().catch((error) => setStatus(`新建失败: ${error instanceof Error ? error.message : String(error)}`));
      } else if (key.backspace || key.delete) setInput((old) => old.slice(0, -1));
      else if (value && !key.ctrl && !key.meta) setInput((old) => old + value);
      return;
    }
    if (inputMode) {
      if (key.return) {
        if (current && input.trim()) void application.runtimeFor(current).steer(input.trim());
        setInput(""); setInputMode(false); setStatus("已加入 Steering 队列");
      } else if (key.escape) { setInput(""); setInputMode(false); }
      else if (key.backspace || key.delete) setInput((old) => old.slice(0, -1));
      else if (value && !key.ctrl && !key.meta) setInput((old) => old + value);
      return;
    }
    if (value === "q") { void application.close().finally(exit); return; }
    if (key.tab) setTabIndex((index) => (index + 1) % TABS.length);
    if (key.upArrow) { setSelectedTaskId(undefined); setSelected((index) => Math.max(0, index - 1)); }
    if (key.downArrow) { setSelectedTaskId(undefined); setSelected((index) => Math.min(tasks.length - 1, index + 1)); }
    if (value === "n") { setNewTaskStep(0); setNewTaskDraft({}); setInput(""); setStatus("新建任务向导"); }
    if (value === "i" && current) setInputMode(true);
    if (value === "a" && current) {
      const runtime = application.runtimeFor(current);
      void runtime.prompt(current.request).then(() => setStatus("调查阶段完成，可按 g 生成报告")).catch((error) => setStatus(`失败: ${error instanceof Error ? error.message : String(error)}`));
    }
    if (value === "r" && current) {
      void application.runtimeFor(current).recover().then(() => setStatus("恢复完成")).catch((error) => setStatus(`恢复失败: ${error instanceof Error ? error.message : String(error)}`));
    }
    if (value === "g" && current) {
      void application.generateReport(current.taskId).then((report) => setStatus(`报告已保存: ${report.path}`)).catch((error) => setStatus(`报告失败: ${error instanceof Error ? error.message : String(error)}`));
    }
  });

  const tab = TABS[tabIndex] ?? "任务";
  const body = useMemo(() => {
    if (!current) return ["暂无任务。按 n 使用向导创建，或通过 --host/--fingerprint 启动参数创建。"]; 
    if (tab === "任务") return [
      `任务: ${current.taskId}`, `目标: ${current.target.username}@${current.target.host}:${current.target.port}`,
      `状态: ${current.status}`, `模式: ${current.mode}`, `轮次/工具: ${current.turnCount}/${current.toolCallCount}`,
      `覆盖: ${JSON.stringify(current.coverage)}`,
    ];
    if (tab === "事件") return application.store.listAudit(current.taskId, 20).map((event) => `${event.createdAt.slice(11, 19)} ${event.level} ${event.event}`);
    if (tab === "发现") return application.store.listFindings(current.taskId).map((finding) => `${finding.findingId} [${finding.severity}/${finding.status}] ${finding.title}`);
    return application.store.listEvidence(current.taskId).map((item) => `${item.evidenceId} ${item.type} ${item.source}`);
  }, [current?.updatedAt, tab, tasks.length]);

  return <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
    <Box justifyContent="space-between"><Text bold color="cyan">HuntWarden</Text><Text>{TABS.map((item, i) => i === tabIndex ? `[${item}]` : item).join("  ")}</Text></Box>
    <Box height={1}><Text dimColor>单任务主机专项检测与受控查杀</Text></Box>
    <Box flexDirection="column" minHeight={12}>{body.slice(-18).map((line, index) => <Text key={`${index}-${line}`}>{line}</Text>)}</Box>
    {liveOutput ? <Box borderStyle="round" borderColor={liveOutput.error ? "red" : "cyan"} flexDirection="column" paddingX={1}><Text bold color={liveOutput.error ? "red" : "cyan"}>SEC AGENT {liveOutput.active ? "· LIVE" : "· 完成"}</Text><Text>{liveOutput.text.split("\n").slice(-6).join("\n") || "正在生成响应…"}{liveOutput.active ? "▌" : ""}</Text></Box> : null}
    {approval ? <Box borderStyle="double" borderColor="yellow" flexDirection="column"><Text bold color="yellow">写操作审批</Text><Text>工具: {approval.tool}</Text><Text>动作: {approval.actionSummary}</Text><Text>目标指纹: {approval.targetFingerprint}</Text><Text>参数摘要: {approval.argsDigest}</Text><Text>Action: {approval.actionId}</Text><Text>按 y 单次批准 / n 拒绝</Text></Box> : null}
    {newTaskStep !== undefined ? <Text color="cyan">新建任务 {newTaskStep + 1}/{NEW_TASK_FIELDS.length} · {NEW_TASK_FIELDS[newTaskStep]?.label} [默认: {NEW_TASK_FIELDS[newTaskStep]?.defaultValue(application) || "自动"}] &gt; {input}_</Text>
      : inputMode ? <Text color="green">Steering&gt; {input}_</Text>
      : <Text dimColor>Tab 切换 | ↑↓ 任务 | n 新建 | a 开始 | r 恢复 | i Steering | g 报告 | q 退出</Text>}
    <Text color={status.startsWith("失败") ? "red" : "green"}>{status}</Text>
  </Box>;
}
