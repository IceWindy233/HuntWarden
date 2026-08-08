import React, { useState } from "react";
import type { ConfigProfile, NewTaskInput } from "../../gui/contracts.js";
import type { TaskContext } from "../../domain/types.js";
import { Button, Field, Input, Modal, Select, Textarea } from "./ui.js";

export function NewTaskDialog({ profile, onClose, onCreated, notify }: { profile: ConfigProfile; onClose: () => void; onCreated: (task: TaskContext) => void; notify: (message: string, tone?: "success" | "error" | "info") => void }) {
  const [form, setForm] = useState<NewTaskInput>({
    request: "排查 WebShell、Tomcat Java 内存马、Linux 后门账户与持久化，并形成结构化报告。",
    mode: profile.config.agent.defaultMode,
    checks: ["webshell", "java_memory_shell", "backdoor_account", "linux_persistence"],
    target: {
      host: "127.0.0.1", port: 22, username: "secagent", hostFingerprint: "",
      privateKeyPath: profile.config.executor.privateKeyPath,
      knownHostsPath: profile.config.executor.knownHostsPath,
    },
  });
  const [busy, setBusy] = useState<string>();

  const updateTarget = (patch: Partial<NewTaskInput["target"]>) => setForm((old) => ({ ...old, target: { ...old.target, ...patch } }));
  const toggleCheck = (check: NewTaskInput["checks"][number]) => setForm((old) => ({ ...old, checks: old.checks.includes(check) ? old.checks.filter((item) => item !== check) : [...old.checks, check] }));

  async function testSsh(): Promise<void> {
    setBusy("test");
    try { const result = await window.huntwarden.testSshTarget(form.target); notify(result.message, result.ok ? "success" : "error"); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function create(): Promise<void> {
    setBusy("create");
    try { const task = await window.huntwarden.createTask(form); notify(`任务 ${task.taskId} 已创建`, "success"); onCreated(task); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  return <Modal title="新建主机调查任务" onClose={onClose} size="wide">
    <div className="wizard-banner"><div className="wizard-step active">1 <span>目标</span></div><div className="wizard-line" /><div className="wizard-step active">2 <span>检测</span></div><div className="wizard-line" /><div className="wizard-step active">3 <span>确认</span></div></div>
    <div className="form-grid">
      <Field label="目标主机"><Input value={form.target.host} onChange={(event) => updateTarget({ host: event.target.value })} placeholder="10.0.0.10" /></Field>
      <Field label="SSH 端口"><Input type="number" min={1} max={65535} value={form.target.port} onChange={(event) => updateTarget({ port: Number(event.target.value) })} /></Field>
      <Field label="SSH 用户"><Input value={form.target.username} onChange={(event) => updateTarget({ username: event.target.value })} /></Field>
      <Field label="任务模式"><Select value={form.mode} onChange={(event) => setForm({ ...form, mode: event.target.value as NewTaskInput["mode"] })}><option value="SCAN">SCAN · 只读调查</option><option value="REMEDIATE">REMEDIATE · 允许逐动作审批处置</option></Select></Field>
      <Field label="SHA-256 Host Key 指纹" wide hint="必须与 known_hosts 中的已知指纹完全一致，不会自动接受未知主机。"><Input value={form.target.hostFingerprint} onChange={(event) => updateTarget({ hostFingerprint: event.target.value })} placeholder="SHA256:..." /></Field>
      <Field label="SSH 私钥" wide><div className="input-action"><Input value={form.target.privateKeyPath} onChange={(event) => updateTarget({ privateKeyPath: event.target.value })} /><Button variant="ghost" onClick={async () => { const path = await window.huntwarden.selectPrivateKey(); if (path) updateTarget({ privateKeyPath: path }); }}>选择</Button></div></Field>
      <Field label="known_hosts" wide><div className="input-action"><Input value={form.target.knownHostsPath} onChange={(event) => updateTarget({ knownHostsPath: event.target.value })} /><Button variant="ghost" onClick={async () => { const path = await window.huntwarden.selectKnownHosts(); if (path) updateTarget({ knownHostsPath: path }); }}>选择</Button></div></Field>
    </div>
    <div className="check-grid">
      <CheckCard active={form.checks.includes("webshell")} title="WebShell" description="近期脚本、YARA、日志关联与文件证据" onClick={() => toggleCheck("webshell")} />
      <CheckCard active={form.checks.includes("java_memory_shell")} title="Java 内存马" description="Tomcat 组件、Class 来源与只读 Dump" onClick={() => toggleCheck("java_memory_shell")} />
      <CheckCard active={form.checks.includes("backdoor_account")} title="后门账户" description="特权账户、SSH Key 与登录历史" onClick={() => toggleCheck("backdoor_account")} />
      <CheckCard active={form.checks.includes("linux_persistence")} title="Linux 持久化" description="Cron、systemd、SSH Key、Shell 启动项及进程网络关联" onClick={() => toggleCheck("linux_persistence")} />
    </div>
    <Field label="调查请求" wide><Textarea rows={4} value={form.request} onChange={(event) => setForm({ ...form, request: event.target.value })} /></Field>
    {form.mode === "REMEDIATE" ? <div className="warning-callout"><strong>处置模式已启用</strong><span>任何文件隔离或账户禁用仍需在 GUI 中逐动作审批，模型不能自行授权。</span></div> : null}
    <footer className="modal-footer"><Button variant="ghost" onClick={testSsh} busy={busy === "test"}>测试 SSH 与 Helper</Button><div className="spacer" /><Button variant="ghost" onClick={onClose}>取消</Button><Button variant="primary" onClick={create} busy={busy === "create"} disabled={form.checks.length === 0}>创建任务</Button></footer>
  </Modal>;
}

function CheckCard({ active, title, description, onClick }: { active: boolean; title: string; description: string; onClick: () => void }) {
  return <button className={`check-card ${active ? "active" : ""}`} onClick={onClick}><span className="check-mark">{active ? "✓" : ""}</span><strong>{title}</strong><small>{description}</small></button>;
}
