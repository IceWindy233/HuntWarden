import React, { useEffect, useMemo, useState } from "react";
import YAML from "yaml";
import type { AppConfig } from "../../config/schema.js";
import type { ConfigProfile, ConfigProfileSummary, ConfigValidationResult, CredentialStatus, ModelProviderSummary, ModelSummary } from "../../gui/contracts.js";
import { Button, Field, Input, Section, Select, StatusPill } from "./ui.js";

interface Props {
  profiles: ConfigProfileSummary[];
  activeProfileId?: string;
  initialProfileId?: string;
  onProfilesChanged: (preferredId?: string) => Promise<void>;
  notify: (message: string, tone?: "success" | "error" | "info") => void;
}

const FALLBACK_CUSTOM: Extract<AppConfig["model"], { source: "custom" }> = {
  source: "custom",
  provider: "custom-gateway",
  model: "security-model",
  thinkingLevel: "off",
  protocol: "openai-completions",
  baseUrl: "https://llm-gateway.example.com/v1",
  authentication: { type: "api-key-env", apiKeyEnv: "HUNTWARDEN_LLM_API_KEY" },
  reasoning: false,
  contextWindow: 131_072,
  maxTokens: 16_384,
  compatibility: { supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStrictMode: false },
};

export function SettingsView({ profiles, activeProfileId, initialProfileId, onProfilesChanged, notify }: Props) {
  const [selectedId, setSelectedId] = useState(initialProfileId ?? activeProfileId ?? profiles[0]?.profileId);
  const [profile, setProfile] = useState<ConfigProfile>();
  const [name, setName] = useState("");
  const [config, setConfig] = useState<AppConfig>();
  const [providers, setProviders] = useState<ModelProviderSummary[]>([]);
  const [models, setModels] = useState<ModelSummary[]>([]);
  const [credential, setCredential] = useState<CredentialStatus>();
  const [secret, setSecret] = useState("");
  const [persistSecret, setPersistSecret] = useState(true);
  const [tiCredential, setTiCredential] = useState<CredentialStatus>();
  const [tiSecret, setTiSecret] = useState("");
  const [persistTiSecret, setPersistTiSecret] = useState(true);
  const [validation, setValidation] = useState<ConfigValidationResult>();
  const [busy, setBusy] = useState<string>();
  const [advancedOpen, setAdvancedOpen] = useState(false);

  useEffect(() => { void window.huntwarden.listModelProviders().then(setProviders); }, []);
  useEffect(() => {
    void window.huntwarden.getCredentialStatus("dbapp-ti").then(setTiCredential).catch(() => setTiCredential(undefined));
  }, []);
  useEffect(() => {
    if (!selectedId) return;
    setBusy("load");
    void window.huntwarden.getConfigProfile(selectedId).then((value) => {
      setProfile(value); setName(value.name); setConfig(value.config); setValidation(undefined);
    }).catch((error) => notify(error instanceof Error ? error.message : String(error), "error")).finally(() => setBusy(undefined));
  }, [selectedId]);

  const providerId = config?.model.provider;
  const source = config?.model.source ?? "builtin";
  useEffect(() => {
    if (!providerId) return;
    void window.huntwarden.getCredentialStatus(providerId).then(setCredential).catch(() => setCredential(undefined));
    if (source === "builtin") void window.huntwarden.listModels(providerId).then(setModels).catch(() => setModels([]));
    else setModels([]);
  }, [providerId, source]);

  const currentModel = source === "builtin" ? models.find((item) => item.id === config?.model.model) : undefined;
  const yamlPreview = useMemo(() => config ? YAML.stringify(config, { lineWidth: 110 }) : "", [config]);

  const updateModel = (next: AppConfig["model"]) => setConfig((old) => old ? { ...old, model: next } : old);
  const updateAgent = (patch: Partial<AppConfig["agent"]>) => setConfig((old) => old ? { ...old, agent: { ...old.agent, ...patch } } : old);
  const updateExecutor = (patch: Partial<AppConfig["executor"]>) => setConfig((old) => old ? { ...old, executor: { ...old.executor, ...patch } } : old);
  const updateThreatIntel = (patch: Partial<AppConfig["threatIntel"]>) => setConfig((old) => old ? { ...old, threatIntel: { ...old.threatIntel, ...patch } } : old);

  async function selectProvider(nextProvider: string): Promise<void> {
    if (!config || source !== "builtin") return;
    setBusy("models");
    try {
      const nextModels = await window.huntwarden.listModels(nextProvider);
      setModels(nextModels);
      const next = nextModels[0];
      if (!next) throw new Error("该 Provider 没有可用 Tool Call 模型");
      const preferred = next.thinkingLevels.includes("medium") ? "medium" : next.thinkingLevels.includes("high") ? "high" : next.thinkingLevels[0] ?? "off";
      updateModel({ source: "builtin", provider: nextProvider, model: next.id, thinkingLevel: preferred as AppConfig["model"]["thinkingLevel"] });
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  function switchSource(next: "builtin" | "custom"): void {
    if (!config) return;
    if (next === "custom") updateModel(structuredClone(FALLBACK_CUSTOM));
    else updateModel({ source: "builtin", provider: "deepseek", model: "deepseek-v4-flash", thinkingLevel: "high" });
  }

  async function save(): Promise<void> {
    if (!config) return;
    setBusy("save");
    try {
      const checked = await window.huntwarden.validateConfigProfile(config);
      setValidation(checked);
      if (!checked.valid) throw new Error(checked.issues.map((item) => item.message).join("；"));
      const saved = await window.huntwarden.saveConfigProfile({ ...(profile ? { profileId: profile.profileId } : {}), name, config });
      setProfile(saved); setSelectedId(saved.profileId);
      await onProfilesChanged(saved.profileId);
      notify("配置 Profile 已安全保存", "success");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function cloneProfile(): Promise<void> {
    if (!config) return;
    setProfile(undefined); setSelectedId(undefined); setName(`${name} 副本`); setConfig(structuredClone(config));
  }

  async function activate(): Promise<void> {
    if (!profile) return;
    setBusy("activate");
    try { await window.huntwarden.activateConfigProfile(profile.profileId); setProfile({ ...profile, active: true }); await onProfilesChanged(profile.profileId); notify("活动 Profile 已切换", "success"); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function remove(): Promise<void> {
    if (!profile || profile.active || !confirm(`确认删除 Profile“${profile.name}”？`)) return;
    setBusy("delete");
    try { await window.huntwarden.deleteConfigProfile(profile.profileId); setSelectedId(activeProfileId); await onProfilesChanged(activeProfileId); notify("Profile 已删除", "success"); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function importProfile(): Promise<void> {
    try { const value = await window.huntwarden.importConfigProfile(); if (value) { await onProfilesChanged(value.profileId); setSelectedId(value.profileId); notify("YAML 已导入", "success"); } }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
  }

  async function saveSecret(): Promise<void> {
    if (!providerId || !secret.trim()) return;
    setBusy("credential");
    try {
      const saved = await window.huntwarden.saveCredential({ provider: providerId, secret, persist: persistSecret });
      setCredential(saved); setSecret("");
      notify(saved.notice ?? "API Key 已保存，GUI 不会再次读取明文", saved.notice ? "info" : "success");
    }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function deleteSecret(): Promise<void> {
    if (!providerId || !confirm("确认删除该 Provider 的 GUI 凭据？")) return;
    await window.huntwarden.deleteCredential(providerId); setCredential(await window.huntwarden.getCredentialStatus(providerId)); notify("凭据已删除", "success");
  }

  async function saveThreatIntelSecret(): Promise<void> {
    if (!tiSecret.trim()) return;
    setBusy("ti-credential");
    try {
      const saved = await window.huntwarden.saveCredential({ provider: "dbapp-ti", secret: tiSecret, persist: persistTiSecret });
      setTiCredential(saved); setTiSecret("");
      notify(saved.notice ?? "安恒威胁情报 Key 已保存，GUI 不会再次读取明文", saved.notice ? "info" : "success");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function deleteThreatIntelSecret(): Promise<void> {
    if (!confirm("确认删除安恒威胁情报 API Key？")) return;
    await window.huntwarden.deleteCredential("dbapp-ti");
    setTiCredential(await window.huntwarden.getCredentialStatus("dbapp-ti"));
    notify("安恒威胁情报凭据已删除", "success");
  }

  async function testThreatIntel(): Promise<void> {
    if (!profile || !confirm("在线测试将查询 example.com，并消耗 1 次安恒威胁情报额度。是否继续？")) return;
    setBusy("ti-test");
    try {
      const result = await window.huntwarden.testThreatIntel(profile.profileId);
      notify(result.message, result.ok ? "success" : "error");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  async function runModelCheck(live: boolean): Promise<void> {
    if (!profile) return;
    setBusy(live ? "smoke" : "check");
    try {
      const result = live ? await window.huntwarden.smokeModel(profile.profileId) : await window.huntwarden.checkModel(profile.profileId);
      notify(result.message, result.ok ? "success" : "error");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "error"); }
    finally { setBusy(undefined); }
  }

  if (!config) return <div className="view-loading"><span className="spinner" />正在加载配置…</div>;

  return <div className="settings-layout">
    <aside className="profile-list-panel">
      <div className="panel-title-row"><div><span className="eyebrow">CONFIGURATION</span><h2>配置中心</h2></div><Button variant="ghost" onClick={cloneProfile}>＋</Button></div>
      <div className="profile-list">{profiles.map((item) => <button key={item.profileId} className={`profile-item ${selectedId === item.profileId ? "selected" : ""}`} onClick={() => setSelectedId(item.profileId)}><span className="profile-provider">{item.provider}</span><strong>{item.name}</strong><small>{item.model}</small>{item.active ? <span className="active-dot">活动</span> : null}</button>)}</div>
      <div className="profile-actions"><Button variant="ghost" onClick={importProfile}>导入 YAML</Button>{profile ? <Button variant="ghost" onClick={() => void window.huntwarden.exportConfigProfile(profile.profileId)}>导出</Button> : null}</div>
    </aside>

    <div className="settings-scroll">
      <div className="settings-hero"><div><span className="eyebrow">PROFILE</span><div className="title-with-status"><h1>{profile ? profile.name : "新建 Profile"}</h1>{profile?.active ? <StatusPill value="ACTIVE" /> : null}</div><p>通过结构化表单配置模型、SSH、检测策略与本地存储。秘密不会进入 YAML。</p></div><div className="hero-actions">{profile && !profile.active ? <Button onClick={activate} busy={busy === "activate"}>设为活动</Button> : null}<Button variant="primary" onClick={save} busy={busy === "save"}>保存配置</Button></div></div>

      <Section title="Profile 标识" description="显示名称可以修改，Profile ID 创建后保持稳定。">
        <div className="form-grid"><Field label="名称" wide><Input value={name} onChange={(event) => setName(event.target.value)} /></Field>{profile ? <Field label="Profile ID"><Input value={profile.profileId} disabled /></Field> : null}</div>
      </Section>

      <Section title="模型与 API" description="内置 Provider 使用 Pi 原生协议；企业网关和本机模型使用自定义端点。" action={<div className="segmented"><button className={source === "builtin" ? "active" : ""} onClick={() => switchSource("builtin")}>内置</button><button className={source === "custom" ? "active" : ""} onClick={() => switchSource("custom")}>自定义</button></div>}>
        {config.model.source !== "custom" ? <div className="form-grid">
          <Field label="Provider"><Select value={config.model.provider} onChange={(event) => void selectProvider(event.target.value)}>{providers.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.modelCount}</option>)}</Select></Field>
          <Field label="模型"><Select value={config.model.model} onChange={(event) => updateModel({ ...config.model, model: event.target.value })}>{models.map((item) => <option key={item.id} value={item.id}>{item.name || item.id}</option>)}</Select></Field>
          <Field label="推理等级" {...(currentModel ? { hint: `支持：${currentModel.thinkingLevels.join(" / ")}` } : {})}><Select value={config.model.thinkingLevel} onChange={(event) => updateModel({ ...config.model, thinkingLevel: event.target.value as AppConfig["model"]["thinkingLevel"] })}>{(currentModel?.thinkingLevels ?? [config.model.thinkingLevel]).map((level) => <option key={level}>{level}</option>)}</Select></Field>
          <Field label="协议"><Input value={currentModel?.protocol ?? "--"} disabled /></Field>
        </div> : <CustomModelForm model={config.model} onChange={updateModel} />}

        <div className="credential-card"><div className="credential-status"><div className={`status-orb ${credential?.configured ? "ok" : "warn"}`} /><div><strong>{providerId} API 凭据</strong><span>{credential?.configured ? `已配置 · ${credential.source ?? "Provider 环境"}` : "尚未配置"}</span>{credential?.secureStorageBackend ? <small>安全存储：{credential.secureStorageBackend}</small> : null}{credential?.notice ? <small>{credential.notice}</small> : null}</div></div><div className="credential-input"><Input type="password" autoComplete="new-password" placeholder="输入 API Key（保存后不可读取）" value={secret} onChange={(event) => setSecret(event.target.value)} /><label className="checkbox-row"><input type="checkbox" checked={persistSecret} onChange={(event) => setPersistSecret(event.target.checked)} />系统安全存储持久化</label><Button onClick={saveSecret} busy={busy === "credential"}>保存 Key</Button>{credential?.configured ? <Button variant="ghost" onClick={deleteSecret}>删除</Button> : null}</div></div>
        <div className="inline-actions"><Button onClick={() => runModelCheck(false)} busy={busy === "check"} disabled={!profile}>静态检查</Button><Button variant="primary" onClick={() => runModelCheck(true)} busy={busy === "smoke"} disabled={!profile}>真实 Tool Call 冒烟</Button><span className="cost-note">冒烟测试会产生少量模型费用</span></div>
      </Section>

      <Section title="安恒威胁情报" description="对当前任务已观测的公网外联 IP、分析师提供的域名/IP 和文件哈希做受控富化；不会读取 Codex Skill 的密钥文件。">
        <div className="form-grid">
          <Field label="启用情报查询"><Select value={config.threatIntel.enabled ? "yes" : "no"} onChange={(event) => updateThreatIntel({ enabled: event.target.value === "yes" })}><option value="no">关闭</option><option value="yes">启用</option></Select></Field>
          <Field label="自动富化可疑外联"><Select value={config.threatIntel.autoEnrichConnections ? "yes" : "no"} onChange={(event) => updateThreatIntel({ autoEnrichConnections: event.target.value === "yes" })}><option value="yes">启用</option><option value="no">仅手动调用</option></Select></Field>
          <Field label="Provider"><Input value="dbapp-ti" disabled /></Field>
          <Field label="API 端点"><Input value={config.threatIntel.baseUrl} disabled /></Field>
          <Field label="请求超时（秒）"><Input type="number" min={1} max={60} value={config.threatIntel.timeoutSeconds} onChange={(event) => updateThreatIntel({ timeoutSeconds: Number(event.target.value) })} /></Field>
          <Field label="单批 IOC 上限"><Input type="number" min={1} max={100} value={config.threatIntel.maxBatchSize} onChange={(event) => updateThreatIntel({ maxBatchSize: Number(event.target.value) })} /></Field>
          <Field label="本地缓存（秒）"><Input type="number" min={0} max={86400} value={config.threatIntel.cacheTtlSeconds} onChange={(event) => updateThreatIntel({ cacheTtlSeconds: Number(event.target.value) })} /></Field>
          <Field label="私网地址上送"><Input value="始终禁止" disabled /></Field>
        </div>
        <div className="credential-card"><div className="credential-status"><div className={`status-orb ${tiCredential?.configured ? "ok" : "warn"}`} /><div><strong>DBAPP TI API 凭据</strong><span>{tiCredential?.configured ? `已配置 · ${tiCredential.source ?? config.threatIntel.apiKeyEnv}` : `尚未配置 · 可使用 ${config.threatIntel.apiKeyEnv}`}</span>{tiCredential?.secureStorageBackend ? <small>安全存储：{tiCredential.secureStorageBackend}</small> : null}{tiCredential?.notice ? <small>{tiCredential.notice}</small> : null}</div></div><div className="credential-input"><Input type="password" autoComplete="new-password" placeholder="nti-…（保存后不可读取）" value={tiSecret} onChange={(event) => setTiSecret(event.target.value)} /><label className="checkbox-row"><input type="checkbox" checked={persistTiSecret} onChange={(event) => setPersistTiSecret(event.target.checked)} />系统安全存储持久化</label><Button onClick={saveThreatIntelSecret} busy={busy === "ti-credential"}>保存情报 Key</Button>{tiCredential?.configured ? <Button variant="ghost" onClick={deleteThreatIntelSecret}>删除</Button> : null}</div></div>
        <div className="inline-actions"><Button variant="primary" onClick={testThreatIntel} busy={busy === "ti-test"} disabled={!profile}>测试情报 API</Button><span className="cost-note">测试会查询 example.com，并消耗 1 次安恒威胁情报额度</span></div>
      </Section>

      <Section title="Agent 预算" description="达到预算后停止调查并在报告中保留未完成项。">
        <div className="form-grid"><Field label="最大轮次"><Input type="number" min={1} max={100} value={config.agent.maxTurns} onChange={(event) => updateAgent({ maxTurns: Number(event.target.value) })} /></Field><Field label="最大 Tool Calls"><Input type="number" min={1} max={1000} value={config.agent.maxToolCalls} onChange={(event) => updateAgent({ maxToolCalls: Number(event.target.value) })} /></Field><Field label="默认模式"><Select value={config.agent.defaultMode} onChange={(event) => updateAgent({ defaultMode: event.target.value as "SCAN" | "REMEDIATE" })}><option>SCAN</option><option>REMEDIATE</option></Select></Field><Field label="Prompt 版本"><Input value={config.agent.promptVersion} onChange={(event) => updateAgent({ promptVersion: event.target.value })} /></Field></div>
      </Section>

      <Section title="SSH 与目标 Helper" description="GUI 仅保存私钥路径；目标 Host Key 始终严格校验。">
        <div className="form-grid"><Field label="SSH 私钥路径" wide><div className="input-action"><Input value={config.executor.privateKeyPath} onChange={(event) => updateExecutor({ privateKeyPath: event.target.value })} /><Button variant="ghost" onClick={async () => { const path = await window.huntwarden.selectPrivateKey(); if (path) updateExecutor({ privateKeyPath: path }); }}>选择</Button></div></Field><Field label="known_hosts 路径" wide><div className="input-action"><Input value={config.executor.knownHostsPath} onChange={(event) => updateExecutor({ knownHostsPath: event.target.value })} /><Button variant="ghost" onClick={async () => { const path = await window.huntwarden.selectKnownHosts(); if (path) updateExecutor({ knownHostsPath: path }); }}>选择</Button></div></Field><Field label="Helper 路径"><Input value={config.executor.helperPath} onChange={(event) => updateExecutor({ helperPath: event.target.value })} /></Field><Field label="超时（秒）"><Input type="number" min={1} max={600} value={config.executor.timeoutSeconds} onChange={(event) => updateExecutor({ timeoutSeconds: Number(event.target.value) })} /></Field></div>
      </Section>

      <Section title="检测与数据边界" description="原始 Evidence、二进制和 Class Dump 不上传模型。">
        <div className="form-grid"><Field label="文本上云上限（字节）"><Input type="number" min={1024} max={262144} value={config.llmData.maxTextBytes} onChange={(event) => setConfig({ ...config, llmData: { maxTextBytes: Number(event.target.value) } })} /></Field><Field label="WebShell 时间窗（小时）"><Input type="number" value={config.webshell.modifiedWithinHours} onChange={(event) => setConfig({ ...config, webshell: { ...config.webshell, modifiedWithinHours: Number(event.target.value) } })} /></Field><Field label="候选文件上限"><Input type="number" value={config.webshell.maxCandidateFiles} onChange={(event) => setConfig({ ...config, webshell: { ...config.webshell, maxCandidateFiles: Number(event.target.value) } })} /></Field><Field label="单文件上限（字节）"><Input type="number" value={config.webshell.maxFileSizeBytes} onChange={(event) => setConfig({ ...config, webshell: { ...config.webshell, maxFileSizeBytes: Number(event.target.value) } })} /></Field><Field label="持久化单来源上限"><Input type="number" min={1} max={5000} value={config.persistence.maxItemsPerSource} onChange={(event) => setConfig({ ...config, persistence: { ...config.persistence, maxItemsPerSource: Number(event.target.value) } })} /></Field><Field label="进程连接上限"><Input type="number" min={1} max={5000} value={config.persistence.maxConnections} onChange={(event) => setConfig({ ...config, persistence: { ...config.persistence, maxConnections: Number(event.target.value) } })} /></Field><Field label="包含用户范围"><Select value={config.persistence.includeUserScope ? "yes" : "no"} onChange={(event) => setConfig({ ...config, persistence: { ...config.persistence, includeUserScope: event.target.value === "yes" } })}><option value="yes">是</option><option value="no">否</option></Select></Field><Field label="分诊进程上限"><Input type="number" min={1} max={10000} value={config.triage.maxProcesses} onChange={(event) => setConfig({ ...config, triage: { ...config.triage, maxProcesses: Number(event.target.value) } })} /></Field><Field label="分诊连接上限"><Input type="number" min={1} max={20000} value={config.triage.maxConnections} onChange={(event) => setConfig({ ...config, triage: { ...config.triage, maxConnections: Number(event.target.value) } })} /></Field><Field label="分诊文件上限"><Input type="number" min={1} max={50000} value={config.triage.maxFiles} onChange={(event) => setConfig({ ...config, triage: { ...config.triage, maxFiles: Number(event.target.value) } })} /></Field><Field label="时间线事件上限"><Input type="number" min={1} max={50000} value={config.triage.maxTimelineEvents} onChange={(event) => setConfig({ ...config, triage: { ...config.triage, maxTimelineEvents: Number(event.target.value) } })} /></Field><Field label="分诊单证据上限（字节）"><Input type="number" min={1024} max={104857600} value={config.triage.maxArtifactBytes} onChange={(event) => setConfig({ ...config, triage: { ...config.triage, maxArtifactBytes: Number(event.target.value) } })} /></Field><Field label="隔离目录"><Input value={config.remediation.quarantineRoot} onChange={(event) => setConfig({ ...config, remediation: { ...config.remediation, quarantineRoot: event.target.value } })} /></Field><Field label="处置审批"><Input value="始终逐动作审批（不可关闭）" disabled /></Field></div>
      </Section>

      <Section title="本地存储" description="数据库、Evidence 和报告仅保存在本机受限目录。">
        <div className="form-grid"><Field label="数据目录" wide><Input value={config.storage.baseDir} onChange={(event) => setConfig({ ...config, storage: { ...config.storage, baseDir: event.target.value } })} /></Field><Field label="数据库文件"><Input value={config.storage.databaseFile} onChange={(event) => setConfig({ ...config, storage: { ...config.storage, databaseFile: event.target.value } })} /></Field></div>
      </Section>

      <Section title="高级 YAML" description="只读预览；导入操作在左侧 Profile 菜单中完成。" action={<Button variant="ghost" onClick={() => setAdvancedOpen((value) => !value)}>{advancedOpen ? "收起" : "展开"}</Button>}>
        {advancedOpen ? <pre className="yaml-preview">{yamlPreview}</pre> : null}
        {validation ? <div className={`validation-box ${validation.valid ? "valid" : "invalid"}`}><strong>{validation.valid ? "配置校验通过" : "配置校验失败"}</strong>{validation.issues.map((item) => <div key={`${item.path}-${item.message}`}>{item.path}: {item.message}</div>)}{validation.warnings.map((item) => <div key={item}>警告：{item}</div>)}</div> : null}
      </Section>

      <div className="danger-zone"><div><strong>危险区域</strong><p>活动 Profile 不允许删除；运行任务期间不允许修改或切换活动 Profile。</p></div>{profile && !profile.active ? <Button variant="danger" onClick={remove} busy={busy === "delete"}>删除 Profile</Button> : null}</div>
    </div>
  </div>;
}

function CustomModelForm({ model, onChange }: { model: Extract<AppConfig["model"], { source: "custom" }>; onChange: (model: AppConfig["model"]) => void }) {
  return <div className="form-grid">
    <Field label="Provider ID"><Input value={model.provider} onChange={(event) => onChange({ ...model, provider: event.target.value })} /></Field>
    <Field label="模型 ID"><Input value={model.model} onChange={(event) => onChange({ ...model, model: event.target.value })} /></Field>
    <Field label="协议"><Select value={model.protocol} onChange={(event) => onChange({ ...model, protocol: event.target.value as typeof model.protocol })}><option value="openai-completions">OpenAI Chat Completions</option><option value="openai-responses">OpenAI Responses</option><option value="anthropic-messages">Anthropic Messages</option></Select></Field>
    <Field label="推理等级"><Select value={model.thinkingLevel} onChange={(event) => onChange({ ...model, thinkingLevel: event.target.value as typeof model.thinkingLevel })}>{["off", "minimal", "low", "medium", "high", "xhigh", "max"].map((item) => <option key={item}>{item}</option>)}</Select></Field>
    <Field label="Base URL" wide><Input value={model.baseUrl} onChange={(event) => onChange({ ...model, baseUrl: event.target.value })} /></Field>
    <Field label="认证"><Select value={model.authentication.type} onChange={(event) => onChange({ ...model, authentication: event.target.value === "none" ? { type: "none" as const } : { type: "api-key-env" as const, apiKeyEnv: "HUNTWARDEN_LLM_API_KEY" } })}><option value="api-key-env">API Key</option><option value="none">本机无认证</option></Select></Field>
    {model.authentication.type === "api-key-env" ? <Field label="环境变量名"><Input value={model.authentication.apiKeyEnv} onChange={(event) => onChange({ ...model, authentication: { type: "api-key-env" as const, apiKeyEnv: event.target.value } })} /></Field> : null}
    <Field label="上下文窗口"><Input type="number" value={model.contextWindow} onChange={(event) => onChange({ ...model, contextWindow: Number(event.target.value) })} /></Field>
    <Field label="最大输出"><Input type="number" value={model.maxTokens} onChange={(event) => onChange({ ...model, maxTokens: Number(event.target.value) })} /></Field>
    <label className="toggle-row"><input type="checkbox" checked={model.reasoning} onChange={(event) => onChange({ ...model, reasoning: event.target.checked })} /><span><strong>模型支持推理</strong><small>启用后发送协议对应的 reasoning 参数</small></span></label>
  </div>;
}
