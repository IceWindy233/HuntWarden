import { EventEmitter } from "node:events";
import { access } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { getSupportedThinkingLevels } from "@earendil-works/pi-ai";
import { checkModel, smokeModel } from "../agent/model-health.js";
import { createModelBundle, type ModelBundle } from "../agent/model.js";
import { getConfigIssues, loadConfig, normalizeConfig } from "../config/load-config.js";
import { ConfigProfileService } from "../config/profile-service.js";
import { isInvalidPackagedLabCredentialPath } from "../config/profile-path-repair.js";
import type { AppConfig } from "../config/schema.js";
import type { DesktopCredentialStore } from "../credentials/credential-store.js";
import { validateTargetConfig } from "../domain/validation.js";
import type { AgentStreamUpdate, ApprovalTicket, AuditEvent, Evidence, Finding, ReportRecord, TaskContext } from "../domain/types.js";
import { SSHExecutor } from "../executor/ssh-executor.js";
import type {
  ConfigProfile,
  ConfigProfileSummary,
  ConfigValidationResult,
  CredentialStatus,
  DesktopEvent,
  ModelCheckResult,
  ModelProviderSummary,
  ModelSummary,
  NewTaskInput,
  TaskSnapshot,
} from "../gui/contracts.js";
import { DESKTOP_API_VERSION } from "../gui/contracts.js";
import { Application } from "../runtime/application.js";
import { RuntimeStore } from "../storage/runtime-store.js";

export interface DesktopBackendOptions {
  userDataDir: string;
  projectRoot: string;
  appVersion: string;
  platform: string;
  credentials: DesktopCredentialStore;
  labStateDir?: string;
  modelBundleFactory?: (config: AppConfig) => ModelBundle;
  checkpoint?: (name: string) => void;
  legacyRuntimeDirs?: string[];
}

export class DesktopBackend extends EventEmitter {
  readonly profiles: ConfigProfileService;
  private application: Application | undefined;
  private activeProfile: ConfigProfile | undefined;
  private closePromise: Promise<void> | undefined;
  private readonly emitted = new Map<string, { findingIds: Set<string>; evidenceIds: Set<string>; auditIds: Set<string> }>();
  private readonly streamBuffers = new Map<string, { update: AgentStreamUpdate; delta: string; timer: ReturnType<typeof setTimeout> }>();

  constructor(private readonly options: DesktopBackendOptions) {
    super();
    this.profiles = new ConfigProfileService(join(options.userDataDir, "configuration"));
  }

  async initialize(): Promise<void> {
    await this.options.credentials.persistent.initialize();
    await this.profiles.initialize();
    if ((await this.profiles.list()).length === 0) await this.seedProfiles();
    await this.openActiveApplication();
  }

  async close(): Promise<void> {
    if (!this.closePromise) {
      const application = this.application;
      this.application = undefined;
      this.closePromise = (async () => {
        this.clearStreamBuffers();
        await application?.close();
        this.clearStreamBuffers();
      })();
    }
    await this.closePromise;
  }

  async getBootstrap() {
    const profiles = await this.profiles.list();
    return {
      apiVersion: DESKTOP_API_VERSION,
      appVersion: this.options.appVersion,
      platform: this.options.platform,
      ...(this.activeProfile ? { activeProfileId: this.activeProfile.profileId } : {}),
      profiles,
      tasks: this.application?.store.listTasks() ?? [],
    };
  }

  async listConfigProfiles(): Promise<ConfigProfileSummary[]> { return await this.profiles.list(); }
  async getConfigProfile(profileId: string): Promise<ConfigProfile> { return await this.profiles.get(profileId); }

  async validateConfigProfile(config: AppConfig): Promise<ConfigValidationResult> {
    const issues = getConfigIssues(config);
    if (issues.length > 0) return { valid: false, issues, warnings: [] };
    try {
      const normalized = normalizeConfig(config, join(this.profiles.profilesDir, "validation.yaml"));
      createModelBundle(normalized, this.options.credentials);
      const warnings: string[] = [];
      if (normalized.model.source === "custom") warnings.push("自定义端点的 Tool Call 兼容性必须通过在线冒烟测试确认");
      if (normalized.agent.maxTurns > 50 || normalized.agent.maxToolCalls > 200) warnings.push("当前 Agent 预算较高，请关注模型费用和调查时长");
      return { valid: true, issues: [], warnings };
    } catch (error) {
      return { valid: false, issues: [{ path: "/", message: error instanceof Error ? error.message : String(error) }], warnings: [] };
    }
  }

  async saveConfigProfile(input: { profileId?: string; name: string; config: AppConfig }): Promise<ConfigProfile> {
    const validation = await this.validateConfigProfile(input.config);
    if (!validation.valid) throw new Error(validation.issues.map((item) => `${item.path}: ${item.message}`).join("；"));
    if (input.profileId && input.profileId === this.activeProfile?.profileId && this.application?.store.hasActiveTask()) {
      throw new Error("活动任务运行期间不能修改当前 Profile");
    }
    const saved = await this.profiles.save(input);
    if (saved.profileId === this.activeProfile?.profileId) await this.reloadApplication();
    return saved;
  }

  async activateConfigProfile(profileId: string): Promise<void> {
    if (this.application?.store.hasActiveTask()) throw new Error("活动任务运行期间不能切换 Profile");
    await this.profiles.activate(profileId);
    await this.reloadApplication();
  }

  async deleteConfigProfile(profileId: string): Promise<void> { await this.profiles.delete(profileId); }
  async importConfigProfile(path: string): Promise<ConfigProfile> { return await this.profiles.import(path); }
  async exportConfigProfile(profileId: string, path: string): Promise<void> { await this.profiles.export(profileId, path); }

  listModelProviders(): ModelProviderSummary[] {
    const models = builtinModels();
    return models.getProviders().map((provider) => ({ id: provider.id, name: provider.name, modelCount: provider.getModels().length }));
  }

  listModels(providerId: string): ModelSummary[] {
    const models = builtinModels();
    if (!models.getProvider(providerId)) throw new Error(`未知 Provider: ${providerId}`);
    return models.getModels(providerId).map((model) => ({
      id: model.id,
      name: model.name,
      provider: model.provider,
      protocol: model.api,
      reasoning: model.reasoning,
      thinkingLevels: getSupportedThinkingLevels(model),
      contextWindow: model.contextWindow,
      maxTokens: model.maxTokens,
    }));
  }

  async getCredentialStatus(provider: string): Promise<CredentialStatus> {
    const status = await this.options.credentials.status(provider);
    return {
      provider,
      configured: status.configured || Boolean(process.env[this.defaultCredentialEnv(provider)]),
      persistent: status.persistent,
      ...(status.source ? { source: status.source } : process.env[this.defaultCredentialEnv(provider)] ? { source: this.defaultCredentialEnv(provider) } : {}),
      secureStorageBackend: status.backend,
      ...(status.persistentIssue ? { notice: status.persistentIssue } : {}),
    };
  }

  async saveCredential(input: { provider: string; secret: string; persist: boolean }): Promise<CredentialStatus> {
    const result = await this.options.credentials.saveApiKey(input.provider, input.secret, input.persist);
    const status = await this.getCredentialStatus(input.provider);
    return result.recoveredUnreadableEntry
      ? { ...status, notice: `检测到旧版不可解密凭据，已用新 Key 安全替换；旧密文备份于 ${result.backupPath}` }
      : status;
  }

  async deleteCredential(provider: string): Promise<void> { await this.options.credentials.delete(provider); }

  async checkModel(profileId: string): Promise<ModelCheckResult> {
    const profile = await this.profiles.get(profileId);
    const { models, model } = createModelBundle(profile.config, this.options.credentials);
    return await checkModel(models, model);
  }

  async smokeModel(profileId: string): Promise<ModelCheckResult> {
    const profile = await this.profiles.get(profileId);
    const { models, model } = createModelBundle(profile.config, this.options.credentials);
    return await smokeModel(profile.config, models, model);
  }

  async testSshTarget(target: NewTaskInput["target"]): Promise<{ ok: boolean; fingerprint?: string; message: string }> {
    validateTargetConfig(target);
    await this.assertTargetFilesReadable(target);
    const config = this.requireApplication().config;
    const executor = new SSHExecutor(target, config.executor.helperPath, config.executor.timeoutSeconds * 1000);
    try {
      const info = await executor.invoke({ operation: "get_host_info", params: {} });
      return { ok: true, fingerprint: target.hostFingerprint, message: `SSH 与 Helper 验证通过：${String(info.hostname ?? target.host)}` };
    } finally {
      await executor.close();
    }
  }

  listTasks(): TaskContext[] { return this.requireApplication().store.listTasks(); }

  getTaskSnapshot(taskId: string): TaskSnapshot {
    const application = this.requireApplication();
    const task = application.store.getTask(taskId);
    if (!task) throw new Error(`任务不存在: ${taskId}`);
    return {
      task,
      findings: application.store.listFindings(taskId),
      evidence: application.store.listEvidence(taskId),
      approvals: application.store.listApprovals(taskId),
      actionReceipts: application.store.listActionReceipts(taskId),
      reports: application.store.listReports(taskId),
      audit: application.store.listAudit(taskId, 500),
      conversation: application.store.loadMessages(taskId).map((message) => {
        if (message.role === "user") {
          const text = typeof message.content === "string" ? message.content : message.content.filter((item) => item.type === "text").map((item) => item.text).join("\n");
          return { role: "user" as const, text, timestamp: message.timestamp };
        }
        if (message.role === "toolResult") {
          return {
            role: "tool" as const,
            text: message.content.filter((item) => item.type === "text").map((item) => item.text).join("\n"),
            timestamp: message.timestamp,
            toolName: message.toolName,
            isError: message.isError,
          };
        }
        if (message.role === "assistant") {
          const text = message.content.flatMap((item) => item.type === "text"
            ? [item.text]
            : item.type === "toolCall" ? [`请求工具：${item.name}`] : []).join("\n");
          return { role: "assistant" as const, text, timestamp: message.timestamp };
        }
        if (message.role === "custom") {
          const text = typeof message.content === "string" ? message.content : message.content.filter((item) => item.type === "text").map((item) => item.text).join("\n");
          return { role: "assistant" as const, text: message.display ? text : "（内部状态消息已隐藏）", timestamp: message.timestamp };
        }
        if (message.role === "branchSummary" || message.role === "compactionSummary") {
          return { role: "assistant" as const, text: `上下文摘要：${message.summary}`, timestamp: message.timestamp };
        }
        return { role: "assistant" as const, text: "（非安全工具执行记录已省略）", timestamp: message.timestamp };
      }),
      toolRuns: application.store.listToolRuns(taskId).map((run) => ({
        toolCallId: run.toolCallId,
        toolName: run.toolName,
        risk: run.risk,
        status: run.status,
        startedAt: run.startedAt,
        ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
        ...(run.error ? { error: run.error } : {}),
      })),
    };
  }

  async createTask(input: NewTaskInput): Promise<TaskContext> {
    await this.assertTargetFilesReadable(input.target);
    return this.requireApplication().createTask(input);
  }

  async startTask(taskId: string): Promise<void> { await this.runAndNotify(taskId, () => this.requireApplication().startTask(taskId)); }
  async recoverTask(taskId: string): Promise<void> { await this.runAndNotify(taskId, () => this.requireApplication().recoverTask(taskId)); }
  async steerTask(taskId: string, text: string): Promise<void> { await this.requireApplication().steerTask(taskId, text); }
  abortTask(taskId: string): void { this.requireApplication().abortTask(taskId); }
  archiveTask(taskId: string): TaskContext { return this.requireApplication().archiveTask(taskId); }
  restoreTask(taskId: string): TaskContext { return this.requireApplication().restoreTask(taskId); }
  decideApproval(approvalId: string, approved: boolean): void { this.requireApplication().decideApproval(approvalId, approved); }
  async generateReport(taskId: string): Promise<ReportRecord> { return await this.runAndNotify(taskId, () => this.requireApplication().generateReport(taskId)); }

  getEvidence(evidenceId: string): Evidence {
    const application = this.requireApplication();
    for (const task of application.store.listTasks()) {
      const evidence = application.store.getEvidence(task.taskId, evidenceId);
      if (evidence) return evidence;
    }
    throw new Error(`Evidence 不存在: ${evidenceId}`);
  }

  async listReports(taskId: string): Promise<ReportRecord[]> {
    this.requireTaskExists(taskId);
    return await this.requireApplication().reports.list(taskId);
  }

  async readReport(taskId: string, reportId?: string): Promise<{ report: ReportRecord; markdown: string } | undefined> {
    this.requireTaskExists(taskId);
    return await this.requireApplication().reports.read(taskId, reportId);
  }

  isManagedPath(path: string): boolean {
    const root = resolve(this.requireApplication().config.storage.baseDir);
    const candidate = resolve(path);
    return candidate === root || candidate.startsWith(`${root}${sep}`);
  }

  private async seedProfiles(): Promise<void> {
    const runtimeDir = join(this.options.userDataDir, "runtime");
    const deepseek = await loadConfig(join(this.options.projectRoot, "config", "deepseek.yaml"));
    deepseek.storage.baseDir = runtimeDir;
    if (this.options.labStateDir) {
      deepseek.executor.knownHostsPath = join(this.options.labStateDir, "known_hosts");
      deepseek.executor.privateKeyPath = join(this.options.labStateDir, "id_ed25519");
    }
    await this.profiles.save({ profileId: "deepseek", name: "DeepSeek V4 Flash", config: deepseek });
    const openai = await loadConfig(join(this.options.projectRoot, "config", "default.yaml"));
    openai.storage.baseDir = runtimeDir;
    if (this.options.labStateDir) {
      openai.executor.knownHostsPath = join(this.options.labStateDir, "known_hosts");
      openai.executor.privateKeyPath = join(this.options.labStateDir, "id_ed25519");
    }
    await this.profiles.save({ profileId: "openai", name: "OpenAI GPT-5.6 Terra", config: openai });
    await this.profiles.activate("deepseek");
  }

  private async openActiveApplication(): Promise<void> {
    this.activeProfile = await this.profiles.getActive();
    if (!this.activeProfile) return;
    const store = await RuntimeStore.open(this.activeProfile.config.storage.baseDir, this.activeProfile.config.storage.databaseFile);
    if (this.options.legacyRuntimeDirs?.length) store.relocateEvidencePaths(this.options.legacyRuntimeDirs, this.activeProfile.config.storage.baseDir);
    store.reconcileInterruptedTasks();
    const { models, model } = this.options.modelBundleFactory?.(this.activeProfile.config)
      ?? createModelBundle(this.activeProfile.config, this.options.credentials);
    this.application = new Application(this.activeProfile.config, store, models, model, this.options.checkpoint);
    this.application.on("changed", (taskId: string) => this.publishTask(taskId));
    this.application.on("stream", (update: AgentStreamUpdate) => this.publishStream(update));
    this.application.on("approval_requested", (ticket: ApprovalTicket) => this.emitDesktop({ type: "approval_requested", ticket }));
  }

  private async reloadApplication(): Promise<void> {
    this.clearStreamBuffers();
    await this.application?.close();
    this.clearStreamBuffers();
    this.application = undefined;
    this.activeProfile = undefined;
    this.emitted.clear();
    await this.openActiveApplication();
  }

  private async assertTargetFilesReadable(target: NewTaskInput["target"]): Promise<void> {
    const entries = [
      { label: "SSH 私钥", path: target.privateKeyPath },
      { label: "known_hosts", path: target.knownHostsPath },
    ];
    for (const entry of entries) {
      if (isInvalidPackagedLabCredentialPath(entry.path)) {
        throw new Error(`${entry.label} 指向应用包内的 Lab 路径，打包应用不包含临时 SSH 凭据；请重新选择项目 labs/.lab-state 中的文件`);
      }
      try { await access(entry.path); }
      catch { throw new Error(`${entry.label}不可读取：${entry.path}；请重新选择有效文件并先执行“测试 SSH 与 Helper”`); }
    }
  }

  private publishTask(taskId: string): void {
    if (!this.application) return;
    const task = this.application.store.getTask(taskId);
    if (!task) return;
    this.emitDesktop({ type: "task_updated", task });
    const state = this.emitted.get(taskId) ?? { findingIds: new Set<string>(), evidenceIds: new Set<string>(), auditIds: new Set<string>() };
    for (const finding of this.application.store.listFindings(taskId)) if (!state.findingIds.has(finding.findingId)) {
      state.findingIds.add(finding.findingId); this.emitDesktop({ type: "finding_recorded", finding });
    }
    for (const evidence of this.application.store.listEvidence(taskId)) if (!state.evidenceIds.has(evidence.evidenceId)) {
      state.evidenceIds.add(evidence.evidenceId); this.emitDesktop({ type: "evidence_recorded", evidence });
    }
    for (const event of this.application.store.listAudit(taskId, 50)) if (!state.auditIds.has(event.eventId)) {
      state.auditIds.add(event.eventId); this.emitDesktop({ type: "audit_recorded", event });
    }
    this.emitted.set(taskId, state);
  }

  private emitDesktop(event: DesktopEvent): void { this.emit("event", event); }

  private publishStream(update: AgentStreamUpdate): void {
    if (update.phase !== "delta") {
      this.flushStream(update.streamId);
      this.emitDesktop({ type: "agent_stream", ...update });
      return;
    }
    const existing = this.streamBuffers.get(update.streamId);
    if (existing) {
      existing.delta += update.delta ?? "";
      return;
    }
    const timer = setTimeout(() => this.flushStream(update.streamId), 32);
    this.streamBuffers.set(update.streamId, { update, delta: update.delta ?? "", timer });
  }

  private flushStream(streamId: string): void {
    const buffered = this.streamBuffers.get(streamId);
    if (!buffered) return;
    clearTimeout(buffered.timer);
    this.streamBuffers.delete(streamId);
    if (buffered.delta) this.emitDesktop({ type: "agent_stream", ...buffered.update, delta: buffered.delta });
  }

  private clearStreamBuffers(): void {
    for (const buffered of this.streamBuffers.values()) clearTimeout(buffered.timer);
    this.streamBuffers.clear();
  }

  private async runAndNotify<T>(taskId: string, operation: () => Promise<T>): Promise<T> {
    try { return await operation(); }
    catch (error) {
      this.emitDesktop({ type: "runtime_error", taskId, message: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally { this.publishTask(taskId); }
  }

  private requireApplication(): Application {
    if (!this.application) throw new Error("尚未激活配置 Profile");
    return this.application;
  }

  private requireTaskExists(taskId: string): void {
    if (!this.requireApplication().store.getTask(taskId)) throw new Error(`任务不存在: ${taskId}`);
  }

  private defaultCredentialEnv(provider: string): string {
    return ({
      openai: "OPENAI_API_KEY", deepseek: "DEEPSEEK_API_KEY", anthropic: "ANTHROPIC_API_KEY",
      google: "GEMINI_API_KEY", openrouter: "OPENROUTER_API_KEY", "azure-openai-responses": "AZURE_OPENAI_API_KEY",
      "moonshotai-cn": "MOONSHOT_API_KEY", zai: "ZAI_API_KEY",
    } as Record<string, string>)[provider] ?? `${provider.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_API_KEY`;
  }
}
