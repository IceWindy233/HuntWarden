import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AuditEvent, Evidence, ReportRecord, TaskContext } from "../domain/types.js";
import { digestObject } from "../common/json.js";
import type { InvestigationAction, InvestigationActionAttempt, InvestigationSession } from "../investigation/types.js";
import type { Assessment, ScanEpoch } from "../protocol-v2/types.js";
import type { RuntimeStore, ToolRunRecord } from "../storage/runtime-store.js";

const remotePrimitives = new Set(["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"]);
const terminalClosed = new Set(["CLOSED_WITH_FINDINGS", "CLOSED_NO_OBSERVED_FINDING"]);
const requiredProposalTools = ["propose_hypothesis", "propose_actions"] as const;

export type ProviderQualificationStore = Pick<RuntimeStore,
  | "getTask"
  | "getScanEpoch"
  | "getInvestigationSession"
  | "getCompletionSnapshot"
  | "listInvestigationActions"
  | "listInvestigationActionAttempts"
  | "listDiscoveryCheckpoints"
  | "listAssessments"
  | "listEvidence"
  | "listToolRuns"
  | "listAudit"
  | "listReports"
>;

export interface ProviderFaultContractProof {
  sha256: string;
  value: unknown;
}

export interface ProviderQualificationInput {
  store: ProviderQualificationStore;
  linuxTaskId: string;
  javaTaskId: string;
  commit: string;
  manifestVersion: string;
  provider: string;
  model: string;
  protocol: string;
  endpoint: string;
  endpointResolution: { before: string[]; after: string[] };
  expectedHelperSha256: string;
  smoke: { toolCallVerified: boolean; usage?: { input: number; output: number } };
  faultContract: ProviderFaultContractProof;
  evaluatedAt?: string;
}

export interface ProviderTaskProof {
  taskId: string;
  epochId: string | null;
  taskStatus: string | null;
  epochStatus: string | null;
  investigationStatus: string | null;
  checks: string[];
  entryMode: string | null;
  iocCount: number;
  completeDiscoveryCheckpoints: number;
  providerHttpAttempts: number;
  successfulProviderHttpAttempts: number;
  modelProposalToolCalls: number;
  modelActions: number;
  successfulModelActionAttempts: number;
  modelAssessments: number;
  reports: number;
  duplicatePrimitiveExecutions: number;
  invalidToolCalls: number;
  controllerCommit: string | null;
  controllerTreeClean: boolean | null;
  controllerCommitAtFinish: string | null;
  controllerTreeCleanAtFinish: boolean | null;
  helperSha256: string | null;
  javaBytecodeEvidence?: number;
  javaEvidenceReferencedByModel?: number;
}

export interface ProviderQualificationResult {
  schemaVersion: 2;
  status: "PASS" | "FAIL";
  evaluationKind: "REAL_PROVIDER";
  evaluatedAt: string;
  commit: string;
  manifestVersion: string;
  networkEndpointClass: "REMOTE_VENDOR" | "NON_RELEASE_ENDPOINT";
  endpointResolution: { beforeCount: number; afterCount: number; allPublic: boolean; stable: boolean };
  helperSha256: string;
  provider: string;
  model: string;
  protocol: string;
  toolCallObserved: boolean;
  failureFallbackVerified: boolean;
  javaEvidenceReferenced: boolean;
  smoke: { usage: { input: number; output: number } };
  faultContract: {
    sha256: string;
    endpointClass: string | null;
    protocolsVerified: number;
    retryStatuses: number[];
    stallAborted: boolean;
    emptyResponseRejected: boolean;
  };
  tasks: { linuxZeroIoc: ProviderTaskProof; javaRuntime: ProviderTaskProof };
  failures: string[];
}

interface TaskState {
  task: TaskContext | undefined;
  epoch: ScanEpoch | undefined;
  session: InvestigationSession | undefined;
  actions: InvestigationAction[];
  attempts: InvestigationActionAttempt[];
  assessments: Assessment[];
  evidence: Evidence[];
  toolRuns: ToolRunRecord[];
  audit: AuditEvent[];
  reports: ReportRecord[];
}

function record(condition: unknown, failures: string[], message: string): condition is true {
  if (!condition) failures.push(message);
  return Boolean(condition);
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function countIocs(task: TaskContext | undefined): number {
  if (!task?.iocs) return 0;
  return Object.values(task.iocs).reduce((total, values) => total + (Array.isArray(values) ? values.length : 0), 0);
}

function providerAttempts(state: TaskState, provider: string, model: string, epochId: string | undefined): AuditEvent[] {
  return state.audit.filter((event) => event.event === "model_provider_http_attempt"
    && event.data.epochId === epochId && event.data.provider === provider && event.data.model === model);
}

function successfulAttempt(event: AuditEvent): boolean {
  return typeof event.data.status === "number" && event.data.status >= 200 && event.data.status < 300;
}

function duplicatePrimitiveExecutions(toolRuns: ToolRunRecord[]): number {
  const counts = new Map<string, number>();
  for (const run of toolRuns) {
    if (run.status !== "SUCCEEDED" || !remotePrimitives.has(run.toolName)) continue;
    const key = `${run.toolName}:${digestObject(run.args)}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.values()].reduce((total, count) => total + Math.max(0, count - 1), 0);
}

function isCurrentVerifiedReport(report: ReportRecord, epochId: string | undefined): boolean {
  if (!epochId || report.epochId !== epochId || report.validationErrors.length > 0 || !/^[a-f0-9]{64}$/.test(report.sha256)) return false;
  try {
    return createHash("sha256").update(readFileSync(report.path)).digest("hex") === report.sha256;
  } catch {
    return false;
  }
}

function loadTask(store: ProviderQualificationStore, taskId: string): TaskState {
  const task = store.getTask(taskId);
  const epoch = task?.activeEpochId ? store.getScanEpoch(taskId, task.activeEpochId) : undefined;
  const epochId = epoch?.epochId;
  return {
    task,
    epoch,
    session: epochId ? store.getInvestigationSession(taskId, epochId) : undefined,
    actions: epochId ? store.listInvestigationActions(taskId, epochId) : [],
    attempts: epochId ? store.listInvestigationActionAttempts(taskId, epochId) : [],
    assessments: epochId ? store.listAssessments(taskId, epochId) : [],
    evidence: store.listEvidence(taskId),
    toolRuns: store.listToolRuns(taskId, 100_000),
    audit: store.listAudit(taskId, 100_000),
    reports: store.listReports(taskId),
  };
}

function baseTaskProof(state: TaskState, provider: string, model: string, store: ProviderQualificationStore): ProviderTaskProof {
  const modelActions = state.actions.filter((action) => action.requestedBy === "MODEL");
  const modelActionIds = new Set(modelActions.map((action) => action.actionId));
  const attempts = state.attempts.filter((attempt) => modelActionIds.has(attempt.actionId));
  const epochId = state.epoch?.epochId;
  const currentToolRuns = state.toolRuns.filter((run) => run.epochId === epochId);
  const http = providerAttempts(state, provider, model, epochId);
  const checkpoints = epochId && state.task ? store.listDiscoveryCheckpoints(state.task.taskId, epochId) : [];
  const proposalCalls = currentToolRuns.filter((run) => run.status === "SUCCEEDED" && requiredProposalTools.includes(run.toolName as typeof requiredProposalTools[number]));
  return {
    taskId: state.task?.taskId ?? "",
    epochId: epochId ?? null,
    taskStatus: state.task?.status ?? null,
    epochStatus: state.epoch?.status ?? null,
    investigationStatus: state.session?.investigationStatus ?? null,
    checks: state.task?.checks ?? [],
    entryMode: state.task?.focus?.entryMode ?? null,
    iocCount: countIocs(state.task),
    completeDiscoveryCheckpoints: checkpoints.filter((item) => item.status === "COMPLETE").length,
    providerHttpAttempts: http.length,
    successfulProviderHttpAttempts: http.filter(successfulAttempt).length,
    modelProposalToolCalls: proposalCalls.length,
    modelActions: modelActions.length,
    successfulModelActionAttempts: attempts.filter((attempt) => attempt.status === "SUCCEEDED" || attempt.status === "PARTIAL").length,
    modelAssessments: state.assessments.filter((item) => item.authorType === "MODEL").length,
    reports: state.reports.filter((item) => isCurrentVerifiedReport(item, epochId)).length,
    duplicatePrimitiveExecutions: duplicatePrimitiveExecutions(currentToolRuns),
    invalidToolCalls: state.audit.filter((event) => event.event === "model_invalid_tool_call" && event.data.epochId === epochId).length,
    controllerCommit: state.epoch?.controllerCommit ?? null,
    controllerTreeClean: state.epoch?.controllerTreeClean ?? null,
    controllerCommitAtFinish: state.epoch?.controllerCommitAtFinish ?? null,
    controllerTreeCleanAtFinish: state.epoch?.controllerTreeCleanAtFinish ?? null,
    helperSha256: state.epoch?.helperSha256 ?? null,
  };
}

function validateCommonTask(
  label: string,
  state: TaskState,
  proof: ProviderTaskProof,
  input: ProviderQualificationInput,
  failures: string[],
  store: ProviderQualificationStore,
): void {
  record(Boolean(state.task), failures, `${label}任务不存在`);
  if (!state.task) return;
  record(state.task.protocolVersion === 2, failures, `${label}任务不是协议 v2`);
  record(state.task.modelProvider === input.provider && state.task.modelId === input.model, failures, `${label}任务模型身份与本次 Provider 冒烟不一致`);
  record(state.task.status === "COMPLETED", failures, `${label}任务未以 COMPLETED 结束`);
  record(Boolean(state.epoch), failures, `${label}任务缺少活动 Epoch`);
  if (state.epoch) {
    record(state.epoch.manifestVersion === input.manifestVersion, failures, `${label}Epoch Manifest 版本不一致`);
    record(state.epoch.controllerCommit === input.commit, failures, `${label}Epoch 未绑定本次控制端提交`);
    record(state.epoch.controllerTreeClean === true, failures, `${label}Epoch 不是从干净控制端工作树创建`);
    record(state.epoch.controllerCommitAtFinish === input.commit && state.epoch.controllerTreeCleanAtFinish === true, failures, `${label}Epoch 结束时控制端提交或工作树不一致`);
    record(state.epoch.helperSha256 === input.expectedHelperSha256, failures, `${label}Epoch Helper 摘要与当前源码不一致`);
    record(state.epoch.status === "COMPLETED", failures, `${label}Epoch 未完整结束`);
  }
  record(Boolean(state.session), failures, `${label}任务缺少调查会话`);
  if (state.session) {
    record(state.session.executionStatus === "STOPPED", failures, `${label}调查执行尚未停止`);
    record(terminalClosed.has(state.session.investigationStatus), failures, `${label}调查未以完整闭合状态结束`);
    const snapshot = state.epoch && state.session.completionSnapshotRef
      ? store.getCompletionSnapshot(state.task.taskId, state.epoch.epochId, state.session.completionSnapshotRef)
      : undefined;
    record(Boolean(snapshot), failures, `${label}任务缺少持久化完成快照`);
  }
  record(proof.completeDiscoveryCheckpoints > 0, failures, `${label}任务没有完整发现检查点`);
  record(proof.successfulProviderHttpAttempts > 0, failures, `${label}任务没有匹配 Provider/模型的成功 HTTP 尝试审计`);
  for (const toolName of requiredProposalTools) {
    record(state.toolRuns.some((run) => run.epochId === state.epoch?.epochId && run.status === "SUCCEEDED" && run.toolName === toolName), failures, `${label}任务当前 Epoch 未实际调用 ${toolName}`);
  }
  record(proof.modelActions > 0 && proof.successfulModelActionAttempts > 0, failures, `${label}任务没有成功的 MODEL Action/Attempt`);
  record(state.actions.filter((action) => action.requestedBy === "MODEL").every((action) => remotePrimitives.has(action.operationRef) || action.operationRef === "query_facts"), failures, `${label}任务存在白名单外 MODEL Action`);
  record(new Set(state.actions.filter((action) => action.requestedBy === "MODEL").map((action) => action.idempotencyKey)).size === proof.modelActions, failures, `${label}任务存在重复 MODEL Action 幂等键`);
  record(proof.duplicatePrimitiveExecutions === 0, failures, `${label}任务存在相同原语参数的重复成功执行`);
  record(proof.invalidToolCalls === 0, failures, `${label}任务存在未恢复的非法模型工具调用`);
  record(proof.reports > 0, failures, `${label}任务没有绑定当前 Epoch、校验通过且文件摘要一致的冻结报告`);
}

function validateFaultContract(input: ProviderQualificationInput, failures: string[]): ProviderQualificationResult["faultContract"] {
  const root = object(input.faultContract.value);
  const protocols = array(root?.protocols).map(object).filter((item): item is Record<string, unknown> => Boolean(item));
  const faults = object(root?.faults);
  const retry = object(faults?.retry);
  const retryAttempts = array(retry?.attempts).map(object).filter((item): item is Record<string, unknown> => Boolean(item));
  const retryStatuses = retryAttempts.map((item) => item.status).filter((status): status is number => typeof status === "number");
  const stall = object(faults?.stall);
  const empty = object(faults?.empty);
  record(root?.status === "PASS" && root.evaluationKind === "PROTOCOL_FIXTURE", failures, "Provider 故障契约不是 PASS/PROTOCOL_FIXTURE");
  record(root?.commit === input.commit && root.manifestVersion === input.manifestVersion, failures, "Provider 故障契约未绑定当前提交和 Manifest");
  record(root?.endpointClass === "LOOPBACK", failures, "Provider 故障契约必须来自隔离回环端点");
  record(protocols.length === 2 && new Set(protocols.map((item) => item.protocol)).size === 2
    && protocols.every((item) => item.toolCallVerified === true && Number(object(item.usage)?.input) > 0 && Number(object(item.usage)?.output) > 0), failures, "Provider 故障契约没有完整验证两种协议、Tool Call 和 usage");
  record(retryStatuses.length === 2 && retryStatuses[0] === 429 && retryStatuses[1] === 200, failures, "Provider 故障契约缺少 429→200 有界重试轨迹");
  record(stall?.stopReason === "aborted" && stall.runtimeClassification === "PROVIDER_FAILURE" && stall.httpStatus === 200, failures, "Provider 故障契约缺少流中停滞中止及失败归类");
  record(empty?.rejected === true, failures, "Provider 故障契约没有拒绝空响应");
  return {
    sha256: input.faultContract.sha256,
    endpointClass: typeof root?.endpointClass === "string" ? root.endpointClass : null,
    protocolsVerified: protocols.filter((item) => item.toolCallVerified === true).length,
    retryStatuses,
    stallAborted: stall?.stopReason === "aborted",
    emptyResponseRejected: empty?.rejected === true,
  };
}

function parseIpv4(address: string): number[] | undefined {
  const parts = address.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part))) return undefined;
  const bytes = parts.map(Number);
  return bytes.every((part) => part >= 0 && part <= 255) ? bytes : undefined;
}

function parseIpv6(address: string): number[] | undefined {
  let value = address.toLowerCase();
  if (value.includes("%") || !/^[0-9a-f:.]+$/.test(value)) return undefined;
  const ipv4Tail = value.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4Tail) {
    const bytes = parseIpv4(ipv4Tail);
    if (!bytes) return undefined;
    value = `${value.slice(0, -ipv4Tail.length)}${((bytes[0]! << 8) | bytes[1]!).toString(16)}:${((bytes[2]! << 8) | bytes[3]!).toString(16)}`;
  }
  if ((value.match(/::/g) ?? []).length > 1) return undefined;
  const [leftRaw, rightRaw] = value.split("::");
  const left = leftRaw ? leftRaw.split(":") : [];
  const right = rightRaw ? rightRaw.split(":") : [];
  if ([...left, ...right].some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return undefined;
  if (!value.includes("::") && left.length !== 8) return undefined;
  const omitted = 8 - left.length - right.length;
  if (omitted < (value.includes("::") ? 1 : 0)) return undefined;
  return [...left, ...Array.from({ length: omitted }, () => "0"), ...right].map((part) => Number.parseInt(part, 16));
}

/** 资格验收只接受全局可路由的单播地址。 */
export function isPublicProviderAddress(address: string): boolean {
  const ipv4 = parseIpv4(address);
  if (ipv4) {
    const [a, b, c] = ipv4;
    return !(a === 0 || a === 10 || a === 127 || a! >= 224
      || (a === 100 && b! >= 64 && b! <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b! >= 16 && b! <= 31)
      || (a === 192 && b === 0 && c === 0)
      || (a === 192 && b === 0 && c === 2)
      || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113));
  }
  const ipv6 = parseIpv6(address.replace(/^\[|\]$/g, ""));
  if (!ipv6) return false;
  const [first, second] = ipv6;
  const mapped = ipv6.slice(0, 5).every((part) => part === 0) && ipv6[5] === 0xffff;
  if (mapped) return isPublicProviderAddress(`${ipv6[6]! >> 8}.${ipv6[6]! & 255}.${ipv6[7]! >> 8}.${ipv6[7]! & 255}`);
  if (first! < 0x2000 || first! > 0x3fff) return false;
  if (first === 0x2001 && second === 0x0db8) return false;
  return true;
}

/** 只按端点类别输出结果，不把 URL、网关路径、地址或凭据信息写进资格证据。 */
export function classifyProviderEndpoint(endpoint: string, resolvedAddresses?: readonly string[]): "REMOTE_VENDOR" | "NON_RELEASE_ENDPOINT" {
  let url: URL;
  try { url = new URL(endpoint); } catch { return "NON_RELEASE_ENDPOINT"; }
  if (url.protocol !== "https:") return "NON_RELEASE_ENDPOINT";
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".home.arpa")) return "NON_RELEASE_ENDPOINT";
  const literal = parseIpv4(host) || parseIpv6(host);
  if (literal && !isPublicProviderAddress(host)) return "NON_RELEASE_ENDPOINT";
  if (!literal && (!host.includes(".") || !/^[a-z0-9.-]+$/.test(host))) return "NON_RELEASE_ENDPOINT";
  if (resolvedAddresses !== undefined && (resolvedAddresses.length === 0 || !resolvedAddresses.every(isPublicProviderAddress))) return "NON_RELEASE_ENDPOINT";
  return "REMOTE_VENDOR";
}

export function evaluateProviderQualification(input: ProviderQualificationInput): ProviderQualificationResult {
  const failures: string[] = [];
  record(/^[a-f0-9]{40}$/.test(input.commit), failures, "提交必须是完整 40 位 Git SHA-1");
  record(/^[a-f0-9]{64}$/.test(input.expectedHelperSha256), failures, "当前 Helper 源码 SHA-256 无效");
  record(/^[a-f0-9]{64}$/.test(input.faultContract.sha256), failures, "Provider 故障契约 SHA-256 无效");
  record(input.smoke.toolCallVerified === true && (input.smoke.usage?.input ?? 0) > 0 && (input.smoke.usage?.output ?? 0) > 0, failures, "真实 Provider 冒烟没有验证 Tool Call 和非零 usage");
  const before = [...new Set(input.endpointResolution.before.map((item) => item.toLowerCase()))].sort();
  const after = [...new Set(input.endpointResolution.after.map((item) => item.toLowerCase()))].sort();
  const allPublic = before.length > 0 && after.length > 0 && [...before, ...after].every(isPublicProviderAddress);
  const stable = before.length === after.length && before.every((item, index) => item === after[index]);
  const endpointClass = classifyProviderEndpoint(input.endpoint, [...before, ...after]);
  record(endpointClass === "REMOTE_VENDOR", failures, "真实 Provider 必须使用 HTTPS 远端厂商端点");
  record(allPublic, failures, "真实 Provider DNS 前后解析结果必须全部是公网地址");
  record(stable, failures, "真实 Provider DNS 在冒烟前后发生变化，不能形成稳定端点证明");
  const contract = validateFaultContract(input, failures);

  const linux = loadTask(input.store, input.linuxTaskId);
  const java = loadTask(input.store, input.javaTaskId);
  record(input.linuxTaskId !== input.javaTaskId, failures, "Linux 与 Java 验收必须引用两个独立任务");
  const linuxProof = baseTaskProof(linux, input.provider, input.model, input.store);
  const javaProof = baseTaskProof(java, input.provider, input.model, input.store);
  validateCommonTask("Linux 零 IOC", linux, linuxProof, input, failures, input.store);
  validateCommonTask("Java 运行态", java, javaProof, input, failures, input.store);

  if (linux.task) {
    record(linux.task.focus?.entryMode === "ZERO_IOC" && countIocs(linux.task) === 0, failures, "Linux 任务不是首次零 IOC 入口");
    record(linux.task.checks.includes("linux_intrusion_triage") && linux.task.checks.includes("linux_persistence"), failures, "Linux 任务没有覆盖入侵分诊与持久化链");
    for (const category of ["linux_intrusion_triage", "linux_persistence"] as const) {
      record(linux.assessments.some((item) => item.authorType === "MODEL" && item.category === category), failures, `Linux 任务缺少 ${category} 模型 Assessment`);
    }
  }

  const epochId = java.epoch?.epochId;
  const javaEvidence = java.evidence.filter((item) => {
    const metadata = item.metadata;
    if (!metadata) return false;
    return item.type === "jvm_class_bytecode" && metadata.epochId === epochId
      && metadata.complete === true && metadata.integrityStatus === "VERIFIED" && /^[a-f0-9]{64}$/.test(item.sha256 ?? "");
  });
  const javaEvidenceIds = new Set(javaEvidence.map((item) => item.evidenceId));
  const referencedEvidence = new Set(java.assessments.filter((item) => item.authorType === "MODEL" && item.category === "java_memory_shell")
    .flatMap((item) => item.evidenceRefs).filter((ref) => javaEvidenceIds.has(ref)));
  javaProof.javaBytecodeEvidence = javaEvidence.length;
  javaProof.javaEvidenceReferencedByModel = referencedEvidence.size;
  if (java.task) record(java.task.checks.includes("java_memory_shell"), failures, "Java 任务没有启用 java_memory_shell 检查");
  record(javaEvidence.length > 0, failures, "Java 任务缺少当前 Epoch 完整且校验通过的类字节码 Evidence");
  record(referencedEvidence.size > 0, failures, "Java 模型 Assessment 没有引用实际类字节码 Evidence");

  const toolCallObserved = input.smoke.toolCallVerified && linuxProof.modelProposalToolCalls >= 2 && javaProof.modelProposalToolCalls >= 2;
  const failureFallbackVerified = contract.protocolsVerified === 2 && contract.retryStatuses.join(",") === "429,200"
    && contract.stallAborted && contract.emptyResponseRejected;
  const javaEvidenceReferenced = referencedEvidence.size > 0;
  return {
    schemaVersion: 2,
    status: failures.length === 0 ? "PASS" : "FAIL",
    evaluationKind: "REAL_PROVIDER",
    evaluatedAt: input.evaluatedAt ?? new Date().toISOString(),
    commit: input.commit,
    manifestVersion: input.manifestVersion,
    networkEndpointClass: endpointClass,
    endpointResolution: { beforeCount: before.length, afterCount: after.length, allPublic, stable },
    helperSha256: input.expectedHelperSha256,
    provider: input.provider,
    model: input.model,
    protocol: input.protocol,
    toolCallObserved,
    failureFallbackVerified,
    javaEvidenceReferenced,
    smoke: { usage: { input: input.smoke.usage?.input ?? 0, output: input.smoke.usage?.output ?? 0 } },
    faultContract: contract,
    tasks: { linuxZeroIoc: linuxProof, javaRuntime: javaProof },
    failures,
  };
}

export function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
