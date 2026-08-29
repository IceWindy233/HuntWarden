import { randomUUID } from "node:crypto";
import type { AgentToolResult } from "@earendil-works/pi-agent-core";
import { Type, type Static, type TSchema } from "typebox";
import { InvalidArgumentError, SecurityError, type SecurityErrorCode } from "../../common/errors.js";
import { digestObject } from "../../common/json.js";
import type { ActionReceipt, CheckCategory, SecurityToolDefinition } from "../../domain/types.js";
import type { ForensicVerb } from "../../executor/protocol-v2-executor.js";
import { categoryGrantAllowsNamespace } from "../../protocol-v2/capability.js";
import { PROTOCOL_MANIFEST, assertManifestField, identityFields, requireNamespace } from "../../protocol-v2/manifest.js";
import { validatePredicate } from "../../protocol-v2/predicate.js";
import type {
  Assessment,
  AssessmentVerdict,
  FactSource,
  NamespaceName,
  Predicate,
  WireCost,
  WireFailure,
  WireRequest,
  WireSuccess,
} from "../../protocol-v2/types.js";
import { assertCostWithinReservation } from "../../protocol-v2/wire.js";
import { defaultFactQuerySelect, FACT_QUERY_SELECT_FIELDS, validateFactQuery, type FactQueryAst, type FactQueryPage } from "../../facts/query.js";
import type { V2ToolDependencies } from "./dependencies.js";
import { isPublicThreatIntelIp } from "../../threat-intel/network-ioc.js";
import { DBAPP_THREAT_INTEL_SOURCE, type ThreatIntelVerdict } from "../../threat-intel/types.js";
import { BUILTIN_YARA_RULESETS } from "../../rulesets/registry.js";

interface RemoteResultDetails {
  status: "success" | "partial";
  runId: string;
  factRefs: string[];
  objectRefs: string[];
  edgeRefs: string[];
  evidenceRefs: string[];
  gaps: WireSuccess["gaps"];
  cursorRef?: string;
  cost: WireCost;
}

const PredicateSchema = Type.Any();
const RefSchema = Type.String({ pattern: "^OBJ-[0-9a-f-]{36}$" });
const CursorSchema = Type.String({ pattern: "^CURSOR-[0-9a-f-]{36}$" });
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const verdicts = ["CONFIRMED_MALICIOUS", "HIGHLY_SUSPICIOUS", "SUSPICIOUS", "BENIGN", "NO_OBSERVED_FINDING", "INCONCLUSIVE"] as const;
// Upper bound on the hit context one `match` object can return: the Helper emits a capped hit
// marker plus MATCH_CONTEXT_HITS windows, each an escaped MATCH_CONTEXT_BYTES window (escaping
// can double the length) with a byte-offset label. Context is a content egress path, so it is
// charged against MODEL_CONTENT_BYTES exactly like `read`.
const MATCH_CONTEXT_MAX_BYTES = 2560;

export function createV2SecurityTools(deps: V2ToolDependencies, phase: "INVESTIGATE" | "REPORT" = "INVESTIGATE"): SecurityToolDefinition[] {
  if (deps.task.protocolVersion !== 2 || deps.task.activeEpochId !== deps.epoch.epochId) throw new SecurityError("RECOVERY_UNCERTAIN", "v2 工具必须绑定任务当前 epoch");
  const local = [createQueryFactsTool(deps), createAssessmentProjectionTool(deps)];
  if (phase === "REPORT") return local;
  const availableNamespaces = Object.keys(deps.capabilities.namespaces) as NamespaceName[];
  if (availableNamespaces.length === 0) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "当前任务没有有效 v2 namespace 能力");
  const namespaceSchema = Type.Union(availableNamespaces.map((value) => Type.Literal(value)));
  const tools: SecurityToolDefinition[] = [
    ...local,
    localTool(deps, "describe_capabilities", "描述有效能力", Type.Object({}, { additionalProperties: false }), async () => ({
      protocolVersion: 2, manifestVersion: PROTOCOL_MANIFEST.version,
      namespaces: Object.fromEntries(Object.entries(deps.capabilities.namespaces).map(([name, value]) => [name, { fields: [...value!.fields], relations: [...value!.relations], verbs: [...value!.verbs] }])),
      matchers: [...deps.capabilities.matchers], probes: [...deps.capabilities.probes], verbs: [...deps.capabilities.verbs], limits: deps.capabilities.limits,
      knownHashDataSets: deps.store.listKnownHashDataSets(),
      protocolAnomalies: deps.capabilities.protocolAnomalies,
    })),
    remoteTool(deps, "enumerate", "枚举取证对象", Type.Object({
      namespace: namespaceSchema, scopeRef: Type.Optional(Type.String({ pattern: "^GRANT-[0-9a-f-]{36}$" })),
      predicate: Type.Optional(PredicateSchema), fields: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 64 }), { maxItems: 32 })),
      sort: Type.Optional(Type.Array(Type.Object({ field: Type.String(), direction: Type.Union([Type.Literal("asc"), Type.Literal("desc")]) }), { maxItems: 3 })),
      limit: Type.Integer({ minimum: 1, maximum: 500 }), cursorRef: Type.Optional(CursorSchema), sinceHours: Type.Optional(Type.Integer({ minimum: 1, maximum: 8760 })),
    }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      const namespace = params.namespace as NamespaceName;
      if (namespace === "task_ioc") throw new InvalidArgumentError("task_ioc 只能通过 query_facts 查询");
      assertEffectiveVerb(deps, namespace, "enumerate");
      const fields = params.fields ?? identityFields(namespace);
      for (const field of fields) {
        assertManifestField(namespace, field, "enumerable");
        assertEffectiveField(deps, namespace, field);
      }
      validatePredicate(namespace, params.predicate as Predicate | undefined);
      for (const sort of params.sort ?? []) assertManifestField(namespace, sort.field, "sortable");
      const canonical = { namespace, scopeRef: params.scopeRef, predicate: params.predicate, fields, sort: params.sort, limit: params.limit, sinceHours: params.sinceHours };
      const requestDigest = digestObject(canonical);
      let helperCursor: string | undefined;
      if (params.cursorRef) {
        const cursor = deps.store.getRemoteCursor(deps.task.taskId, deps.epoch.epochId, params.cursorRef);
        if (!cursor || cursor.namespace !== namespace || cursor.requestDigest !== requestDigest) throw new InvalidArgumentError("Cursor 与当前 enumerate 请求不匹配");
        helperCursor = cursor.helperCursor;
      }
      const scope = params.scopeRef ? resolveGrant(deps, params.scopeRef, "SCOPE").binding : undefined;
      return { namespace, ...(scope ? { scope } : {}), predicate: params.predicate, fields, sort: params.sort, limit: params.limit, ...(helperCursor ? { cursor: helperCursor } : {}), ...(params.sinceHours ? { sinceHours: params.sinceHours } : {}), _cursorBinding: { requestDigest } };
    }),
    remoteTool(deps, "project", "投影对象字段", Type.Object({ ref: RefSchema, fields: Type.Array(Type.String({ minLength: 1, maxLength: 64 }), { minItems: 1, maxItems: 32 }) }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      const binding = resolveObject(deps, params.ref);
      assertEffectiveVerb(deps, binding.namespace, "project");
      for (const field of params.fields) {
        assertManifestField(binding.namespace, field, "projectable");
        assertEffectiveField(deps, binding.namespace, field);
      }
      return { ...binding, fields: params.fields };
    }),
    remoteTool(deps, "read", "受限读取文本", Type.Object({ ref: RefSchema, offset: Type.Integer({ minimum: 0 }), length: Type.Integer({ minimum: 1, maximum: 65_536 }), encoding: Type.Union([Type.Literal("utf-8"), Type.Literal("ascii")]), purpose: Type.Union([Type.Literal("SYSTEM_TEXT"), Type.Literal("CONFIG_REVIEW"), Type.Literal("LOG_REVIEW"), Type.Literal("SCRIPT_REVIEW")]) }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      const binding = resolveObject(deps, params.ref, "file");
      assertEffectiveVerb(deps, binding.namespace, "read");
      const latest = latestPrivateFact(deps, params.ref);
      const contentClass = effectiveContentClass(latest.path, latest.contentClass);
      if (contentClass === "DENIED_TEXT") throw new SecurityError("PERMISSION_DENIED", "DENIED_TEXT 永不进入模型");
      if (contentClass !== "SAFE_TEXT") requireSensitiveGrant(deps, params.ref);
      consumeUsageOrGap(deps, "MODEL_CONTENT_BYTES", params.length);
      return { ...binding, offset: params.offset, length: params.length, encoding: params.encoding, purpose: params.purpose };
    }),
    remoteTool(deps, "match", "匹配对象内容", Type.Object({ refs: Type.Array(RefSchema, { minItems: 1, maxItems: 128 }), matcher: Type.Union([
      Type.Object({ engine: Type.Union([Type.Literal("literal"), Type.Literal("re2")]), pattern: Type.String({ minLength: 1, maxLength: 4096 }) }, { additionalProperties: false }),
      Type.Object({ engine: Type.Literal("yara"), ruleSetRef: Type.Union(Object.keys(BUILTIN_YARA_RULESETS).map((value) => Type.Literal(value))) }, { additionalProperties: false }),
    ]), maxHits: Type.Integer({ minimum: 1, maximum: 500 }), includeContext: Type.Boolean() }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      if (!deps.capabilities.matchers.has(params.matcher.engine)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", `目标不支持 matcher ${params.matcher.engine}`);
      const objects = params.refs.map((ref) => {
        const binding = resolveObject(deps, ref, "file");
        assertEffectiveVerb(deps, binding.namespace, "match");
        // 命中上下文是一次内容出境，必须走与 read 完全相同的分级与授权链路；只要有一个对象
        // 不满足就整体失败，避免模型拿到「部分对象有上下文」而无法判断缺的是哪些。
        if (params.includeContext) {
          const latest = latestPrivateFact(deps, ref);
          const contentClass = effectiveContentClass(latest.path, latest.contentClass);
          if (contentClass === "DENIED_TEXT") throw new SecurityError("PERMISSION_DENIED", "DENIED_TEXT 不返回命中上下文；请以 includeContext=false 匹配后再用 read 取受控文本");
          if (contentClass !== "SAFE_TEXT") requireSensitiveGrant(deps, ref);
        }
        return binding;
      });
      if (params.includeContext) consumeUsageOrGap(deps, "MODEL_CONTENT_BYTES", params.refs.length * MATCH_CONTEXT_MAX_BYTES);
      return { objects, matcher: params.matcher, maxHits: params.maxHits, includeContext: params.includeContext };
    }),
    remoteTool(deps, "relate", "观察对象关系", Type.Object({ ref: RefSchema, relation: Type.String({ minLength: 1, maxLength: 64 }), parameters: Type.Optional(Type.Record(Type.String(), Type.Unknown())), limit: Type.Integer({ minimum: 1, maximum: 500 }), cursorRef: Type.Optional(CursorSchema) }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      const binding = resolveObject(deps, params.ref);
      assertEffectiveVerb(deps, binding.namespace, "relate");
      if (!requireNamespace(binding.namespace).relations.includes(params.relation)) throw new InvalidArgumentError("Relation 未在 Manifest 注册");
      if (!deps.capabilities.namespaces[binding.namespace]?.relations.has(params.relation)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "目标未声明该 Relation 能力");
      const requestDigest = digestObject({ ref: params.ref, relation: params.relation, parameters: params.parameters, limit: params.limit });
      let helperCursor: string | undefined;
      if (params.cursorRef) {
        const cursor = deps.store.getRemoteCursor(deps.task.taskId, deps.epoch.epochId, params.cursorRef);
        if (!cursor || cursor.namespace !== binding.namespace || cursor.requestDigest !== requestDigest) throw new InvalidArgumentError("Cursor 与当前 relate 请求不匹配");
        helperCursor = cursor.helperCursor;
      }
      return { ...binding, relation: params.relation, parameters: params.parameters, limit: params.limit, ...(helperCursor ? { cursor: helperCursor } : {}), _cursorBinding: { requestDigest } };
    }),
    remoteTool(deps, "verify", "对照权威基线", Type.Object({ ref: RefSchema, baseline: Type.Union([Type.Literal("package_db"), Type.Literal("known_hash_set")]), dataSetRef: Type.Optional(Type.String({ pattern: "^DATASET-[0-9a-f-]{36}$" })) }, { additionalProperties: false }), "READ", "SAFE_REOBSERVE", (params) => {
      const binding = resolveObject(deps, params.ref, "file");
      assertEffectiveVerb(deps, binding.namespace, "verify");
      if (params.baseline === "package_db") {
        if (params.dataSetRef) throw new InvalidArgumentError("package_db verify 不接受 dataSetRef");
        return { ...binding, baseline: params.baseline };
      }
      if (!params.dataSetRef) throw new InvalidArgumentError("known_hash_set verify 必须提供控制端 dataSetRef");
      if (!deps.store.getKnownHashDataSet(params.dataSetRef)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "known_hash_set 数据集不存在或尚未导入");
      return { ...binding, baseline: params.baseline, dataSetRef: params.dataSetRef };
    }, (response, params) => {
      if (params.baseline !== "known_hash_set" || !params.dataSetRef) return response;
      const dataSet = deps.store.getKnownHashDataSet(params.dataSetRef);
      if (!dataSet) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "known_hash_set 数据集在验证期间不可用");
      const hashes = new Set(dataSet.sha256);
      return {
        ...response,
        objects: response.objects.map((object) => {
          const sha256 = object.fields.sha256;
          if (object.namespace !== "file" || typeof sha256 !== "string" || !/^[a-f0-9]{64}$/.test(sha256)) {
            throw new SecurityError("RECOVERY_UNCERTAIN", "Helper 未返回可用于 known_hash_set 裁定的文件 SHA-256");
          }
          return { ...object, fields: { ...object.fields, baseline: `known_hash_set:${dataSet.dataSetRef}@${dataSet.version}`, baselineStatus: hashes.has(sha256) ? "MATCH" : "MISMATCH" } };
        }),
      };
    }),
    remoteTool(deps, "collect", "固化完整证据", Type.Object({ ref: RefSchema, maxBytes: Type.Integer({ minimum: 1, maximum: 104_857_600 }), purpose: Type.String({ minLength: 1, maxLength: 128 }) }, { additionalProperties: false }), "COLLECT", "RESUME_OR_RECOLLECT", (params) => {
      const binding = resolveObject(deps, params.ref);
      if (binding.namespace !== "file" && binding.namespace !== "process") throw new SecurityError("UNSUPPORTED_ENVIRONMENT", "collect 只支持 file 或稳定 process executable 对象");
      assertEffectiveVerb(deps, binding.namespace, "collect");
      consumeUsageOrGap(deps, "EVIDENCE_BYTES", params.maxBytes);
      return { ...binding, maxBytes: params.maxBytes, purpose: params.purpose };
    }),
    remoteTool(deps, "probe", "执行受限诊断探针", Type.Object({ ref: RefSchema, probeKind: Type.Union([Type.Literal("jvm.tomcat.inventory"), Type.Literal("jvm.class.inspect")]), parameters: Type.Record(Type.String(), Type.Unknown()) }, { additionalProperties: false }), "INTRUSIVE_READ", "SAFE_REOBSERVE", (params) => {
      if (!deps.capabilities.probes.has(params.probeKind)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", `目标不支持 probe ${params.probeKind}`);
      assertEffectiveVerb(deps, "jvm", "probe");
      const granted = deps.store.listTaskGrants(deps.task.taskId).some((grant) => grant.kind === "PROBE" && grant.status === "ACTIVE" && grant.targetFingerprint === deps.task.target.hostFingerprint && grant.binding.probeKind === params.probeKind && (!grant.expiresAt || Date.parse(grant.expiresAt) > Date.now()));
      if (!granted) throw new SecurityError("PERMISSION_DENIED", `Probe ${params.probeKind} 未获得任务级授权`);
      return { ...resolveObject(deps, params.ref, "jvm"), probeKind: params.probeKind, parameters: params.parameters };
    }),
    createRequestScopeTool(deps), createRequestSensitiveTool(deps), createRecordAssessmentTool(deps), createAdjudicateAssessmentTool(deps),
  ];
  if (deps.config.threatIntel.enabled) tools.push(createThreatIntelTool(deps));
  if (deps.task.mode === "REMEDIATE") {
    if (deps.config.remediation.allowedTools.includes("quarantine_file")) tools.push(createQuarantineFileTool(deps));
    if (deps.config.remediation.allowedTools.includes("disable_account")) tools.push(createDisableAccountTool(deps));
  }
  return tools;
}

function createThreatIntelTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return localTool(deps, "enrich_threat_intel", "查询安恒威胁情报", Type.Object({
    refs: Type.Array(Type.String({ pattern: "^(OBJ|EV)-[0-9a-f-]{36}$" }), { minItems: 1, maxItems: 100, uniqueItems: true }),
  }, { additionalProperties: false }), async (params, toolCallId, signal) => {
    if (!deps.threatIntel) throw new InvalidArgumentError("安恒威胁情报客户端不可用");
    if (params.refs.length > deps.config.threatIntel.maxBatchSize) throw new InvalidArgumentError(`单次情报查询最多 ${deps.config.threatIntel.maxBatchSize} 个引用`);
    const network = new Map<string, Array<{ namespace: NamespaceName; identity: Record<string, unknown> }>>();
    const hashes = new Map<string, Array<{ namespace: NamespaceName; identity: Record<string, unknown> }>>();
    const add = (target: typeof network, value: string, binding: { namespace: NamespaceName; identity: Record<string, unknown> }) => target.set(value, [...(target.get(value) ?? []), binding]);
    for (const ref of params.refs) {
      if (ref.startsWith("EV-")) {
        const evidence = deps.store.getEvidence(deps.task.taskId, ref);
        const subjectRef = evidence?.metadata?.subjectRef;
        if (!evidence?.sha256 || typeof subjectRef !== "string") throw new InvalidArgumentError(`Evidence ${ref} 缺少 SHA-256 或当前对象绑定`);
        const binding = resolveObject(deps, subjectRef, "file");
        add(hashes, evidence.sha256.toLowerCase(), { namespace: binding.namespace, identity: binding.identity });
        continue;
      }
      const object = deps.store.getObjectReference(deps.task.taskId, deps.epoch.epochId, ref);
      if (!object) throw new InvalidArgumentError(`ObjectRef ${ref} 不存在或跨 task/epoch`);
      const payload = latestPrivateFact(deps, ref);
      if (object.namespace === "socket") {
        const ip = payload.remoteAddress;
        if (typeof ip !== "string" || !isPublicThreatIntelIp(ip)) throw new InvalidArgumentError(`Socket ${ref} 的远端不是允许送检的公网 IP`);
        add(network, ip.toLowerCase(), { namespace: object.namespace, identity: object.stableIdentity });
      } else if (object.namespace === "task_ioc") {
        const kind = payload.kind; const value = payload.value;
        if (typeof kind !== "string" || typeof value !== "string") throw new InvalidArgumentError(`task_ioc ${ref} 缺少类型或值`);
        const normalized = value.toLowerCase();
        if (kind === "ip") {
          if (!isPublicThreatIntelIp(normalized)) throw new InvalidArgumentError("私网、保留、回环或链路本地 IP 永不发送外部 Provider");
          add(network, normalized, { namespace: object.namespace, identity: object.stableIdentity });
        } else if (kind === "domain") add(network, normalized, { namespace: object.namespace, identity: object.stableIdentity });
        else if (kind === "hash") add(hashes, normalized, { namespace: object.namespace, identity: object.stableIdentity });
        else throw new InvalidArgumentError(`task_ioc 类型 ${kind} 不支持情报查询`);
      } else if (object.namespace === "file") {
        const hash = payload.sha256;
        if (typeof hash !== "string") throw new InvalidArgumentError(`File ${ref} 尚无 sha256 Fact`);
        add(hashes, hash.toLowerCase(), { namespace: object.namespace, identity: object.stableIdentity });
      } else throw new InvalidArgumentError("情报工具只接受 socket/file/task_ioc/Evidence 引用");
    }
    const results = [] as Array<{ verdict: ThreatIntelVerdict; bindings: Array<{ namespace: NamespaceName; identity: Record<string, unknown> }> }>;
    const warnings: string[] = [];
    consumeUsageOrGap(deps, "THREAT_INTEL_IOCS", network.size + hashes.size);
    if (network.size > 0) {
      consumeUsageOrGap(deps, "THREAT_INTEL_CALLS", 1);
      const response = await invokeThreatIntelWithinWallBudget(deps, () => deps.threatIntel!.compromiseDetection([...network.keys()], signal));
      warnings.push(...response.warnings);
      for (const verdict of response.verdicts) results.push({ verdict, bindings: network.get(verdict.ioc.toLowerCase()) ?? [] });
    }
    if (hashes.size > 0) {
      consumeUsageOrGap(deps, "THREAT_INTEL_CALLS", 1);
      const response = await invokeThreatIntelWithinWallBudget(deps, () => deps.threatIntel!.batchFileInfo([...hashes.keys()], signal));
      warnings.push(...response.warnings);
      for (const verdict of response.verdicts) results.push({ verdict, bindings: hashes.get(verdict.ioc.toLowerCase()) ?? [] });
    }
    const observedAt = new Date().toISOString();
    const observations = results.flatMap(({ verdict, bindings }) => bindings.map((binding) => ({
      namespace: binding.namespace, identity: binding.identity,
      fields: { ...binding.identity, intelProvider: "dbapp-ti", ...(verdict.malicious === null ? {} : { intelMalicious: verdict.malicious }), intelRiskLevel: verdict.riskLevel, ...(verdict.confidence === null ? {} : { intelConfidence: verdict.confidence }), intelThreatTypes: verdict.threatTypes, intelQueriedAt: observedAt },
      observedAt, consistency: "EXTERNAL_BASELINE" as const,
    })));
    const batch = deps.store.commitFactBatch({
      taskId: deps.task.taskId, epochId: deps.epoch.epochId, sourceRunId: toolCallId, source: { kind: "EXTERNAL", externalProvider: "dbapp-ti" },
      targetFingerprint: deps.task.target.hostFingerprint, requestId: toolCallId, collector: { name: "dbapp-ti", version: "2.0.0" },
      observations, edges: [], gaps: [], wireDigest: digestObject({ provider: "dbapp-ti", verdictDigests: results.map(({ verdict }) => digestObject(verdict)), warnings: warnings.map(digestObject) }),
    });
    deps.store.appendAudit({ taskId: deps.task.taskId, event: "v2_threat_intel", level: "info", data: { provider: DBAPP_THREAT_INTEL_SOURCE, inputRefs: params.refs, factRefs: batch.facts.map((fact) => fact.factId), verdictCount: results.length, warningCount: warnings.length } });
    return { provider: DBAPP_THREAT_INTEL_SOURCE, factRefs: batch.facts.map((fact) => fact.factId), objectRefs: [...new Set(batch.facts.map((fact) => fact.subjectRef))], queried: network.size + hashes.size, warnings };
  });
}

async function invokeThreatIntelWithinWallBudget<T>(deps: V2ToolDependencies, invoke: () => Promise<T>): Promise<T> {
  const startedAt = Date.now();
  try {
    return await invoke();
  } finally {
    consumeUsageOrGap(deps, "THREAT_INTEL_WALL_MS", Math.max(1, Date.now() - startedAt));
  }
}

function createQuarantineFileTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return writeTool(deps, "quarantine_file", "隔离已固化证据对应的文件", Type.Object({
    evidenceRef: Type.String({ pattern: "^EV-[0-9a-f-]{36}$" }),
  }, { additionalProperties: false }), async (params, ticket, signal) => {
    const evidence = deps.store.getEvidence(deps.task.taskId, params.evidenceRef);
    const subjectRef = evidence?.metadata?.subjectRef;
    if (!evidence?.sha256 || evidence.metadata?.complete !== true || typeof subjectRef !== "string") throw new SecurityError("EVIDENCE_COLLECTION", "隔离必须绑定当前 epoch 的完整 Evidence");
    const binding = resolveObject(deps, subjectRef, "file");
    const action = { actionId: ticket.actionId, path: evidence.source, expectedSha256: evidence.sha256,
      expectedDevice: binding.identity.device, expectedInode: binding.identity.inode, quarantineRoot: deps.config.remediation.quarantineRoot };
    return await invokeWrite(deps, "quarantine_file", ticket.argsDigest, action, signal);
  });
}

function createDisableAccountTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return writeTool(deps, "disable_account", "禁用已观察账户", Type.Object({
    accountRef: RefSchema,
  }, { additionalProperties: false }), async (params, ticket, signal) => {
    resolveObject(deps, params.accountRef, "account");
    const account = latestPrivateFact(deps, params.accountRef);
    const username = account.username;
    if (typeof username !== "string") throw new InvalidArgumentError("账户 Fact 缺少 username");
    if (username === "root" || username === deps.task.target.username) throw new SecurityError("PERMISSION_DENIED", "root 与当前 SSH 执行账户永久禁止禁用");
    const action = { actionId: ticket.actionId, username, executorUsername: deps.task.target.username };
    return await invokeWrite(deps, "disable_account", ticket.argsDigest, action, signal);
  });
}

function writeTool<T extends TSchema>(
  deps: V2ToolDependencies,
  name: "quarantine_file" | "disable_account",
  label: string,
  parameters: T,
  run: (params: Static<T>, ticket: NonNullable<ReturnType<ApprovalServiceLike["consume"]>>, signal?: AbortSignal) => Promise<Record<string, unknown>>,
): SecurityToolDefinition<T, { status: "success"; actionId: string }> {
  return {
    name, label, description: `${label}；仅 REMEDIATE 模式、配置白名单和一次性精确参数审批同时满足时执行。`,
    parameters, risk: "WRITE", replayPolicy: "NEVER", timeoutMs: 60_000, auditEvent: `v2_${name}`, executionMode: "sequential",
    execute: async (toolCallId, params, signal) => {
      if (deps.task.mode !== "REMEDIATE" || !deps.config.remediation.allowedTools.includes(name)) throw new SecurityError("PERMISSION_DENIED", "写工具未获模式或白名单授权");
      const ticket = deps.approvals.consume(deps.task, name, params);
      if (!ticket) throw new SecurityError("APPROVAL_REQUIRED", "缺少与 task、target、tool、args digest 完全绑定的一次性审批");
      const started: ActionReceipt = { actionId: ticket.actionId, taskId: deps.task.taskId, tool: name, targetFingerprint: deps.task.target.hostFingerprint, status: "STARTED", startedAt: new Date().toISOString() };
      deps.store.putActionReceipt(started);
      try {
        const remote = await run(params, ticket, signal);
        deps.checkpoint?.("remote_write_succeeded_before_local_receipt");
        const status = remote.status === "SUCCEEDED" ? "SUCCEEDED" : "FAILED";
        deps.store.putActionReceipt({ ...started, status, result: remote, finishedAt: new Date().toISOString() });
        if (status !== "SUCCEEDED") throw new SecurityError("EVIDENCE_COLLECTION", `${label}未成功`, { actionId: ticket.actionId });
        const details = { status: "success" as const, actionId: ticket.actionId };
        const result = { content: [{ type: "text" as const, text: JSON.stringify(details) }], details };
        deps.store.finishToolRun(toolCallId, "SUCCEEDED", result);
        deps.store.appendAudit({ taskId: deps.task.taskId, event: `v2_${name}`, level: "warn", data: { actionId: ticket.actionId, approvalId: ticket.approvalId, status } });
        return result;
      } catch (error) {
        const uncertain = error instanceof SecurityError && ["RECOVERY_UNCERTAIN", "TOOL_TIMEOUT", "TARGET_UNAVAILABLE"].includes(error.code);
        deps.store.putActionReceipt({ ...started, status: uncertain ? "UNKNOWN" : "FAILED", result: { error: error instanceof Error ? error.message : String(error) }, finishedAt: new Date().toISOString() });
        const toolRun = deps.store.getToolRunForTask(deps.task.taskId, toolCallId);
        if (toolRun?.status === "STARTED") deps.store.finishToolRun(toolCallId, "FAILED", undefined, error instanceof Error ? error.message : String(error));
        throw error;
      }
    },
  };
}

type ApprovalServiceLike = V2ToolDependencies["approvals"];

async function invokeWrite(
  deps: V2ToolDependencies,
  verb: "quarantine_file" | "disable_account",
  argsDigest: string,
  action: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const wireArgsDigest = digestObject(action);
  const request: WireRequest = {
    protocolVersion: 2, requestId: `${action.actionId}:WRITE`, epochId: deps.epoch.epochId, deadlineMs: 55_000,
    reservation: { reservationId: `${action.actionId}:WRITE`, estimate: { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 55_000, probeCalls: 0 } },
    params: { authorization: { mode: "REMEDIATE", tool: verb, actionId: action.actionId, argsDigest, wireArgsDigest }, action },
  };
  return await deps.executor.invokeMaintenanceV2(verb, request, signal);
}

function remoteTool<T extends TSchema>(deps: V2ToolDependencies, verb: ForensicVerb, label: string, parameters: T, risk: "READ" | "INTRUSIVE_READ" | "COLLECT", replayPolicy: SecurityToolDefinition["replayPolicy"], build: (params: Static<T>) => Record<string, unknown>, postprocess?: (response: WireSuccess, params: Static<T>) => WireSuccess): SecurityToolDefinition<T, RemoteResultDetails> {
  return {
    name: verb, label, description: `${label}；参数由控制端 Manifest、引用、Grant 与预算闸门校验后才会发送到当前任务绑定目标。`, parameters,
    risk, replayPolicy, timeoutMs: 120_000, auditEvent: `v2_${verb}`,
    execute: async (toolCallId, params, signal, onUpdate) => {
      const existing = deps.store.getToolRunForTask(deps.task.taskId, toolCallId);
      if (existing?.status === "SUCCEEDED" && existing.result) return existing.result as AgentToolResult<RemoteResultDetails>;
      const built = build(params);
      const cursorBinding = built._cursorBinding as { requestDigest: string } | undefined;
      delete built._cursorBinding;
      const estimate = estimateRemoteCost(verb, built);
      const reservationId = `BRES-${randomUUID()}`;
      const request: WireRequest = { protocolVersion: 2, requestId: toolCallId, epochId: deps.epoch.epochId, deadlineMs: Math.min(115_000, estimate.wallTimeMs), reservation: { reservationId, estimate }, params: built };
      deps.store.startToolRun({ toolCallId, taskId: deps.task.taskId, toolName: verb, risk, replayPolicy, args: digestObject(params) });
      onUpdate?.({ content: [{ type: "text", text: `${label}正在执行` }], details: {} as RemoteResultDetails });
      try {
        deps.store.reserveBudget(reservationId, deps.task.taskId, deps.epoch.epochId, deps.budgetOwner, estimate);
      } catch (error) {
        deps.store.finishToolRun(toolCallId, "BLOCKED", undefined, "BUDGET_EXHAUSTED");
        deps.store.putInvestigationGap({ gapId: `IGAP-${randomUUID()}`, taskId: deps.task.taskId, epochId: deps.epoch.epochId, code: "BUDGET_DENIED", reasonCode: "BUDGET_EXHAUSTED", createdAt: new Date().toISOString() });
        throw error;
      }
      try {
        const wireResponse = await deps.executor.invokeV2(verb, request, signal);
        assertCostWithinReservation(wireResponse.cost, estimate);
        deps.store.settleBudget(reservationId, wireResponse.cost);
        if (wireResponse.status === "ERROR") throw wireFailure(wireResponse);
        const rawWireDigest = digestObject(wireResponse);
        const response = postprocess ? postprocess(wireResponse, params) : wireResponse;
        let cursorRef: string | undefined;
        if (response.cursor) {
          if (verb !== "enumerate" && verb !== "relate") throw new SecurityError("INTERNAL_ERROR", `${verb} 不得返回 cursor`);
          cursorRef = `CURSOR-${randomUUID()}`;
          const namespace = String(built.namespace) as NamespaceName;
          deps.store.putRemoteCursor({ cursorRef, taskId: deps.task.taskId, epochId: deps.epoch.epochId, namespace, requestDigest: cursorBinding?.requestDigest ?? digestObject(built), helperCursor: response.cursor });
        }
        let evidenceRefs: string[] = [];
        if (verb === "collect" && response.artifact) {
          const sourceRef = String((params as Record<string, unknown>).ref);
          const latest = latestPrivateFact(deps, sourceRef);
          const evidence = await deps.evidence.putStream({
            taskId: deps.task.taskId, host: deps.task.target.host, type: "collected_object", source: String(latest.path ?? latest.exe ?? sourceRef), tool: "collect", toolCallId,
            metadata: { epochId: deps.epoch.epochId, subjectRef: sourceRef, complete: response.artifact.complete, remoteSha256: response.artifact.sha256, remoteSize: response.artifact.size },
            transfer: async (onChunk) => deps.executor.downloadArtifact({ artifactToken: response.artifact!.token, sha256: response.artifact!.sha256, size: response.artifact!.size, expiresAt: response.artifact!.expiresAt }, onChunk, signal),
          });
          evidenceRefs = [evidence.evidenceId];
        }
        const source: FactSource = deps.budgetOwner === "PRESET"
          ? deps.factSource ?? (() => { throw new SecurityError("INTERNAL_ERROR", "Preset 必须提供完整 Fact 来源"); })()
          : { kind: "MODEL" };
        const placeholder: RemoteResultDetails = { status: response.status === "PARTIAL" ? "partial" : "success", runId: toolCallId, factRefs: [], objectRefs: [], edgeRefs: [], evidenceRefs, gaps: response.gaps, ...(cursorRef ? { cursorRef } : {}), cost: response.cost };
        const batch = deps.store.commitFactBatch({
          taskId: deps.task.taskId, epochId: deps.epoch.epochId, sourceRunId: toolCallId, source,
          targetFingerprint: deps.task.target.hostFingerprint, requestId: request.requestId, collector: { name: verb, version: "2.0.0" },
          observations: response.objects, edges: response.edges, gaps: response.gaps, wireDigest: rawWireDigest,
          toolRun: { toolCallId, status: "SUCCEEDED", resultFactory: (prepared) => {
            const finalDetails: RemoteResultDetails = { ...placeholder, factRefs: prepared.facts.map((fact) => fact.factId), objectRefs: [...new Set(prepared.facts.map((fact) => fact.subjectRef))], edgeRefs: prepared.edges.map((edge) => edge.edgeId) };
            return { content: [{ type: "text", text: JSON.stringify(finalDetails) }], details: finalDetails } satisfies AgentToolResult<RemoteResultDetails>;
          } },
        });
        const details: RemoteResultDetails = { ...placeholder, factRefs: batch.facts.map((fact) => fact.factId), objectRefs: [...new Set(batch.facts.map((fact) => fact.subjectRef))], edgeRefs: batch.edges.map((edge) => edge.edgeId) };
        const result: AgentToolResult<RemoteResultDetails> = { content: [{ type: "text", text: JSON.stringify(details) }], details };
        deps.store.appendAudit({ taskId: deps.task.taskId, event: `v2_${verb}`, level: response.status === "PARTIAL" ? "warn" : "info", data: { toolCallId, factCount: batch.facts.length, edgeCount: batch.edges.length, gapCodes: response.gaps.map((gap) => gap.code), cursorRef, evidenceRefs, cost: response.cost } });
        return result;
      } catch (error) {
        // 无 Envelope 时无法获得实际成本；按最坏预留结算，避免断线重试绕过远程预算。
        try { deps.store.settleBudget(reservationId, estimate); } catch { /* 已由有效 Wire Response 结算 */ }
        const run = deps.store.getToolRunForTask(deps.task.taskId, toolCallId);
        if (run?.status === "STARTED") deps.store.finishToolRun(toolCallId, "FAILED", undefined, error instanceof Error ? error.message : String(error));
        throw error;
      }
    },
  };
}

export function estimateRemoteCost(verb: ForensicVerb, params: Record<string, unknown>): WireCost {
  const nodes = verb === "enumerate" || verb === "relate"
    ? Number(params.limit ?? 500)
    : verb === "match"
      ? Number(params.maxHits ?? 500)
      : verb === "probe" && params.probeKind === "jvm.tomcat.inventory"
        ? 500
        : 1;
  // Helper 以 Observation JSON 的 UTF-8 字节数结算，而不是仅读取的原始字节数。
  // 非法 UTF-8 可被替换为 U+FFFD，json.dumps(ensure_ascii=true) 最坏会膨胀到
  // 每个输入字节 6 字节；另留固定空间给 identity、文件元数据和 Envelope。
  const readLength = Number(params.length ?? 65_536);
  const bytes = verb === "read"
    ? Math.min(1_572_864, readLength * 6 + 16_384)
    : verb === "collect"
      ? Number(params.maxBytes ?? 104_857_600)
      : 1_572_864;
  return { remoteCalls: 1, nodes, bytes, wallTimeMs: verb === "probe" ? 115_000 : 60_000, probeCalls: verb === "probe" ? 1 : 0 };
}

function wireFailure(failure: WireFailure): SecurityError {
  // 目标端错误码必须映射成分析师与模型都能据此行动的类别：预算类提示收窄请求，
  // 探针失败不能被折叠成「环境不支持」，否则模型会放弃该方向而不是重试或换路径。
  const mapping: Record<WireFailure["error"]["code"], SecurityErrorCode> = {
    INVALID_ARGUMENT: "INVALID_ARGUMENT",
    PERMISSION_DENIED: "PERMISSION_DENIED",
    UNSUPPORTED_CAPABILITY: "UNSUPPORTED_ENVIRONMENT",
    STALE_REF: "RECOVERY_UNCERTAIN",
    EPOCH_MISMATCH: "RECOVERY_UNCERTAIN",
    SOURCE_CHANGED: "RECOVERY_UNCERTAIN",
    BUDGET_EXHAUSTED: "BUDGET_EXCEEDED",
    DEADLINE_EXCEEDED: "TOOL_TIMEOUT",
    OUTPUT_LIMIT_EXCEEDED: "BUDGET_EXCEEDED",
    EVIDENCE_COLLECTION_FAILED: "EVIDENCE_COLLECTION",
    PROBE_FAILED: "EVIDENCE_COLLECTION",
    TARGET_UNAVAILABLE: "TARGET_UNAVAILABLE",
    INTERNAL_ERROR: "INTERNAL_ERROR",
  };
  return new SecurityError(mapping[failure.error.code] ?? "RECOVERY_UNCERTAIN", failure.error.message ?? failure.error.code, { protocolCode: failure.error.code });
}

function resolveObject(deps: V2ToolDependencies, ref: string, namespace?: NamespaceName): { namespace: NamespaceName; identity: Record<string, unknown>; locator: Record<string, unknown> } {
  const value = deps.store.getObjectReference(deps.task.taskId, deps.epoch.epochId, ref, namespace);
  if (!value) throw new SecurityError("INVALID_ARGUMENT", "ObjectRef 不存在、类型错误或跨 task/epoch");
  const latest = latestPrivateFact(deps, ref);
  const locator: Record<string, unknown> = {};
  if (typeof latest.path === "string") locator.path = latest.path;
  return { namespace: value.namespace, identity: value.stableIdentity, locator };
}

function latestPrivateFact(deps: V2ToolDependencies, ref: string): Record<string, unknown> {
  const facts = deps.store.listFacts(deps.task.taskId, deps.epoch.epochId).filter((item) => item.subjectRef === ref);
  if (facts.length === 0) throw new InvalidArgumentError("ObjectRef 尚无可复核 Fact");
  return Object.assign({}, ...facts.map((fact) => fact.privatePayload));
}

function assertEffectiveField(deps: V2ToolDependencies, namespace: NamespaceName, field: string): void {
  if (!deps.capabilities.namespaces[namespace]?.fields.has(field)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", `目标未声明字段能力 ${namespace}.${field}`);
}

function assertEffectiveVerb(deps: V2ToolDependencies, namespace: NamespaceName, verb: ForensicVerb): void {
  if (!categoryGrantAllowsNamespace(deps.store.listTaskGrants(deps.task.taskId), namespace)) throw new SecurityError("PERMISSION_DENIED", `namespace ${namespace} 的 Category Grant 已失效或被撤销`);
  if (!deps.capabilities.verbs.has(verb) || !deps.capabilities.namespaces[namespace]?.verbs.has(verb)) throw new SecurityError("UNSUPPORTED_ENVIRONMENT", `目标未声明能力 ${namespace}.${verb}`);
}

function consumeUsageOrGap(deps: V2ToolDependencies, kind: string, amount: number): void {
  try {
    deps.store.consumeUsage(deps.task.taskId, deps.epoch.epochId, kind, amount);
  } catch (error) {
    recordBudgetGap(deps, kind);
    throw error;
  }
}

function recordBudgetGap(deps: V2ToolDependencies, reasonCode: string): void {
  deps.store.putInvestigationGap({ gapId: `IGAP-${randomUUID()}`, taskId: deps.task.taskId, epochId: deps.epoch.epochId, code: "BUDGET_DENIED", reasonCode, createdAt: new Date().toISOString() });
}

function resolveGrant(deps: V2ToolDependencies, grantId: string, kind: "SCOPE" | "SENSITIVE_READ") {
  const grant = deps.store.listTaskGrants(deps.task.taskId).find((item) => item.grantId === grantId && item.kind === kind && item.status === "ACTIVE" && item.targetFingerprint === deps.task.target.hostFingerprint && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()));
  if (!grant) throw new SecurityError("PERMISSION_DENIED", `${kind} Grant 不存在、已过期或目标不匹配`);
  return grant;
}

function requireSensitiveGrant(deps: V2ToolDependencies, subjectRef: string): void {
  const active = deps.store.listTaskGrants(deps.task.taskId).some((item) => item.kind === "SENSITIVE_READ" && item.status === "ACTIVE" && item.targetFingerprint === deps.task.target.hostFingerprint && item.binding.subjectRef === subjectRef && (!item.expiresAt || Date.parse(item.expiresAt) > Date.now()));
  if (!active) throw new SecurityError("PERMISSION_DENIED", "SENSITIVE_TEXT 需要绑定当前对象的 Sensitive-read Grant");
}

function effectiveContentClass(pathValue: unknown, helperValue: unknown): "SAFE_TEXT" | "SENSITIVE_TEXT" | "DENIED_TEXT" {
  const helper = helperValue === "SAFE_TEXT" || helperValue === "SENSITIVE_TEXT" || helperValue === "DENIED_TEXT" ? helperValue : "SENSITIVE_TEXT";
  const path = typeof pathValue === "string" ? pathValue : "";
  const denied = path === "/etc/shadow" || path === "/etc/gshadow" || path === "/proc/kcore"
    || /^\/proc\/\d+\/(mem|pagemap)$/.test(path)
    || /\/(?:id_rsa|id_ed25519|credentials|secrets?)(?:\.[^/]*)?$/i.test(path)
    || /\/(?:\.aws|\.gnupg|\.kube)\//.test(path);
  const controller = denied ? "DENIED_TEXT" : ["/etc/os-release", "/usr/lib/os-release", "/proc/version", "/proc/uptime", "/etc/hostname"].includes(path) ? "SAFE_TEXT" : "SENSITIVE_TEXT";
  const rank = { SAFE_TEXT: 0, SENSITIVE_TEXT: 1, DENIED_TEXT: 2 } as const;
  return rank[helper] >= rank[controller] ? helper : controller;
}

function localTool<T extends TSchema, R>(deps: V2ToolDependencies, name: string, label: string, parameters: T, run: (params: Static<T>, toolCallId: string, signal?: AbortSignal) => R | Promise<R>): SecurityToolDefinition<T, R> {
  return { name, label, description: `${label}；仅访问当前 task + epoch 的控制端数据。`, parameters, risk: "LOCAL", replayPolicy: name === "enrich_threat_intel" ? "SAFE_REOBSERVE" : "IDEMPOTENT_LOCAL", timeoutMs: name === "enrich_threat_intel" ? Math.min(65_000, (deps.config.threatIntel.timeoutSeconds + 5) * 1_000) : 10_000, auditEvent: `v2_${name}`, executionMode: "sequential", execute: async (toolCallId, params, signal) => {
    const existing = deps.store.getToolRunForTask(deps.task.taskId, toolCallId);
    if (existing?.status === "SUCCEEDED" && existing.result) return existing.result as AgentToolResult<R>;
    deps.store.startToolRun({ toolCallId, taskId: deps.task.taskId, toolName: name, risk: "LOCAL", replayPolicy: "IDEMPOTENT_LOCAL", args: digestObject(params) });
    try { const details = await run(params, toolCallId, signal); const result: AgentToolResult<R> = { content: [{ type: "text", text: JSON.stringify(details) }], details }; deps.store.finishToolRun(toolCallId, "SUCCEEDED", result); return result; }
    catch (error) { deps.store.finishToolRun(toolCallId, "FAILED", undefined, error instanceof Error ? error.message : String(error)); throw error; }
  } };
}

function createQueryFactsTool(deps: V2ToolDependencies): SecurityToolDefinition {
  const selectFieldSchema = Type.Union([...new Set(Object.values(FACT_QUERY_SELECT_FIELDS).flat())].map((value) => Type.Literal(value)));
  return localTool(deps, "query_facts", "查询模型事实平面；优先省略 select 使用默认字段，Preset 已有事实不要重复远程枚举", Type.Object({
    view: Type.Union([Type.Literal("facts"), Type.Literal("edges"), Type.Literal("evidence_meta"), Type.Literal("assessments"), Type.Literal("coverage")]),
    namespace: Type.Optional(Type.Union(Object.keys(PROTOCOL_MANIFEST.namespaces).map((value) => Type.Literal(value)))),
    predicate: Type.Optional(Type.Any({ description: "仅 facts 视图可用且同时必须提供 namespace；predicate 的 field 只能是该 namespace Manifest 中标为 filterable 的 payload 字段，factId/subjectRef/sourceRunId 等事实元数据禁止写入 predicate，应改用同名顶层过滤参数。非必要不要传 predicate。" })),
    select: Type.Optional(Type.Array(selectFieldSchema, { minItems: 1, maxItems: 32, description: "建议省略以使用当前 view 的安全默认字段；payload 内的路径等字段不能直接写进 select。" })),
    sourceRunId: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })), subjectRef: Type.Optional(RefSchema),
    sourceKind: Type.Optional(Type.Union([Type.Literal("PRESET"), Type.Literal("MODEL"), Type.Literal("SYSTEM"), Type.Literal("EXTERNAL")])),
    completeness: Type.Optional(Type.Union([Type.Literal("COMPLETE"), Type.Literal("PARTIAL")])),
    category: Type.Optional(Type.Union(deps.task.checks.map((value) => Type.Literal(value)))),
    authorType: Type.Optional(Type.Union([Type.Literal("RULE"), Type.Literal("MODEL"), Type.Literal("HUMAN"), Type.Literal("SYSTEM")])),
    verdict: Type.Optional(Type.Union(verdicts.map((value) => Type.Literal(value)))),
    status: Type.Optional(Type.Union([Type.Literal("COMPLETE"), Type.Literal("PARTIAL"), Type.Literal("ERROR"), Type.Literal("NOT_RUN")])),
    applicability: Type.Optional(Type.Union([Type.Literal("APPLICABLE"), Type.Literal("NOT_APPLICABLE"), Type.Literal("UNKNOWN")])),
    orderBy: Type.Optional(Type.Array(Type.Object({ field: selectFieldSchema, direction: Type.Union([Type.Literal("asc"), Type.Literal("desc")]) }), { maxItems: 3 })),
    limit: Type.Integer({ minimum: 1, maximum: 500 }), cursorRef: Type.Optional(Type.String({ pattern: "^QCUR-[0-9a-f-]{36}$" })),
  }, { additionalProperties: false }), async (params) => queryWithinBudget(deps, params as Omit<FactQueryAst, "select"> & { select?: string[] }));
}

function queryWithinBudget(deps: V2ToolDependencies, input: Omit<FactQueryAst, "select"> & { select?: string[] }): FactQueryPage | { error: "ROW_TOO_LARGE"; instruction: string } {
  const ast: FactQueryAst = { ...input, select: input.select ?? defaultFactQuerySelect(input.view) };
  // 参数错误不应消耗本地查询预算，否则模型一次可恢复的字段错误会制造
  // BUDGET_DENIED Gap，并挤掉后续合法查询与类别 Assessment。
  validateFactQuery(ast);
  const startedAt = Date.now();
  consumeUsageOrGap(deps, "LOCAL_QUERY_CALLS", 1);
  const remainingRows = deps.store.remainingUsage(deps.task.taskId, deps.epoch.epochId, "LOCAL_QUERY_ROWS");
  if (remainingRows <= 0) {
    recordBudgetGap(deps, "LOCAL_QUERY_ROWS");
    throw new SecurityError("BUDGET_EXCEEDED", "本地查询行预算已耗尽");
  }
  const boundedAst = { ...ast, limit: Math.min(ast.limit, remainingRows) };
  let answer: FactQueryPage | { error: "ROW_TOO_LARGE"; instruction: string };
  if (ast.cursorRef) {
    const preview = deps.store.previewQueryFacts(deps.task.taskId, deps.epoch.epochId, boundedAst);
    answer = Buffer.byteLength(JSON.stringify(preview), "utf8") > deps.config.llmData.maxTextBytes
      ? { error: "ROW_TOO_LARGE", instruction: "收窄 select；查询游标未推进。" }
      : deps.store.queryFacts(deps.task.taskId, deps.epoch.epochId, boundedAst);
  } else {
    let low = 1; let high = boundedAst.limit; let bestLimit: number | undefined;
    while (low <= high) {
      const limit = Math.floor((low + high) / 2);
      const preview = deps.store.previewQueryFacts(deps.task.taskId, deps.epoch.epochId, { ...boundedAst, limit });
      if (Buffer.byteLength(JSON.stringify(preview), "utf8") <= deps.config.llmData.maxTextBytes) { bestLimit = limit; low = limit + 1; } else high = limit - 1;
    }
    answer = bestLimit === undefined
      ? { error: "ROW_TOO_LARGE", instruction: "单行无法进入模型上下文；请收窄 select。" }
      : deps.store.queryFacts(deps.task.taskId, deps.epoch.epochId, { ...boundedAst, limit: bestLimit });
  }
  if ("rows" in answer) consumeUsageOrGap(deps, "LOCAL_QUERY_ROWS", answer.rows.length);
  consumeUsageOrGap(deps, "LOCAL_QUERY_WALL_MS", Math.max(1, Date.now() - startedAt));
  return answer;
}

function createRequestScopeTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return localTool(deps, "request_scope_extension", "请求 Scope 扩展", Type.Object({ namespace: Type.Literal("file"), requestedRoot: Type.String({ minLength: 1, maxLength: 4096 }), reason: Type.String({ minLength: 1, maxLength: 1000 }) }, { additionalProperties: false }), async (params) => {
    consumeUsageOrGap(deps, "GRANT_REQUESTS", 1);
    const requestId = `GRQ-${randomUUID()}`;
    deps.store.putGrantRequest({ requestId, taskId: deps.task.taskId, targetFingerprint: deps.task.target.hostFingerprint, kind: "SCOPE", status: "PENDING", bindingDigest: digestObject(params), binding: structuredClone(params), createdAt: new Date().toISOString() });
    return { requestId, status: "PENDING", note: "审批后仍需由控制端 scope_resolve 固化 canonical root 与 mount identity。" };
  });
}

function createRequestSensitiveTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return localTool(deps, "request_sensitive_read", "请求敏感文本读取", Type.Object({ ref: RefSchema, reason: Type.String({ minLength: 1, maxLength: 1000 }) }, { additionalProperties: false }), async (params) => {
    consumeUsageOrGap(deps, "GRANT_REQUESTS", 1);
    resolveObject(deps, params.ref, "file");
    const contentClass = latestPrivateFact(deps, params.ref).contentClass;
    if (contentClass === "DENIED_TEXT") throw new SecurityError("PERMISSION_DENIED", "DENIED_TEXT 永不允许授权读取");
    const requestId = `GRQ-${randomUUID()}`;
    const binding = { subjectRef: params.ref, contentClass, reason: params.reason };
    deps.store.putGrantRequest({ requestId, taskId: deps.task.taskId, targetFingerprint: deps.task.target.hostFingerprint, kind: "SENSITIVE_READ", status: "PENDING", bindingDigest: digestObject(binding), binding, createdAt: new Date().toISOString() });
    return { requestId, status: "PENDING" };
  });
}

function assessmentSchema(deps: V2ToolDependencies) {
  const allowed = deps.task.checks;
  return Type.Object({
    category: Type.Union(allowed.map((value) => Type.Literal(value))),
    subjectRef: Type.Optional(Type.String({ pattern: "^OBJ-[0-9a-f-]{36}$", description: "scope=SUBJECT 时必填并绑定被裁定对象；scope=OBSERVED_CATEGORY 时必须省略。" })),
    scope: Type.Union([
      Type.Literal("SUBJECT", { description: "对象级裁定；必须同时提供 subjectRef。" }),
      Type.Literal("OBSERVED_CATEGORY", { description: "类别级收尾结论；必须省略 subjectRef。" }),
    ]),
    verdict: Type.Union(verdicts.map((value) => Type.Literal(value)), { description: "OBSERVED_CATEGORY 仅允许 NO_OBSERVED_FINDING 或 INCONCLUSIVE；SUSPICIOUS/HIGHLY_SUSPICIOUS/CONFIRMED_MALICIOUS/BENIGN 必须使用 SUBJECT 并绑定 subjectRef。" }), severity: Type.Union(severities.map((value) => Type.Literal(value))), confidence: Type.Number({ minimum: 0, maximum: 1 }), rationale: Type.String({ minLength: 1, maxLength: 8000 }), evidenceRefs: Type.Array(Type.String({ pattern: "^EV-[0-9a-f-]{36}$" }), { maxItems: 100 }), factRefs: Type.Array(Type.String({ pattern: "^FACT-[0-9a-f-]{36}$" }), { maxItems: 500 }), queryRefs: Type.Array(Type.String({ pattern: "^QUERY-[0-9a-f-]{36}$" }), { maxItems: 100 }),
  }, { additionalProperties: false });
}

function createRecordAssessmentTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return localTool(deps, "record_assessment", "记录模型 Assessment", assessmentSchema(deps), async (params) => {
    const assessment: Assessment = { assessmentId: `ASM-${randomUUID()}`, taskId: deps.task.taskId, epochId: deps.epoch.epochId, authorType: "MODEL", category: params.category as CheckCategory, ...(params.subjectRef ? { subjectRef: params.subjectRef } : {}), scope: params.scope, verdict: params.verdict as AssessmentVerdict, severity: params.severity, confidence: params.confidence, rationale: params.rationale, evidenceRefs: params.evidenceRefs, factRefs: params.factRefs, queryRefs: params.queryRefs, createdAt: new Date().toISOString() };
    deps.store.putAssessment(assessment); return assessment;
  });
}

function createAdjudicateAssessmentTool(deps: V2ToolDependencies): SecurityToolDefinition {
  const base = assessmentSchema(deps);
  // 部分 OpenAI-compatible Provider（包括 DeepSeek）拒绝顶层仅含 allOf、
  // 没有显式 type: object 的函数参数 Schema。裁定参数在语义上本来就是
  // Assessment 字段加 targetAssessmentId，因此直接生成扁平对象 Schema。
  const parameters = Type.Object({
    ...base.properties,
    targetAssessmentId: Type.String({ pattern: "^ASM-[0-9a-f-]{36}$" }),
  }, { additionalProperties: false });
  return localTool(deps, "adjudicate_assessment", "裁定已有 Assessment", parameters, async (params) => {
    const target = deps.store.listAssessments(deps.task.taskId, deps.epoch.epochId).find((item) => item.assessmentId === params.targetAssessmentId);
    if (!target) throw new InvalidArgumentError("目标 Assessment 不存在或跨 epoch");
    if (params.subjectRef !== target.subjectRef) throw new InvalidArgumentError("裁定必须针对同一 subject");
    const assessment: Assessment = { assessmentId: `ASM-${randomUUID()}`, taskId: deps.task.taskId, epochId: deps.epoch.epochId, authorType: "MODEL", category: params.category as CheckCategory, ...(params.subjectRef ? { subjectRef: params.subjectRef } : {}), scope: params.scope, verdict: params.verdict as AssessmentVerdict, severity: params.severity, confidence: params.confidence, rationale: params.rationale, evidenceRefs: params.evidenceRefs, factRefs: params.factRefs, queryRefs: params.queryRefs, createdAt: new Date().toISOString() };
    deps.store.putAssessment(assessment);
    deps.store.putAssessmentRelation({ relationId: `AREL-${randomUUID()}`, taskId: deps.task.taskId, epochId: deps.epoch.epochId, kind: "ADJUDICATES", fromAssessmentId: assessment.assessmentId, toAssessmentId: target.assessmentId, createdAt: new Date().toISOString() });
    return assessment;
  });
}

function createAssessmentProjectionTool(deps: V2ToolDependencies): SecurityToolDefinition {
  return localTool(deps, "get_assessment_projection", "读取 Assessment 投影", Type.Object({}, { additionalProperties: false }), async () => ({ coverage: deps.store.listCoverageRuns(deps.task.taskId, deps.epoch.epochId), assessments: deps.store.listAssessments(deps.task.taskId, deps.epoch.epochId), relations: deps.store.listAssessmentRelations(deps.task.taskId, deps.epoch.epochId), investigationGaps: deps.store.listInvestigationGaps(deps.task.taskId, deps.epoch.epochId) }));
}
