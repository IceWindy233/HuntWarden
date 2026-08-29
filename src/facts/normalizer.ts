import { randomUUID } from "node:crypto";
import { InvalidArgumentError, SecurityError } from "../common/errors.js";
import { digestObject } from "../common/json.js";
import { identityFields, requireNamespace } from "../protocol-v2/manifest.js";
import type { EdgeRecord, FactBatchInput, FactRecord, NamespaceName, ObjectReference, WireObservation } from "../protocol-v2/types.js";

export interface PreparedFactBatch {
  batchId: string;
  facts: FactRecord[];
  refs: ObjectReference[];
  edges: EdgeRecord[];
}

export function prepareFactBatch(
  input: FactBatchInput,
  lookup: (namespace: NamespaceName, identityDigest: string) => ObjectReference | undefined,
): PreparedFactBatch {
  if (input.observations.length > 2_048) throw new InvalidArgumentError("FactBatch 超过 2048 行硬上限");
  assertSource(input.source);
  const refs = new Map<string, ObjectReference>();
  const getRef = (namespace: NamespaceName, identity: Record<string, unknown>, observedAt: string): ObjectReference => {
    const stableIdentity: Record<string, unknown> = {};
    for (const field of identityFields(namespace)) {
      const value = identity[field];
      if (value === undefined || value === null || value === "") throw new InvalidArgumentError(`${namespace} Observation 缺少身份字段 ${field}`);
      stableIdentity[field] = value;
    }
    const stableIdentityDigest = digestObject({ namespace, stableIdentity });
    const key = `${namespace}:${stableIdentityDigest}`;
    const existing = refs.get(key) ?? lookup(namespace, stableIdentityDigest);
    if (existing) return existing;
    if (namespace === "task_ioc" && input.source.kind !== "SYSTEM") throw new SecurityError("INVALID_ARGUMENT", "task_ioc ObjectRef 只能由控制端 SYSTEM 来源首次物化");
    const created: ObjectReference = {
      ref: `OBJ-${randomUUID()}`, taskId: input.taskId, epochId: input.epochId,
      targetFingerprint: input.targetFingerprint, namespace, stableIdentityDigest, stableIdentity,
      assertions: [], createdAt: observedAt,
    };
    refs.set(key, created);
    return created;
  };

  const facts = input.observations.map((observation) => normalizeObservation(input, observation, getRef));
  const edges = input.edges.map((edge) => {
    const from = getRef(edge.fromIdentity.namespace, edge.fromIdentity.identity, edge.observedAt);
    const to = getRef(edge.toIdentity.namespace, edge.toIdentity.identity, edge.observedAt);
    const allowed = requireNamespace(from.namespace).relations;
    if (!allowed.includes(edge.relation)) throw new InvalidArgumentError(`关系未在 Manifest 注册: ${from.namespace}.${edge.relation}`);
    return {
      edgeId: `EDGE-${randomUUID()}`, taskId: input.taskId, epochId: input.epochId,
      relation: edge.relation, fromRef: from.ref, toRef: to.ref, sourceRunId: input.sourceRunId,
      observedAt: edge.observedAt,
    } satisfies EdgeRecord;
  });
  return { batchId: `BATCH-${randomUUID()}`, facts, refs: [...refs.values()], edges };
}

function normalizeObservation(
  input: FactBatchInput,
  observation: WireObservation,
  getRef: (namespace: NamespaceName, identity: Record<string, unknown>, observedAt: string) => ObjectReference,
): FactRecord {
  const manifest = requireNamespace(observation.namespace);
  const subject = getRef(observation.namespace, observation.identity, observation.observedAt);
  const privatePayload: Record<string, unknown> = {};
  const modelPayload: Record<string, unknown> = {};
  const redactedFields: string[] = [];
  for (const [fieldName, value] of Object.entries({ ...observation.identity, ...observation.fields })) {
    const field = manifest.fields[fieldName];
    if (!field) throw new InvalidArgumentError(`Helper 返回 Manifest 外字段: ${observation.namespace}.${fieldName}`);
    assertFieldValue(observation.namespace, fieldName, field.type, value);
    privatePayload[fieldName] = value;
    if (field.sensitivity === "SECRET") {
      modelPayload[fieldName] = field.modelExposure === "HASH_ONLY" ? digestObject(value) : value !== undefined && value !== null;
      redactedFields.push(fieldName);
    } else if (field.sensitivity === "EVIDENCE_ONLY" || field.modelExposure === "DENY") {
      redactedFields.push(fieldName);
    } else if (field.modelExposure === "HASH_ONLY") {
      modelPayload[fieldName] = digestObject(value);
      redactedFields.push(fieldName);
    } else if (field.modelExposure === "PRESENCE_ONLY") {
      modelPayload[fieldName] = value !== undefined && value !== null;
      redactedFields.push(fieldName);
    } else {
      modelPayload[fieldName] = value;
    }
  }
  const unavailableFields = observation.unavailableFields ?? [];
  for (const unavailable of unavailableFields) if (!manifest.fields[unavailable.field]) throw new InvalidArgumentError(`未知 unavailable field: ${observation.namespace}.${unavailable.field}`);
  const combinedGaps = [...input.gaps];
  for (const unavailable of unavailableFields) combinedGaps.push({ code: "FIELD_UNAVAILABLE", field: unavailable.field, detail: unavailable.reasonCode, resumable: false });
  const payloadDigest = digestObject({ privatePayload, unavailableFields });
  return {
    factId: `FACT-${randomUUID()}`, factSeq: 0, taskId: input.taskId, epochId: input.epochId,
    namespace: observation.namespace, subjectRef: subject.ref, schemaVersion: "2.0.0",
    observedAt: observation.observedAt, sourceRunId: input.sourceRunId, source: structuredClone(input.source),
    collector: structuredClone(input.collector), consistency: observation.consistency,
    completeness: combinedGaps.length > 0 ? "PARTIAL" : "COMPLETE", gaps: combinedGaps,
    privatePayload, modelPayload, redactedFields, unavailableFields, payloadDigest,
    provenance: {
      targetFingerprint: input.targetFingerprint, requestId: input.requestId, wireDigest: input.wireDigest,
      stableIdentityDigest: subject.stableIdentityDigest,
    },
  };
}

function assertFieldValue(namespace: NamespaceName, fieldName: string, type: string, value: unknown): void {
  const valid = type === "string" ? typeof value === "string"
    : type === "integer" ? Number.isSafeInteger(value)
      : type === "number" ? typeof value === "number" && Number.isFinite(value)
        : type === "boolean" ? typeof value === "boolean"
          : type === "timestamp" ? typeof value === "string" && Number.isFinite(Date.parse(value))
            : type === "string[]" ? Array.isArray(value) && value.every((item) => typeof item === "string")
              : type === "object" ? typeof value === "object" && value !== null && !Array.isArray(value)
                : false;
  if (!valid) throw new InvalidArgumentError(`${namespace}.${fieldName} 不符合 Manifest 类型 ${type}`);
}

function assertSource(source: FactBatchInput["source"]): void {
  if (source.kind === "PRESET") {
    if (!source.presetRunId || !source.presetId || !source.presetVersion || !source.stepId) throw new InvalidArgumentError("PRESET Fact 必须包含完整 preset 来源");
  } else if (source.presetRunId || source.presetId || source.presetVersion || source.stepId) {
    throw new InvalidArgumentError(`${source.kind} Fact 不得伪造 PRESET 来源`);
  }
  if (source.kind === "EXTERNAL" && !source.externalProvider) throw new InvalidArgumentError("EXTERNAL Fact 必须标识 provider");
}
