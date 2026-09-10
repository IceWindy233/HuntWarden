import { digestObject } from "../common/json.js";
import type { EdgeRecord, FactRecord } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { AuthorizationEnvelope, DerivedObjectRequest, DerivedObjectResult, DerivedResolverRef, EntityVersion, RelationProvenance } from "./types.js";

interface ResolverDefinition {
  sourceNamespace: FactRecord["namespace"];
  targetNamespace: FactRecord["namespace"];
  relation: string;
  sourceJoinField: string;
  targetJoinField: string;
}

export const DERIVED_RESOLVERS: Readonly<Record<DerivedResolverRef, ResolverDefinition>> = {
  "socket.owner_by_pid@1.0.0": { sourceNamespace: "socket", targetNamespace: "process", relation: "owned_by", sourceJoinField: "pid", targetJoinField: "pid" },
  "process.parent_by_ppid@1.0.0": { sourceNamespace: "process", targetNamespace: "process", relation: "parent", sourceJoinField: "ppid", targetJoinField: "pid" },
};

export class DerivedObjectResolver {
  constructor(private readonly store: RuntimeStore) {}

  resolve(request: DerivedObjectRequest, authorization: AuthorizationEnvelope): DerivedObjectResult {
    const definition = DERIVED_RESOLVERS[request.resolverRef];
    const source = this.store.getFact(request.taskId, request.epochId, request.sourceFactRef);
    if (!source || source.namespace !== definition.sourceNamespace) throw new Error("派生请求必须引用当前 Epoch 且类型匹配的来源 Fact");
    if (!authorization.derivedRelations.includes(definition.relation)
      || !authorization.namespaces.includes(definition.sourceNamespace)
      || !authorization.namespaces.includes(definition.targetNamespace)) throw new Error("派生关系不在当前授权包络内");
    const joinValue = source.privatePayload[definition.sourceJoinField];
    if (joinValue === undefined || joinValue === null || joinValue === "") return this.empty(request);

    const candidates = latestBySubject(this.store.listFacts(request.taskId, request.epochId, { namespace: definition.targetNamespace }))
      .filter((fact) => fact.privatePayload[definition.targetJoinField] === joinValue && fact.subjectRef !== source.subjectRef)
      .sort((left, right) => distance(source, left) - distance(source, right) || left.subjectRef.localeCompare(right.subjectRef));
    if (candidates.length === 0) return this.empty(request);
    const targets = candidates.filter((target) => hasStableProcessRelationship(request.resolverRef, source, target));
    if (targets.length !== 1) return this.ambiguous(request, candidates);
    const target = targets[0]!;

    const edgeId = `EDGE-DERIVED-${digestObject({ taskId: request.taskId, epochId: request.epochId, resolverRef: request.resolverRef, sourceFactRef: request.sourceFactRef, targetFactRef: target.factId }).slice(0, 40)}`;
    const observedAt = later(source.observedAt, target.observedAt);
    const edge: EdgeRecord = {
      edgeId, taskId: request.taskId, epochId: request.epochId, relation: definition.relation,
      fromRef: source.subjectRef, toRef: target.subjectRef, sourceRunId: request.requestId, observedAt,
    };
    const fromVersion = latestVersion(this.store.listEntityVersions(request.taskId, request.epochId, source.subjectRef));
    const toVersion = latestVersion(this.store.listEntityVersions(request.taskId, request.epochId, target.subjectRef));
    const provenance: RelationProvenance = {
      edgeRef: edge.edgeId, taskId: edge.taskId, epochId: edge.epochId,
      ...(fromVersion ? { fromVersionRef: fromVersion.versionRef } : {}),
      ...(toVersion ? { toVersionRef: toVersion.versionRef } : {}),
      derivation: "DERIVED", sourceRefs: [source.factId, target.factId], resolverVersion: request.resolverRef,
      timeErrorMs: distance(source, target),
    };
    this.store.putDerivedEdge(edge, provenance);
    return { requestId: request.requestId, resolverRef: request.resolverRef, sourceFactRef: request.sourceFactRef, status: "RESOLVED", objectRefs: [target.subjectRef], edgeRefs: [edge.edgeId] };
  }

  private ambiguous(request: DerivedObjectRequest, candidates: FactRecord[]): DerivedObjectResult {
    return { requestId: request.requestId, resolverRef: request.resolverRef, sourceFactRef: request.sourceFactRef, status: "AMBIGUOUS", objectRefs: [...new Set(candidates.map((fact) => fact.subjectRef))], edgeRefs: [] };
  }

  private empty(request: DerivedObjectRequest): DerivedObjectResult {
    return { requestId: request.requestId, resolverRef: request.resolverRef, sourceFactRef: request.sourceFactRef, status: "NO_MATCH", objectRefs: [], edgeRefs: [] };
  }
}

function hasStableProcessRelationship(resolverRef: DerivedResolverRef, source: FactRecord, target: FactRecord): boolean {
  const targetBootId = stringField(target, "bootId");
  const targetStartTicks = integerStringField(target, "startTicks");
  const targetPidNamespace = namespaceField(target);
  if (!targetBootId || !targetStartTicks || !targetPidNamespace) return false;
  if (resolverRef === "socket.owner_by_pid@1.0.0") {
    return stringField(source, "ownerBootId") === targetBootId
      && integerStringField(source, "ownerStartTicks") === targetStartTicks
      && stringField(source, "ownerPidNamespace") === targetPidNamespace;
  }
  const sourceBootId = stringField(source, "bootId");
  const sourceStartTicks = integerStringField(source, "startTicks");
  const sourcePidNamespace = namespaceField(source);
  return source.sourceRunId === target.sourceRunId
    && sourceBootId === targetBootId
    && sourcePidNamespace === targetPidNamespace
    && sourceStartTicks !== undefined
    && BigInt(targetStartTicks) < BigInt(sourceStartTicks);
}

function stringField(fact: FactRecord, field: string): string | undefined {
  const value = fact.privatePayload[field];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function integerStringField(fact: FactRecord, field: string): string | undefined {
  const value = stringField(fact, field);
  return value && /^\d+$/.test(value) ? value : undefined;
}

function namespaceField(fact: FactRecord): string | undefined {
  const namespaces = fact.privatePayload.namespaces;
  if (!namespaces || typeof namespaces !== "object" || Array.isArray(namespaces)) return undefined;
  const value = (namespaces as Record<string, unknown>).pid;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function latestBySubject(facts: FactRecord[]): FactRecord[] {
  const latest = new Map<string, FactRecord>();
  for (const fact of facts) if ((latest.get(fact.subjectRef)?.factSeq ?? -1) < fact.factSeq) latest.set(fact.subjectRef, fact);
  return [...latest.values()];
}

function latestVersion(versions: EntityVersion[]): EntityVersion | undefined {
  return versions.sort((left, right) => left.validFrom.localeCompare(right.validFrom)).at(-1);
}

function distance(left: FactRecord, right: FactRecord): number {
  return Math.abs(Date.parse(left.observedAt) - Date.parse(right.observedAt));
}

function later(left: string, right: string): string {
  return Date.parse(left) >= Date.parse(right) ? left : right;
}
