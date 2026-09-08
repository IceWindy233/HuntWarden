import { randomUUID } from "node:crypto";
import type { EdgeRecord, FactRecord } from "../protocol-v2/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";
import type { RelationProvenance } from "./types.js";

export const JAVA_RELATION_RESOLVER_VERSION = "java-runtime-relations@1.0.0";

/**
 * Join independently observed probe/file facts using exact JVM, class and loader identities.
 * These joins are controller-derived and are therefore persisted separately from Helper edges.
 */
export class JavaRelationResolver {
  constructor(private readonly store: RuntimeStore) {}

  resolve(taskId: string, epochId: string): string[] {
    const facts = latestBySubject(this.store.listFacts(taskId, epochId));
    const edges = this.store.listEdges(taskId, epochId);
    const componentFacts = facts.filter((item) => item.namespace === "java_component");
    const classFacts = facts.filter((item) => item.namespace === "class");
    const fileFacts = facts.filter((item) => item.namespace === "file");
    const created: string[] = [];

    for (const component of componentFacts) {
      const hostedBy = edges.find((edge) => edge.relation === "hosts_component" && edge.toRef === component.subjectRef);
      if (!hostedBy) continue;
      for (const classFact of classFacts) {
        if (component.privatePayload.jvmDigest !== classFact.privatePayload.jvmDigest
          || component.privatePayload.className !== classFact.privatePayload.className
          || component.privatePayload.classLoaderId !== classFact.privatePayload.loaderId) continue;
        if (!edges.some((edge) => edge.relation === "loads_class" && edge.fromRef === hostedBy.fromRef && edge.toRef === classFact.subjectRef)) continue;
        const edge = this.put(taskId, epochId, component, classFact, "implemented_by");
        if (edge) { edges.push(edge); created.push(edge.edgeId); }
      }
    }

    for (const classFact of classFacts) {
      const sourcePath = normalizeCodeSource(classFact.privatePayload.codeSource);
      if (!sourcePath) continue;
      const file = fileFacts.find((item) => item.privatePayload.path === sourcePath || item.privatePayload.canonicalPath === sourcePath);
      if (!file) continue;
      const edge = this.put(taskId, epochId, classFact, file, "defined_in");
      if (edge) { edges.push(edge); created.push(edge.edgeId); }
    }
    return created;
  }

  private put(taskId: string, epochId: string, from: FactRecord, to: FactRecord, relation: string): EdgeRecord | undefined {
    if (this.store.listEdges(taskId, epochId).some((edge) => edge.fromRef === from.subjectRef && edge.toRef === to.subjectRef && edge.relation === relation)) return undefined;
    const fromVersionRef = this.store.listEntityVersions(taskId, epochId, from.subjectRef).at(-1)?.versionRef;
    const toVersionRef = this.store.listEntityVersions(taskId, epochId, to.subjectRef).at(-1)?.versionRef;
    const edge: EdgeRecord = {
      edgeId: `EDGE-${randomUUID()}`,
      taskId,
      epochId,
      relation,
      fromRef: from.subjectRef,
      toRef: to.subjectRef,
      sourceRunId: JAVA_RELATION_RESOLVER_VERSION,
      observedAt: new Date(Math.max(Date.parse(from.observedAt), Date.parse(to.observedAt))).toISOString(),
    };
    const provenance: RelationProvenance = {
      edgeRef: edge.edgeId,
      taskId,
      epochId,
      ...(fromVersionRef ? { fromVersionRef } : {}),
      ...(toVersionRef ? { toVersionRef } : {}),
      derivation: "DERIVED",
      sourceRefs: [from.factId, to.factId],
      resolverVersion: JAVA_RELATION_RESOLVER_VERSION,
      timeErrorMs: Math.abs(Date.parse(from.observedAt) - Date.parse(to.observedAt)),
    };
    return this.store.putDerivedEdge(edge, provenance);
  }
}

function latestBySubject(facts: FactRecord[]): FactRecord[] {
  const latest = new Map<string, FactRecord>();
  for (const fact of facts) {
    const previous = latest.get(fact.subjectRef);
    if (!previous || previous.factSeq < fact.factSeq) latest.set(fact.subjectRef, fact);
  }
  return [...latest.values()];
}

function normalizeCodeSource(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  if (value.startsWith("file:")) {
    try { return decodeURIComponent(new URL(value).pathname); } catch { return undefined; }
  }
  return value.startsWith("/") ? value : undefined;
}
