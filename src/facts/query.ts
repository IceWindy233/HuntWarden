import { randomUUID } from "node:crypto";
import { InvalidArgumentError, SecurityError } from "../common/errors.js";
import { digestObject } from "../common/json.js";
import { evaluatePredicate } from "../protocol-v2/predicate.js";
import { validatePredicate } from "../protocol-v2/predicate.js";
import { PROTOCOL_MANIFEST } from "../protocol-v2/manifest.js";
import type { FactRecord, NamespaceName, Predicate, QuerySnapshot } from "../protocol-v2/types.js";

export interface FactQueryAst {
  view: "facts" | "edges" | "evidence_meta" | "assessments" | "coverage";
  namespace?: NamespaceName;
  predicate?: Predicate;
  sourceRunId?: string;
  subjectRef?: string;
  sourceKind?: FactRecord["source"]["kind"];
  completeness?: FactRecord["completeness"];
  category?: string;
  authorType?: string;
  verdict?: string;
  status?: string;
  applicability?: string;
  select: string[];
  orderBy?: Array<{ field: string; direction: "asc" | "desc" }>;
  limit: number;
  cursorRef?: string;
}

export interface FactQueryPage {
  queryRef: string;
  rows: Record<string, unknown>[];
  nextCursorRef?: string;
  snapshotMaxFactSeq: number;
}

export const FACT_QUERY_SELECT_FIELDS = Object.freeze({
  facts: ["factId", "factSeq", "namespace", "subjectRef", "observedAt", "sourceRunId", "source", "collector", "consistency", "completeness", "gaps", "payload", "redactedFields", "unavailableFields"],
  edges: ["edgeId", "relation", "fromRef", "toRef", "sourceRunId", "observedAt"],
  evidence_meta: ["evidenceId", "type", "source", "sha256", "size", "collectedAt", "tool", "toolCallId", "subjectRef", "complete"],
  assessments: ["assessmentId", "authorType", "category", "subjectRef", "scope", "verdict", "severity", "confidence", "rationale", "evidenceRefs", "factRefs", "queryRefs", "createdAt"],
  coverage: ["coverageId", "category", "presetId", "presetVersion", "status", "applicability", "completedCriteria", "missingCriteria", "createdAt"],
} satisfies Record<FactQueryAst["view"], readonly string[]>);

const allowedFields = Object.fromEntries(
  Object.entries(FACT_QUERY_SELECT_FIELDS).map(([view, fields]) => [view, new Set(fields)]),
) as unknown as Record<FactQueryAst["view"], ReadonlySet<string>>;

export function defaultFactQuerySelect(view: FactQueryAst["view"]): string[] {
  if (view === "facts") return ["factId", "namespace", "subjectRef", "sourceRunId", "completeness", "gaps", "payload"];
  return [...FACT_QUERY_SELECT_FIELDS[view]];
}

export type StaticQueryCursor = { taskId: string; epochId: string; astDigest: string; view: Exclude<FactQueryAst["view"], "facts">; remainingKeys: string[]; snapshotMaxFactSeq: number };
export type FactQueryCursor = {
  taskId: string;
  epochId: string;
  astDigest: string;
  snapshotMaxFactSeq: number;
} & (
  | { mode: "FACT_SEQ"; lastFactSeq: number }
  | { mode: "REMAINING"; remainingFactSeqs: number[] }
  // 兼容升级前已持久化的默认顺序游标；新游标始终带 mode。
  | { mode?: undefined; lastFactSeq: number }
);

export function validateFactQuery(ast: FactQueryAst): void {
  if (!(ast.view in allowedFields)) throw new InvalidArgumentError("未知 query_facts 视图");
  if (!Number.isInteger(ast.limit) || ast.limit < 1 || ast.limit > 500) throw new InvalidArgumentError("query limit 必须在 1..500");
  const allowed = allowedFields[ast.view];
  if (ast.select.length < 1 || ast.select.length > 32 || ast.select.some((field) => !allowed.has(field))) throw new InvalidArgumentError("query select 含非法字段或超过上限");
  if ((ast.orderBy?.length ?? 0) > 3) throw new InvalidArgumentError("query orderBy 超过上限");
  if (ast.orderBy?.some((item) => !allowed.has(item.field))) throw new InvalidArgumentError("query orderBy 含非法字段");
  if (ast.view === "facts") {
    if (ast.predicate && !ast.namespace) throw new InvalidArgumentError("带 predicate 的 facts 查询必须指定 namespace");
    if (ast.namespace) validatePredicate(ast.namespace, ast.predicate, { depth: PROTOCOL_MANIFEST.hardLimits.queryPredicateDepth!, nodes: PROTOCOL_MANIFEST.hardLimits.queryPredicateNodes! });
    if (ast.category || ast.authorType || ast.verdict || ast.status || ast.applicability) throw new InvalidArgumentError("facts 视图不接受其他视图的过滤条件");
  } else if (ast.namespace || ast.predicate || ast.sourceKind || ast.completeness) {
    throw new InvalidArgumentError(`${ast.view} 视图不接受 facts 专用过滤条件`);
  }
  if (ast.view === "edges" && (ast.category || ast.authorType || ast.verdict || ast.status || ast.applicability)) throw new InvalidArgumentError("edges 视图过滤条件不合法");
  if (ast.view === "evidence_meta" && (ast.sourceRunId || ast.category || ast.authorType || ast.verdict || ast.status || ast.applicability)) throw new InvalidArgumentError("evidence_meta 视图过滤条件不合法");
  if (ast.view === "assessments" && (ast.sourceRunId || ast.status || ast.applicability)) throw new InvalidArgumentError("assessments 视图过滤条件不合法");
  if (ast.view === "coverage" && (ast.sourceRunId || ast.subjectRef || ast.authorType || ast.verdict)) throw new InvalidArgumentError("coverage 视图过滤条件不合法");
}

export function runFactQuery(
  taskId: string,
  epochId: string,
  ast: FactQueryAst,
  facts: readonly FactRecord[],
  snapshotMaxFactSeq: number,
  cursor?: FactQueryCursor,
): { page: FactQueryPage; snapshot: QuerySnapshot; cursor?: { ref: string; value: FactQueryCursor } } {
  validateFactQuery(ast);
  if (ast.view !== "facts") throw new InvalidArgumentError("runFactQuery 只处理 facts 视图");
  const canonicalAst = { ...ast, cursorRef: undefined, limit: undefined };
  const astDigest = digestObject(canonicalAst);
  if (cursor && (cursor.taskId !== taskId || cursor.epochId !== epochId || cursor.astDigest !== astDigest)) throw new SecurityError("INVALID_ARGUMENT", "Query cursor 与当前 task/epoch/query 不匹配");
  let candidates = facts.filter((fact) => fact.taskId === taskId && fact.epochId === epochId && fact.factSeq <= snapshotMaxFactSeq);
  if (ast.namespace) candidates = candidates.filter((fact) => fact.namespace === ast.namespace);
  if (ast.sourceRunId) candidates = candidates.filter((fact) => fact.sourceRunId === ast.sourceRunId);
  if (ast.subjectRef) candidates = candidates.filter((fact) => fact.subjectRef === ast.subjectRef);
  if (ast.sourceKind) candidates = candidates.filter((fact) => fact.source.kind === ast.sourceKind);
  if (ast.completeness) candidates = candidates.filter((fact) => fact.completeness === ast.completeness);
  if (ast.predicate) candidates = candidates.filter((fact) => evaluatePredicate(ast.predicate, fact.modelPayload));
  const order = ast.orderBy ?? [{ field: "factSeq", direction: "asc" as const }];
  const defaultFactOrder = order.length === 1 && order[0]?.field === "factSeq" && order[0].direction === "asc";
  if (cursor?.mode === "REMAINING") {
    const bySeq = new Map(candidates.map((fact) => [fact.factSeq, fact]));
    candidates = cursor.remainingFactSeqs.flatMap((factSeq) => bySeq.get(factSeq) ? [bySeq.get(factSeq)!] : []);
  } else {
    if (cursor) candidates = candidates.filter((fact) => fact.factSeq > cursor.lastFactSeq);
    candidates.sort((left, right) => compare(left, right, order) || left.factSeq - right.factSeq);
  }
  const selected = candidates.slice(0, ast.limit);
  const rows = selected.map((fact) => Object.fromEntries(ast.select.map((field) => [field, project(fact, field)])));
  const queryRef = `QUERY-${randomUUID()}`;
  const last = selected.at(-1);
  const hasMore = candidates.length > selected.length;
  const next = hasMore && last ? {
    ref: `QCUR-${randomUUID()}`,
    value: defaultFactOrder
      ? { taskId, epochId, astDigest, mode: "FACT_SEQ" as const, lastFactSeq: last.factSeq, snapshotMaxFactSeq }
      : { taskId, epochId, astDigest, mode: "REMAINING" as const, remainingFactSeqs: candidates.slice(selected.length).map((fact) => fact.factSeq), snapshotMaxFactSeq },
  } : undefined;
  const snapshot: QuerySnapshot = { queryRef, taskId, epochId, view: "facts", astDigest, maxFactSeq: snapshotMaxFactSeq, rowCount: rows.length, rowRefs: selected.map((fact) => fact.factId), createdAt: new Date().toISOString() };
  return { page: { queryRef, rows, ...(next ? { nextCursorRef: next.ref } : {}), snapshotMaxFactSeq }, snapshot, ...(next ? { cursor: next } : {}) };
}

export function runStaticQuery(
  taskId: string,
  epochId: string,
  ast: FactQueryAst,
  rows: Array<Record<string, unknown> & { _key: string }>,
  snapshotMaxFactSeq: number,
  cursor?: StaticQueryCursor,
): { page: FactQueryPage; snapshot: QuerySnapshot; cursor?: { ref: string; value: StaticQueryCursor } } {
  validateFactQuery(ast);
  if (ast.view === "facts") throw new InvalidArgumentError("runStaticQuery 不处理 facts 视图");
  const canonicalAst = { ...ast, cursorRef: undefined, limit: undefined };
  const astDigest = digestObject(canonicalAst);
  if (cursor && (cursor.taskId !== taskId || cursor.epochId !== epochId || cursor.astDigest !== astDigest || cursor.view !== ast.view)) throw new SecurityError("INVALID_ARGUMENT", "Query cursor 与当前 task/epoch/query 不匹配");
  let candidates = rows;
  for (const field of ["sourceRunId", "category", "authorType", "verdict", "status", "applicability"] as const) {
    const expected = ast[field];
    if (expected !== undefined) candidates = candidates.filter((row) => row[field] === expected);
  }
  if (ast.subjectRef !== undefined) candidates = candidates.filter((row) => ast.view === "edges" ? row.fromRef === ast.subjectRef || row.toRef === ast.subjectRef : row.subjectRef === ast.subjectRef);
  if (cursor) {
    const byKey = new Map(candidates.map((row) => [row._key, row]));
    candidates = cursor.remainingKeys.flatMap((key) => byKey.get(key) ? [byKey.get(key)!] : []);
  } else {
    const order = ast.orderBy ?? [{ field: defaultOrderField(ast.view), direction: "asc" as const }];
    candidates = [...candidates].sort((left, right) => compareRows(left, right, order) || left._key.localeCompare(right._key));
  }
  const selected = candidates.slice(0, ast.limit);
  const remaining = candidates.slice(selected.length).map((row) => row._key);
  const projected = selected.map((row) => Object.fromEntries(ast.select.map((field) => [field, row[field]])));
  const queryRef = `QUERY-${randomUUID()}`;
  const next = remaining.length > 0 ? { ref: `QCUR-${randomUUID()}`, value: { taskId, epochId, astDigest, view: ast.view, remainingKeys: remaining, snapshotMaxFactSeq } satisfies StaticQueryCursor } : undefined;
  const snapshot: QuerySnapshot = { queryRef, taskId, epochId, view: ast.view, astDigest, maxFactSeq: snapshotMaxFactSeq, rowCount: projected.length, rowRefs: selected.map((row) => row._key), createdAt: new Date().toISOString() };
  return { page: { queryRef, rows: projected, ...(next ? { nextCursorRef: next.ref } : {}), snapshotMaxFactSeq }, snapshot, ...(next ? { cursor: next } : {}) };
}

function project(fact: FactRecord, field: string): unknown {
  if (field === "payload") return fact.modelPayload;
  return fact[field as keyof FactRecord];
}

function compare(left: FactRecord, right: FactRecord, order: NonNullable<FactQueryAst["orderBy"]>): number {
  for (const item of order) {
    const a = left[item.field as keyof FactRecord]; const b = right[item.field as keyof FactRecord];
    const value = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b));
    if (value !== 0) return item.direction === "asc" ? value : -value;
  }
  return 0;
}

function defaultOrderField(view: Exclude<FactQueryAst["view"], "facts">): string {
  return view === "edges" ? "observedAt" : view === "evidence_meta" ? "collectedAt" : "createdAt";
}

function compareRows(left: Record<string, unknown>, right: Record<string, unknown>, order: NonNullable<FactQueryAst["orderBy"]>): number {
  for (const item of order) {
    const a = left[item.field]; const b = right[item.field];
    const value = typeof a === "number" && typeof b === "number" ? a - b : String(a ?? "").localeCompare(String(b ?? ""));
    if (value !== 0) return item.direction === "asc" ? value : -value;
  }
  return 0;
}
