import { createId, type IdKind } from "../common/ids.js";
import { InvalidArgumentError } from "../common/errors.js";
import type { CandidateReference } from "../domain/types.js";
import type { RuntimeStore } from "../storage/runtime-store.js";

export function createReference<T>(
  store: RuntimeStore,
  taskId: string,
  kind: CandidateReference["kind"],
  idKind: IdKind,
  value: T,
): CandidateReference<T> {
  const reference: CandidateReference<T> = {
    ref: createId(idKind), taskId, kind, value, createdAt: new Date().toISOString(),
  };
  store.putReference(reference);
  return reference;
}

export function requireReference<T>(
  store: RuntimeStore,
  taskId: string,
  ref: string,
  kind: CandidateReference["kind"],
): CandidateReference<T> {
  const value = store.getReference<T>(taskId, ref, kind);
  if (!value) throw new InvalidArgumentError(`无效或跨任务引用: ${ref}`);
  return value;
}
