export interface RemotePageCompleteness {
  status?: unknown;
  cursorRef?: unknown;
  gaps?: unknown;
}

/** NODE_LIMIT 只表示当前页装满；存在续页且最终被耗尽时不构成覆盖缺口。 */
export function isIncompleteRemotePage(details: RemotePageCompleteness): boolean {
  if (details.status !== "partial") return false;
  const gaps = Array.isArray(details.gaps) ? details.gaps : [];
  const onlyResumablePageBoundary = typeof details.cursorRef === "string" && gaps.length > 0 && gaps.every((value) => {
    if (!value || typeof value !== "object") return false;
    const gap = value as Record<string, unknown>;
    return gap.code === "NODE_LIMIT" && gap.resumable === true;
  });
  return !onlyResumablePageBoundary;
}
