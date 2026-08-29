export function effectiveDeadlineTimeout(explicit: number | undefined, fallback: number): number {
  return explicit ?? fallback;
}
