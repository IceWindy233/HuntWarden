const SECRET_PATTERNS: RegExp[] = [
  /(?<=\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+/giu,
  /(?<=\bAuthorization:\s*(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+/giu,
  /(?<=\bCookie:\s*)[^\r\n]+/giu,
  /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/giu,
];

export interface SanitizedText {
  text: string;
  truncated: boolean;
  originalBytes: number;
  outputBytes: number;
}

export function sanitizeForLlm(input: string, maxBytes = 65_536): SanitizedText {
  let text = input;
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, "[REDACTED]");

  const originalBytes = Buffer.byteLength(text, "utf8");
  if (originalBytes <= maxBytes) {
    return { text, truncated: false, originalBytes, outputBytes: originalBytes };
  }

  const marker = `\n[TRUNCATED: original=${originalBytes} bytes]`;
  const contentBudget = Math.max(0, maxBytes - Buffer.byteLength(marker, "utf8"));
  let output = Buffer.from(text, "utf8").subarray(0, contentBudget).toString("utf8");
  while (Buffer.byteLength(output + marker, "utf8") > maxBytes) output = output.slice(0, -1);
  const result = output + marker;
  return {
    text: result,
    truncated: true,
    originalBytes,
    outputBytes: Buffer.byteLength(result, "utf8"),
  };
}
