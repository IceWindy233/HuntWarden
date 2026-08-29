/**
 * 进入模型上下文之前的脱敏与预算内序列化。
 *
 * 两条不变量：
 * 1. **脱敏发生在序列化之前。** 正则一旦作用在 `JSON.stringify` 的输出上，字符串里的换行是
 *    `\` + `n` 两个字符，`\s` 匹配不到，`[^\s,;]+` 会跨行吞掉后续真实代码（实测会删除
 *    `@eval(...)`），并且会吃掉 `"}` 使 JSON 结构损坏。因此纯文本正则只允许作用在真正的
 *    字符串叶子上。
 * 2. **超预算按结构丢弃，不按字节切。** 字节切会把 JSON 切成非法文本，模型既无法解析、
 *    也无法得知丢了什么。改为丢弃数组尾部元素并显式写回 `status: "partial"` +
 *    `itemsOmitted` + warning；v2 事实由 Fact Plane 固化，可据此缩小查询或用 `query_facts` 回取。
 */

const SECRET_PATTERNS: RegExp[] = [
  /(?<=\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+/giu,
  /(?<=\bAuthorization:\s*(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+/giu,
  /(?<=\bCookie:\s*)[^\r\n]+/giu,
  /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/giu,
];

/** 粗筛：绝大多数字符串叶子不含凭据形态，先用一次 test 避开四次 replace。 */
const SECRET_HINT = /password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|BEGIN [^-]*PRIVATE KEY/iu;

/**
 * 结构化字段的凭据键名。
 *
 * 按"规范化键名以关键词结尾"判定，因此 `dbPassword`、`csrf-token`、`X_API_KEY` 都会被整体
 * 抹掉，而 HuntWarden 自己的 `passwordLocked`、`lastPasswordChangeDays` 这类**判定字段不会**
 * 被误删 —— 它们是分析依据，不是凭据。
 */
const SECRET_KEY_SUFFIXES = [
  "password", "passwd", "pwd", "secret", "token", "apikey", "authorization", "cookie", "privatekey",
] as const;

const REDACTED = "[REDACTED]";

function isSecretKey(key: string): boolean {
  const normalized = key.toLowerCase().replaceAll(/[_\-\s]/gu, "");
  return SECRET_KEY_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

/** 对单个字符串叶子脱敏。作用在真实字符串上，`\s` 能匹配换行，因此匹配不会跨行蔓延。 */
export function redactText(input: string): string {
  if (!SECRET_HINT.test(input)) return input;
  let text = input;
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, REDACTED);
  return text;
}

/** 深度脱敏：字符串叶子按正则处理，凭据键名整体抹掉。返回新值，不修改入参。 */
export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item));
  if (value === null || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    output[key] = isSecretKey(key) ? REDACTED : redactValue(item);
  }
  return output;
}

export interface SanitizedText {
  text: string;
  truncated: boolean;
  originalBytes: number;
  outputBytes: number;
}

/**
 * 纯文本路径：脱敏后按 UTF-8 字节截断。
 *
 * 只用于本身就是自由文本、没有结构可保留的载荷（当前仅崩溃恢复的远端回执文本）。
 * 结构化结果一律走 `serializeToolResultForLlm` / `encodeWithinBudget`。
 */
export function sanitizeForLlm(input: string, maxBytes = 65_536): SanitizedText {
  const text = redactText(input);
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

export interface BudgetedJson {
  /** 始终是合法 JSON。 */
  text: string;
  truncated: boolean;
  /** 被丢弃的可丢弃元素个数。 */
  omitted: number;
  /** 完整载荷（未丢弃）的字节数。 */
  originalBytes: number;
  outputBytes: number;
  /** 连保留 0 个可丢弃元素都超预算：不可丢弃部分本身太大。 */
  overBudget: boolean;
}

/**
 * 预算内序列化。**入参必须已经过 `redactValue`**，本函数只做编码与取舍。
 *
 * `rebuild(keep)` 必须返回"只保留前 `keep` 个可丢弃元素"的完整值。命中预算的常见路径只序列化
 * 一次；超预算时按二分法定位最大可保留前缀，序列化次数是 O(log n) 而不是 O(n)。
 */
export function encodeWithinBudget(
  totalDroppable: number,
  rebuild: (keep: number) => unknown,
  maxBytes: number,
): BudgetedJson {
  const encode = (keep: number) => {
    const text = JSON.stringify(rebuild(keep)) ?? "null";
    return { text, bytes: Buffer.byteLength(text, "utf8") };
  };

  const full = encode(totalDroppable);
  if (full.bytes <= maxBytes) {
    return { text: full.text, truncated: false, omitted: 0, originalBytes: full.bytes, outputBytes: full.bytes, overBudget: false };
  }

  let low = 0;
  let high = totalDroppable - 1;
  let bestKeep = -1;
  let bestText = "";
  let bestBytes = 0;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const attempt = encode(middle);
    if (attempt.bytes <= maxBytes) {
      bestKeep = middle;
      bestText = attempt.text;
      bestBytes = attempt.bytes;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }

  if (bestKeep < 0) {
    const floor = encode(0);
    return { text: floor.text, truncated: true, omitted: totalDroppable, originalBytes: full.bytes, outputBytes: floor.bytes, overBudget: true };
  }
  return {
    text: bestText,
    truncated: true,
    omitted: totalDroppable - bestKeep,
    originalBytes: full.bytes,
    outputBytes: bestBytes,
    overBudget: false,
  };
}

interface ItemsEnvelope {
  status: unknown;
  items: unknown[];
  warnings: unknown;
}

function hasDroppableItems(value: unknown): value is ItemsEnvelope {
  return value !== null && typeof value === "object"
    && "items" in value && Array.isArray(value.items)
    && "status" in value && "warnings" in value;
}

function omissionWarning(omitted: number, total: number): string {
  return `结果超出模型文本预算：共 ${total} 项，已省略末尾 ${omitted} 项；事实仍在 Model Fact Plane，可用 query_facts 查询，省略不代表不存在。`;
}

/**
 * 分页工具的 summary 必须描述**实际进入模型上下文**的条目数。
 *
 * 分页结果会先构造 offset 后的全部剩余条目，再由本序列化器按字节预算取前缀；如果
 * 仍保留截断前的 `returned`，模型按 `offset + returned` 翻页就会直接跳过被省略的中间条目。
 */
function adjustPaginationSummary(summary: unknown, keep: number): unknown {
  if (summary === null || typeof summary !== "object" || Array.isArray(summary)) return summary;
  if (!("offset" in summary) || typeof summary.offset !== "number" || !Number.isInteger(summary.offset)) return summary;
  if (!("returned" in summary) || typeof summary.returned !== "number") return summary;
  const nextOffset = summary.offset + keep;
  const total = "total" in summary && typeof summary.total === "number" ? summary.total : undefined;
  return {
    ...summary,
    returned: keep,
    nextOffset,
    ...(total === undefined ? {} : { remaining: Math.max(0, total - nextOffset) }),
  };
}

/**
 * 工具结果进入模型上下文的唯一路径。
 *
 * `SecurityToolResult` 形状的载荷丢弃 `items` 尾部并写回 `status: "partial"`、`itemsOmitted`
 * 与一条 warning；`summary` 里的真实总数（如 `count`）保持不变，模型可用它与 `items.length`
 * 对比得知缺口。非该形状的载荷整体编码，超预算时降级为固定小信封。
 */
export function serializeToolResultForLlm(details: unknown, maxBytes: number): BudgetedJson {
  const redacted = redactValue(details);
  if (!hasDroppableItems(redacted)) {
    const encoded = encodeWithinBudget(0, () => redacted, maxBytes);
    if (!encoded.overBudget) return encoded;
    return encodeWithinBudget(0, () => ({
      status: "partial",
      summary: { note: "结果摘要超出模型文本预算，未进入模型上下文" },
      items: [],
      artifactRefs: [],
      warnings: [omissionWarning(0, 0)],
    }), maxBytes);
  }

  const total = redacted.items.length;
  const baseWarnings = Array.isArray(redacted.warnings) ? redacted.warnings : [];
  const encoded = encodeWithinBudget(total, (keep) => (keep === total ? redacted : {
    ...redacted,
    status: "partial",
    ...("summary" in redacted ? { summary: adjustPaginationSummary(redacted.summary, keep) } : {}),
    items: redacted.items.slice(0, keep),
    itemsOmitted: total - keep,
    warnings: [...baseWarnings, omissionWarning(total - keep, total)],
  }), maxBytes);
  if (!encoded.overBudget) return encoded;

  return encodeWithinBudget(0, () => ({
    status: "partial",
    summary: { note: "结果摘要超出模型文本预算，未进入模型上下文" },
    items: [],
    itemsOmitted: total,
    artifactRefs: [],
    warnings: [omissionWarning(total, total)],
  }), maxBytes);
}
