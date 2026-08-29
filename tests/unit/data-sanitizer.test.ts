import { describe, expect, it } from "vitest";
import { redactValue, sanitizeForLlm, serializeToolResultForLlm } from "../../src/agent/data-sanitizer.js";

describe("sanitizeForLlm", () => {
  it("删除凭据并保留允许的主机信息", () => {
    const result = sanitizeForLlm("host=10.0.0.8 path=/var/www/a.php password=hunter2 Authorization: Bearer abc.def Cookie: sid=123");
    expect(result.text).toContain("10.0.0.8");
    expect(result.text).toContain("/var/www/a.php");
    expect(result.text).not.toContain("hunter2");
    expect(result.text).not.toContain("abc.def");
    expect(result.text).not.toContain("sid=123");
  });

  it("包含截断标记时仍严格不超过 64 KiB", () => {
    const result = sanitizeForLlm("安全日志🙂".repeat(20_000), 65_536);
    expect(result.truncated).toBe(true);
    expect(Buffer.byteLength(result.text, "utf8")).toBeLessThanOrEqual(65_536);
    expect(result.outputBytes).toBe(Buffer.byteLength(result.text, "utf8"));
    expect(result.text).toContain("[TRUNCATED:");
  });
});

describe("redactValue", () => {
  it("脱敏不跨行吞掉后续代码", () => {
    // 正则一旦作用在 JSON.stringify 的结果上，字符串里的换行是 `\` + `n`，`\s` 匹配不到，
    // `[^\s,;]+` 会一路吃到下一个 `;`，把 `@eval(...)` 整段删掉，恶意文件在模型眼里变干净。
    const source = "$secret=Ax9k2Lm\n@eval($_POST[$secret]);";
    const redacted = redactValue({ excerpt: source });

    expect(JSON.stringify(redacted)).not.toContain("Ax9k2Lm");
    expect(JSON.stringify(redacted)).toContain("@eval($_POST[$secret])");
  });

  it("抹掉结构化字段里的凭据值，但保留同名判定字段", () => {
    const redacted = redactValue({
      password: "Hunter2",
      dbPassword: "Hunter3",
      "csrf-token": "Hunter4",
      passwordLocked: false,
      lastPasswordChangeDays: 19_800,
    });
    const encoded = JSON.stringify(redacted);

    expect(encoded).not.toContain("Hunter2");
    expect(encoded).not.toContain("Hunter3");
    expect(encoded).not.toContain("Hunter4");
    expect(encoded).toContain("\"passwordLocked\":false");
    expect(encoded).toContain("\"lastPasswordChangeDays\":19800");
  });

  it("脱敏访问日志里的后门口令参数", () => {
    const line = '1.2.3.4 - - [20/Aug/2026:03:12:44 +0800] "POST /uploads/x.php?token=9f2b1c HTTP/1.1" 200 31';
    const encoded = JSON.stringify(redactValue({ items: [{ raw: line }] }));

    expect(encoded).not.toContain("9f2b1c");
    expect(encoded).toContain("/uploads/x.php");
    expect(() => JSON.parse(encoded)).not.toThrow();
  });
});

describe("serializeToolResultForLlm", () => {
  const result = (count: number) => ({
    status: "success" as const,
    summary: { count },
    items: Array.from({ length: count }, (_unused, index) => ({ path: `/tmp/file-${index}`, sha256: String(index % 10).repeat(64), inode: String(index) })),
    artifactRefs: Array.from({ length: count }, (_unused, index) => `CAND-${index}`),
    warnings: [],
  });

  it("未超预算时原样保留全部条目", () => {
    const encoded = serializeToolResultForLlm(result(3), 65_536);
    expect(encoded.truncated).toBe(false);
    expect(encoded.omitted).toBe(0);
    const parsed = JSON.parse(encoded.text) as { items: unknown[]; status: string };
    expect(parsed.items).toHaveLength(3);
    expect(parsed.status).toBe("success");
  });

  it("超预算时输出仍是合法 JSON，并显式声明省略了多少条", () => {
    const total = 4_000;
    const encoded = serializeToolResultForLlm(result(total), 65_536);

    expect(encoded.truncated).toBe(true);
    expect(encoded.outputBytes).toBeLessThanOrEqual(65_536);
    const parsed = JSON.parse(encoded.text) as {
      status: string; items: unknown[]; itemsOmitted: number; summary: { count: number }; warnings: string[];
    };
    // 结构化省略：模型能解析，能对比 summary.count 与 items.length，能知道差额并回取。
    expect(parsed.status).toBe("partial");
    expect(parsed.summary.count).toBe(total);
    expect(parsed.items.length).toBeGreaterThan(0);
    expect(parsed.items.length).toBeLessThan(total);
    expect(parsed.itemsOmitted).toBe(total - parsed.items.length);
    expect(parsed.warnings.join(" ")).toContain("query_facts");
  });

  it("不可丢弃部分本身超预算时降级为固定小信封而不是坏 JSON", () => {
    const encoded = serializeToolResultForLlm({
      status: "success",
      summary: { note: "x".repeat(200_000) },
      items: [{ a: 1 }],
      artifactRefs: [],
      warnings: [],
    }, 4_096);

    expect(encoded.outputBytes).toBeLessThanOrEqual(4_096);
    const parsed = JSON.parse(encoded.text) as { status: string; items: unknown[]; itemsOmitted: number };
    expect(parsed.status).toBe("partial");
    expect(parsed.items).toHaveLength(0);
    expect(parsed.itemsOmitted).toBe(1);
  });

  it("分页结果截断后按实际可见条目重写 returned 与 nextOffset", () => {
    const total = 200;
    const offset = 20;
    const page = Array.from({ length: total - offset }, (_unused, index) => ({
      index: index + offset,
      value: "x".repeat(120),
    }));
    const encoded = serializeToolResultForLlm({
      status: "success",
      summary: { toolCallId: "CORE-page", tool: "demo", total, offset, returned: page.length, nextOffset: total, remaining: 0 },
      items: page,
      artifactRefs: [],
      warnings: [],
    }, 4_096);
    const parsed = JSON.parse(encoded.text) as {
      summary: { offset: number; returned: number; nextOffset: number; remaining: number };
      items: unknown[];
      itemsOmitted: number;
    };

    expect(encoded.truncated).toBe(true);
    expect(parsed.summary.returned).toBe(parsed.items.length);
    expect(parsed.summary.nextOffset).toBe(offset + parsed.items.length);
    expect(parsed.summary.remaining).toBe(total - parsed.summary.nextOffset);
    expect(parsed.itemsOmitted).toBe(total - offset - parsed.items.length);
  });
});
