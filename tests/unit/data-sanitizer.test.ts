import { describe, expect, it } from "vitest";
import { sanitizeForLlm } from "../../src/agent/data-sanitizer.js";

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
