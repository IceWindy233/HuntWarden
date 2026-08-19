import { describe, expect, it } from "vitest";
import { SecurityError } from "../../src/common/errors.js";
import { helperDeadline, parseHelperEnvelope } from "../../src/executor/ssh-executor.js";

function rejection(operation: string, raw: string): SecurityError {
  try {
    parseHelperEnvelope(operation, raw);
  } catch (error) {
    if (error instanceof SecurityError) return error;
    throw error;
  }
  throw new Error(`${operation} 未按预期抛出 SecurityError`);
}

describe("Helper Envelope 运行期校验", () => {
  it("透传结构完整的成功 Envelope，包含 partial 与 warnings", () => {
    const raw = JSON.stringify({ ok: true, result: { items: [{ pid: 1 }], partial: true, warnings: ["audit.log 不可用"] } });
    expect(parseHelperEnvelope("query_exec_events", raw)).toEqual({
      items: [{ pid: 1 }], partial: true, warnings: ["audit.log 不可用"],
    });
  });

  it("接受数组形态的 result", () => {
    const raw = JSON.stringify({ ok: true, result: [{ path: "/var/www/html/a.php", matches: [] }] });
    expect(parseHelperEnvelope("yara_scan_files", raw)).toEqual([{ path: "/var/www/html/a.php", matches: [] }]);
  });

  it("拒绝无效 JSON、非对象 Envelope 与标量 result", () => {
    expect(rejection("get_host_info", "not json").code).toBe("UNSUPPORTED_ENVIRONMENT");
    expect(() => parseHelperEnvelope("get_host_info", "[]")).toThrow(/Envelope 必须是 JSON 对象/);
    expect(() => parseHelperEnvelope("get_host_info", JSON.stringify({ ok: true, result: "done" }))).toThrow(/result 必须是对象或数组/);
    expect(() => parseHelperEnvelope("get_host_info", JSON.stringify({ ok: true, result: null }))).toThrow(/result 必须是对象或数组/);
  });

  it("拒绝缺少 ok 字段或缺少 result 的 Envelope", () => {
    expect(() => parseHelperEnvelope("get_host_info", JSON.stringify({ result: {} }))).toThrow(/缺少 ok 布尔字段/);
    expect(() => parseHelperEnvelope("get_host_info", JSON.stringify({ ok: "true", result: {} }))).toThrow(/缺少 ok 布尔字段/);
    expect(() => parseHelperEnvelope("get_host_info", JSON.stringify({ ok: true }))).toThrow(/必须含 result 字段/);
  });

  it("拒绝 partial、warnings 与 items 的类型漂移，而不是静默透传", () => {
    const partial = JSON.stringify({ ok: true, result: { items: [], partial: "yes", warnings: [] } });
    const warnings = JSON.stringify({ ok: true, result: { items: [], partial: false, warnings: [1, 2] } });
    const items = JSON.stringify({ ok: true, result: { items: { count: 1 }, partial: false, warnings: [] } });
    expect(() => parseHelperEnvelope("list_suspicious_processes", partial)).toThrow(/result\.partial 必须是 boolean/);
    expect(() => parseHelperEnvelope("list_suspicious_processes", warnings)).toThrow(/result\.warnings 必须是字符串数组/);
    expect(() => parseHelperEnvelope("list_suspicious_processes", items)).toThrow(/result\.items 必须是数组/);
  });

  it("按已知错误码映射失败 Envelope", () => {
    const denied = JSON.stringify({ ok: false, error: { code: "PERMISSION_DENIED", message: "cannot read process identity" } });
    const invalid = JSON.stringify({ ok: false, error: { code: "INVALID_ARGUMENT", message: "invalid maxFiles" } });
    expect(rejection("inspect_process_fds", denied).code).toBe("PERMISSION_DENIED");
    expect(rejection("inspect_process_fds", denied).message).toBe("cannot read process identity");
    expect(rejection("find_recent_web_files", invalid).code).toBe("INVALID_ARGUMENT");
  });

  it("未知错误码与残缺 error 结构一律视为协议违规", () => {
    const unknown = JSON.stringify({ ok: false, error: { code: "NOT_A_CODE", message: "boom" } });
    const truncated = JSON.stringify({ ok: false, error: { message: "boom" } });
    const missing = JSON.stringify({ ok: false });
    expect(() => parseHelperEnvelope("get_host_info", unknown)).toThrow(/未知错误码 NOT_A_CODE/);
    expect(rejection("get_host_info", unknown).code).toBe("UNSUPPORTED_ENVIRONMENT");
    expect(() => parseHelperEnvelope("get_host_info", truncated)).toThrow(/error\.code 与 error\.message/);
    expect(() => parseHelperEnvelope("get_host_info", missing)).toThrow(/error\.code 与 error\.message/);
  });
});

describe("helper 墙钟预算注入", () => {
  it("为 SSH 往返预留 5s headroom", () => {
    expect(helperDeadline(30_000)).toBe(25_000);
    expect(helperDeadline(120_000)).toBe(115_000);
  });

  it("短超时收敛到 helper 接受的下限，长超时不超过上限", () => {
    expect(helperDeadline(5_000)).toBe(1_000);
    expect(helperDeadline(1_000)).toBe(1_000);
    expect(helperDeadline(900_000)).toBe(600_000);
  });
});
