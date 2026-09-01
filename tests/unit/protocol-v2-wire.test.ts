import { describe, expect, it } from "vitest";
import { helperDeadline } from "../../src/executor/ssh-executor.js";
import { assertCostWithinReservation, parseWireResponse } from "../../src/protocol-v2/wire.js";

const cost = { remoteCalls: 1, nodes: 1, bytes: 256, wallTimeMs: 10, probeCalls: 0 };

describe("v2 Wire Envelope 运行期校验", () => {
  it("接受身份匹配的 SUCCESS 与带 CoverageGap 的 PARTIAL", () => {
    const success = JSON.stringify({ protocolVersion: 2, requestId: "REQ-1", status: "SUCCESS", objects: [], edges: [], gaps: [], cost });
    expect(parseWireResponse(success, "REQ-1")).toMatchObject({ status: "SUCCESS", requestId: "REQ-1" });
    const partial = JSON.stringify({ protocolVersion: 2, requestId: "REQ-2", status: "PARTIAL", objects: [], edges: [], gaps: [{ code: "NODE_LIMIT", resumable: true }], cost });
    expect(parseWireResponse(partial, "REQ-2")).toMatchObject({ status: "PARTIAL", gaps: [{ code: "NODE_LIMIT", resumable: true }] });
  });

  it("拒绝错误协议、请求串线、未知状态与无缺口的 PARTIAL", () => {
    expect(() => parseWireResponse("not json", "REQ-1")).toThrow(/无效 JSON/);
    expect(() => parseWireResponse(JSON.stringify({ protocolVersion: 1, requestId: "REQ-1", status: "SUCCESS", objects: [], edges: [], gaps: [], cost }), "REQ-1")).toThrow(/身份不匹配/);
    expect(() => parseWireResponse(JSON.stringify({ protocolVersion: 2, requestId: "OTHER", status: "SUCCESS", objects: [], edges: [], gaps: [], cost }), "REQ-1")).toThrow(/身份不匹配/);
    expect(() => parseWireResponse(JSON.stringify({ protocolVersion: 2, requestId: "REQ-1", status: "PARTIAL", objects: [], edges: [], gaps: [], cost }), "REQ-1")).toThrow(/CoverageGap/);
    // CoverageGap 白名单必须与 InvestigationGap 码空间不相交：模型侧的授权/预算缺口
    // 不能伪装成目标采集缺口混进 Coverage。
    expect(() => parseWireResponse(JSON.stringify({ protocolVersion: 2, requestId: "REQ-1", status: "PARTIAL", objects: [], edges: [], gaps: [{ code: "GRANT_DENIED", resumable: false }], cost }), "REQ-1")).toThrow(/非法 CoverageGap/);
    expect(() => parseWireResponse(JSON.stringify({ protocolVersion: 2, requestId: "REQ-1", status: "PARTIAL", objects: [], edges: [], gaps: [{ code: "NODE_LIMIT" }], cost }), "REQ-1")).toThrow(/非法 CoverageGap/);
  });

  it("只接受白名单错误码和合法成本，并拒绝超过 Reservation 的实际成本", () => {
    const error = JSON.stringify({ protocolVersion: 2, requestId: "REQ-3", status: "ERROR", error: { code: "SOURCE_CHANGED", message: "changed" }, cost });
    expect(parseWireResponse(error, "REQ-3")).toMatchObject({ status: "ERROR", error: { code: "SOURCE_CHANGED" } });
    const unknown = JSON.stringify({ protocolVersion: 2, requestId: "REQ-3", status: "ERROR", error: { code: "INVENTED", message: "bad" }, cost });
    expect(() => parseWireResponse(unknown, "REQ-3")).toThrow(/未知错误码/);
    expect(() => assertCostWithinReservation({ ...cost, nodes: 2 }, cost)).toThrow(/超过预算预留/);
  });
});

describe("helper 墙钟预算", () => {
  it("保留 SSH headroom，并夹在 helper 接受范围内", () => {
    expect(helperDeadline(30_000)).toBe(25_000);
    expect(helperDeadline(120_000)).toBe(115_000);
    expect(helperDeadline(1_000)).toBe(1_000);
    expect(helperDeadline(900_000)).toBe(600_000);
  });
});
