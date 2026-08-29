import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import type { ForensicVerb } from "../../src/executor/protocol-v2-executor.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import type { WireRequest, WireSuccess } from "../../src/protocol-v2/types.js";

const enabled = process.env.HUNTWARDEN_VM_JOURNAL_TESTS === "1";
const run = promisify(execFile);

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`缺少真实 VM journald 验收环境变量: ${name}`);
  return value;
}

describe.skipIf(!enabled)("授权真实 VM journald 身份与 generation 验收", () => {
  let remote: SSHExecutor;
  let sequence = 0;
  let vmName: string;

  async function invoke(verb: ForensicVerb, params: Record<string, unknown>): Promise<WireSuccess> {
    sequence += 1;
    const requestId = `VM-JOURNAL-${sequence}`;
    const request: WireRequest = {
      protocolVersion: 2, requestId, epochId: "EPOCH-VM-JOURNAL", deadlineMs: 60_000,
      reservation: { reservationId: `BRES-${requestId}`, estimate: { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 0 } },
      params,
    };
    const response = await remote.invokeV2(verb, request);
    if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message}`);
    return response;
  }

  async function allPages(verb: "enumerate" | "relate", params: Record<string, unknown>): Promise<WireSuccess["objects"]> {
    const objects: WireSuccess["objects"] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const response = await invoke(verb, { ...params, limit: 500, ...(cursor ? { cursor } : {}) });
      objects.push(...response.objects);
      cursor = response.cursor;
      if (!cursor) return objects;
    }
    throw new Error(`${verb} 超过 journald 验收分页上限`);
  }

  beforeAll(async () => {
    if (required("HUNTWARDEN_VM_CONFIRM_READ_ONLY") !== "I_HAVE_AUTHORIZATION"
      || required("HUNTWARDEN_VM_CONFIRM_JOURNAL_FIXTURE") !== "I_HAVE_AUTHORIZATION") {
      throw new Error("必须显式确认 VM 授权与无害 journal fixture 写入授权");
    }
    vmName = required("HUNTWARDEN_VM_MULTIPASS_NAME");
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(vmName)) throw new Error("Multipass VM 名称无效");
    const port = Number(required("HUNTWARDEN_VM_PORT"));
    const privateKeyPath = required("HUNTWARDEN_VM_PRIVATE_KEY");
    const knownHostsPath = required("HUNTWARDEN_VM_KNOWN_HOSTS");
    if (!Number.isInteger(port) || port < 1 || port > 65_535 || !isAbsolute(privateKeyPath) || !isAbsolute(knownHostsPath)) throw new Error("VM SSH 配置无效");
    await Promise.all([readFile(privateKeyPath), readFile(knownHostsPath)]);
    const target: TargetConfig = {
      host: required("HUNTWARDEN_VM_HOST"), port, username: required("HUNTWARDEN_VM_USER"),
      hostFingerprint: required("HUNTWARDEN_VM_FINGERPRINT"), privateKeyPath, knownHostsPath,
    };
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 60_000);
    await remote.getCapabilitiesV2();
  }, 120_000);

  afterAll(async () => await remote?.close());

  it("journald 是可关联的一等 log_source，追加事件推进 generation 且事件身份稳定", async () => {
    const sourcesBefore = await allPages("enumerate", { namespace: "log_source", fields: ["sourceId", "generation", "kind", "path"] });
    const journalBefore = sourcesBefore.find((item) => item.fields.kind === "journald");
    if (!journalBefore) throw new Error("真实 VM 未声明 journald log_source");
    expect(String(journalBefore.fields.path)).toMatch(/^\/(?:run|var)\/log\/journal$/);

    const marker = `huntwarden-v2-journal-${Date.now()}`;
    await run("multipass", ["exec", vmName, "--", "logger", "--tag", "huntwarden-v2-acceptance", "--", marker], { timeout: 30_000 });

    let journalAfter: WireSuccess["objects"][number] | undefined;
    let markerEvent: WireSuccess["objects"][number] | undefined;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const [sources, events] = await Promise.all([
        allPages("enumerate", { namespace: "log_source", fields: ["sourceId", "generation", "kind", "path"] }),
        allPages("enumerate", { namespace: "log_event", fields: ["sourceId", "cursor", "timestamp", "program", "message"], sinceHours: 1 }),
      ]);
      journalAfter = sources.find((item) => item.fields.kind === "journald");
      markerEvent = events.find((item) => item.fields.program === "huntwarden-v2-acceptance" && String(item.fields.message).includes(marker));
      if (journalAfter?.fields.generation !== journalBefore.fields.generation && markerEvent) break;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    if (!journalAfter || !markerEvent) throw new Error("journal fixture 未在时限内成为 v2 事件");
    expect(journalAfter.fields.generation).not.toBe(journalBefore.fields.generation);
    expect(markerEvent.fields.sourceId).toBe(journalAfter.fields.sourceId);

    const repeated = await allPages("enumerate", { namespace: "log_event", fields: ["sourceId", "cursor", "timestamp", "program", "message"], sinceHours: 1 });
    const sameEvent = repeated.find((item) => item.fields.program === "huntwarden-v2-acceptance" && String(item.fields.message).includes(marker));
    expect(sameEvent?.identity).toEqual(markerEvent.identity);

    const contained = await allPages("relate", {
      namespace: "log_source", identity: journalAfter.identity, locator: { path: journalAfter.fields.path }, relation: "contains",
    });
    const relatedMarker = contained.find((item) => item.namespace === "log_event" && item.fields.program === "huntwarden-v2-acceptance" && String(item.fields.message).includes(marker));
    expect(relatedMarker?.fields.sourceId).toBe(journalAfter.fields.sourceId);
    expect(contained.some((item) => item.namespace === "auth_event" && item.fields.sourceId === journalAfter.fields.sourceId)).toBe(true);
  }, 120_000);
});
