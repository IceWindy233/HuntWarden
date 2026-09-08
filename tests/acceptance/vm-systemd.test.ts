import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import type { ForensicVerb } from "../../src/executor/protocol-v2-executor.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import type { WireRequest, WireSuccess } from "../../src/protocol-v2/types.js";

const enabled = process.env.HUNTWARDEN_VM_SYSTEMD_TESTS === "1";
const run = promisify(execFile);

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`缺少真实 VM systemd 验收环境变量: ${name}`);
  return value;
}

describe.skipIf(!enabled)("授权真实 VM systemd transient unit 验收", () => {
  let remote: SSHExecutor;
  let sequence = 0;
  let vmName = "";
  const unitName = "huntwarden-transient-acceptance.service";

  async function invoke(verb: ForensicVerb, params: Record<string, unknown>): Promise<WireSuccess> {
    sequence += 1;
    const requestId = `VM-SYSTEMD-${sequence}`;
    const response = await remote.invokeV2(verb, {
      protocolVersion: 2, requestId, epochId: "EPOCH-VM-SYSTEMD", deadlineMs: 60_000,
      reservation: { reservationId: `BRES-${requestId}`, estimate: { remoteCalls: 1, nodes: 5_000, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 0 } },
      params,
    } satisfies WireRequest);
    if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message}`);
    return response;
  }

  async function allUnits(): Promise<WireSuccess["objects"]> {
    const objects: WireSuccess["objects"] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const response = await invoke("enumerate", {
        namespace: "unit", fields: ["name", "path", "active", "transient", "execStart", "user"],
        predicate: { op: "eq", field: "name", value: unitName }, limit: 500, ...(cursor ? { cursor } : {}),
      });
      objects.push(...response.objects);
      cursor = response.cursor;
      if (!cursor) return objects;
    }
    throw new Error("systemd unit 枚举超过验收分页上限");
  }

  beforeAll(async () => {
    if (required("HUNTWARDEN_VM_CONFIRM_READ_ONLY") !== "I_HAVE_AUTHORIZATION"
      || required("HUNTWARDEN_VM_CONFIRM_SYSTEMD_FIXTURE") !== "I_HAVE_AUTHORIZATION") {
      throw new Error("必须显式确认 VM 授权与无害 systemd transient fixture 授权");
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
    await run("multipass", ["exec", vmName, "--", "sudo", "systemd-run", `--unit=${unitName}`, "--property=Type=exec", "/usr/bin/sleep", "300"], { timeout: 30_000 });
  }, 120_000);

  afterAll(async () => {
    await remote?.close();
    if (!vmName) return;
    try {
      await run("multipass", ["exec", vmName, "--", "sudo", "systemctl", "stop", unitName], { timeout: 30_000 });
    } catch {
      // VM 或 unit 已停止时无需掩盖原始验收结果；systemd-run 的 transient unit 不会持久化到下次启动。
    }
  });

  it("从运行态 transient fragment 读取身份、命令并关联执行文件", async () => {
    const units = await allUnits();
    const unit = units.find((item) => item.fields.name === unitName);
    if (!unit) throw new Error("未发现 systemd transient fixture");
    expect(unit.fields).toMatchObject({ transient: true, active: true, user: "root" });
    expect(String(unit.fields.path)).toBe(`/run/systemd/transient/${unitName}`);
    expect(String(unit.fields.execStart)).toMatch(/"?\/usr\/bin\/sleep"?\s+"?300"?/);

    const related = await invoke("relate", { namespace: "unit", identity: unit.identity, locator: {}, relation: "executes", limit: 20 });
    expect(related.objects.some((item) => item.namespace === "file" && item.fields.path === "/usr/bin/sleep")).toBe(true);
    await writeFile("acceptance/vm/result-ubuntu-24.04-aarch64-systemd.json", `${JSON.stringify({
      status: "PASS",
      environment: { distribution: required("HUNTWARDEN_VM_EXPECT_DISTRO"), version: required("HUNTWARDEN_VM_EXPECT_VERSION"), architecture: required("HUNTWARDEN_VM_EXPECT_ARCH") },
      unit: { name: unitName, path: unit.fields.path, transient: unit.fields.transient, active: unit.fields.active, user: unit.fields.user, execStart: unit.fields.execStart },
      relation: { executes: "/usr/bin/sleep" },
      cleanup: "systemctl stop in afterAll",
    }, null, 2)}\n`, "utf8");
  }, 120_000);
});
