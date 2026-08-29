import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import type { ForensicVerb } from "../../src/executor/protocol-v2-executor.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";
import type { HelperCapabilitiesV2, WireRequest, WireSuccess } from "../../src/protocol-v2/types.js";

const enabled = process.env.HUNTWARDEN_VM_TESTS === "1";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`缺少真实 VM 验收环境变量: ${name}`);
  return value;
}

describe.skipIf(!enabled)("授权真实 VM v2 只读兼容性冒烟", () => {
  let remote: SSHExecutor;
  let capabilities: HelperCapabilitiesV2;
  let expectedDistribution: string;
  let expectedVersion: string;
  let expectedArchitecture: string;
  let sequence = 0;

  async function invoke(verb: ForensicVerb, params: Record<string, unknown>, estimate = { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 0 }): Promise<WireSuccess> {
    sequence += 1;
    const requestId = `VM-V2-${sequence}`;
    const request: WireRequest = { protocolVersion: 2, requestId, epochId: "EPOCH-VM-SMOKE", deadlineMs: 60_000, reservation: { reservationId: `BRES-${requestId}`, estimate }, params };
    const response = await remote.invokeV2(verb, request);
    if (response.status === "ERROR") throw new Error(`${response.error.code}: ${response.error.message}`);
    return response;
  }

  beforeAll(async () => {
    if (required("HUNTWARDEN_VM_CONFIRM_READ_ONLY") !== "I_HAVE_AUTHORIZATION") throw new Error("必须显式确认目标授权: HUNTWARDEN_VM_CONFIRM_READ_ONLY=I_HAVE_AUTHORIZATION");
    const port = Number(required("HUNTWARDEN_VM_PORT"));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("HUNTWARDEN_VM_PORT 无效");
    const privateKeyPath = required("HUNTWARDEN_VM_PRIVATE_KEY"); const knownHostsPath = required("HUNTWARDEN_VM_KNOWN_HOSTS");
    if (!isAbsolute(privateKeyPath) || !isAbsolute(knownHostsPath)) throw new Error("SSH Key 与 known_hosts 必须使用绝对路径");
    await Promise.all([readFile(privateKeyPath), readFile(knownHostsPath, "utf8")]);
    const target: TargetConfig = { host: required("HUNTWARDEN_VM_HOST"), port, username: required("HUNTWARDEN_VM_USER"), hostFingerprint: required("HUNTWARDEN_VM_FINGERPRINT"), privateKeyPath, knownHostsPath };
    if (!/^SHA256:[A-Za-z0-9+/]+$/.test(target.hostFingerprint)) throw new Error("Host Key 指纹格式无效");
    expectedDistribution = required("HUNTWARDEN_VM_EXPECT_DISTRO").toLowerCase(); expectedVersion = required("HUNTWARDEN_VM_EXPECT_VERSION"); expectedArchitecture = required("HUNTWARDEN_VM_EXPECT_ARCH");
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 60_000);
    capabilities = await remote.getCapabilitiesV2();
  }, 120_000);

  afterAll(async () => await remote?.close());

  it("绑定 Manifest v2、架构和受支持 namespace", async () => {
    expect(capabilities).toMatchObject({ protocolVersion: 2, manifestVersion: "2.0.0", helper: { name: "huntwarden-helper-v2", version: expect.any(String) } });
    expect(capabilities.verbs).toEqual(expect.arrayContaining(["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"]));
    expect(Object.keys(capabilities.namespaces)).toEqual(expect.arrayContaining(["host", "process", "socket", "file", "account", "web_root", "jvm", "cron_entry", "unit", "persistence"]));
    const host = await invoke("enumerate", { namespace: "host", fields: ["bootId", "hostname", "os", "release", "architecture"], limit: 1 });
    expect(host.objects[0]?.fields).toMatchObject({ hostname: expect.any(String), architecture: expectedArchitecture });
  }, 120_000);

  it("通过 file Object 身份读取 os-release，核对发行版而不走任意路径工具", async () => {
    // Ubuntu/systemd 通常把 /etc/os-release 做成指向 /usr/lib/os-release 的
    // 符号链接。V2 文件原语有意拒绝跟随符号链接，因此优先绑定规范普通文件，
    // 同时兼容把 /etc/os-release 直接安装为普通文件的发行版。
    let file: WireSuccess["objects"][number] | undefined;
    for (const path of ["/usr/lib/os-release", "/etc/os-release"]) {
      const root = path.slice(0, path.lastIndexOf("/"));
      const inventory = await invoke("enumerate", { namespace: "file", scope: { namespace: "file", canonicalRoot: root }, fields: ["path", "contentClass"], predicate: { op: "eq", field: "path", value: path }, limit: 1 });
      file = inventory.objects[0];
      if (file) break;
    }
    if (!file) throw new Error("未发现普通文件形式的 os-release");
    expect(file.fields.contentClass).toBe("SAFE_TEXT");
    const path = String(file.fields.path);
    const read = await invoke("read", { namespace: "file", identity: file.identity, locator: { path }, offset: 0, length: 65_536, encoding: "utf-8", purpose: "SYSTEM_TEXT" }, { remoteCalls: 1, nodes: 1, bytes: 65_536, wallTimeMs: 60_000, probeCalls: 0 });
    const text = String(read.objects[0]?.fields.content ?? "");
    expect(text.toLowerCase()).toContain(`id=${expectedDistribution}`);
    expect(text).toMatch(new RegExp(`VERSION_ID=["']?${expectedVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  }, 120_000);

  it("目标与控制端时钟漂移时仍能完成 collect、SFTP 和摘要校验", async () => {
    const path = "/var/www/html/huntwarden-acceptance-benign.php";
    const inventory = await invoke("enumerate", {
      namespace: "file", scope: { namespace: "file", canonicalRoot: "/var/www/html" },
      fields: ["path", "size", "contentClass"], predicate: { op: "eq", field: "path", value: path }, limit: 1,
    });
    const file = inventory.objects[0];
    if (!file) throw new Error("未安装 VM 良性验收夹具");
    const collected = await invoke("collect", {
      namespace: "file", identity: file.identity, locator: { path }, maxBytes: 4096, purpose: "CLOCK_SKEW_ACCEPTANCE",
    });
    const artifact = collected.artifact;
    if (!artifact) throw new Error("collect 未返回 Artifact");
    const transferred = await remote.downloadArtifact({
      artifactToken: artifact.token, sha256: artifact.sha256, size: artifact.size, expiresAt: artifact.expiresAt,
    }, () => undefined);
    expect(transferred).toEqual({ size: artifact.size, sha256: artifact.sha256 });
  }, 120_000);

  it("通过通用 enumerate 完成进程、网络、账户、Web、Java 与持久化入口冒烟", async () => {
    for (const [namespace, fields] of [
      ["process", ["pid", "comm", "exe"]], ["socket", ["protocol", "localAddress", "localPort", "state"]],
      ["account", ["uid", "username", "groups", "locked"]], ["web_root", ["path", "server", "effective"]],
      ["jvm", ["pid", "command", "attachSupported"]], ["cron_entry", ["source", "schedule", "command"]],
      ["unit", ["name", "enabled", "execStart"]], ["persistence", ["kind", "source", "command"]],
    ] as const) {
      const result = await invoke("enumerate", { namespace, fields, limit: 500 });
      expect(result.objects).toBeInstanceOf(Array); expect(result.gaps).toBeInstanceOf(Array);
    }
  }, 240_000);
});
