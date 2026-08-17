import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import type { HostCapabilities } from "../../src/executor/operations.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";

const enabled = process.env.HUNTWARDEN_VM_TESTS === "1";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`缺少真实 VM 验收环境变量: ${name}`);
  return value;
}

describe.skipIf(!enabled)("授权真实 VM 只读兼容性冒烟", () => {
  let remote: SSHExecutor;
  let capabilities: HostCapabilities;
  let expectedDistribution: string;
  let expectedVersion: string;
  let expectedArchitecture: string;

  beforeAll(async () => {
    if (required("HUNTWARDEN_VM_CONFIRM_READ_ONLY") !== "I_HAVE_AUTHORIZATION") {
      throw new Error("必须显式确认目标授权: HUNTWARDEN_VM_CONFIRM_READ_ONLY=I_HAVE_AUTHORIZATION");
    }
    const port = Number(required("HUNTWARDEN_VM_PORT"));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("HUNTWARDEN_VM_PORT 无效");
    const privateKeyPath = required("HUNTWARDEN_VM_PRIVATE_KEY");
    const knownHostsPath = required("HUNTWARDEN_VM_KNOWN_HOSTS");
    if (!isAbsolute(privateKeyPath) || !isAbsolute(knownHostsPath)) throw new Error("SSH Key 与 known_hosts 必须使用绝对路径");
    await Promise.all([readFile(privateKeyPath), readFile(knownHostsPath, "utf8")]);

    const target: TargetConfig = {
      host: required("HUNTWARDEN_VM_HOST"),
      port,
      username: required("HUNTWARDEN_VM_USER"),
      hostFingerprint: required("HUNTWARDEN_VM_FINGERPRINT"),
      privateKeyPath,
      knownHostsPath,
    };
    if (!/^SHA256:[A-Za-z0-9+/]+$/.test(target.hostFingerprint)) throw new Error("Host Key 指纹格式无效");
    expectedDistribution = required("HUNTWARDEN_VM_EXPECT_DISTRO").toLowerCase();
    expectedVersion = required("HUNTWARDEN_VM_EXPECT_VERSION");
    expectedArchitecture = required("HUNTWARDEN_VM_EXPECT_ARCH");
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 60_000);
    capabilities = await remote.invoke({ operation: "get_capabilities", params: {} });
  }, 120_000);

  afterAll(async () => await remote?.close());

  it("绑定官方发行版身份、架构和 Helper 协议", () => {
    expect(capabilities.protocolVersion).toBeGreaterThanOrEqual(1);
    expect(capabilities.helper).toMatchObject({ name: "huntwarden-helper", version: expect.any(String) });
    expect(capabilities.platform.distribution).toMatchObject({
      id: expectedDistribution,
      versionId: expect.stringMatching(new RegExp(`^${expectedVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`)),
    });
    expect(capabilities.platform.architecture).toBe(expectedArchitecture);
    expect(capabilities.operations).toEqual(expect.arrayContaining([
      "get_host_info", "capture_volatile_snapshot", "discover_web_roots", "list_java_processes",
      "list_privileged_accounts", "list_cron_entries", "list_systemd_units",
      "list_ssh_persistence", "list_shell_startup_files",
    ]));
  });

  it("通过固定 READ 操作完成主机、进程和账户冒烟", async () => {
    const host = await remote.invoke({ operation: "get_host_info", params: {} });
    const volatile = await remote.invoke({ operation: "capture_volatile_snapshot", params: { maxProcesses: 500, maxConnections: 500 } });
    const accounts = await remote.invoke({ operation: "list_privileged_accounts", params: {} });
    expect(host).toEqual(expect.objectContaining({ hostname: expect.any(String) }));
    expect(volatile.processes).toBeInstanceOf(Array);
    expect(accounts).toBeInstanceOf(Array);
  }, 120_000);

  it("通过固定 READ 操作完成 Web 与 Java 入口冒烟", async () => {
    const roots = await remote.invoke({ operation: "discover_web_roots", params: {} });
    const java = await remote.invoke({ operation: "list_java_processes", params: {} });
    expect(roots).toBeInstanceOf(Array);
    expect(java).toBeInstanceOf(Array);
  }, 120_000);

  it("通过固定 READ 操作完成四类持久化源冒烟", async () => {
    const params = { maxItems: 500, includeUserScope: true } as const;
    const cron = await remote.invoke({ operation: "list_cron_entries", params });
    const systemd = await remote.invoke({ operation: "list_systemd_units", params });
    const ssh = await remote.invoke({ operation: "list_ssh_persistence", params });
    const shell = await remote.invoke({ operation: "list_shell_startup_files", params });
    expect(cron).toMatchObject({ items: expect.any(Array), partial: expect.any(Boolean), warnings: expect.any(Array) });
    expect(systemd).toMatchObject({ items: expect.any(Array), partial: expect.any(Boolean), warnings: expect.any(Array) });
    expect(ssh).toMatchObject({ items: expect.any(Array), partial: expect.any(Boolean), warnings: expect.any(Array), sshdConfig: expect.any(Object) });
    expect(shell).toMatchObject({ items: expect.any(Array), partial: expect.any(Boolean), warnings: expect.any(Array) });
  }, 120_000);
});
