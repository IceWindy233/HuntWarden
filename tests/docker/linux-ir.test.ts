import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { TargetConfig } from "../../src/domain/types.js";
import type { StableProcessIdentity } from "../../src/executor/operations.js";
import { SSHExecutor } from "../../src/executor/ssh-executor.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";
const stateDir = resolve("labs/.lab-state");

describe.skipIf(!enabled)("Docker Lab-Linux-IR 通用入侵分诊", () => {
  let remote: SSHExecutor;

  beforeAll(async () => {
    const knownHostsPath = resolve(stateDir, "known_hosts");
    const knownHosts = await readFile(knownHostsPath, "utf8");
    const fingerprint = knownHosts.match(/# (SHA256:[A-Za-z0-9+/]+) port=2226/)?.[1];
    if (!fingerprint) throw new Error("known_hosts 缺少 2226 的指纹");
    const target: TargetConfig = {
      host: "127.0.0.1", port: 2226, username: "secagent", hostFingerprint: fingerprint,
      privateKeyPath: resolve(stateDir, "id_ed25519"), knownHostsPath,
    };
    remote = new SSHExecutor(target, "/usr/local/libexec/huntwarden-helper", 30_000);
  });

  afterAll(async () => remote?.close());

  function identity(value: Record<string, unknown>): StableProcessIdentity {
    return {
      bootId: String(value.bootId), pid: Number(value.pid), startTicks: String(value.startTicks),
      exeInode: String(value.exeInode), exeSha256: String(value.exeSha256),
    };
  }

  it("完成稳定进程身份、关联调查与可执行文件流式采集", async () => {
    const capabilities = await remote.invoke({ operation: "get_capabilities", params: {} });
    expect(capabilities.operations).toEqual(expect.arrayContaining([
      "capture_volatile_snapshot", "list_suspicious_processes", "collect_process_executable",
    ]));

    const snapshot = await remote.invoke({ operation: "capture_volatile_snapshot", params: { maxProcesses: 500, maxConnections: 500 } });
    expect(snapshot.bootId).toMatch(/^[0-9a-f-]{36}$/);
    expect(snapshot.processes[0]).toMatchObject({
      bootId: snapshot.bootId,
      startTicks: expect.stringMatching(/^\d+$/),
      exeInode: expect.stringMatching(/^\d+$/),
      exeSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      cwd: expect.any(String),
      root: expect.any(String),
      namespaces: expect.objectContaining({ pid: expect.stringMatching(/^pid:\[\d+\]$/) }),
      cgroups: expect.any(Array),
    });
    expect((snapshot.connections as Record<string, unknown>[]).every((item) => !("processPid" in item) || Number.isInteger(item.processPid))).toBe(true);

    const suspicious = await remote.invoke({ operation: "list_suspicious_processes", params: { maxProcesses: 500 } });
    const client = suspicious.items.find((item) => item.launcherPath === "/tmp/.update");
    const deleted = suspicious.items.find((item) => item.exeDeleted === true && String(item.exePath).includes(".cache-worker"));
    expect(client?.signals).toEqual(expect.arrayContaining(["temporary_executable", "hidden_executable"]));
    expect(deleted?.signals).toContain("deleted_executable");
    expect(client).toMatchObject({ bootId: expect.stringMatching(/^[0-9a-f-]{36}$/), startTicks: expect.stringMatching(/^\d+$/) });

    const stable = identity(client!);
    const tree = await remote.invoke({ operation: "inspect_process_tree", params: { ...stable, maxDepth: 8, maxNodes: 500 } });
    expect(tree.items.some((item) => item.relation === "target" && item.pid === stable.pid)).toBe(true);
    const fds = await remote.invoke({ operation: "inspect_process_fds", params: { ...stable, maxItems: 500 } });
    expect(fds.items.length).toBeGreaterThan(0);
    const maps = await remote.invoke({ operation: "inspect_process_memory_maps", params: { ...stable, maxItems: 2000 } });
    expect(maps.items.some((item) => String(item.path).includes("python"))).toBe(true);
    const connections = await remote.invoke({ operation: "list_process_connections", params: { ...stable, maxConnections: 500 } });
    expect(connections.items.some((item) => String(item.remote).endsWith(":46666") && item.state === "ESTABLISHED")).toBe(true);

    const deletedStable = identity(deleted!);
    const collected = await remote.invoke({ operation: "collect_process_executable", params: { ...deletedStable, maxBytes: 10 * 1024 * 1024 } });
    expect(collected.artifact).toBeTruthy();
    const chunks: Buffer[] = [];
    await remote.downloadArtifact(collected.artifact!, (chunk) => { chunks.push(Buffer.from(chunk)); });
    const bytes = Buffer.concat(chunks);
    expect(bytes.length).toBe(collected.size);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(deletedStable.exeSha256);

    await expect(remote.invoke({ operation: "inspect_process_fds", params: {
      ...stable, startTicks: String(BigInt(stable.startTicks) + 1n), maxItems: 10,
    } })).rejects.toMatchObject({ code: "EVIDENCE_COLLECTION" });
  }, 120_000);

  it("完成近期文件、特权文件、包校验、动态加载与规范化时间线", async () => {
    const recent = await remote.invoke({ operation: "list_recent_executables", params: {
      modifiedWithinHours: 168, maxItems: 5000, maxFileSizeBytes: 100 * 1024 * 1024,
    } });
    const corrupted = recent.items.find((item) => item.path === "/usr/bin/yes");
    expect(corrupted).toMatchObject({ inode: expect.stringMatching(/^\d+$/), sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    const integrity = await remote.invoke({ operation: "verify_package_integrity", params: {
      path: String(corrupted!.path), expectedInode: String(corrupted!.inode), expectedSha256: String(corrupted!.sha256),
    } });
    expect(integrity).toMatchObject({ packageManager: "dpkg", changed: true });

    const privileged = await remote.invoke({ operation: "list_privileged_files", params: { maxItems: 5000 } });
    expect(privileged.items.some((item) => item.setuid === true || item.setgid === true || Boolean(item.capabilities))).toBe(true);

    const loader = await remote.invoke({ operation: "inspect_dynamic_loader", params: { maxItems: 500 } });
    expect(loader.items.some((item) => item.path === "/etc/ld.so.preload")).toBe(true);
    expect(loader.items.some((item) => item.path === "/opt/huntwarden-lab/libpreload.so" && item.kind === "loaded_library")).toBe(true);

    const auth = await remote.invoke({ operation: "query_auth_events", params: { sinceHours: 168, maxEvents: 500 } });
    expect(auth.items.some((item) => item.eventType === "authentication_success" && item.sourceIp === "192.0.2.45")).toBe(true);
    expect(JSON.stringify(auth)).not.toMatch(/password\s*[:=]\s*[^\[]/i);

    const executions = await remote.invoke({ operation: "query_exec_events", params: { sinceHours: 168, maxEvents: 500 } });
    expect(executions).toMatchObject({ partial: true });
    expect(executions.warnings.join(" ")).toContain("audit.log");

    const timeline = await remote.invoke({ operation: "build_incident_timeline", params: { sinceHours: 168, maxEvents: 5000 } });
    expect(timeline.items.some((item) => item.timelineSource === "auth")).toBe(true);
    expect(timeline).toMatchObject({ partial: true });
  }, 180_000);
});
