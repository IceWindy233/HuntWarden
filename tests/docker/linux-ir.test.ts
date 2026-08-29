import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dockerV2Remote, type DockerV2Remote } from "./v2-remote.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";

describe.skipIf(!enabled)("Docker Lab-Linux-IR v2 通用入侵分诊", () => {
  let client: DockerV2Remote;
  beforeAll(async () => { client = await dockerV2Remote(2226); });
  afterAll(async () => await client?.close());

  it("稳定进程身份、关系与 process executable collect 全走 v2", async () => {
    const processes = await client.enumerate("process", ["pid", "ppid", "uid", "username", "comm", "exe", "exeSha256", "command", "state"]);
    const suspicious = processes.find((item) => String(item.fields.command).includes("/tmp/.update"));
    const deleted = processes.find((item) => String(item.fields.exe).includes(".cache-worker"));
    expect(suspicious?.identity).toMatchObject({ bootId: expect.stringMatching(/^[0-9a-f-]{36}$/), pid: expect.any(Number), startTicks: expect.stringMatching(/^\d+$/), exeInode: expect.stringMatching(/^\d+$/), exeSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
    if (!suspicious || !deleted) throw new Error("缺少 Linux IR 进程样本");
    const binding = { namespace: "process", identity: suspicious.identity, locator: {} };
    const children = await client.invoke("relate", { ...binding, relation: "children", limit: 500 });
    const connections = await client.invoke("relate", { ...binding, relation: "connects", limit: 500 });
    expect(children.edges).toBeInstanceOf(Array);
    expect(connections.objects.some((item) => item.namespace === "socket" && item.fields.remotePort === 46666)).toBe(true);
    const collected = await client.invoke("collect", { namespace: "process", identity: deleted.identity, locator: {}, maxBytes: 10 * 1024 * 1024, purpose: "PROCESS_EXECUTABLE" }, { remoteCalls: 1, nodes: 1, bytes: 10 * 1024 * 1024, wallTimeMs: 60_000, probeCalls: 0 });
    expect(collected.artifact?.complete).toBe(true);
    const chunks: Buffer[] = []; await client.executor.downloadArtifact({ artifactToken: collected.artifact!.token, sha256: collected.artifact!.sha256, size: collected.artifact!.size, expiresAt: collected.artifact!.expiresAt }, (chunk) => { chunks.push(Buffer.from(chunk)); });
    expect(createHash("sha256").update(Buffer.concat(chunks)).digest("hex")).toBe(deleted.identity.exeSha256);
    await client.maintenance("artifact_release", { artifactToken: collected.artifact!.token });
    await expect(client.invoke("project", { namespace: "process", identity: { ...suspicious.identity, startTicks: String(BigInt(String(suspicious.identity.startTicks)) + 1n) }, locator: {}, fields: ["comm"] })).rejects.toThrow(/EVIDENCE_COLLECTION_FAILED|STALE_REF/);
  }, 180_000);

  it("文件 package_db verify、模块、认证与执行事件保留 PARTIAL/Gaps", async () => {
    const files = await client.enumerate("file", ["path", "size", "mtime"], { scope: { namespace: "file", canonicalRoot: "/usr/bin" }, predicate: { op: "eq", field: "path", value: "/usr/bin/yes" } });
    const executable = files[0]; if (!executable) throw new Error("缺少 /usr/bin/yes");
    const verified = await client.invoke("verify", { namespace: "file", identity: executable.identity, locator: { path: "/usr/bin/yes" }, baseline: "package_db" });
    expect(verified.objects[0]?.fields).toMatchObject({ baseline: "package_db", baselineStatus: "MISMATCH" });
    const packages = await client.enumerate("package", ["manager", "name", "version", "architecture"]);
    const coreutils = packages.find((item) => item.fields.manager === "dpkg" && item.fields.name === "coreutils"); if (!coreutils) throw new Error("缺少 coreutils package");
    const owned = await client.invoke("relate", { namespace: "package", identity: coreutils.identity, locator: {}, relation: "owns_file", limit: 500 });
    expect(owned.objects.some((item) => item.namespace === "file" && item.fields.path === "/usr/bin/yes")).toBe(true);
    const modules = await client.enumerate("module", ["name", "address", "size", "path"]);
    expect(modules).toBeInstanceOf(Array);
    const authFields = ["timestamp", "eventType", "username", "sourceAddress", "success", "sourceId"];
    const auth = await client.invoke("enumerate", { namespace: "auth_event", fields: authFields, sinceHours: 168, limit: 500 });
    expect(auth.objects.some((item) => item.fields.success === true && item.fields.sourceAddress === "192.0.2.45")).toBe(true);
    expect(JSON.stringify(auth.objects)).not.toMatch(/password\s*[:=]\s*[^[]/i);
    const accounts = await client.enumerate("account", ["uid", "username"]);
    const iruser = accounts.find((item) => item.fields.username === "iruser"); if (!iruser) throw new Error("缺少 iruser");
    const loginEvents = await client.invoke("relate", { namespace: "account", identity: iruser.identity, locator: {}, relation: "login_event", limit: 20 });
    expect(loginEvents.objects.some((item) => item.namespace === "auth_event" && item.fields.sourceAddress === "192.0.2.45")).toBe(true);
    const logs = await client.invoke("enumerate", { namespace: "log_event", fields: ["timestamp", "program", "message", "fields"], sinceHours: 168, limit: 500 });
    expect(logs.objects.some((item) => item.fields.program === "system-health" && String(item.fields.message).includes("scan completed"))).toBe(true);
    expect(JSON.stringify(logs.objects)).toContain("token=[REDACTED]");
    expect(JSON.stringify(logs.objects)).not.toContain("lab-secret-value");
    const sources = await client.enumerate("log_source", ["sourceId", "generation", "kind", "path"]);
    const systemSource = sources.find((item) => item.fields.path === "/var/log/syslog"); if (!systemSource) throw new Error("缺少 system log source");
    const contained = await client.invoke("relate", { namespace: "log_source", identity: systemSource.identity, locator: { path: systemSource.fields.path }, relation: "contains", limit: 20 });
    expect(contained.objects.some((item) => item.namespace === "log_event" && item.fields.program === "system-health")).toBe(true);
    // 每个事件的 sourceId 必须能在 log_source 清单里解析。此前 auth_event/exec_event 的
    // sourceId 是硬编码的 "auth"/"exec"，落在 log_source 的身份空间之外，事件与其来源
    // 之间没有任何可走的关系路径。
    const sourceIds = new Set(sources.map((item) => String(item.fields.sourceId)));
    expect(sourceIds.size).toBeGreaterThan(0);
    for (const event of auth.objects) expect(sourceIds).toContain(String(event.fields.sourceId));
    // auth 类日志源的 contains 必须能到达 auth_event。此前 contains 只查 log_event，
    // 所以认证事件通过关系永远不可达。
    const authSource = sources.find((item) => item.fields.path === "/var/log/auth.log"); if (!authSource) throw new Error("缺少 auth log source");
    const authContained = await client.invoke("relate", { namespace: "log_source", identity: authSource.identity, locator: { path: authSource.fields.path }, relation: "contains", limit: 200 });
    expect(authContained.objects.some((item) => item.namespace === "auth_event" && item.fields.sourceAddress === "192.0.2.45")).toBe(true);
    // cursor 属于事件身份，只能由事件内容决定。此前它是页内数组下标,换一个时间窗口后
    // 同一个事件就会得到不同的 identity 和 ObjectRef。
    const narrower = await client.invoke("enumerate", { namespace: "auth_event", fields: authFields, sinceHours: 24, limit: 500 });
    const keyOf = (item: { fields: Record<string, unknown> }) => `${item.fields.timestamp}|${item.fields.username}|${item.fields.eventType}`;
    const wide = new Map(auth.objects.map((item) => [keyOf(item), JSON.stringify(item.identity)]));
    let compared = 0;
    for (const item of narrower.objects) {
      const previous = wide.get(keyOf(item));
      if (previous === undefined) continue;
      expect(JSON.stringify(item.identity)).toBe(previous);
      compared += 1;
    }
    expect(compared).toBeGreaterThan(0);
    const executions = await client.invoke("enumerate", { namespace: "exec_event", fields: ["timestamp", "pid", "uid", "executable", "arguments", "cwd"], sinceHours: 168, limit: 500 });
    expect(executions.status).toBe("PARTIAL");
    expect(executions.gaps.some((gap) => gap.code === "COLLECTOR_ERROR")).toBe(true);
    for (const execution of executions.objects) {
      if (execution.fields.pid !== undefined) expect(Number.isInteger(execution.fields.pid)).toBe(true);
      if (execution.fields.uid !== undefined) expect(Number.isInteger(execution.fields.uid)).toBe(true);
    }
  }, 180_000);
});
