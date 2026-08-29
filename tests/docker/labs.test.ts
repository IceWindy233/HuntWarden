import { afterAll, describe, expect, it } from "vitest";
import type { WireObservation } from "../../src/protocol-v2/types.js";
import { dockerV2Remote, type DockerV2Remote } from "./v2-remote.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";

describe.skipIf(!enabled)("Docker 五类 Lab v2 通用取证原语", () => {
  const remotes: DockerV2Remote[] = [];
  async function remote(port: number) { const value = await dockerV2Remote(port); remotes.push(value); return value; }
  afterAll(async () => await Promise.all(remotes.map(async (value) => await value.close())));
  const fields = (item: WireObservation | undefined) => item?.fields ?? {};

  it("Lab-Web 通过 web_stack/web_root/file + match/collect 完成事实链", async () => {
    const client = await remote(2222);
    const capabilities = await client.executor.getCapabilitiesV2();
    expect(capabilities).toMatchObject({ protocolVersion: 2, manifestVersion: "2.0.0" });
    const stacks = await client.enumerate("web_stack", ["kind", "instanceId", "pid", "configPaths"]);
    expect(stacks.some((item) => String(item.fields.kind).match(/nginx|apache|httpd/))).toBe(true);
    const roots = await client.enumerate("web_root", ["path", "server", "effective"]);
    expect(roots.some((item) => item.fields.path === "/var/www/html")).toBe(true);
    const stack = stacks.find((item) => String(item.fields.kind).match(/nginx|apache|httpd/));
    const root = roots.find((item) => item.fields.path === "/var/www/html");
    if (!stack || !root) throw new Error("缺少 Web Stack/Root 关系源");
    const serves = await client.invoke("relate", { namespace: "web_stack", identity: stack.identity, locator: {}, relation: "serves_root", limit: 20 });
    expect(serves.objects.some((item) => item.namespace === "web_root" && item.fields.path === "/var/www/html")).toBe(true);
    const servedBy = await client.invoke("relate", { namespace: "web_root", identity: root.identity, locator: { path: root.fields.path }, relation: "served_by", limit: 20 });
    expect(servedBy.objects.some((item) => item.namespace === "web_stack" && String(item.fields.kind).match(/nginx|apache|httpd/))).toBe(true);
    const files = await client.enumerate("file", ["path", "size", "mtime", "contentClass"], { scope: { namespace: "file", canonicalRoot: "/var/www/html" } });
    const sample = files.find((item) => item.fields.path === "/var/www/html/lab-webshell.php"); if (!sample) throw new Error("缺少 Web Lab 样本");
    const binding = { namespace: "file", identity: sample.identity, locator: { path: sample.fields.path } };
    const matched = await client.invoke("match", { objects: [binding], matcher: { engine: "literal", pattern: "shell_exec" }, maxHits: 20, includeContext: false });
    expect(matched.objects.length).toBeGreaterThan(0);
    // includeContext 走内容出境路径：命中标记之后是带字节偏移的有界窗口，偏移可直接交给 read。
    const withContext = await client.invoke("match", { objects: [binding], matcher: { engine: "literal", pattern: "shell_exec" }, maxHits: 20, includeContext: true });
    const contextContent = String(withContext.objects[0]?.fields.content);
    const [marker, ...windows] = contextContent.split("\n");
    expect(marker).toBe("MATCH");
    expect(windows.length).toBeGreaterThan(0);
    expect(windows.every((window) => /^@\d+:/.test(window))).toBe(true);
    expect(contextContent.length).toBeLessThanOrEqual(2560);
    const firstOffset = Number(/^@(\d+):/.exec(windows[0] ?? "")?.[1]);
    const reread = await client.invoke("read", { ...binding, offset: firstOffset, length: 256, encoding: "utf-8", purpose: "SCRIPT_REVIEW" });
    expect(String(reread.objects[0]?.fields.content).length).toBeGreaterThan(0);
    const requests = await client.invoke("relate", { ...binding, relation: "requested_in", limit: 20 });
    expect(requests.objects.some((item) => item.namespace === "log_event" && String(item.fields.message).includes("lab-webshell.php"))).toBe(true);
    if (capabilities.matchers.includes("yara")) {
      const yara = await client.invoke("match", { objects: [binding], matcher: { engine: "yara", ruleSetRef: "RULESET-WEBSHELL-BUILTIN-2" }, maxHits: 20, includeContext: false });
      expect(String(yara.objects[0]?.fields.content)).toContain("YARA_MATCH:");
      const yaraContext = await client.invoke("match", { objects: [binding], matcher: { engine: "yara", ruleSetRef: "RULESET-WEBSHELL-BUILTIN-2" }, maxHits: 20, includeContext: true });
      const yaraLines = String(yaraContext.objects[0]?.fields.content).split("\n");
      expect(yaraLines[0]).toContain("YARA_MATCH:");
      expect(yaraLines.slice(1).every((window) => /^@\d+:/.test(window))).toBe(true);
      expect(yaraLines.length).toBeGreaterThan(1);
    }
    const collected = await client.invoke("collect", { ...binding, maxBytes: 10 * 1024 * 1024, purpose: "LAB_EVIDENCE" }, { remoteCalls: 1, nodes: 1, bytes: 10 * 1024 * 1024, wallTimeMs: 60_000, probeCalls: 0 });
    expect(collected.artifact).toMatchObject({ token: expect.stringMatching(/^[a-f0-9]{64}$/), sha256: expect.stringMatching(/^[a-f0-9]{64}$/), complete: true });
    const chunks: Buffer[] = []; await client.executor.downloadArtifact({ artifactToken: collected.artifact!.token, sha256: collected.artifact!.sha256, size: collected.artifact!.size, expiresAt: collected.artifact!.expiresAt }, (chunk) => { chunks.push(Buffer.from(chunk)); });
    expect(Buffer.concat(chunks).length).toBe(collected.artifact!.size);
    await client.maintenance("artifact_release", { artifactToken: collected.artifact!.token });
  }, 180_000);

  it("Lab-Java 通过 jvm enumerate 与两个受限 probe 完成组件和类检查", async () => {
    const client = await remote(2223);
    const jvms = await client.enumerate("jvm", ["pid", "command", "attachSupported", "container"]);
    const jvm = jvms.find((item) => String(item.fields.command).toLowerCase().includes("catalina")) ?? jvms[0]; if (!jvm) throw new Error("缺少 JVM");
    const binding = { namespace: "jvm", identity: jvm.identity, locator: {} };
    const inventory = await client.invoke("probe", { ...binding, probeKind: "jvm.tomcat.inventory", parameters: {} }, { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
    const component = inventory.objects.find((item) => item.namespace === "java_component" && item.fields.className === "lab.DynamicMarkerFilter");
    expect(component).toBeDefined();
    expect(inventory.edges.some((edge) => edge.relation === "hosts_component" && edge.fromIdentity.namespace === "jvm" && edge.toIdentity.namespace === "java_component")).toBe(true);
    const inspected = await client.invoke("probe", { ...binding, probeKind: "jvm.class.inspect", parameters: { className: "lab.DynamicMarkerFilter" } }, { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
    expect(fields(inspected.objects[0])).toMatchObject({ className: "lab.DynamicMarkerFilter", bytecodeSha256: expect.any(String) });
    expect(inspected.edges.map((edge) => edge.relation)).toEqual(expect.arrayContaining(["loads_class", "loaded_by"]));
  }, 180_000);

  it("Lab-Account 通过 account/ssh_key/auth_event 建立账户与信任事实", async () => {
    const client = await remote(2224);
    const accounts = await client.enumerate("account", ["uid", "username", "gid", "home", "shell", "groups", "locked"]);
    const lab = accounts.find((item) => item.fields.username === "labroot");
    expect(fields(lab)).toMatchObject({ uid: 0, username: "labroot" });
    const keys = await client.enumerate("ssh_key", ["fingerprint", "ownerUid", "type", "comment", "sourceFile"]);
    expect(keys.some((item) => item.fields.ownerUid === 0)).toBe(true);
    if (!lab) throw new Error("缺少 Lab Account");
    const accountKeys = await client.invoke("relate", { namespace: "account", identity: lab.identity, locator: {}, relation: "authorized_key", limit: 20 });
    expect(accountKeys.objects.some((item) => item.namespace === "ssh_key" && item.fields.ownerUid === 0)).toBe(true);
    const key = keys.find((item) => item.fields.ownerUid === 0); if (!key) throw new Error("缺少 Lab SSH Key");
    const owner = await client.invoke("relate", { namespace: "ssh_key", identity: key.identity, locator: { path: key.fields.sourceFile }, relation: "owned_by", limit: 20 });
    expect(owner.objects.some((item) => item.namespace === "account" && item.fields.username === "labroot")).toBe(true);
    const auth = await client.enumerate("auth_event", ["timestamp", "eventType", "username", "sourceAddress", "success"], { sinceHours: 168 });
    expect(auth).toBeInstanceOf(Array);
  }, 180_000);

  it("Lab-Persistence 通过 cron/unit/persistence 覆盖四类来源", async () => {
    const client = await remote(2225);
    const cron = await client.enumerate("cron_entry", ["source", "schedule", "user", "command"]);
    const units = await client.enumerate("unit", ["name", "path", "enabled", "active", "execStart", "user"]);
    const extended = await client.enumerate("persistence", ["kind", "source", "user", "command", "enabled"]);
    expect(cron.length).toBeGreaterThan(0);
    const executable = await client.invoke("relate", { namespace: "cron_entry", identity: cron[0]!.identity, locator: { path: cron[0]!.fields.source }, relation: "executes", limit: 20 });
    expect(executable.objects.some((item) => item.namespace === "file")).toBe(true);
    expect(units.some((item) => item.fields.name === "huntwarden-lab.service")).toBe(true);
    expect(extended.some((item) => ["ssh", "shell", "extended"].includes(String(item.fields.kind)))).toBe(true);
  }, 180_000);
});
