import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { dockerV2Remote } from "./v2-remote.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";
interface EquivalenceCase { id: string; port: number; v1Capabilities: string[]; expected: Record<string, string | number> }
const corpus = JSON.parse(await readFile(resolve("tests/fixtures/v1-v2-equivalence.json"), "utf8")) as { schemaVersion: number; cases: EquivalenceCase[] };

describe.skipIf(!enabled)("冻结的 v1 能力基线可由 v2 通用原语等价到达", () => {
  for (const scenario of corpus.cases) it(`${scenario.id}: ${scenario.v1Capabilities.join(" / ")}`, async () => {
    const client = await dockerV2Remote(scenario.port);
    try {
      if (scenario.id === "webshell") {
        const roots = await client.enumerate("web_root", ["path", "server", "effective"]);
        expect(roots.some((item) => item.fields.path === scenario.expected.webRoot)).toBe(true);
        const files = await client.enumerate("file", ["path", "size", "mtime"], { scope: { namespace: "file", canonicalRoot: scenario.expected.webRoot } });
        const file = files.find((item) => item.fields.path === scenario.expected.file); if (!file) throw new Error("v2 未到达冻结 Web 文件");
        const binding = { namespace: "file", identity: file.identity, locator: { path: file.fields.path } };
        const matched = await client.invoke("match", { objects: [binding], matcher: { engine: "literal", pattern: scenario.expected.literal }, maxHits: 20, includeContext: false });
        expect(matched.objects).toHaveLength(1);
        const requested = await client.invoke("relate", { ...binding, relation: "requested_in", limit: 20 });
        expect(requested.objects.some((item) => item.namespace === "log_event")).toBe(true);
      } else if (scenario.id === "java_memory_shell") {
        const jvms = await client.enumerate("jvm", ["pid", "command", "attachSupported"]);
        const jvm = jvms[0]; if (!jvm) throw new Error("v2 未发现冻结 JVM");
        const binding = { namespace: "jvm", identity: jvm.identity, locator: {} };
        const inventory = await client.invoke("probe", { ...binding, probeKind: "jvm.tomcat.inventory", parameters: {} }, { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
        expect(inventory.objects.some((item) => item.namespace === "java_component" && item.fields.className === scenario.expected.className)).toBe(true);
        const inspected = await client.invoke("probe", { ...binding, probeKind: "jvm.class.inspect", parameters: { className: scenario.expected.className } }, { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
        expect(inspected.objects.some((item) => item.namespace === "class" && item.fields.className === scenario.expected.className)).toBe(true);
      } else if (scenario.id === "backdoor_account") {
        const accounts = await client.enumerate("account", ["uid", "username", "home"]);
        const account = accounts.find((item) => item.fields.username === scenario.expected.username && item.fields.uid === scenario.expected.uid); if (!account) throw new Error("v2 未发现冻结 UID 0 账户");
        const keys = await client.invoke("relate", { namespace: "account", identity: account.identity, locator: {}, relation: "authorized_key", limit: 20 });
        const key = keys.objects.find((item) => item.namespace === "ssh_key"); if (!key) throw new Error("v2 未发现冻结 SSH Key");
        const owner = await client.invoke("relate", { namespace: "ssh_key", identity: key.identity, locator: { path: key.fields.sourceFile }, relation: "owned_by", limit: 20 });
        expect(owner.objects.some((item) => item.fields.username === scenario.expected.username)).toBe(true);
      } else if (scenario.id === "linux_persistence") {
        const cron = await client.enumerate("cron_entry", ["source", "command"]);
        const entry = cron.find((item) => String(item.fields.command).includes(String(scenario.expected.cronContains))); if (!entry) throw new Error("v2 未发现冻结 Cron");
        const executes = await client.invoke("relate", { namespace: "cron_entry", identity: entry.identity, locator: { path: entry.fields.source }, relation: "executes", limit: 20 });
        expect(executes.objects.some((item) => item.namespace === "file")).toBe(true);
        const units = await client.enumerate("unit", ["name", "execStart"]);
        expect(units.some((item) => item.fields.name === scenario.expected.unit)).toBe(true);
        expect((await client.enumerate("persistence", ["kind", "source", "command"])).length).toBeGreaterThan(0);
      } else if (scenario.id === "linux_intrusion_triage") {
        const processes = await client.enumerate("process", ["pid", "command", "exe"]);
        const process = processes.find((item) => String(item.fields.command).includes(String(scenario.expected.processCommandContains))); if (!process) throw new Error("v2 未发现冻结进程");
        const sockets = await client.invoke("relate", { namespace: "process", identity: process.identity, locator: {}, relation: "connects", limit: 20 });
        expect(sockets.objects.some((item) => item.fields.remotePort === scenario.expected.remotePort)).toBe(true);
        const files = await client.enumerate("file", ["path"], { scope: { namespace: "file", canonicalRoot: "/usr/bin" }, predicate: { op: "eq", field: "path", value: scenario.expected.tamperedFile } });
        const file = files[0]; if (!file) throw new Error("v2 未发现冻结完整性样本");
        const verified = await client.invoke("verify", { namespace: "file", identity: file.identity, locator: { path: file.fields.path }, baseline: "package_db" });
        expect(verified.objects[0]?.fields.baselineStatus).toBe("MISMATCH");
        const auth = await client.enumerate("auth_event", ["sourceAddress", "success"], { sinceHours: 168 });
        expect(auth.some((item) => item.fields.sourceAddress === scenario.expected.sourceAddress && item.fields.success === true)).toBe(true);
        const logs = await client.enumerate("log_event", ["program", "message"], { sinceHours: 168 });
        expect(logs.some((item) => item.fields.program === scenario.expected.logProgram)).toBe(true);
      } else throw new Error(`未实现的等价语料场景: ${scenario.id}`);
    } finally { await client.close(); }
  }, 180_000);
});
