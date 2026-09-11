import { afterAll, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { WireObservation } from "../../src/protocol-v2/types.js";
import { dockerV2Remote, type DockerV2Remote } from "./v2-remote.js";
import { RuntimeStore } from "../../src/storage/runtime-store.js";
import { EvidenceStore } from "../../src/evidence/evidence-store.js";
import { ApprovalService } from "../../src/agent/approval-service.js";
import { bootstrapProtocolV2 } from "../../src/runtime/v2-bootstrap.js";
import { InvestigationCompletionValidator } from "../../src/investigation/completion-validator.js";
import { testConfig, testTask } from "../helpers.js";

const enabled = (process.env.HUNTWARDEN_DOCKER_TESTS ?? process.env.SECHOST_DOCKER_TESTS) === "1";
const projectRoot = process.cwd();

describe.skipIf(!enabled)("Docker 五类 Lab v2 通用取证原语", () => {
  const remotes: DockerV2Remote[] = [];
  async function remote(port: number) { const value = await dockerV2Remote(port); remotes.push(value); return value; }
  afterAll(async () => await Promise.all(remotes.map(async (value) => await value.close())));
  const fields = (item: WireObservation | undefined) => item?.fields ?? {};

  it("Lab-Web 通过 web_stack/web_root/file + match/collect 完成事实链", async () => {
    const client = await remote(2222);
    const capabilities = await client.executor.getCapabilitiesV2();
    expect(capabilities).toMatchObject({ protocolVersion: 2, manifestVersion: "3.0.0" });
    const stacks = await client.enumerate("web_stack", ["kind", "instanceId", "pid", "configPaths"]);
    expect(stacks.some((item) => String(item.fields.kind).match(/nginx|apache|httpd/))).toBe(true);
    const roots = await client.enumerate("web_root", ["path", "server", "effective"]);
    expect(roots.some((item) => item.fields.path === "/var/www/html")).toBe(true);
    const apache = stacks.find((item) => ["apache2", "httpd"].includes(String(item.fields.kind)));
    const phpFpm = stacks.find((item) => item.fields.kind === "php-fpm");
    const apacheRoot = roots.find((item) => item.fields.path === "/srv/apache-app" && item.fields.server === "apache");
    expect(apache).toBeDefined();
    expect(phpFpm).toBeDefined();
    expect(apacheRoot?.fields.effective).toBe(true);
    if (!apache || !apacheRoot) throw new Error("缺少 Apache/PHP-FPM 有效 Include 场景");
    const apacheServes = await client.invoke("relate", { namespace: "web_stack", identity: apache.identity, locator: {}, relation: "serves_root", limit: 20 });
    expect(apacheServes.objects.some((item) => item.namespace === "web_root" && item.fields.path === "/srv/apache-app")).toBe(true);
    const stack = stacks.find((item) => String(item.fields.kind).match(/nginx|apache|httpd/));
    const root = roots.find((item) => item.fields.path === "/var/www/html");
    if (!stack || !root) throw new Error("缺少 Web Stack/Root 关系源");
    const serves = await client.invoke("relate", { namespace: "web_stack", identity: stack.identity, locator: {}, relation: "serves_root", limit: 20 });
    expect(serves.objects.some((item) => item.namespace === "web_root" && item.fields.path === "/var/www/html")).toBe(true);
    const servedBy = await client.invoke("relate", { namespace: "web_root", identity: root.identity, locator: { path: root.fields.path }, relation: "served_by", limit: 20 });
    expect(servedBy.objects.some((item) => item.namespace === "web_stack" && String(item.fields.kind).match(/nginx|apache|httpd/))).toBe(true);
    const files = await client.enumerate("file", ["path", "size", "mtime", "contentClass"], { scope: { namespace: "file", canonicalRoot: "/var/www/html" } });
    expect(files.some((item) => item.fields.path === "/var/www/html/old-webshell.php" && String(item.fields.mtime).startsWith("2010-01-02T03:04:05"))).toBe(true);
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

  it("Lab-Web 从零 IOC 自动扫描旧时间戳脚本、YARA 判别并保全 Evidence", async () => {
    const client = await remote(2222);
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-web-controller-"));
    const store = await RuntimeStore.open(directory, "runtime.db");
    try {
      const task = testTask();
      task.taskId = "TASK-DOCKER-WEB-AUTONOMOUS";
      task.protocolVersion = 2;
      task.checks = ["webshell"];
      task.profile = "DEEP";
      store.createTask(task);
      const result = await bootstrapProtocolV2({
        task, config: testConfig(directory), store, executor: client.executor,
        evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store),
      });
      const facts = store.listFacts(task.taskId, result.epoch.epochId);
      const old = facts.find((fact) => fact.namespace === "file" && fact.privatePayload.path === "/var/www/html/old-webshell.php");
      if (!old) throw new Error("全历史 Web 候选扫描遗漏旧时间戳脚本");
      expect(facts.some((fact) => fact.subjectRef === old.subjectRef && String(fact.privatePayload.content).startsWith("YARA_MATCH:"))).toBe(true);
      expect(store.listAssessments(task.taskId, result.epoch.epochId).some((item) => item.subjectRef === old.subjectRef && item.rationale.includes("HW2-WEB-YARA-001"))).toBe(true);
      expect(store.listEvidence(task.taskId).some((item) => item.metadata?.subjectRef === old.subjectRef && item.metadata.complete === true && item.metadata.integrityStatus === "VERIFIED")).toBe(true);
      const normal = facts.find((fact) => fact.namespace === "file" && fact.privatePayload.path === "/var/www/html/normal-framework-dynamic.php");
      expect(normal).toBeDefined();
      expect(store.listAssessments(task.taskId, result.epoch.epochId).some((item) => item.subjectRef === normal?.subjectRef && ["SUSPICIOUS", "HIGHLY_SUSPICIOUS", "CONFIRMED_MALICIOUS"].includes(item.verdict))).toBe(false);
      const validator = new InvestigationCompletionValidator(store);
      const completion = validator.freeze(task.taskId, result.epoch.epochId);
      expect(completion.investigationStatus, JSON.stringify({
        evaluation: validator.evaluate(task.taskId, result.epoch.epochId),
        checkpoints: store.listDiscoveryCheckpoints(task.taskId, result.epoch.epochId),
        obligations: store.listInvestigationObligations(task.taskId, result.epoch.epochId),
        actions: store.listInvestigationActions(task.taskId, result.epoch.epochId),
      })).toBe("CLOSED_WITH_FINDINGS");
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }, 240_000);

  it("Lab-Java 通过 jvm enumerate 与两个受限 probe 完成组件和类检查", async () => {
    const client = await remote(2223);
    const jvms = await client.enumerate("jvm", ["pid", "command", "attachSupported", "container"]);
    const jvm = jvms.find((item) => String(item.fields.command).toLowerCase().includes("catalina")) ?? jvms[0]; if (!jvm) throw new Error("缺少 JVM");
    const binding = { namespace: "jvm", identity: jvm.identity, locator: {} };
    const inventory = await client.invoke("probe", { ...binding, probeKind: "jvm.tomcat.inventory", parameters: {} }, { remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
    const component = inventory.objects.find((item) => item.namespace === "java_component" && item.fields.className === "lab.DynamicMarkerFilter");
    const webSocket = inventory.objects.find((item) => item.namespace === "java_component" && item.fields.className === "lab.LabWebSocketEndpoint");
    const springController = inventory.objects.find((item) => item.namespace === "java_component" && item.fields.className === "lab.LabSpringController");
    const springInterceptor = inventory.objects.find((item) => item.namespace === "java_component" && item.fields.className === "lab.LabSpringInterceptor");
    expect(component).toBeDefined();
    expect(component?.fields.context).toBe("/lab");
    expect(webSocket?.fields).toMatchObject({ componentKind: "websocket_endpoint", context: "/lab", name: "/ws/{id}" });
    expect(webSocket?.fields.mappings).toEqual(expect.arrayContaining(["endpointPath:/ws/{id}"]));
    expect(webSocket?.fields.classLoaderId).toBe(component?.fields.classLoaderId);
    expect(springController?.fields).toMatchObject({ componentKind: "spring_controller", context: "/lab" });
    expect(springController?.fields.mappings).toEqual(expect.arrayContaining([expect.stringMatching(/^mapping:.*\/health/)]));
    expect(springController?.fields.classLoaderId).toBe(component?.fields.classLoaderId);
    expect(springInterceptor?.fields).toMatchObject({ componentKind: "spring_interceptor", context: "/lab" });
    expect(springInterceptor?.fields.classLoaderId).toBe(component?.fields.classLoaderId);
    expect(inventory.edges.some((edge) => edge.relation === "hosts_component" && edge.fromIdentity.namespace === "jvm" && edge.toIdentity.namespace === "java_component")).toBe(true);
    const classLoaderId = String(component?.fields.classLoaderId);
    const inspected = await client.invoke("probe", { ...binding, probeKind: "jvm.class.inspect", parameters: { className: "lab.DynamicMarkerFilter", classLoaderId } }, { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
    expect(fields(inspected.objects[0])).toMatchObject({ className: "lab.DynamicMarkerFilter", loaderId: classLoaderId });
    expect(inspected.edges.map((edge) => edge.relation)).toEqual(expect.arrayContaining(["loads_class", "loaded_by"]));
    const dumped = await client.invoke("probe", { ...binding, probeKind: "jvm.class.dump", parameters: { className: "lab.DynamicMarkerFilter", classLoaderId } }, { remoteCalls: 1, nodes: 1, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1 });
    expect(fields(dumped.objects[0])).toMatchObject({ className: "lab.DynamicMarkerFilter", loaderId: classLoaderId, bytecodeSha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(dumped.artifact).toMatchObject({ complete: true, sha256: fields(dumped.objects[0]).bytecodeSha256 });
    const chunks: Buffer[] = []; await client.executor.downloadArtifact({ artifactToken: dumped.artifact!.token, sha256: dumped.artifact!.sha256, size: dumped.artifact!.size, expiresAt: dumped.artifact!.expiresAt }, (chunk) => { chunks.push(Buffer.from(chunk)); });
    expect(Buffer.concat(chunks).length).toBeGreaterThan(0);
    await client.maintenance("artifact_release", { artifactToken: dumped.artifact!.token });
  }, 180_000);

  it("Lab-Java 在持续 HTTP 流量下连续 Attach，保持服务可用与 JVM 身份稳定", async () => {
    const client = await remote(2223);
    const before = await client.enumerate("jvm", ["pid", "command", "attachSupported", "container"]);
    const jvm = before.find((item) => String(item.fields.command).toLowerCase().includes("catalina")) ?? before[0];
    if (!jvm) throw new Error("缺少 JVM");
    const binding = { namespace: "jvm", identity: jvm.identity, locator: {} };
    const endpoint = "http://127.0.0.1:8081/lab/";
    const springEndpoint = "http://127.0.0.1:8081/lab/spring/health";
    const baselineLatenciesMs: number[] = [];
    const loadedLatenciesMs: number[] = [];
    const failures: string[] = [];
    let requestSequence = 0;
    const requestOnce = async (latencies: number[]) => {
      const started = performance.now();
      try {
        const target = requestSequence++ % 2 === 0 ? endpoint : springEndpoint;
        const response = await fetch(target, { signal: AbortSignal.timeout(10_000) });
        await response.arrayBuffer();
        if (!response.ok) failures.push(`HTTP ${response.status}`);
      } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error));
      } finally {
        latencies.push(performance.now() - started);
      }
    };
    for (let index = 0; index < 20; index += 1) await requestOnce(baselineLatenciesMs);

    let running = true;
    const workers = Array.from({ length: 8 }, async () => {
      while (running) {
        await requestOnce(loadedLatenciesMs);
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    });
    const attachWallTimeMs: number[] = [];
    let componentMisses = 0;
    let invalidProbeCosts = 0;
    try {
      for (let index = 0; index < 12; index += 1) {
        const inventory = await client.invoke("probe", { ...binding, probeKind: "jvm.tomcat.inventory", parameters: {} }, {
          remoteCalls: 1, nodes: 500, bytes: 1_572_864, wallTimeMs: 60_000, probeCalls: 1,
        });
        if (inventory.cost.probeCalls !== 1) invalidProbeCosts += 1;
        const hasFilter = inventory.objects.some((item) => item.namespace === "java_component" && item.fields.className === "lab.DynamicMarkerFilter");
        const hasWebSocket = inventory.objects.some((item) => item.namespace === "java_component"
          && item.fields.className === "lab.LabWebSocketEndpoint" && item.fields.name === "/ws/{id}"
          && Array.isArray(item.fields.mappings) && item.fields.mappings.includes("endpointPath:/ws/{id}"));
        const hasSpringController = inventory.objects.some((item) => item.namespace === "java_component"
          && item.fields.className === "lab.LabSpringController" && item.fields.componentKind === "spring_controller"
          && Array.isArray(item.fields.mappings) && item.fields.mappings.some((mapping) => mapping.startsWith("mapping:") && mapping.includes("/health")));
        const hasSpringInterceptor = inventory.objects.some((item) => item.namespace === "java_component"
          && item.fields.className === "lab.LabSpringInterceptor" && item.fields.componentKind === "spring_interceptor");
        if (!hasFilter || !hasWebSocket || !hasSpringController || !hasSpringInterceptor) componentMisses += 1;
        attachWallTimeMs.push(inventory.cost.wallTimeMs);
      }
    } finally {
      running = false;
      await Promise.all(workers);
    }
    const after = await client.enumerate("jvm", ["pid", "command", "attachSupported", "container"]);
    const identityStable = after.some((item) => JSON.stringify(item.identity) === JSON.stringify(jvm.identity));
    const percentile = (values: number[], quantile: number) => {
      const sorted = values.toSorted((left, right) => left - right);
      return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * quantile) - 1)] ?? 0;
    };
    const loadedP95Ms = percentile(loadedLatenciesMs, 0.95);
    const passed = failures.length === 0 && loadedLatenciesMs.length >= 50 && loadedP95Ms < 5_000
      && componentMisses === 0 && invalidProbeCosts === 0 && identityStable;
    const report = {
      status: passed ? "PASS" : "FAIL",
      environment: { target: "tomcat:9.0-jdk17-temurin-jammy Docker + Spring MVC 5.3.39", architecture: process.arch, endpoints: [endpoint, springEndpoint] },
      traffic: {
        concurrency: 8,
        baselineRequests: baselineLatenciesMs.length,
        loadedRequests: loadedLatenciesMs.length,
        failures,
        baselineP95Ms: Math.round(percentile(baselineLatenciesMs, 0.95)),
        loadedP95Ms: Math.round(loadedP95Ms),
        loadedMaxMs: Math.round(Math.max(...loadedLatenciesMs)),
      },
      attach: {
        attempts: attachWallTimeMs.length,
        componentMisses,
        invalidProbeCosts,
        requiredComponents: [
          { componentKind: "filter", className: "lab.DynamicMarkerFilter" },
          { componentKind: "websocket_endpoint", className: "lab.LabWebSocketEndpoint", mapping: "/ws/{id}" },
          { componentKind: "spring_controller", className: "lab.LabSpringController", mapping: "/health" },
          { componentKind: "spring_interceptor", className: "lab.LabSpringInterceptor" },
        ],
        wallTimeMs: attachWallTimeMs,
        maxWallTimeMs: Math.max(...attachWallTimeMs),
      },
      identityStable,
    };
    const outputDirectory = join(projectRoot, "acceptance/jvm-attach");
    await mkdir(outputDirectory, { recursive: true });
    await writeFile(join(outputDirectory, "result-docker.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");

    expect(failures).toEqual([]);
    expect(loadedLatenciesMs.length).toBeGreaterThanOrEqual(50);
    expect(loadedP95Ms).toBeLessThan(5_000);
    expect(attachWallTimeMs).toHaveLength(12);
    expect(attachWallTimeMs.every((value) => value >= 0 && value <= 30_000)).toBe(true);
    expect(componentMisses).toBe(0);
    expect(invalidProbeCosts).toBe(0);
    expect(identityStable).toBe(true);
  }, 240_000);

  it("Lab-Java 由控制器自动完成精确 ClassLoader 与字节码保全，并闭合完整分页来源", async () => {
    const client = await remote(2223);
    const directory = await mkdtemp(join(tmpdir(), "huntwarden-java-controller-"));
    const store = await RuntimeStore.open(directory, "runtime.db");
    try {
      const task = testTask();
      task.taskId = "TASK-DOCKER-JAVA-AUTONOMOUS";
      task.protocolVersion = 2;
      task.checks = ["java_memory_shell"];
      task.profile = "DEEP";
      store.createTask(task);
      const result = await bootstrapProtocolV2({
        task, config: testConfig(directory), store, executor: client.executor,
        evidence: new EvidenceStore(directory, store), approvals: new ApprovalService(store),
      });
      const facts = store.listFacts(task.taskId, result.epoch.epochId);
      const component = facts.find((fact) => fact.namespace === "java_component"
        && fact.privatePayload.className === "lab.DynamicMarkerFilter");
      if (!component) throw new Error("控制器未发现动态 Filter 组件");
      expect(component.privatePayload.context).toBe("/lab");
      const exactClass = facts.find((fact) => fact.namespace === "class"
        && fact.privatePayload.className === component.privatePayload.className
        && fact.privatePayload.loaderId === component.privatePayload.classLoaderId);
      if (!exactClass) throw new Error("控制器未检查组件绑定的精确 ClassLoader");
      const implementedBy = store.listEdges(task.taskId, result.epoch.epochId).find((edge) => edge.relation === "implemented_by"
        && edge.fromRef === component.subjectRef && edge.toRef === exactClass.subjectRef);
      expect(implementedBy).toBeDefined();
      expect(store.listRelationProvenance(task.taskId, result.epoch.epochId)).toContainEqual(
        expect.objectContaining({ edgeRef: implementedBy?.edgeId, derivation: "DERIVED", resolverVersion: "java-runtime-relations@1.0.0" }),
      );
      expect(store.listEvidence(task.taskId)).toContainEqual(expect.objectContaining({
        type: "jvm_class_bytecode",
        metadata: expect.objectContaining({
          epochId: result.epoch.epochId, artifactSubjectRef: exactClass.subjectRef,
          complete: true, integrityStatus: "VERIFIED",
        }),
      }));
      const completion = new InvestigationCompletionValidator(store).freeze(task.taskId, result.epoch.epochId);
      expect(completion.investigationStatus).toBe("CLOSED_NO_OBSERVED_FINDING");
      expect(store.listInvestigationObligations(task.taskId, result.epoch.epochId)).toContainEqual(expect.objectContaining({
        obligationKind: "CATEGORY_SCOPE_JAVA_MEMORY_SHELL", required: true, status: "SATISFIED",
        resultRefs: expect.arrayContaining([expect.stringMatching(/^COV-/)]), gapRefs: [],
      }));
    } finally {
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }, 300_000);

  it("Lab-Account 通过账户、委派、有效 sshd 配置与认证事件建立信任事实", async () => {
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
    const delegation = await client.enumerate("delegation_rule", ["mechanism", "sourceDigest", "line", "ruleDigest", "source", "effect", "subject", "runAs", "statement"]);
    expect(delegation.some((item) => item.fields.mechanism === "sudo" && String(item.fields.statement).includes("huntwarden-helper"))).toBe(true);
    expect([...new Set(delegation.map((item) => item.fields.mechanism))]).toEqual(expect.arrayContaining(["sudo", "doas", "polkit"]));
    const trust = await client.enumerate("ssh_trust_config", ["scope", "directive", "valueDigest", "value", "source", "effective"]);
    expect(trust.some((item) => item.fields.directive === "authorizedkeysfile" && item.fields.effective === true)).toBe(true);
    expect(trust.some((item) => item.fields.directive === "permitrootlogin" && item.fields.effective === true)).toBe(true);
    const contextual = trust.find((item) => item.fields.directive === "authorizedprincipalsfile" && String(item.fields.scope).includes("user=labroot") && item.fields.value === "/etc/ssh/labroot_principals");
    expect(contextual?.fields.source).toBe("sshd -T -C (observed auth context)");
    if (!contextual) throw new Error("缺少按已观察认证上下文解析的 SSH Match 配置");
    const referenced = await client.invoke("relate", { namespace: "ssh_trust_config", identity: contextual.identity, locator: {}, relation: "references", limit: 20 });
    expect(referenced.objects.some((item) => item.namespace === "file" && item.fields.path === "/etc/ssh/labroot_principals")).toBe(true);
  }, 180_000);

  it("Lab-Persistence 通过 cron/unit/persistence 覆盖四类来源", async () => {
    const client = await remote(2225);
    const cron = await client.enumerate("cron_entry", ["source", "schedule", "user", "command"]);
    const units = await client.enumerate("unit", ["name", "path", "enabled", "active", "execStart", "user"]);
    const extended = await client.enumerate("persistence", ["kind", "source", "user", "command", "enabled"]);
    expect(cron.length).toBeGreaterThan(0);
    const executable = await client.invoke("relate", { namespace: "cron_entry", identity: cron[0]!.identity, locator: { path: cron[0]!.fields.source }, relation: "executes", limit: 20 });
    expect(executable.objects.some((item) => item.namespace === "file")).toBe(true);
    expect(units.some((item) => item.fields.name === "huntwarden-lab.service"
      && item.fields.user === "root"
      && item.fields.execStart === "/usr/bin/python3 /opt/huntwarden-lab/listener.py --from-drop-in")).toBe(true);
    expect(extended.some((item) => ["ssh", "shell", "extended"].includes(String(item.fields.kind)))).toBe(true);
  }, 180_000);
});
