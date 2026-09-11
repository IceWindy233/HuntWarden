#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import process from "node:process";

const root = resolve(new URL("..", import.meta.url).pathname);
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const requireProbe = args.includes("--require-probe");
const requireBuildIdentity = args.includes("--require-build-identity");
const artifactDir = option("--artifacts");
const manifestOutput = option("--write-manifest");
const failures = [];
const pass = [];

function file(path) { return readFileSync(join(root, path), "utf8"); }
function match(path, pattern, label) {
  const value = file(path).match(pattern)?.[1];
  if (!value) failures.push(`${label} 无法从 ${path} 解析`);
  return value;
}
function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function treeSha256(paths) {
  const files = [];
  const visit = (path) => {
    const info = statSync(path);
    if (info.isDirectory()) for (const name of readdirSync(path).sort()) visit(join(path, name));
    else if (info.isFile()) files.push(path);
  };
  for (const path of paths.map((value) => resolve(root, value)).sort()) visit(path);
  const digest = createHash("sha256");
  for (const path of files.sort()) digest.update(`${relative(root, path)}\0${sha256(path)}\n`);
  return digest.digest("hex");
}
function same(label, values) {
  const known = values.filter(Boolean);
  if (known.length !== values.length || new Set(known).size !== 1) failures.push(`${label} 不一致: ${values.join(" / ")}`);
  else pass.push(`${label}=${known[0]}`);
}

const packageVersion = JSON.parse(file("package.json")).version;
const controllerProtocol = Number(match("src/protocol-v2/types.ts", /PROTOCOL_VERSION\s*=\s*(\d+)/, "控制端协议"));
const controllerManifest = match("src/protocol-v2/types.ts", /MANIFEST_VERSION\s*=\s*"([^"]+)"/, "控制端 Manifest");
const helperVersion = match("host-helper/huntwarden_helper.py", /^HELPER_VERSION\s*=\s*"([^"]+)"/m, "Helper 版本");
const helperProtocol = Number(match("host-helper/huntwarden_helper.py", /^PROTOCOL_VERSION\s*=\s*(\d+)/m, "Helper 协议"));
const helperManifest = match("host-helper/huntwarden_helper.py", /^MANIFEST_VERSION\s*=\s*"([^"]+)"/m, "Helper Manifest");
const compatibleHelper = match("src/investigation/version.ts", /minimumHelperVersion:\s*"([^"]+)"/, "兼容矩阵 Helper");
const investigationEngineVersion = match("src/investigation/version.ts", /INVESTIGATION_ENGINE_VERSION\s*=\s*"([^"]+)"/, "调查引擎版本");
const ruleRegistryVersion = match("src/investigation/version.ts", /RULE_REGISTRY_VERSION\s*=\s*"([^"]+)"/, "规则注册表版本");
const playbookRegistryVersion = match("src/playbooks/registry.ts", /PLAYBOOK_REGISTRY_VERSION\s*=\s*"([^"]+)"/, "流程包注册表版本");
const installedSelfCheckManifest = match("host-helper/self-check-helper.sh", /REQUIRED_MANIFEST\s*=\s*"([^"]+)"/, "安装自检 Manifest");
const currentCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
same("协议版本", [String(controllerProtocol), String(helperProtocol)]);
same("Manifest 版本", [controllerManifest, helperManifest, installedSelfCheckManifest]);
same("Helper 兼容版本", [helperVersion, compatibleHelper]);

for (const shell of ["host-helper/install-helper.sh", "host-helper/self-check-helper.sh", "host-helper/uninstall-helper.sh", "scripts/build-release.sh"]) {
  const result = spawnSync("bash", ["-n", join(root, shell)], { encoding: "utf8" });
  if (result.status !== 0) failures.push(`${shell} shell 语法失败: ${result.stderr.trim()}`);
}
const compile = spawnSync("python3", ["-m", "py_compile", join(root, "host-helper/huntwarden_helper.py")], { encoding: "utf8" });
if (compile.status !== 0) failures.push(`Helper Python 编译失败: ${compile.stderr.trim()}`);

const capabilityRequest = JSON.stringify({ protocolVersion: controllerProtocol, requestId: "RELEASE-SELF-CHECK", epochId: "PRECHECK", deadlineMs: 10000, reservation: { reservationId: "RELEASE-SELF-CHECK", estimate: { remoteCalls: 1, nodes: 1, bytes: 1572864, wallTimeMs: 10000, probeCalls: 0 } }, params: {} });
const capabilityRun = spawnSync("python3", [join(root, "host-helper/huntwarden_helper.py"), "capabilities"], { input: capabilityRequest, encoding: "utf8", maxBuffer: 3 * 1024 * 1024 });
try {
  const envelope = JSON.parse(capabilityRun.stdout);
  const capability = envelope.capabilities;
  const requiredVerbs = ["enumerate", "project", "read", "match", "relate", "verify", "collect", "probe"];
  if (envelope.status !== "SUCCESS" || capability?.protocolVersion !== controllerProtocol || capability?.manifestVersion !== controllerManifest) failures.push("Helper capabilities Envelope 与控制端不兼容");
  if (capability?.helper?.sha256 !== sha256(join(root, "host-helper/huntwarden_helper.py"))) failures.push("Helper capabilities 没有返回当前源文件 SHA-256");
  const missing = requiredVerbs.filter((verb) => !capability?.verbs?.includes(verb));
  if (missing.length > 0) failures.push(`Helper 缺少取证原语: ${missing.join(", ")}`);
  if (capability?.namespaces?.task_ioc) failures.push("Helper 错误声明了 controller-local task_ioc");
  pass.push(`取证原语=${requiredVerbs.length}`);
} catch (error) {
  failures.push(`Helper capabilities 不能解析: ${error instanceof Error ? error.message : String(error)}`);
}

const rulePath = join(root, "rules/yara/webshell.yar");
if (!existsSync(rulePath) || !statSync(rulePath).isFile()) failures.push("固定 YARA RuleSet 缺失");
const probePath = join(root, "java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar");
const buildIdentityPath = join(root, "dist/build-identity.json");
if (requireBuildIdentity) {
  try {
    const identity = JSON.parse(readFileSync(buildIdentityPath, "utf8"));
    if (identity.schemaVersion !== 1 || identity.clean !== true || identity.commit !== currentCommit) failures.push("发布构建身份与当前干净提交不一致");
  } catch (error) {
    failures.push(`发布构建身份不可读: ${error instanceof Error ? error.message : String(error)}`);
  }
}
if (!existsSync(probePath)) {
  if (requireProbe) failures.push("Tomcat Probe JAR 缺失");
} else {
  const unzip = spawnSync("unzip", ["-p", probePath, "META-INF/MANIFEST.MF"], { encoding: "utf8" });
  if (unzip.status !== 0 || !/^Main-Class: io\.huntwarden\.probe\.Main\r?$/m.test(unzip.stdout) || !/^Agent-Class: io\.huntwarden\.probe\.ProbeAgent\r?$/m.test(unzip.stdout)) failures.push("Tomcat Probe JAR Manifest 不完整");
}

const componentManifest = {
  schemaVersion: 1,
  applicationVersion: packageVersion,
  protocolVersion: controllerProtocol,
  manifestVersion: controllerManifest,
  helperVersion,
  investigationEngineVersion,
  ruleRegistryVersion,
  playbookRegistryVersion,
  commit: currentCommit,
  components: {
    controller: { paths: ["src", "package.json", "package-lock.json"], sha256: treeSha256(["src", "package.json", "package-lock.json"]) },
    protocolManifest: { paths: ["src/protocol-v2"], sha256: treeSha256(["src/protocol-v2"]) },
    investigationEngine: { paths: ["src/investigation", "src/discovery", "src/evaluation"], sha256: treeSha256(["src/investigation", "src/discovery", "src/evaluation"]) },
    ruleRegistry: { paths: ["src/rules", "rules"], sha256: treeSha256(["src/rules", "rules"]) },
    playbookRegistry: { paths: ["src/playbooks"], sha256: treeSha256(["src/playbooks"]) },
    helper: { path: "host-helper/huntwarden_helper.py", sha256: sha256(join(root, "host-helper/huntwarden_helper.py")) },
    ...(existsSync(buildIdentityPath) ? { buildIdentity: { path: "dist/build-identity.json", sha256: sha256(buildIdentityPath) } } : {}),
    yaraRuleset: { path: "rules/yara/webshell.yar", sha256: sha256(rulePath) },
    ...(existsSync(probePath) ? { tomcatProbe: { path: "java/tomcat-probe/build/libs/huntwarden-tomcat-probe.jar", sha256: sha256(probePath) } } : {}),
  },
};
if (manifestOutput) writeFileSync(resolve(root, manifestOutput), `${JSON.stringify(componentManifest, null, 2)}\n`, { flag: "w" });

if (artifactDir) {
  const directory = resolve(root, artifactDir);
  const sumsPath = join(directory, "SHA256SUMS");
  if (!existsSync(sumsPath)) failures.push("发布目录缺少 SHA256SUMS");
  else {
    const records = readFileSync(sumsPath, "utf8").trim().split(/\r?\n/).filter(Boolean);
    const names = [];
    for (const line of records) {
      const parsed = line.match(/^([a-f0-9]{64})\s+\*?(?:\.\/)?(.+)$/);
      if (!parsed) { failures.push(`无法解析 SHA256SUMS 行: ${line}`); continue; }
      const [, expected, name] = parsed; const target = join(directory, name); names.push(name);
      if (!existsSync(target)) failures.push(`校验清单引用缺失文件: ${name}`);
      else if (sha256(target) !== expected) failures.push(`发布资产摘要不匹配: ${name}`);
    }
    if (!names.some((name) => name.endsWith(`-${packageVersion}.zip`))) failures.push(`缺少版本 ${packageVersion} 的 ZIP`);
    if (!names.some((name) => name.includes(packageVersion) && name.endsWith(".dmg"))) failures.push(`缺少版本 ${packageVersion} 的 DMG`);
    if (!names.includes("COMPONENTS.json")) failures.push("SHA256SUMS 未包含 COMPONENTS.json");
  }
}

if (failures.length > 0) {
  console.error("HuntWarden 发布自检失败:\n- " + failures.join("\n- "));
  process.exit(1);
}
console.log(`HuntWarden 发布自检通过：app=${packageVersion}，${pass.join("，")}${artifactDir ? "，发布资产摘要已验证" : ""}`);
