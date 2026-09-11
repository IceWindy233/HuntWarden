import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { TargetConfig } from "../domain/types.js";
import { SSHExecutor } from "../executor/ssh-executor.js";
import { parseBusinessJvmQualificationManifest, runBusinessJvmQualification } from "../evaluation/business-jvm-qualification.js";
import { sha256Bytes } from "../evaluation/provider-qualification.js";
import { loadConfig } from "../config/load-config.js";

const args = process.argv.slice(2);
function option(name: string, required = false): string | undefined {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : undefined;
  if (index >= 0 && (!value || value.startsWith("--"))) throw new Error(`${name} 缺少参数值`);
  if (required && !value) throw new Error(`缺少必需参数 ${name}`);
  return value;
}
const manifestPath = resolve(option("--manifest", true)!);
const targetPath = resolve(option("--target", true)!);
const outputPath = resolve(option("--output", true)!);
const root = fileURLToPath(new URL("../..", import.meta.url));
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (dirty) throw new Error("真实业务 JVM 发布资格证据只能从干净固定提交生成；请先提交或移除工作树修改");
if (process.env.HUNTWARDEN_BUSINESS_JVM_CONFIRM !== "I_HAVE_AUTHORIZATION") throw new Error("必须设置 HUNTWARDEN_BUSINESS_JVM_CONFIRM=I_HAVE_AUTHORIZATION，确认业务流量与只读 Attach 已获授权");

const manifestBytes = await readFile(manifestPath);
const helperBytes = await readFile(resolve(root, "host-helper/huntwarden_helper.py"));
const manifest = parseBusinessJvmQualificationManifest(JSON.parse(manifestBytes.toString("utf8")));
const target = JSON.parse(await readFile(targetPath, "utf8")) as Partial<TargetConfig>;
if (typeof target.host !== "string" || !target.host || !Number.isInteger(target.port) || Number(target.port) < 1 || Number(target.port) > 65_535
  || typeof target.username !== "string" || !target.username || typeof target.hostFingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]+$/.test(target.hostFingerprint)
  || typeof target.privateKeyPath !== "string" || !isAbsolute(target.privateKeyPath) || typeof target.knownHostsPath !== "string" || !isAbsolute(target.knownHostsPath)) {
  throw new Error("--target 必须是含 host/port/username/hostFingerprint/绝对 privateKeyPath/knownHostsPath 的有效 TargetConfig JSON");
}
const config = await loadConfig(option("--config"));
const executor = new SSHExecutor(target as TargetConfig, config.executor.helperPath, config.executor.timeoutSeconds * 1_000);
try {
  const result = await runBusinessJvmQualification({ manifest, manifestSha256: sha256Bytes(manifestBytes), expectedHelperSha256: sha256Bytes(helperBytes), remote: executor, commit });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  if (result.status !== "PASS") {
    process.stderr.write(`真实业务 JVM 验收失败:\n- ${result.failures.join("\n- ")}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`真实业务 JVM 验收通过：Attach=${result.attach.attempts}，请求=${result.traffic.loadedRequests}，结果已写入 ${outputPath}\n`);
  }
} finally {
  await executor.close();
}
