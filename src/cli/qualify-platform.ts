import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../config/load-config.js";
import type { TargetConfig } from "../domain/types.js";
import { SSHExecutor } from "../executor/ssh-executor.js";
import { parsePlatformQualificationManifest, runPlatformQualification } from "../evaluation/platform-qualification.js";
import { sha256Bytes } from "../evaluation/provider-qualification.js";

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
if (dirty) throw new Error("平台发布资格证据只能从干净固定提交生成；请先提交或移除工作树修改");
if (process.env.HUNTWARDEN_PLATFORM_CONFIRM !== "I_HAVE_AUTHORIZATION") throw new Error("必须设置 HUNTWARDEN_PLATFORM_CONFIRM=I_HAVE_AUTHORIZATION，确认平台只读与 Evidence 验收已获授权");
const manifestBytes = await readFile(manifestPath);
const helperBytes = await readFile(resolve(root, "host-helper/huntwarden_helper.py"));
const manifest = parsePlatformQualificationManifest(JSON.parse(manifestBytes.toString("utf8")));
const target = JSON.parse(await readFile(targetPath, "utf8")) as Partial<TargetConfig>;
if (typeof target.host !== "string" || !target.host || !Number.isInteger(target.port) || Number(target.port) < 1 || Number(target.port) > 65_535
  || typeof target.username !== "string" || !target.username || typeof target.hostFingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]+$/.test(target.hostFingerprint)
  || typeof target.privateKeyPath !== "string" || !isAbsolute(target.privateKeyPath) || typeof target.knownHostsPath !== "string" || !isAbsolute(target.knownHostsPath)) {
  throw new Error("--target 必须是含 host/port/username/hostFingerprint/绝对 privateKeyPath/knownHostsPath 的有效 TargetConfig JSON");
}
const config = await loadConfig(option("--config"));
const result = await runPlatformQualification({
  manifest,
  manifestSha256: sha256Bytes(manifestBytes),
  commit,
  expectedHelperSha256: sha256Bytes(helperBytes),
  createRemote: () => new SSHExecutor(target as TargetConfig, config.executor.helperPath, config.executor.timeoutSeconds * 1_000),
});
await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
if (result.status !== "PASS") {
  process.stderr.write(`平台验收失败:\n- ${result.failures.join("\n- ")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`平台验收通过：${result.environment.platformId}，结果已写入 ${outputPath}\n`);
}
