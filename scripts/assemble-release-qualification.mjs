#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
function option(name) {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`缺少 ${name}`);
  return resolve(args[index + 1]);
}
const inputPath = option("--inputs");
const outputPath = option("--output");
const root = fileURLToPath(new URL("..", import.meta.url));
const outputDirectory = await realpath(dirname(outputPath));
const fromRoot = relative(root, outputDirectory);
if (fromRoot !== ".." && !fromRoot.startsWith("../") && !isAbsolute(fromRoot)) throw new Error("资格清单必须写到仓库外");
const inputs = JSON.parse(await readFile(inputPath, "utf8"));
const failures = [];
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const platforms = ["ubuntu-24.04-arm64", "ubuntu-24.04-x86_64", "debian-12-systemd-x86_64", "rocky-or-alma-9-x86_64-selinux-enforcing", "amazon-linux-2023-x86_64"];
const allowed = new Set(["provider", "providerContract", "blindEvaluation", "businessJvm", "operational", "platforms"]);
if (!inputs || typeof inputs !== "object" || Array.isArray(inputs) || Object.keys(inputs).some((key) => !allowed.has(key))) throw new Error("输入只允许五类资格、协议契约和 platforms 路径映射");
async function reference(value, label) {
  if (typeof value !== "string" || !value) { failures.push(`${label}: MISSING`); return undefined; }
  let path;
  try { path = await realpath(resolve(dirname(inputPath), value)); }
  catch { failures.push(`${label}: FILE_UNAVAILABLE`); return undefined; }
  const child = relative(outputDirectory, path);
  if (!child || child === ".." || child.startsWith("../") || isAbsolute(child)) { failures.push(`${label}: OUTSIDE_QUALIFICATION_DIRECTORY`); return undefined; }
  const bytes = await readFile(path);
  try { JSON.parse(bytes.toString("utf8")); } catch { failures.push(`${label}: INVALID_JSON`); return undefined; }
  return { path: child, sha256: createHash("sha256").update(bytes).digest("hex") };
}
const evidence = {};
for (const key of ["provider", "providerContract", "blindEvaluation", "businessJvm", "operational"]) {
  const item = await reference(inputs[key], key);
  if (item) evidence[key] = item;
}
evidence.platforms = [];
if (inputs.platforms && (typeof inputs.platforms !== "object" || Array.isArray(inputs.platforms) || Object.keys(inputs.platforms).some((key) => !platforms.includes(key)))) throw new Error("platforms 必须为五个固定 platformId 的路径映射");
for (const platformId of platforms) {
  const artifact = await reference(inputs.platforms?.[platformId], platformId);
  if (artifact) evidence.platforms.push({ platformId, artifact });
}
const qualification = { schemaVersion: 1, commit, manifestVersion: "3.0.0", evidence };
if (failures.length) {
  await writeFile(outputPath, `${JSON.stringify({ schemaVersion: 1, status: "BLOCKED", commit, failures, availableEvidence: evidence }, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.error(`资格材料未齐；写入 BLOCKED 清单，不能用于发布：\n- ${failures.join("\n- ")}`);
  process.exitCode = 1;
} else {
  await writeFile(outputPath, `${JSON.stringify(qualification, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  const checked = spawnSync(process.execPath, [resolve(root, "scripts/release-qualification-check.mjs"), "--qualification", outputPath], { cwd: root, stdio: "inherit" });
  if (checked.error) throw checked.error;
  process.exitCode = checked.status ?? 1;
}
