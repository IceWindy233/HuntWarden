import { execFileSync } from "node:child_process";
import { lookup } from "node:dns/promises";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { createModelBundle } from "../agent/model.js";
import { smokeModel } from "../agent/model-health.js";
import { loadConfig } from "../config/load-config.js";
import { evaluateProviderQualification, sha256Bytes } from "../evaluation/provider-qualification.js";
import { MANIFEST_VERSION } from "../protocol-v2/types.js";
import { RuntimeStore } from "../storage/runtime-store.js";

const args = process.argv.slice(2);
function option(name: string, required = false): string | undefined {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : undefined;
  if (index >= 0 && (!value || value.startsWith("--"))) throw new Error(`${name} 缺少参数值`);
  if (required && !value) throw new Error(`缺少必需参数 ${name}`);
  return value;
}

const linuxTaskId = option("--linux-task", true)!;
const javaTaskId = option("--java-task", true)!;
const contractPath = resolve(option("--provider-contract", true)!);
const outputPath = resolve(option("--output", true)!);
const configPath = option("--config");
const root = fileURLToPath(new URL("../..", import.meta.url));
const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim();
if (dirty) throw new Error("真实 Provider 发布资格证据只能从干净固定提交生成；请先提交或移除工作树修改");

const config = await loadConfig(configPath);
const contractBytes = await readFile(contractPath);
const helperBytes = await readFile(resolve(root, "host-helper/huntwarden_helper.py"));
const contract = JSON.parse(contractBytes.toString("utf8")) as unknown;
const { models, model } = createModelBundle(config);
async function resolveEndpoint(endpoint: string): Promise<string[]> {
  const hostname = new URL(endpoint).hostname.replace(/^\[|\]$/g, "");
  return [...new Set((await lookup(hostname, { all: true, verbatim: true })).map((item) => item.address.toLowerCase()))].sort();
}
const endpoint = model.baseUrl;
const resolvedBefore = await resolveEndpoint(endpoint);
const smoke = await smokeModel(config, models, model);
if (!smoke.ok) throw new Error(smoke.message);
const resolvedAfter = await resolveEndpoint(endpoint);

const baseDir = resolve(option("--data-dir") ?? process.env.HUNTWARDEN_DATA_DIR ?? config.storage.baseDir);
const databaseFile = option("--database-file") ?? process.env.HUNTWARDEN_DATABASE_FILE ?? config.storage.databaseFile;
const store = await RuntimeStore.open(baseDir, databaseFile);
try {
  const result = evaluateProviderQualification({
    store,
    linuxTaskId,
    javaTaskId,
    commit,
    manifestVersion: MANIFEST_VERSION,
    provider: smoke.provider,
    model: smoke.model,
    protocol: smoke.protocol,
    endpoint: smoke.endpoint,
    endpointResolution: { before: resolvedBefore, after: resolvedAfter },
    expectedHelperSha256: sha256Bytes(helperBytes),
    smoke: { toolCallVerified: smoke.toolCallVerified, ...(smoke.usage ? { usage: smoke.usage } : {}) },
    faultContract: { sha256: sha256Bytes(contractBytes), value: contract },
  });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  if (result.status !== "PASS") {
    process.stderr.write(`真实 Provider 联合验收失败:\n- ${result.failures.join("\n- ")}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`真实 Provider 联合验收通过：${result.provider}/${result.model}，结果已写入 ${outputPath}\n`);
  }
} finally {
  store.close();
}
