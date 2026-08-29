import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { loadConfig } from "../config/load-config.js";
import { evaluateModelCapability, parseModelCapabilityManifest, renderModelCapabilityMarkdown } from "../evaluation/model-capability.js";
import { RuntimeStore } from "../storage/runtime-store.js";

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const manifestPath = argument("--manifest");
if (!manifestPath) throw new Error("用法: npm run eval:model -- --manifest <labels.json> [--storage-dir dir] [--database-file runtime.db] [--json result.json] [--markdown result.md]");
const config = await loadConfig();
const manifest = parseModelCapabilityManifest(JSON.parse(await readFile(resolve(manifestPath), "utf8")));
const storageDir = argument("--storage-dir") ?? config.storage.baseDir;
const databaseFile = argument("--database-file") ?? config.storage.databaseFile;
const store = await RuntimeStore.open(resolve(storageDir), databaseFile);
try {
  const result = evaluateModelCapability(store, manifest);
  const json = `${JSON.stringify(result, null, 2)}\n`;
  const markdown = renderModelCapabilityMarkdown(result);
  const jsonPath = argument("--json");
  const markdownPath = argument("--markdown");
  if (jsonPath) await writeFile(resolve(jsonPath), json, { encoding: "utf8", mode: 0o600 });
  if (markdownPath) await writeFile(resolve(markdownPath), markdown, { encoding: "utf8", mode: 0o600 });
  process.stdout.write(markdown);
  if (result.status !== "PASS") process.exitCode = 1;
} finally {
  store.close();
}
