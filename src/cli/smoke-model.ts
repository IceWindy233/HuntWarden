import { createModelBundle } from "../agent/model.js";
import { smokeModel } from "../agent/model-health.js";
import { loadConfig } from "../config/load-config.js";

const config = await loadConfig();
const { models, model } = createModelBundle(config);
const result = await smokeModel(config, models, model);
if (!result.ok) throw new Error(result.message);

process.stdout.write([
  "模型在线冒烟通过",
  `provider=${result.provider}`,
  `model=${result.model}`,
  `protocol=${result.protocol}`,
  "tool=connection_probe",
  `usage.input=${result.usage?.input ?? 0}`,
  `usage.output=${result.usage?.output ?? 0}`,
  "",
].join("\n"));
