import { createModelBundle } from "../agent/model.js";
import { checkModel } from "../agent/model-health.js";
import { loadConfig } from "../config/load-config.js";

const config = await loadConfig();
const { models, model } = createModelBundle(config);
const result = await checkModel(models, model);

if (!result.ok) {
  const hint = config.model.source === "custom" && config.model.authentication.type === "api-key-env"
    ? `请设置环境变量 ${config.model.authentication.apiKeyEnv}`
    : `请设置 ${config.model.provider} Provider 所需的凭据环境变量`;
  throw new Error(`模型配置有效，但未找到可用凭据；${hint}`);
}

process.stdout.write([
  "模型配置检查通过",
  `source=${config.model.source ?? "builtin"}`,
  `provider=${model.provider}`,
  `model=${model.id}`,
  `protocol=${model.api}`,
  `endpoint=${model.baseUrl}`,
  `credentialSource=${result.credentialSource ?? "configured"}`,
  "说明：本检查不发起网络请求，也不会输出密钥。",
  "",
].join("\n"));
