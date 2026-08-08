import { builtinModels } from "@earendil-works/pi-ai/providers/all";

const models = builtinModels();
const providerId = process.argv[2];

if (!providerId) {
  process.stdout.write([
    "Pi 内置模型供应商：",
    ...models.getProviders().map((provider) => `${provider.id}\t${provider.name}\t${provider.getModels().length} models`),
    "",
    "查看模型：npm run model:list -- <provider-id>",
    "",
  ].join("\n"));
} else {
  const provider = models.getProvider(providerId);
  if (!provider) throw new Error(`未知内置 Provider: ${providerId}`);
  process.stdout.write([
    `${provider.name} (${provider.id})：`,
    ...provider.getModels().map((model) => `${model.id}\t${model.api}\treasoning=${model.reasoning}`),
    "",
  ].join("\n"));
}
