import React from "react";
import { render } from "ink";
import { createModelBundle } from "./agent/model.js";
import { loadConfig } from "./config/load-config.js";
import type { TaskMode } from "./domain/types.js";
import { Application } from "./runtime/application.js";
import { RuntimeStore } from "./storage/runtime-store.js";
import { App } from "./tui/App.js";
import { DbappThreatIntelClient } from "./threat-intel/dbapp-client.js";

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const config = await loadConfig();
const store = await RuntimeStore.open(config.storage.baseDir, config.storage.databaseFile);
store.reconcileInterruptedTasks();
const { models, model } = createModelBundle(config);
const threatIntel = new DbappThreatIntelClient(config.threatIntel, async () => process.env[config.threatIntel.apiKeyEnv]);
const application = new Application(config, store, models, model, undefined, threatIntel);

let task = arg("--resume") ? store.getTask(arg("--resume")!) : undefined;
if (!task && arg("--host")) {
  const port = Number(arg("--port") ?? 22);
  const fingerprint = arg("--fingerprint") ?? await application.inferLabFingerprint(config.executor.knownHostsPath, port);
  task = application.createTask({
    request: arg("--request") ?? "排查 WebShell、Tomcat Java 内存马、Linux 后门账户、持久化与入侵迹象，并形成结构化报告。",
    mode: (arg("--mode") ?? config.agent.defaultMode) as TaskMode,
    target: {
      host: arg("--host")!,
      port,
      username: arg("--user") ?? "secagent",
      hostFingerprint: fingerprint,
      privateKeyPath: arg("--identity") ?? config.executor.privateKeyPath,
      knownHostsPath: arg("--known-hosts") ?? config.executor.knownHostsPath,
    },
  });
}

render(
  <App application={application} {...(task ? { initialTask: task } : {})} autoStart={process.argv.includes("--auto-start")} />,
  { alternateScreen: true },
);
