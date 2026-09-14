import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { app } from "electron";
import { loadConfig, serializeConfig } from "../config/load-config.js";
import type { AppConfig } from "../config/schema.js";
import { ElectronSafeStorageCipher } from "../desktop/electron-safe-storage-cipher.js";

// External, same-identity bundles must bake in their trusted checkout; this is
// deliberately not an environment variable or a user-supplied executable path.
declare const HUNTWARDEN_CREDENTIAL_REPO_ROOT: string | undefined;
const repositoryRoot = typeof HUNTWARDEN_CREDENTIAL_REPO_ROOT === "string"
  ? HUNTWARDEN_CREDENTIAL_REPO_ROOT
  : fileURLToPath(new URL("../../../", import.meta.url));
const provider = "tokenrhythm";
const apiKeyEnv = "HUNTWARDEN_LLM_API_KEY";
const endpoint = "https://tokenrhythm.studio/v1";

const commands = {
  "model:check": { file: "check-model.ts", required: ["--config"], optional: [] },
  "model:smoke": { file: "smoke-model.ts", required: ["--config"], optional: [] },
  "run:investigation": {
    file: "run-investigation.ts",
    required: ["--config", "--manifest", "--output-dir"], optional: [],
  },
  "qualify:provider:tasks": {
    file: "run-provider-qualification.ts",
    required: ["--config", "--linux-target", "--java-target", "--output"], optional: [],
  },
  "qualify:provider": {
    file: "qualify-provider.ts",
    required: ["--config", "--linux-task", "--java-task", "--provider-contract", "--output"],
    optional: ["--data-dir", "--database-file"],
  },
} satisfies Record<string, { file: string; required: string[]; optional: string[] }>;

type Command = keyof typeof commands;
class BridgeError extends Error {}
function report(event: string, details: Record<string, unknown> = {}): void {
  process.stdout.write(`${JSON.stringify({ component: "desktop-credential", event, ...details })}\n`);
}

function parseArguments(): { command: Command; options: Map<string, string>; args: string[] } {
  const args = process.argv.slice(process.defaultApp ? 2 : 1);
  const command = args.shift();
  if (!command || !Object.hasOwn(commands, command)) throw new BridgeError("必须指定受控的 model:check、model:smoke、run:investigation 或 Provider 资格命令；不接受任意脚本/命令");
  const specification = commands[command as Command];
  const allowed: readonly string[] = [...specification.required, ...specification.optional];
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]!;
    const value = args[index + 1];
    if (!allowed.includes(name) || options.has(name) || !value || value.startsWith("-") || /\p{Cc}/u.test(value)) {
      throw new BridgeError("拒绝未知、重复、缺值或控制字符参数");
    }
    options.set(name, value);
  }
  if (specification.required.some((name) => !options.has(name))) throw new BridgeError("缺少受控命令的必需参数");
  return { command: command as Command, options, args };
}

async function validateDestination(configPath: string): Promise<AppConfig> {
  // A caller-controlled endpoint would turn even a fixed CLI into a credential
  // export. Only this explicitly authorized provider/destination is supported.
  const config = await loadConfig(configPath);
  const model = config.model;
  if (model.source !== "custom" || model.provider !== provider || model.model !== "glm-5.3-flash"
      || model.protocol !== "openai-completions" || model.baseUrl !== endpoint
      || model.authentication.type !== "api-key-env" || model.authentication.apiKeyEnv !== apiKeyEnv
      || config.threatIntel.enabled) {
    throw new BridgeError("配置必须使用已授权的 tokenrhythm/glm-5.3-flash、固定 HTTPS 端点与 HUNTWARDEN_LLM_API_KEY；禁止启用其他凭据使用方");
  }
  return config;
}

async function readAuthorizedKey(): Promise<string> {
  const cipher = new ElectronSafeStorageCipher();
  if (!(await cipher.isSecure())) throw new BridgeError("系统安全存储不可用；未尝试明文后端或其他凭据");
  // Do not initialize/list the credential store: those operations mutate its
  // permissions or inspect other entries. Read only the authorized map member.
  const path = join(app.getPath("appData"), "HuntWarden", "credentials.enc.json");
  const container: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!container || typeof container !== "object" || !("version" in container) || container.version !== 1
      || !("entries" in container) || !container.entries || typeof container.entries !== "object"
      || !(provider in container.entries)) throw new BridgeError("指定 tokenrhythm 加密条目不存在或容器格式无效");
  const encrypted: unknown = (container.entries as Record<string, unknown>)[provider];
  if (typeof encrypted !== "string" || !encrypted) throw new BridgeError("指定 tokenrhythm 加密条目格式无效");
  let plaintext: string;
  try { plaintext = await cipher.decrypt(encrypted); }
  catch { throw new BridgeError("同应用身份的系统安全存储解密失败；请检查当前登录桌面的系统授权提示，未修改钥匙串 ACL、未尝试其他凭据"); }
  let credential: unknown;
  try { credential = JSON.parse(plaintext); }
  catch { throw new BridgeError("指定 tokenrhythm 已解密条目格式无效"); }
  plaintext = "";
  if (!credential || typeof credential !== "object" || !("type" in credential) || credential.type !== "api_key"
      || !("key" in credential) || typeof credential.key !== "string" || !credential.key.trim()
      || credential.key.length > 16_384 || credential.key.includes("\0")) throw new BridgeError("指定 tokenrhythm 条目不是有效 API Key");
  return credential.key;
}

function terminateGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (!child.pid) return;
  try { process.kill(process.platform === "win32" ? child.pid : -child.pid, signal); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") child.kill(signal); }
}

async function runChild(command: Command, args: string[], key: string): Promise<number> {
  const entry = join(repositoryRoot, "src", "cli", commands[command].file);
  if (await realpath(entry) !== entry) throw new BridgeError("拒绝符号链接重定向受控 CLI");
  const environment: NodeJS.ProcessEnv = {
    HOME: app.getPath("home"),
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
    LANG: "en_US.UTF-8",
    ELECTRON_RUN_AS_NODE: "1",
    [apiKeyEnv]: key,
  };
  if (command === "run:investigation") environment.HUNTWARDEN_INVESTIGATION_CONFIRM = "I_HAVE_AUTHORIZATION";
  // No shell, npm lifecycle hooks, inherited NODE_OPTIONS, loader overrides,
  // proxy/CA overrides, desktop test hooks, or ambient credentials.
  const child = spawn(process.execPath, [
    "--import", pathToFileURL(join(repositoryRoot, "node_modules", "tsx", "dist", "loader.mjs")).href,
    entry, ...args,
  ], { cwd: repositoryRoot, env: environment, stdio: ["ignore", "pipe", "ignore"], detached: process.platform !== "win32" });
  delete environment[apiKeyEnv];
  key = "";
  report("child-started", { command });
  let output = "";
  // Never forward raw child logs, stack traces, HTTP errors or provider text.
  // Retain only a bounded buffer to recognize the fixed health CLI success and
  // numeric usage fields. All other stdout and all stderr are discarded.
  child.stdout!.on("data", (chunk: Buffer) => {
    if (command === "model:check" || command === "model:smoke") {
      if (output.length < 65_536) output += chunk.toString("utf8").slice(0, 65_536 - output.length);
    }
  });
  let interruption: NodeJS.Signals | undefined;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const interrupt = (signal: NodeJS.Signals): void => {
    interruption ??= signal;
    terminateGroup(child, signal);
    killTimer ??= setTimeout(() => terminateGroup(child, "SIGKILL"), 5_000);
  };
  const onInterrupt = (): void => interrupt("SIGINT");
  const onTerminate = (): void => interrupt("SIGTERM");
  const onExit = (): void => terminateGroup(child, "SIGKILL");
  process.on("SIGINT", onInterrupt);
  process.on("SIGTERM", onTerminate);
  process.on("exit", onExit);
  try {
    const exitCode = await new Promise<number>((resolveExit, reject) => {
      child.once("error", () => reject(new BridgeError("受控 CLI 子进程启动失败；原始错误日志已抑制")));
      child.once("close", (code, signal) => {
        const finalSignal = interruption ?? signal;
        resolveExit(finalSignal ? 128 + constants.signals[finalSignal] : code ?? 1);
      });
    });
    const health: Record<string, unknown> = {};
    if (exitCode === 0 && command === "model:check") health.offlineCredentialCheck = output.includes("模型配置检查通过");
    if (exitCode === 0 && command === "model:smoke") {
      health.toolCallVerified = output.includes("模型在线冒烟通过") && output.includes("tool=connection_probe");
      for (const field of ["input", "output"] as const) {
        const match = new RegExp(`^usage\\.${field}=(\\d+)$`, "mu").exec(output);
        if (match) health[`usage.${field}`] = Number(match[1]);
      }
    }
    report("child-complete", { command, exitCode, ...health });
    return exitCode;
  } finally {
    output = "";
    if (killTimer) clearTimeout(killTimer);
    terminateGroup(child, "SIGKILL");
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
    process.off("exit", onExit);
  }
}

async function main(): Promise<number> {
  process.umask(0o077);
  const { command, options, args } = parseArguments();
  if (command === "run:investigation" && process.env.HUNTWARDEN_INVESTIGATION_CONFIRM !== "I_HAVE_AUTHORIZATION") throw new BridgeError("批跑前必须显式设置 HUNTWARDEN_INVESTIGATION_CONFIRM=I_HAVE_AUTHORIZATION");
  if (process.platform !== "darwin" || !process.versions.electron || app.getName() !== "HuntWarden") {
    throw new BridgeError("此入口要求 macOS 上与 HuntWarden 相同应用名称/身份的 Electron 主进程");
  }
  const packagePath = join(repositoryRoot, "package.json");
  const metadata = JSON.parse(await readFile(packagePath, "utf8")) as { name?: unknown; productName?: unknown };
  if (metadata.name !== "huntwarden-agent" || metadata.productName !== "HuntWarden") throw new BridgeError("受控仓库根目录无效");
  const configPath = resolve(options.get("--config")!);
  const config = await validateDestination(configPath);
  // Separate Chromium state: never open or migrate the user's desktop profile.
  const scratch = await mkdtemp(join(app.getPath("temp"), "huntwarden-credential-"));
  app.setPath("userData", scratch);
  app.setPath("sessionData", scratch);
  app.setAppLogsPath(join(scratch, "logs"));
  app.dock?.hide();
  try {
    // The child must consume this validated snapshot, not re-read a mutable
    // caller path after the credential has been unlocked.
    const snapshotPath = join(scratch, "config.yaml");
    await writeFile(snapshotPath, serializeConfig(config), { mode: 0o600 });
    args[args.indexOf("--config") + 1] = snapshotPath;
    await app.whenReady();
    report("credential-unlock-started", { provider, backend: "macOS Keychain" });
    const deadline = setTimeout(() => {
      report("blocked", { reason: "系统安全存储等待 60 秒超时；可能需要当前登录桌面的系统授权，未修改 ACL、未重试" });
      app.exit(2);
    }, 60_000);
    let key: string;
    try { key = await readAuthorizedKey(); } finally { clearTimeout(deadline); }
    report("credential-resolved", { provider, backend: "macOS Keychain", plaintextPersisted: false });
    try { return await runChild(command, args, key); } finally { key = ""; }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

void main().then((code) => app.exit(code)).catch((error: unknown) => {
  // Only our fixed messages are printable; unexpected errors may carry secrets.
  report("failed", { reason: error instanceof BridgeError ? error.message : "凭据入口失败；原始异常已抑制以保护凭据" });
  app.exit(2);
});
