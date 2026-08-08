import { access, chmod, cp, mkdir, readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  net,
  protocol,
  session,
  shell,
  type IpcMainInvokeEvent,
} from "electron";
import { DesktopBackend, type DesktopBackendOptions } from "./backend.js";
import { DesktopCredentialStore, EncryptedCredentialStore } from "../credentials/credential-store.js";
import { ElectronSafeStorageCipher } from "./electron-safe-storage-cipher.js";
import { IPC } from "../gui/channels.js";
import type { DesktopEvent } from "../gui/contracts.js";
import { appConfig, boolean, exactObject, newTaskInput, text } from "./ipc-validation.js";
import { parseConfig, serializeConfig } from "../config/load-config.js";
import { findLocalLabStateDir, repairProfilePaths } from "../config/profile-path-repair.js";

protocol.registerSchemesAsPrivileged([{
  scheme: "huntwarden",
  privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false, codeCache: true },
}]);

const diagnostics = (process.env.HUNTWARDEN_GUI_DEV_DIAGNOSTICS ?? process.env.SECHOST_GUI_DEV_DIAGNOSTICS) === "1";
function diagnostic(stage: string): void { if (diagnostics) process.stderr.write(`[HuntWarden GUI] ${stage}\n`); }
diagnostic("main module loaded");

const lock = app.requestSingleInstanceLock();
diagnostic(`single instance lock: ${String(lock)}`);
if (!lock) app.quit();

let mainWindow: BrowserWindow | undefined;
let backend: DesktopBackend | undefined;
let backendClosed = false;
let backendClosing = false;
const devUrl = process.env.HUNTWARDEN_GUI_DEV_URL ?? process.env.SECHOST_GUI_DEV_URL;

function allowedRendererUrl(url: string): boolean {
  if (devUrl) return url === devUrl || url.startsWith(`${devUrl}/`);
  return url.startsWith("huntwarden://bundle/");
}

function validateSender(event: IpcMainInvokeEvent): void {
  const url = event.senderFrame?.url ?? event.sender.getURL();
  if (!allowedRendererUrl(url)) throw new Error("拒绝来自非受信 Renderer 的 IPC 请求");
}

function requireBackend(): DesktopBackend {
  if (!backend) throw new Error("桌面服务尚未初始化");
  return backend;
}

function handle(channel: string, fn: (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown | Promise<unknown>): void {
  ipcMain.handle(channel, async (event, ...args) => {
    validateSender(event);
    try { return await fn(event, ...args); }
    catch (error) { throw new Error(error instanceof Error ? error.message : String(error)); }
  });
}

function registerIpc(): void {
  handle(IPC.bootstrap, async () => await requireBackend().getBootstrap());
  handle(IPC.configList, async () => await requireBackend().listConfigProfiles());
  handle(IPC.configGet, async (_event, profileId) => await requireBackend().getConfigProfile(text(profileId, "Profile ID", 64)));
  handle(IPC.configValidate, async (_event, config) => await requireBackend().validateConfigProfile(appConfig(config)));
  handle(IPC.configSave, async (_event, value) => {
    const input = exactObject(value, ["profileId", "name", "config"], "Profile");
    return await requireBackend().saveConfigProfile({
      ...(input.profileId === undefined ? {} : { profileId: text(input.profileId, "Profile ID", 64) }),
      name: text(input.name, "Profile 名称", 80),
      config: appConfig(input.config),
    });
  });
  handle(IPC.configActivate, async (_event, profileId) => await requireBackend().activateConfigProfile(text(profileId, "Profile ID", 64)));
  handle(IPC.configDelete, async (_event, profileId) => await requireBackend().deleteConfigProfile(text(profileId, "Profile ID", 64)));
  handle(IPC.configImport, async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { title: "导入 HuntWarden 配置", properties: ["openFile"], filters: [{ name: "YAML", extensions: ["yaml", "yml"] }] });
    return result.canceled || !result.filePaths[0] ? undefined : await requireBackend().importConfigProfile(result.filePaths[0]);
  });
  handle(IPC.configExport, async (_event, profileIdValue) => {
    const profileId = text(profileIdValue, "Profile ID", 64);
    const result = await dialog.showSaveDialog(mainWindow!, { title: "导出 HuntWarden 配置", defaultPath: `${profileId}.yaml`, filters: [{ name: "YAML", extensions: ["yaml"] }] });
    if (result.canceled || !result.filePath) return undefined;
    await requireBackend().exportConfigProfile(profileId, result.filePath);
    return result.filePath;
  });

  handle(IPC.modelProviders, () => requireBackend().listModelProviders());
  handle(IPC.modelList, (_event, provider) => requireBackend().listModels(text(provider, "Provider", 64)));
  handle(IPC.credentialStatus, async (_event, provider) => await requireBackend().getCredentialStatus(text(provider, "Provider", 64)));
  handle(IPC.credentialSave, async (_event, value) => {
    const input = exactObject(value, ["provider", "secret", "persist"], "凭据");
    return await requireBackend().saveCredential({
      provider: text(input.provider, "Provider", 64),
      secret: text(input.secret, "API Key", 16_384),
      persist: boolean(input.persist, "持久化标记"),
    });
  });
  handle(IPC.credentialDelete, async (_event, provider) => await requireBackend().deleteCredential(text(provider, "Provider", 64)));
  handle(IPC.modelCheck, async (_event, profileId) => await requireBackend().checkModel(text(profileId, "Profile ID", 64)));
  handle(IPC.modelSmoke, async (_event, profileId) => await requireBackend().smokeModel(text(profileId, "Profile ID", 64)));

  handle(IPC.selectPrivateKey, async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { title: "选择 SSH 私钥", properties: ["openFile", "showHiddenFiles"] });
    return result.canceled ? undefined : result.filePaths[0];
  });
  handle(IPC.selectKnownHosts, async () => {
    const result = await dialog.showOpenDialog(mainWindow!, { title: "选择 known_hosts", properties: ["openFile", "showHiddenFiles"] });
    return result.canceled ? undefined : result.filePaths[0];
  });
  handle(IPC.sshTest, async (_event, value) => {
    const wrapper = exactObject(value, ["host", "port", "username", "hostFingerprint", "privateKeyPath", "knownHostsPath"], "目标");
    const input = newTaskInput({ request: "SSH 连接测试", mode: "SCAN", checks: ["webshell"], target: wrapper });
    return await requireBackend().testSshTarget(input.target);
  });

  handle(IPC.taskList, () => requireBackend().listTasks());
  handle(IPC.taskSnapshot, (_event, taskId) => requireBackend().getTaskSnapshot(text(taskId, "Task ID", 64)));
  handle(IPC.taskCreate, (_event, input) => requireBackend().createTask(newTaskInput(input)));
  handle(IPC.taskStart, (_event, taskIdValue) => {
    const taskId = text(taskIdValue, "Task ID", 64);
    void requireBackend().startTask(taskId).catch(() => undefined);
  });
  handle(IPC.taskAbort, (_event, taskId) => requireBackend().abortTask(text(taskId, "Task ID", 64)));
  handle(IPC.taskRecover, (_event, taskIdValue) => {
    const taskId = text(taskIdValue, "Task ID", 64);
    void requireBackend().recoverTask(taskId).catch(() => undefined);
  });
  handle(IPC.taskSteer, async (_event, value) => {
    const input = exactObject(value, ["taskId", "text"], "Steering");
    await requireBackend().steerTask(text(input.taskId, "Task ID", 64), text(input.text, "Steering", 20_000));
  });
  handle(IPC.approvalDecide, (_event, value) => {
    const input = exactObject(value, ["approvalId", "approved"], "审批");
    requireBackend().decideApproval(text(input.approvalId, "Approval ID", 64), boolean(input.approved, "审批结果"));
  });
  handle(IPC.reportGenerate, async (_event, taskIdValue) => {
    const taskId = text(taskIdValue, "Task ID", 64);
    return await requireBackend().generateReport(taskId);
  });
  handle(IPC.reportList, async (_event, taskId) => await requireBackend().listReports(text(taskId, "Task ID", 64)));
  handle(IPC.reportRead, async (_event, value) => {
    const input = exactObject(value, ["taskId", "reportId"], "报告读取参数");
    return await requireBackend().readReport(
      text(input.taskId, "Task ID", 64),
      input.reportId === undefined ? undefined : text(input.reportId, "Report ID", 64),
    );
  });
  handle(IPC.evidenceReveal, async (_event, evidenceId) => {
    const evidence = requireBackend().getEvidence(text(evidenceId, "Evidence ID", 64));
    if (!evidence.storagePath || !requireBackend().isManagedPath(evidence.storagePath)) throw new Error("该 Evidence 没有可显示的受管本地文件");
    await access(evidence.storagePath);
    shell.showItemInFolder(evidence.storagePath);
  });
  handle(IPC.reportReveal, async (_event, value) => {
    const input = exactObject(value, ["taskId", "reportId"], "报告定位参数");
    const result = await requireBackend().readReport(
      text(input.taskId, "Task ID", 64),
      input.reportId === undefined ? undefined : text(input.reportId, "Report ID", 64),
    );
    if (!result || !requireBackend().isManagedPath(result.report.path)) throw new Error("报告不存在或路径超出受管目录");
    await access(result.report.path);
    shell.showItemInFolder(result.report.path);
  });
}

async function registerAppProtocol(): Promise<void> {
  const rendererRoot = resolve(app.getAppPath(), "dist", "renderer");
  await protocol.handle("huntwarden", async (request) => {
    const url = new URL(request.url);
    const requested = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
    const path = resolve(rendererRoot, `.${requested}`);
    const rel = relative(rendererRoot, path);
    if (rel.startsWith("..") || rel.includes(`..${sep}`)) return new Response("Not found", { status: 404 });
    try { return await net.fetch(pathToFileURL(path).toString()); }
    catch { return new Response("Not found", { status: 404 }); }
  });
}

function hardenSession(): void {
  const ses = session.defaultSession;
  ses.setPermissionCheckHandler(() => false);
  ses.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  ses.webRequest.onHeadersReceived((details, callback) => {
    const csp = devUrl
      ? "default-src 'self' http://127.0.0.1:5173; script-src 'self' 'unsafe-eval' http://127.0.0.1:5173; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:5173 http://127.0.0.1:5173; img-src 'self' data:"
      : "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'none'; img-src 'self' data:; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'";
    callback({ responseHeaders: { ...details.responseHeaders, "Content-Security-Policy": [csp] } });
  });
}

async function createWindow(): Promise<BrowserWindow> {
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 720,
    show: false,
    backgroundColor: "#071019",
    title: "HuntWarden",
    ...(process.platform === "darwin" ? { titleBarStyle: "hiddenInset" as const } : {}),
    webPreferences: {
      preload: join(app.getAppPath(), "dist", "desktop", "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
    },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event, url) => { if (!allowedRendererUrl(url)) event.preventDefault(); });
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());
  window.once("ready-to-show", () => window.show());
  if (devUrl) await window.loadURL(devUrl); else await window.loadURL("huntwarden://bundle/index.html");
  return window;
}

async function pathExists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

async function assertLegacyRuntimeIdle(legacyDir: string): Promise<void> {
  const lockPath = join(legacyDir, "runtime", "runtime.db.writer.lock");
  if (!(await pathExists(lockPath))) return;
  let ownerPid = 0;
  try { ownerPid = Number(JSON.parse(await readFile(lockPath, "utf8")).pid); } catch { ownerPid = 0; }
  if (ownerPid <= 0) return;
  let alive = true;
  try { process.kill(ownerPid, 0); } catch (error) { alive = (error as NodeJS.ErrnoException).code === "EPERM"; }
  if (alive) throw new Error(`旧版 SecHostAgent（PID ${ownerPid}）仍在运行，请退出后再启动 HuntWarden`);
}

async function repairStoredProfiles(configurationDir: string, currentUserData: string, labStateDir?: string): Promise<number> {
  const profilesDir = join(configurationDir, "profiles");
  if (!(await pathExists(profilesDir))) return 0;
  let repaired = 0;
  for (const name of await readdir(profilesDir)) {
    if (!/\.ya?ml$/i.test(name)) continue;
    const path = join(profilesDir, name);
    const config = parseConfig(await readFile(path, "utf8"), path);
    const changed = repairProfilePaths(config, { appPath: app.getAppPath(), currentUserData, ...(labStateDir ? { labStateDir } : {}) });
    if (!changed) continue;
    await writeFile(path, serializeConfig(config), { encoding: "utf8", mode: 0o600 });
    await chmod(path, 0o600);
    repaired += 1;
  }
  return repaired;
}

async function migrateLegacyUserData(): Promise<string | undefined> {
  if (process.env.HUNTWARDEN_SKIP_LEGACY_MIGRATION === "1") return undefined;
  const currentUserData = app.getPath("userData");
  if (await pathExists(join(currentUserData, "configuration", "settings.json"))) return undefined;
  const candidates = ["SecHostAgent", "sechost-agent"].map((name) => join(app.getPath("appData"), name));
  for (const legacyUserData of candidates) {
    if (resolve(legacyUserData) === resolve(currentUserData) || !(await pathExists(join(legacyUserData, "configuration", "settings.json")))) continue;
    await assertLegacyRuntimeIdle(legacyUserData);
    await mkdir(currentUserData, { recursive: true, mode: 0o700 });
    // safeStorage 密文绑定应用身份，重命名后的应用无法可靠解密旧密文；凭据必须由用户重新录入。
    for (const entry of ["configuration", "runtime"]) {
      const source = join(legacyUserData, entry);
      const destination = join(currentUserData, entry);
      if (await pathExists(source) && !(await pathExists(destination))) await cp(source, destination, { recursive: true, errorOnExist: true });
    }
    await unlink(join(currentUserData, "runtime", "runtime.db.writer.lock")).catch(() => undefined);
    diagnostic(`legacy application data copied from ${legacyUserData}`);
    return legacyUserData;
  }
  return undefined;
}

async function bootstrapDesktop(): Promise<void> {
  diagnostic("electron app ready");
  if (!devUrl) await registerAppProtocol();
  diagnostic("application protocol ready");
  hardenSession();
  diagnostic("session hardened");
  const migratedFrom = await migrateLegacyUserData();
  const labStateDir = await findLocalLabStateDir({
    appPath: app.getAppPath(),
    cwd: process.cwd(),
    ...(process.env.HUNTWARDEN_LAB_STATE_DIR ? { explicit: process.env.HUNTWARDEN_LAB_STATE_DIR } : {}),
  });
  const repairedProfiles = await repairStoredProfiles(join(app.getPath("userData"), "configuration"), app.getPath("userData"), labStateDir);
  if (repairedProfiles > 0) diagnostic(`repaired ${repairedProfiles} stored profile path(s)`);
  const cipher = new ElectronSafeStorageCipher();
  const persistent = new EncryptedCredentialStore(join(app.getPath("userData"), "credentials.enc.json"), cipher);
  let modelBundleFactory: DesktopBackendOptions["modelBundleFactory"];
  let checkpoint: DesktopBackendOptions["checkpoint"];
  const e2eScenario = process.env.HUNTWARDEN_E2E_FAUX_SCENARIO;
  if (!app.isPackaged && process.env.NODE_ENV === "test" && e2eScenario) {
    const { createE2eFauxModelBundle } = await import("../testing/e2e-faux-model.js");
    modelBundleFactory = () => createE2eFauxModelBundle(e2eScenario);
    diagnostic(`E2E Faux scenario enabled: ${e2eScenario}`);
  }
  const crashAt = process.env.HUNTWARDEN_E2E_CRASH_AT;
  if (!app.isPackaged && process.env.NODE_ENV === "test" && crashAt) {
    let fired = false;
    checkpoint = (name) => {
      if (fired || name !== crashAt) return;
      fired = true;
      diagnostic(`E2E crash checkpoint reached: ${name}`);
      process.exit(86);
    };
  }
  backend = new DesktopBackend({
    userDataDir: app.getPath("userData"),
    projectRoot: app.getAppPath(),
    appVersion: app.getVersion(),
    platform: process.platform,
    credentials: new DesktopCredentialStore(persistent),
    ...(labStateDir ? { labStateDir } : {}),
    ...(modelBundleFactory ? { modelBundleFactory } : {}),
    ...(checkpoint ? { checkpoint } : {}),
    ...(migratedFrom ? { legacyRuntimeDirs: [join(migratedFrom, "runtime")] } : {}),
  });
  try { await backend.initialize(); diagnostic("desktop backend initialized"); }
  catch (error) {
    await dialog.showMessageBox({ type: "error", title: "HuntWarden 启动失败", message: error instanceof Error ? error.message : String(error) });
    backendClosed = true;
    await backend.close().catch(() => undefined);
    app.quit();
    return;
  }
  registerIpc();
  diagnostic("IPC registered");
  backend.on("event", (event: DesktopEvent) => {
    const window = mainWindow;
    if (window && !window.isDestroyed()) window.webContents.send(IPC.event, event);
  });
  mainWindow = await createWindow();
  diagnostic("main window loaded");
  mainWindow.on("closed", () => { mainWindow = undefined; });
  app.on("activate", () => {
    const window = mainWindow;
    if ((!window || window.isDestroyed()) && !backendClosing && !backendClosed) {
      void createWindow().then((created) => {
        if (backendClosing || backendClosed) {
          if (!created.isDestroyed()) created.destroy();
          return;
        }
        mainWindow = created;
        created.on("closed", () => { if (mainWindow === created) mainWindow = undefined; });
      }).catch((error: unknown) => diagnostic(`window recreation failed: ${error instanceof Error ? error.message : String(error)}`));
    }
  });
  app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
  app.on("before-quit", (event) => {
    if (backendClosed) return;
    event.preventDefault();
    if (backendClosing) return;
    backendClosing = true;
    void (backend?.close() ?? Promise.resolve())
      .catch((error: unknown) => diagnostic(`backend close failed: ${error instanceof Error ? error.message : String(error)}`))
      .finally(() => { backendClosed = true; backendClosing = false; app.quit(); });
  });
}

if (lock) {
  app.on("second-instance", () => {
    const window = mainWindow;
    if (!window || window.isDestroyed() || backendClosing || backendClosed) return;
    if (window.isMinimized()) window.restore();
    window.focus();
  });
  void app.whenReady().then(bootstrapDesktop).catch(async (error: unknown) => {
    diagnostic(`startup failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    await dialog.showMessageBox({ type: "error", title: "HuntWarden 启动失败", message: error instanceof Error ? error.message : String(error) });
    backendClosed = true;
    await backend?.close().catch(() => undefined);
    app.quit();
  });
}
