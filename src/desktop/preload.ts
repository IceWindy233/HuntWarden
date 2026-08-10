import { contextBridge, ipcRenderer } from "electron";
import type { DesktopEvent, HuntWardenDesktopApi } from "../gui/contracts.js";
import { IPC } from "../gui/channels.js";

const api: HuntWardenDesktopApi = {
  getBootstrap: async () => await ipcRenderer.invoke(IPC.bootstrap),
  listConfigProfiles: async () => await ipcRenderer.invoke(IPC.configList),
  getConfigProfile: async (profileId) => await ipcRenderer.invoke(IPC.configGet, profileId),
  validateConfigProfile: async (config) => await ipcRenderer.invoke(IPC.configValidate, config),
  saveConfigProfile: async (input) => await ipcRenderer.invoke(IPC.configSave, input),
  activateConfigProfile: async (profileId) => await ipcRenderer.invoke(IPC.configActivate, profileId),
  deleteConfigProfile: async (profileId) => await ipcRenderer.invoke(IPC.configDelete, profileId),
  importConfigProfile: async () => await ipcRenderer.invoke(IPC.configImport),
  exportConfigProfile: async (profileId) => await ipcRenderer.invoke(IPC.configExport, profileId),
  listModelProviders: async () => await ipcRenderer.invoke(IPC.modelProviders),
  listModels: async (provider) => await ipcRenderer.invoke(IPC.modelList, provider),
  getCredentialStatus: async (provider) => await ipcRenderer.invoke(IPC.credentialStatus, provider),
  saveCredential: async (input) => await ipcRenderer.invoke(IPC.credentialSave, input),
  deleteCredential: async (provider) => await ipcRenderer.invoke(IPC.credentialDelete, provider),
  checkModel: async (profileId) => await ipcRenderer.invoke(IPC.modelCheck, profileId),
  smokeModel: async (profileId) => await ipcRenderer.invoke(IPC.modelSmoke, profileId),
  testThreatIntel: async (profileId) => await ipcRenderer.invoke(IPC.threatIntelTest, profileId),
  selectPrivateKey: async () => await ipcRenderer.invoke(IPC.selectPrivateKey),
  selectKnownHosts: async () => await ipcRenderer.invoke(IPC.selectKnownHosts),
  discoverSshHostKey: async (input) => await ipcRenderer.invoke(IPC.sshHostKeyDiscover, input),
  confirmSshHostKey: async (input) => await ipcRenderer.invoke(IPC.sshHostKeyConfirm, input),
  testSshTarget: async (input) => await ipcRenderer.invoke(IPC.sshTest, input),
  listTasks: async () => await ipcRenderer.invoke(IPC.taskList),
  getTaskSnapshot: async (taskId) => await ipcRenderer.invoke(IPC.taskSnapshot, taskId),
  createTask: async (input) => await ipcRenderer.invoke(IPC.taskCreate, input),
  startTask: async (taskId) => await ipcRenderer.invoke(IPC.taskStart, taskId),
  abortTask: async (taskId) => await ipcRenderer.invoke(IPC.taskAbort, taskId),
  archiveTask: async (taskId) => await ipcRenderer.invoke(IPC.taskArchive, taskId),
  restoreTask: async (taskId) => await ipcRenderer.invoke(IPC.taskRestore, taskId),
  recoverTask: async (taskId) => await ipcRenderer.invoke(IPC.taskRecover, taskId),
  steerTask: async (input) => await ipcRenderer.invoke(IPC.taskSteer, input),
  decideApproval: async (input) => await ipcRenderer.invoke(IPC.approvalDecide, input),
  generateReport: async (taskId) => await ipcRenderer.invoke(IPC.reportGenerate, taskId),
  listReports: async (taskId) => await ipcRenderer.invoke(IPC.reportList, taskId),
  readReport: async (input) => await ipcRenderer.invoke(IPC.reportRead, input),
  revealEvidence: async (evidenceId) => await ipcRenderer.invoke(IPC.evidenceReveal, evidenceId),
  revealReport: async (input) => await ipcRenderer.invoke(IPC.reportReveal, input),
  subscribe: (listener) => {
    const wrapped = (_event: Electron.IpcRendererEvent, value: DesktopEvent) => listener(value);
    ipcRenderer.on(IPC.event, wrapped);
    return () => ipcRenderer.removeListener(IPC.event, wrapped);
  },
};

contextBridge.exposeInMainWorld("huntwarden", api);
