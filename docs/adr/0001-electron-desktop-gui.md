# ADR-0001：使用 Electron 构建本地桌面 GUI

- 状态：Accepted
- 日期：2026-08-07

## 背景

HuntWarden 已有 Node.js/TypeScript 核心、React/Ink TUI、`node:sqlite`、`ssh2` 与 Pi Agent。GUI 需要安全访问本地文件、系统密钥存储、SQLite、SSH、报告和 Evidence，同时不能把这些高权限能力交给渲染层。

## 决策

采用 Electron 主进程承载现有核心，React Renderer 运行于隔离沙箱，Preload 仅暴露 `src/gui/contracts.ts` 定义的逐方法白名单。Vite 独立构建 Renderer，Electron Forge 负责打包。

不采用远程 Web GUI，因为它会新增本地 HTTP 服务、认证、CSRF、端口暴露和浏览器下载边界；不在首期采用 Tauri，因为现有 Node 高权限核心迁移到 Rust sidecar/command 边界会显著扩大首个 GUI 里程碑。

## 安全后果

- Renderer 视为不可信输入面，不能直接访问 Node、Electron、文件系统、数据库、SSH 或密钥。
- 主进程必须验证 sender、Schema、任务绑定和权限。
- API Key 使用系统加密能力保存，配置文件不含秘密。
- Electron/Chromium 成为新的安全更新责任，必须固定版本并建立升级回归。

## 兼容性后果

- 核心 Application、RuntimeStore、SecurityAgentRuntime 和 Tool 保持 UI 无关。
- TUI 与 CLI 继续存在，使用同一领域服务和事件模型。
- 首期打包优先 macOS，Linux 次之，Windows 延后。
